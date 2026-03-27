use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::Utc;
use futures::StreamExt;
use futures::future::poll_fn;
use nex::datalink::async_io::{AsyncChannel, async_channel};
use nex::net::interface::Interface as NexInterface;
use nex::packet::{arp::ArpOperation, frame::Frame, icmpv6::Icmpv6Type};
use tokio::time::timeout;

use crate::{
    config::NeighborConfig,
    host::resolve_host_targets,
    model::{NeighborMetadata, NeighborMethod, NeighborReport, NeighborResolution, Target},
};

pub async fn resolve_neighbor(input: &str, config: &NeighborConfig) -> Result<NeighborReport> {
    let target = resolve_single_target(input)?;
    let interface = resolve_interface(config.interface.as_deref())?;
    let method = match (config.method, target.address) {
        (Some(NeighborMethod::Arp), IpAddr::V6(_)) => {
            anyhow::bail!("ARP can only be used with IPv4 targets")
        }
        (Some(NeighborMethod::Ndp), IpAddr::V4(_)) => {
            anyhow::bail!("NDP can only be used with IPv6 targets")
        }
        (Some(method), _) => method,
        (None, IpAddr::V4(_)) => NeighborMethod::Arp,
        (None, IpAddr::V6(_)) => NeighborMethod::Ndp,
    };

    let result = match method {
        NeighborMethod::Arp => discover_arp(&interface, target.address, config.timeout).await?,
        NeighborMethod::Ndp => discover_ndp(&interface, target.address, config.timeout).await?,
    };

    Ok(NeighborReport {
        metadata: NeighborMetadata {
            version: env!("CARGO_PKG_VERSION").to_string(),
            target,
            method,
            generated_at: Utc::now(),
        },
        result: Some(result),
        errors: Vec::new(),
    })
}

async fn discover_arp(
    interface: &netdev::Interface,
    address: IpAddr,
    timeout_window: Duration,
) -> Result<NeighborResolution> {
    let target_ip = match resolve_next_hop(interface, address) {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => anyhow::bail!("ARP requires an IPv4 target"),
    };
    let packet = build_arp_packet(interface, target_ip)?;
    let datalink_config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(timeout_window),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let nex_interface = NexInterface::from(interface.clone());
    let AsyncChannel::Ethernet(mut tx, mut rx) =
        async_channel(&nex_interface, datalink_config).map_err(std::io::Error::other)?
    else {
        anyhow::bail!("unsupported datalink channel");
    };

    let started = std::time::Instant::now();
    poll_fn(|cx| tx.poll_send(cx, &packet))
        .await
        .map_err(std::io::Error::other)?;

    while started.elapsed() < timeout_window {
        let remaining = timeout_window.saturating_sub(started.elapsed());
        match timeout(remaining, rx.next()).await {
            Ok(Some(Ok(frame_bytes))) => {
                let Some(frame) =
                    Frame::from_buf(&frame_bytes, nex::packet::frame::ParseOption::default())
                else {
                    continue;
                };
                let Some(datalink) = &frame.datalink else {
                    continue;
                };
                let Some(arp) = &datalink.arp else {
                    continue;
                };
                if arp.operation == ArpOperation::Reply && arp.sender_proto_addr == target_ip {
                    return Ok(NeighborResolution {
                        resolved_ip: IpAddr::V4(target_ip),
                        mac_address: arp.sender_hw_addr.to_string(),
                        latency: started.elapsed(),
                        interface_name: interface.name.clone(),
                        interface_friendly_name: interface.friendly_name.clone(),
                        interface_index: interface.index,
                    });
                }
            }
            Ok(Some(Err(error))) => return Err(anyhow::Error::new(error)),
            Ok(None) => break,
            Err(_) => break,
        }
    }

    anyhow::bail!("ARP request timed out")
}

async fn discover_ndp(
    interface: &netdev::Interface,
    address: IpAddr,
    timeout_window: Duration,
) -> Result<NeighborResolution> {
    let target_ip = match resolve_next_hop(interface, address) {
        IpAddr::V6(ip) => ip,
        IpAddr::V4(_) => anyhow::bail!("NDP requires an IPv6 target"),
    };
    let src_ip = interface
        .ipv6
        .iter()
        .map(|network| network.addr())
        .find(|ip| ip.is_unicast_link_local())
        .or_else(|| interface.ipv6.first().map(|network| network.addr()))
        .context("interface does not have an IPv6 address")?;
    let packet = build_ndp_packet(interface, src_ip, target_ip)?;
    let datalink_config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(timeout_window),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let nex_interface = NexInterface::from(interface.clone());
    let AsyncChannel::Ethernet(mut tx, mut rx) =
        async_channel(&nex_interface, datalink_config).map_err(std::io::Error::other)?
    else {
        anyhow::bail!("unsupported datalink channel");
    };
    let parse_option = capture_parse_option(interface);

    let started = std::time::Instant::now();
    poll_fn(|cx| tx.poll_send(cx, &packet))
        .await
        .map_err(std::io::Error::other)?;

    while started.elapsed() < timeout_window {
        let remaining = timeout_window.saturating_sub(started.elapsed());
        match timeout(remaining, rx.next()).await {
            Ok(Some(Ok(frame_bytes))) => {
                let Some(frame) = Frame::from_buf(&frame_bytes, parse_option.clone()) else {
                    continue;
                };
                let Some(ip) = &frame.ip else {
                    continue;
                };
                let Some(ipv6) = &ip.ipv6 else {
                    continue;
                };
                let Some(icmpv6) = &ip.icmpv6 else {
                    continue;
                };
                if icmpv6.icmpv6_type != Icmpv6Type::NeighborAdvertisement
                    || ipv6.source != target_ip
                {
                    continue;
                }
                let mac_address = frame
                    .datalink
                    .as_ref()
                    .and_then(|datalink| datalink.ethernet.as_ref().map(|ethernet| ethernet.source))
                    .context("failed to extract target MAC address from NDP reply")?;

                return Ok(NeighborResolution {
                    resolved_ip: IpAddr::V6(target_ip),
                    mac_address: mac_address.to_string(),
                    latency: started.elapsed(),
                    interface_name: interface.name.clone(),
                    interface_friendly_name: interface.friendly_name.clone(),
                    interface_index: interface.index,
                });
            }
            Ok(Some(Err(error))) => return Err(anyhow::Error::new(error)),
            Ok(None) => break,
            Err(_) => break,
        }
    }

    anyhow::bail!("NDP request timed out")
}

fn resolve_single_target(input: &str) -> Result<Target> {
    resolve_host_targets(&[input.to_string()])?
        .into_iter()
        .next()
        .with_context(|| format!("failed to resolve {input}"))
}

fn resolve_interface(name: Option<&str>) -> Result<netdev::Interface> {
    if let Some(name) = name {
        crate::interface::get_interface_by_name(name.to_string())
            .with_context(|| format!("interface not found: {name}"))
    } else {
        netdev::get_default_interface().map_err(anyhow::Error::msg)
    }
}

fn resolve_next_hop(interface: &netdev::Interface, address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            if interface
                .ipv4
                .iter()
                .any(|network| network.contains(&address))
            {
                IpAddr::V4(address)
            } else {
                interface
                    .gateway
                    .as_ref()
                    .and_then(|gateway| gateway.ipv4.first().copied())
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V4(address))
            }
        }
        IpAddr::V6(address) => {
            if interface
                .ipv6
                .iter()
                .any(|network| network.contains(&address))
            {
                IpAddr::V6(address)
            } else {
                interface
                    .gateway
                    .as_ref()
                    .and_then(|gateway| gateway.ipv6.first().copied())
                    .map(IpAddr::V6)
                    .unwrap_or(IpAddr::V6(address))
            }
        }
    }
}

fn capture_parse_option(interface: &netdev::Interface) -> nex::packet::frame::ParseOption {
    let mut parse_option = nex::packet::frame::ParseOption::default();
    if interface.is_tun()
        || (cfg!(any(target_os = "macos", target_os = "ios")) && interface.is_loopback())
    {
        parse_option.from_ip_packet = true;
        parse_option.offset = if interface.is_loopback() { 14 } else { 0 };
    }
    parse_option
}

fn build_arp_packet(interface: &netdev::Interface, dst_ip: Ipv4Addr) -> Result<Vec<u8>> {
    use nex::packet::builder::{arp::ArpPacketBuilder, ethernet::EthernetPacketBuilder};
    use nex::packet::{ethernet::EtherType, packet::Packet};

    let src_mac = interface.mac_addr.unwrap_or(netdev::MacAddr::zero());
    let src_ip = interface
        .ipv4
        .first()
        .map(|network| network.addr())
        .context("interface does not have an IPv4 address")?;
    let arp = ArpPacketBuilder::new(src_mac, src_ip, dst_ip)
        .operation(ArpOperation::Request)
        .build();
    let ethernet = EthernetPacketBuilder::new()
        .source(src_mac)
        .destination(netdev::MacAddr::broadcast())
        .ethertype(EtherType::Arp)
        .payload(arp.to_bytes())
        .build();
    Ok(ethernet.to_bytes().to_vec())
}

fn build_ndp_packet(
    interface: &netdev::Interface,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
) -> Result<Vec<u8>> {
    use nex::packet::builder::{
        ethernet::EthernetPacketBuilder, ipv6::Ipv6PacketBuilder, ndp::NdpPacketBuilder,
    };
    use nex::packet::{ethernet::EtherType, ip::IpNextProtocol, packet::Packet};

    let src_mac = interface.mac_addr.unwrap_or(netdev::MacAddr::zero());
    let dst_mac = ipv6_multicast_mac(dst_ip);
    let ndp = NdpPacketBuilder::new(src_mac, src_ip, dst_ip)
        .dst_mac(dst_mac)
        .build();
    let ipv6 = Ipv6PacketBuilder::new()
        .source(src_ip)
        .destination(dst_ip)
        .next_header(IpNextProtocol::Icmpv6)
        .hop_limit(255)
        .payload(ndp.to_bytes())
        .build();
    let ethernet = EthernetPacketBuilder::new()
        .source(src_mac)
        .destination(dst_mac)
        .ethertype(EtherType::Ipv6)
        .payload(ipv6.to_bytes())
        .build();
    Ok(ethernet.to_bytes().to_vec())
}

fn ipv6_multicast_mac(ip: Ipv6Addr) -> netdev::MacAddr {
    let segments = ip.segments();
    netdev::MacAddr::new(
        0x33,
        0x33,
        ((segments[6] >> 8) & 0xff) as u8,
        (segments[6] & 0xff) as u8,
        ((segments[7] >> 8) & 0xff) as u8,
        (segments[7] & 0xff) as u8,
    )
}
