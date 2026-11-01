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
            schema_version: crate::model::REPORT_SCHEMA_VERSION,
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
    let datalink_config = nex::datalink::Config::default()
        .with_read_timeout(Some(timeout_window))
        .with_promiscuous(false);
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

    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "ARP request timed out").into())
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
    let datalink_config = nex::datalink::Config::default()
        .with_read_timeout(Some(timeout_window))
        .with_promiscuous(false);
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
                let Some(mac_address) = ndp_reply_mac(&frame, target_ip) else {
                    continue;
                };

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

    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "NDP request timed out").into())
}

fn ndp_reply_mac(frame: &Frame, target: Ipv6Addr) -> Option<netdev::MacAddr> {
    let ip = frame.ip.as_ref()?;
    let ipv6 = ip.ipv6.as_ref()?;
    let icmp = ip.icmpv6.as_ref()?;
    if ipv6.hop_limit != 255
        || icmp.icmpv6_type != Icmpv6Type::NeighborAdvertisement
        || icmp.icmpv6_code.0 != 0
        || target.is_multicast()
        || frame.payload.get(4..20) != Some(target.octets().as_slice())
    {
        return None;
    }
    let mut options = frame.payload.get(20..)?;
    let mut advertised = None;
    while !options.is_empty() {
        let length = usize::from(*options.get(1)?) * 8;
        if length == 0 || length > options.len() {
            return None;
        }
        if options[0] == 2 {
            if length != 8 {
                return None;
            }
            advertised = Some(netdev::MacAddr::new(
                options[2], options[3], options[4], options[5], options[6], options[7],
            ));
        }
        options = &options[length..];
    }
    advertised.or_else(|| {
        frame
            .datalink
            .as_ref()?
            .ethernet
            .as_ref()
            .map(|ethernet| ethernet.source)
    })
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

pub(crate) async fn destination_mac(
    interface: &netdev::Interface,
    address: IpAddr,
    timeout_window: Duration,
) -> std::io::Result<netdev::MacAddr> {
    if interface.is_loopback() || interface.is_tun() {
        return Ok(netdev::MacAddr::zero());
    }
    let next_hop = resolve_next_hop(interface, address);
    let result = match next_hop {
        IpAddr::V4(_) => discover_arp(interface, next_hop, timeout_window).await,
        IpAddr::V6(_) => discover_ndp(interface, next_hop, timeout_window).await,
    };
    result
        .map_err(|error| match error.downcast::<std::io::Error>() {
            Ok(error) => error,
            Err(error) => std::io::Error::other(error),
        })?
        .mac_address
        .parse()
        .map_err(std::io::Error::other)
}

/// Resolve each next hop once, with bounded concurrency for sparse subnets.
pub(crate) async fn destination_macs(
    interface: &netdev::Interface,
    addresses: &[IpAddr],
    timeout_window: Duration,
) -> std::io::Result<std::collections::HashMap<IpAddr, netdev::MacAddr>> {
    let next_hops: std::collections::HashSet<_> = addresses
        .iter()
        .map(|address| resolve_next_hop(interface, *address))
        .collect();
    let mut pending = futures::stream::iter(next_hops)
        .map(|address| async move {
            (
                address,
                destination_mac(interface, address, timeout_window).await,
            )
        })
        .buffer_unordered(16);
    let mut resolved = std::collections::HashMap::new();
    while let Some((address, result)) = pending.next().await {
        match result {
            Ok(mac) => {
                resolved.insert(address, mac);
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => return Err(error),
        }
    }
    Ok(addresses
        .iter()
        .filter_map(|address| {
            resolved
                .get(&resolve_next_hop(interface, *address))
                .map(|mac| (*address, *mac))
        })
        .collect())
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
    let IpAddr::V4(src_ip) = crate::interface::source_ip_for(interface, IpAddr::V4(dst_ip)) else {
        unreachable!("IPv4 source selection preserves the address family");
    };
    anyhow::ensure!(
        !src_ip.is_unspecified(),
        "interface does not have an IPv4 address"
    );
    let arp = ArpPacketBuilder::new(src_mac, src_ip, dst_ip)
        .operation(ArpOperation::Request)
        .build()?;
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
    let octets = dst_ip.octets();
    let multicast = Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(octets[13]),
        u16::from_be_bytes([octets[14], octets[15]]),
    );
    let dst_mac = ipv6_multicast_mac(multicast);
    let mut ndp = NdpPacketBuilder::new(src_mac, src_ip, dst_ip)
        .dst_mac(dst_mac)
        .build()?;
    ndp.header.checksum = nex::packet::icmpv6::checksum(&ndp, &src_ip, &multicast);
    let ipv6 = Ipv6PacketBuilder::new()
        .source(src_ip)
        .destination(multicast)
        .next_header(IpNextProtocol::Icmpv6)
        .hop_limit(255)
        .payload(ndp.to_bytes())
        .build()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use nex::packet::{icmpv6::Icmpv6Packet, packet::Packet};

    #[test]
    fn ndp_reply_validates_target_hop_limit_and_options() {
        let mut interface = netdev::Interface::dummy();
        interface.mac_addr = Some("02:00:00:00:00:01".parse().unwrap());
        let target: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let packet = build_ndp_packet(&interface, "fe80::1".parse().unwrap(), target).unwrap();
        let mut reply = Frame::from_buf(&packet, Default::default()).unwrap();
        reply
            .ip
            .as_mut()
            .unwrap()
            .icmpv6
            .as_mut()
            .unwrap()
            .icmpv6_type = Icmpv6Type::NeighborAdvertisement;
        let mut payload = reply.payload.to_vec();
        payload[20] = 2;
        reply.payload = payload.clone().into();
        assert_eq!(ndp_reply_mac(&reply, target), interface.mac_addr);
        assert!(ndp_reply_mac(&reply, "2001:db8::3".parse().unwrap()).is_none());
        reply.ip.as_mut().unwrap().ipv6.as_mut().unwrap().hop_limit = 64;
        assert!(ndp_reply_mac(&reply, target).is_none());
        reply.ip.as_mut().unwrap().ipv6.as_mut().unwrap().hop_limit = 255;
        payload[21] = 0;
        reply.payload = payload.into();
        assert!(ndp_reply_mac(&reply, target).is_none());
    }

    #[test]
    fn solicitation_uses_solicited_node_multicast_and_matching_checksum() {
        let mut interface = netdev::Interface::dummy();
        interface.mac_addr = Some("02:00:00:00:00:01".parse().unwrap());
        let source = "fe80::1".parse().unwrap();
        let target = "2001:db8::1234:5678".parse().unwrap();
        let multicast = "ff02::1:ff34:5678".parse().unwrap();
        let packet = build_ndp_packet(&interface, source, target).unwrap();
        assert_eq!(&packet[..6], &[0x33, 0x33, 0xff, 0x34, 0x56, 0x78]);
        let frame = Frame::from_buf(&packet, Default::default()).unwrap();
        let ip = frame.ip.unwrap();
        let ipv6 = ip.ipv6.unwrap();
        assert_eq!(ipv6.destination, multicast);
        assert_eq!(ipv6.hop_limit, 255);
        let icmp =
            Icmpv6Packet::try_from_bytes(bytes::Bytes::copy_from_slice(&packet[54..])).unwrap();
        assert_eq!(
            icmp.header.checksum,
            nex::packet::icmpv6::checksum(&icmp, &source, &multicast)
        );
        assert_eq!(&icmp.to_bytes()[8..24], &target.octets());
    }

    #[test]
    fn on_link_targets_do_not_use_the_gateway() {
        let mut interface = netdev::Interface::dummy();
        interface.ipv4.push("192.0.2.1/24".parse().unwrap());
        interface.ipv6.push("2001:db8::1/64".parse().unwrap());
        for address in ["192.0.2.2", "2001:db8::2"] {
            let address = address.parse().unwrap();
            assert_eq!(resolve_next_hop(&interface, address), address);
        }
    }
}
