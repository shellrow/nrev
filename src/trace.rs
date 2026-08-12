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
use nex::packet::frame::Frame;
use nex::packet::{icmp::IcmpType, icmpv6::Icmpv6Type, packet::Packet};
use tokio::time::timeout;
use tracing::info;

use crate::{
    config::TraceConfig,
    host::resolve_host_targets,
    model::{Target, TraceHop, TraceMetadata, TraceMethod, TraceReport},
};

const TRACE_SOURCE_PORT: u16 = 53445;

pub async fn run_trace(input: &str, config: &TraceConfig) -> Result<TraceReport> {
    let target = resolve_single_target(input)?;
    let interface = resolve_interface(config.interface.as_deref())?;
    let datalink_config = nex::datalink::Config::default()
        .with_read_timeout(Some(config.timeout))
        .with_promiscuous(false);
    let nex_interface = NexInterface::from(interface.clone());
    let AsyncChannel::Ethernet(mut tx, mut rx) =
        async_channel(&nex_interface, datalink_config).map_err(std::io::Error::other)?
    else {
        anyhow::bail!("unsupported datalink channel");
    };
    let parse_option = capture_parse_option(&interface);
    let started = std::time::Instant::now();
    let mut hops = Vec::new();

    for ttl in 1..=config.max_hops {
        let packet = match config.method {
            TraceMethod::Udp => build_udp_trace_packet(
                &interface,
                target.address,
                config.port.unwrap_or(33435),
                ttl,
            )?,
            TraceMethod::Icmp => build_icmp_trace_packet(&interface, target.address, ttl)?,
        };
        let send_started = std::time::Instant::now();
        poll_fn(|cx| tx.poll_send(cx, &packet))
            .await
            .map_err(std::io::Error::other)?;

        let mut hop = TraceHop {
            ttl,
            responder: None,
            outcome: "timeout".to_string(),
            reached_destination: false,
            latency: None,
            ttl_hint: None,
            mac_address: None,
        };

        while send_started.elapsed() < config.timeout {
            let remaining = config.timeout.saturating_sub(send_started.elapsed());
            match timeout(remaining, rx.next()).await {
                Ok(Some(Ok(frame_bytes))) => {
                    let Some(frame) = Frame::from_buf(&frame_bytes, parse_option.clone()) else {
                        continue;
                    };
                    if let Some(candidate) = parse_trace_frame(
                        config.method,
                        target.address,
                        ttl,
                        &frame,
                        send_started.elapsed(),
                    ) {
                        hop = candidate;
                        break;
                    }
                }
                Ok(Some(Err(error))) => {
                    hop.outcome = error.to_string();
                    break;
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        let reached = hop.reached_destination;
        log_trace_hop(config.method, &hop);
        hops.push(hop);
        if reached {
            break;
        }
        if ttl != config.max_hops && !config.interval.is_zero() {
            tokio::time::sleep(config.interval).await;
        }
    }

    let errors = if hops.iter().any(|hop| hop.reached_destination) {
        Vec::new()
    } else {
        vec!["trace did not reach the destination".to_string()]
    };

    Ok(TraceReport {
        metadata: TraceMetadata {
            schema_version: crate::model::REPORT_SCHEMA_VERSION,
            version: env!("CARGO_PKG_VERSION").to_string(),
            target,
            method: config.method,
            port: config.port,
            max_hops: config.max_hops,
            generated_at: Utc::now(),
            total: Some(started.elapsed()),
        },
        hops,
        errors,
    })
}

fn parse_trace_frame(
    method: TraceMethod,
    target: IpAddr,
    ttl: u8,
    frame: &Frame,
    latency: Duration,
) -> Option<TraceHop> {
    let ip = frame.ip.as_ref()?;
    let mac = frame.datalink.as_ref().and_then(|datalink| {
        datalink
            .ethernet
            .as_ref()
            .map(|ethernet| ethernet.source.to_string())
    });

    if let Some(ipv4) = &ip.ipv4 {
        let responder = IpAddr::V4(ipv4.source);
        let ttl_hint = Some(ipv4.ttl);
        let icmp = ip.icmp.as_ref()?;
        match icmp.icmp_type {
            IcmpType::TimeExceeded => {
                return Some(TraceHop {
                    ttl,
                    responder: Some(responder),
                    outcome: "time-exceeded".to_string(),
                    reached_destination: false,
                    latency: Some(latency),
                    ttl_hint,
                    mac_address: mac,
                });
            }
            IcmpType::DestinationUnreachable
                if method == TraceMethod::Udp && responder == target =>
            {
                return Some(TraceHop {
                    ttl,
                    responder: Some(responder),
                    outcome: "destination-unreachable".to_string(),
                    reached_destination: true,
                    latency: Some(latency),
                    ttl_hint,
                    mac_address: mac,
                });
            }
            IcmpType::EchoReply if method == TraceMethod::Icmp && responder == target => {
                return Some(TraceHop {
                    ttl,
                    responder: Some(responder),
                    outcome: "echo-reply".to_string(),
                    reached_destination: true,
                    latency: Some(latency),
                    ttl_hint,
                    mac_address: mac,
                });
            }
            _ => {}
        }
    }

    if let Some(ipv6) = &ip.ipv6 {
        let responder = IpAddr::V6(ipv6.source);
        let ttl_hint = Some(ipv6.hop_limit);
        let icmpv6 = ip.icmpv6.as_ref()?;
        match icmpv6.icmpv6_type {
            Icmpv6Type::TimeExceeded => {
                return Some(TraceHop {
                    ttl,
                    responder: Some(responder),
                    outcome: "time-exceeded".to_string(),
                    reached_destination: false,
                    latency: Some(latency),
                    ttl_hint,
                    mac_address: mac,
                });
            }
            Icmpv6Type::DestinationUnreachable
                if method == TraceMethod::Udp && responder == target =>
            {
                return Some(TraceHop {
                    ttl,
                    responder: Some(responder),
                    outcome: "destination-unreachable".to_string(),
                    reached_destination: true,
                    latency: Some(latency),
                    ttl_hint,
                    mac_address: mac,
                });
            }
            Icmpv6Type::EchoReply if method == TraceMethod::Icmp && responder == target => {
                return Some(TraceHop {
                    ttl,
                    responder: Some(responder),
                    outcome: "echo-reply".to_string(),
                    reached_destination: true,
                    latency: Some(latency),
                    ttl_hint,
                    mac_address: mac,
                });
            }
            _ => {}
        }
    }

    None
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

fn build_icmp_trace_packet(
    interface: &netdev::Interface,
    dst_ip: IpAddr,
    ttl: u8,
) -> Result<Vec<u8>> {
    use nex::packet::builder::{
        ethernet::EthernetPacketBuilder, icmp::IcmpPacketBuilder, icmpv6::Icmpv6PacketBuilder,
        ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder,
    };
    use nex::packet::{ethernet::EtherType, ip::IpNextProtocol, ipv4::Ipv4Flags};

    let src_mac = interface.mac_addr.unwrap_or(netdev::MacAddr::zero());
    let dst_mac = interface
        .gateway
        .as_ref()
        .map(|gateway| gateway.mac_addr)
        .unwrap_or(netdev::MacAddr::zero());
    let src_ip = source_ip_for(interface, dst_ip);
    let ip_only = interface.is_tun() || interface.is_loopback();

    let ip_packet = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let icmp = IcmpPacketBuilder::new(src, dst)
                .echo_fields(0x4e52, ttl as u16)
                .build()?;
            Ipv4PacketBuilder::new()
                .source(src)
                .destination(dst)
                .protocol(IpNextProtocol::Icmp)
                .flags(Ipv4Flags::DontFragment)
                .ttl(ttl)
                .payload(icmp.to_bytes())
                .build()?
                .to_bytes()
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let icmp = Icmpv6PacketBuilder::new(src, dst)
                .echo_fields(0x4e52, ttl as u16)
                .build()?;
            Ipv6PacketBuilder::new()
                .source(src)
                .destination(dst)
                .next_header(nex::packet::ip::IpNextProtocol::Icmpv6)
                .hop_limit(ttl)
                .payload(icmp.to_bytes())
                .build()?
                .to_bytes()
        }
        _ => anyhow::bail!("mismatched address family"),
    };

    let ethernet = EthernetPacketBuilder::new()
        .source(if ip_only {
            netdev::MacAddr::zero()
        } else {
            src_mac
        })
        .destination(if ip_only {
            netdev::MacAddr::zero()
        } else {
            dst_mac
        })
        .ethertype(match dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    Ok(if ip_only {
        ethernet
            .ip_packet()
            .context("failed to extract IP packet")?
            .to_vec()
    } else {
        ethernet.to_bytes().to_vec()
    })
}

fn build_udp_trace_packet(
    interface: &netdev::Interface,
    dst_ip: IpAddr,
    dst_port: u16,
    ttl: u8,
) -> Result<Vec<u8>> {
    use nex::packet::builder::{
        ethernet::EthernetPacketBuilder, ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder,
        udp::UdpPacketBuilder,
    };
    use nex::packet::{ethernet::EtherType, ip::IpNextProtocol, ipv4::Ipv4Flags};

    let src_mac = interface.mac_addr.unwrap_or(netdev::MacAddr::zero());
    let dst_mac = interface
        .gateway
        .as_ref()
        .map(|gateway| gateway.mac_addr)
        .unwrap_or(netdev::MacAddr::zero());
    let src_ip = source_ip_for(interface, dst_ip);
    let ip_only = interface.is_tun() || interface.is_loopback();
    let udp = UdpPacketBuilder::new(src_ip, dst_ip)
        .source(TRACE_SOURCE_PORT)
        .destination(dst_port)
        .build()?;

    let ip_packet = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ipv4PacketBuilder::new()
            .source(src)
            .destination(dst)
            .protocol(IpNextProtocol::Udp)
            .flags(Ipv4Flags::DontFragment)
            .ttl(ttl)
            .payload(udp.to_bytes())
            .build()?
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .next_header(IpNextProtocol::Udp)
            .hop_limit(ttl)
            .payload(udp.to_bytes())
            .build()?
            .to_bytes(),
        _ => anyhow::bail!("mismatched address family"),
    };

    let ethernet = EthernetPacketBuilder::new()
        .source(if ip_only {
            netdev::MacAddr::zero()
        } else {
            src_mac
        })
        .destination(if ip_only {
            netdev::MacAddr::zero()
        } else {
            dst_mac
        })
        .ethertype(match dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    Ok(if ip_only {
        ethernet
            .ip_packet()
            .context("failed to extract IP packet")?
            .to_vec()
    } else {
        ethernet.to_bytes().to_vec()
    })
}

fn source_ip_for(interface: &netdev::Interface, dst_ip: IpAddr) -> IpAddr {
    match dst_ip {
        IpAddr::V4(_) => interface
            .ipv4
            .first()
            .map(|ip| IpAddr::V4(ip.addr()))
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        IpAddr::V6(_) => interface
            .ipv6
            .first()
            .map(|ip| IpAddr::V6(ip.addr()))
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
    }
}

fn log_trace_hop(_method: TraceMethod, hop: &TraceHop) {
    let rtt = hop
        .latency
        .map(|value| format!("{}ms", value.as_millis()))
        .unwrap_or_else(|| "-".to_string());
    let ttl = hop
        .ttl_hint
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    let src = hop
        .responder
        .map(|value| value.to_string())
        .unwrap_or_else(|| "*".to_string());
    let hop_type = if hop.reached_destination {
        "destination"
    } else if hop.ttl == 1 {
        "gateway"
    } else {
        "hop"
    };
    info!(
        "#{} Reply from {} type={} TTL: {} RTT: {}",
        hop.ttl, src, hop_type, ttl, rtt
    );
}
