use crate::interface::source_ip_for;
use std::{net::IpAddr, time::Duration};

use anyhow::{Context, Result};
use chrono::Utc;
use futures::StreamExt;
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
    let dst_mac =
        crate::neighbor::destination_mac(&interface, target.address, config.timeout).await?;
    let started = std::time::Instant::now();
    let mut hops = Vec::new();

    let probe_id = 49_152 + rand::random::<u16>() % 16_000;
    for ttl in 1..=config.max_hops {
        let packet = match config.method {
            TraceMethod::Udp => build_udp_trace_packet(
                &interface,
                target.address,
                config.port.unwrap_or(33435),
                ttl,
                dst_mac,
                probe_id,
            )?,
            TraceMethod::Icmp => {
                build_icmp_trace_packet(&interface, target.address, ttl, dst_mac, probe_id)?
            }
        };
        let send_started = std::time::Instant::now();
        crate::capture::send_packet(&mut *tx, &interface, &packet)
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
                        &packet[14..],
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
    sent_ip: &[u8],
) -> Option<TraceHop> {
    let ip = frame.ip.as_ref()?;
    let echo_reply = ip
        .icmp
        .as_ref()
        .is_some_and(|icmp| icmp.icmp_type == IcmpType::EchoReply)
        || ip
            .icmpv6
            .as_ref()
            .is_some_and(|icmp| icmp.icmpv6_type == Icmpv6Type::EchoReply);
    if echo_reply {
        let offset = ip_transport_offset(sent_ip)?;
        if frame.payload.get(..4) != sent_ip.get(offset + 4..offset + 8) {
            return None;
        }
    } else if !quoted_probe_matches(frame.payload.get(4..)?, sent_ip) {
        return None;
    }
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
                if method == TraceMethod::Udp && responder == target && icmp.icmp_code.0 == 3 =>
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
                if method == TraceMethod::Udp
                    && responder == target
                    && icmpv6.icmpv6_code.0 == 4 =>
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
    dst_mac: netdev::MacAddr,
    probe_id: u16,
) -> Result<Vec<u8>> {
    use nex::packet::builder::{
        ethernet::EthernetPacketBuilder, icmp::IcmpPacketBuilder, icmpv6::Icmpv6PacketBuilder,
        ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder,
    };
    use nex::packet::{ethernet::EtherType, ip::IpNextProtocol, ipv4::Ipv4Flags};

    let src_mac = interface.mac_addr.unwrap_or(netdev::MacAddr::zero());

    let src_ip = source_ip_for(interface, dst_ip);

    let ip_packet = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let icmp = IcmpPacketBuilder::new(src, dst)
                .echo_fields(probe_id, ttl as u16)
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
                .echo_fields(probe_id, ttl as u16)
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
        .source(src_mac)
        .destination(dst_mac)
        .ethertype(match dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    Ok(ethernet.to_bytes().to_vec())
}

fn build_udp_trace_packet(
    interface: &netdev::Interface,
    dst_ip: IpAddr,
    dst_port: u16,
    ttl: u8,
    dst_mac: netdev::MacAddr,
    probe_id: u16,
) -> Result<Vec<u8>> {
    use nex::packet::builder::{
        ethernet::EthernetPacketBuilder, ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder,
        udp::UdpPacketBuilder,
    };
    use nex::packet::{ethernet::EtherType, ip::IpNextProtocol, ipv4::Ipv4Flags};

    let src_mac = interface.mac_addr.unwrap_or(netdev::MacAddr::zero());

    let src_ip = source_ip_for(interface, dst_ip);
    let udp = UdpPacketBuilder::new(src_ip, dst_ip)
        .source(probe_id.wrapping_add(u16::from(ttl)))
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
        .source(src_mac)
        .destination(dst_mac)
        .ethertype(match dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    Ok(ethernet.to_bytes().to_vec())
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

// ICMP errors may quote only the IP header and eight transport bytes.
fn ip_transport_offset(packet: &[u8]) -> Option<usize> {
    let offset = match packet.first()? >> 4 {
        4 => usize::from(packet[0] & 0x0f) * 4,
        6 => 40,
        _ => return None,
    };
    (offset >= 20 && packet.len() >= offset + 8).then_some(offset)
}

fn quoted_probe_matches(quoted: &[u8], sent: &[u8]) -> bool {
    let (Some(q), Some(s)) = (ip_transport_offset(quoted), ip_transport_offset(sent)) else {
        return false;
    };
    if quoted[0] >> 4 != sent[0] >> 4 {
        return false;
    }
    let addresses_match = if sent[0] >> 4 == 4 {
        quoted[9] == sent[9] && quoted[12..20] == sent[12..20]
    } else {
        quoted[6] == sent[6] && quoted[8..40] == sent[8..40]
    };
    // Kernels may clear an offloaded UDP checksum in the quoted packet.
    // The per-run source port, destination port, and length identify the probe.
    let protocol = if sent[0] >> 4 == 4 { sent[9] } else { sent[6] };
    let length = if protocol == 17 { 6 } else { 8 };
    addresses_match && quoted[q..q + length] == sent[s..s + length]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_packets_keep_the_ethernet_header_required_by_datalink() {
        let mut interface = netdev::Interface::dummy();
        interface.flags = nex::net::interface::IFF_LOOPBACK;
        interface.ipv4.push("127.0.0.1/8".parse().unwrap());
        interface.ipv6.push("::1/128".parse().unwrap());
        for address in ["127.0.0.1", "::1"] {
            let address: IpAddr = address.parse().unwrap();
            let packet =
                build_icmp_trace_packet(&interface, address, 1, netdev::MacAddr::zero(), 123)
                    .unwrap();
            let frame = Frame::from_buf(&packet, Default::default()).unwrap();
            assert!(frame.datalink.unwrap().ethernet.is_some());
            let ip = frame.ip.unwrap();
            assert!(ip.icmp.is_some() || ip.icmpv6.is_some());

            let packet = build_udp_trace_packet(
                &interface,
                address,
                33435,
                1,
                netdev::MacAddr::zero(),
                53445,
            )
            .unwrap();
            assert!(
                Frame::from_buf(&packet, Default::default())
                    .unwrap()
                    .transport
                    .unwrap()
                    .udp
                    .is_some()
            );
        }
    }

    #[test]
    fn trace_rejects_unrelated_truncated_and_stale_icmp_errors() {
        let mut interface = netdev::Interface::dummy();
        interface.ipv4.push("192.0.2.1/24".parse().unwrap());
        interface.ipv6.push("2001:db8::1/64".parse().unwrap());
        for target in ["192.0.2.2", "2001:db8::2"] {
            let target = target.parse().unwrap();
            let packet = build_udp_trace_packet(
                &interface,
                target,
                33435,
                1,
                netdev::MacAddr::zero(),
                53445,
            )
            .unwrap();
            let sent = &packet[14..];
            let offset = ip_transport_offset(sent).unwrap();
            assert!(quoted_probe_matches(&sent[..offset + 8], sent));
            let mut offloaded = sent.to_vec();
            offloaded[offset + 6..offset + 8].fill(0);
            assert!(quoted_probe_matches(&offloaded, sent));
            assert!(!quoted_probe_matches(&sent[..offset + 7], sent));
            let stale = build_udp_trace_packet(
                &interface,
                target,
                33435,
                2,
                netdev::MacAddr::zero(),
                53445,
            )
            .unwrap();
            assert!(!quoted_probe_matches(&stale[14..], sent));
            let unrelated = build_udp_trace_packet(
                &interface,
                target,
                33436,
                1,
                netdev::MacAddr::zero(),
                53445,
            )
            .unwrap();
            assert!(!quoted_probe_matches(&unrelated[14..], sent));

            let other_run = build_udp_trace_packet(
                &interface,
                target,
                33435,
                1,
                netdev::MacAddr::zero(),
                53446,
            )
            .unwrap();
            assert!(!quoted_probe_matches(&other_run[14..], sent));
            let outer =
                build_icmp_trace_packet(&interface, target, 1, netdev::MacAddr::zero(), 53445)
                    .unwrap();
            let mut frame = Frame::from_buf(&outer, Default::default()).unwrap();
            let ip = frame.ip.as_mut().unwrap();
            if let Some(ipv4) = ip.ipv4.as_mut() {
                ipv4.source = match target {
                    IpAddr::V4(ip) => ip,
                    _ => unreachable!(),
                };
                let icmp = ip.icmp.as_mut().unwrap();
                icmp.icmp_type = IcmpType::DestinationUnreachable;
                icmp.icmp_code.0 = 3;
            } else {
                ip.ipv6.as_mut().unwrap().source = match target {
                    IpAddr::V6(ip) => ip,
                    _ => unreachable!(),
                };
                let icmp = ip.icmpv6.as_mut().unwrap();
                icmp.icmpv6_type = Icmpv6Type::DestinationUnreachable;
                icmp.icmpv6_code.0 = 4;
            }
            frame.payload = [vec![0; 4], sent.to_vec()].concat().into();
            assert!(
                parse_trace_frame(TraceMethod::Udp, target, 1, &frame, Duration::ZERO, sent)
                    .unwrap()
                    .reached_destination
            );
            frame.payload = [vec![0; 4], unrelated[14..].to_vec()].concat().into();
            assert!(
                parse_trace_frame(TraceMethod::Udp, target, 1, &frame, Duration::ZERO, sent)
                    .is_none()
            );
        }
    }
}
