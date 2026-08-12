use std::{
    net::{IpAddr, SocketAddr},
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
    config::PingConfig,
    host::resolve_host_targets,
    model::{PingMetadata, PingMethod, PingReply, PingReport, PingSummary, Target, Transport},
    transport::{Connector, SocketConnector},
};

pub async fn run_ping(input: &str, config: &PingConfig) -> Result<PingReport> {
    let target = resolve_single_target(input)?;
    let started = std::time::Instant::now();
    let replies = match config.method {
        PingMethod::Icmp => run_icmp_ping(&target, config).await?,
        PingMethod::Udp => run_udp_ping(&target, config).await,
        PingMethod::Tcp => run_tcp_ping(&target, config).await,
        PingMethod::Quic => run_quic_ping(&target, config).await,
    };

    let received = replies.iter().filter(|reply| reply.success).count() as u32;
    let latencies = replies
        .iter()
        .filter_map(|reply| reply.latency)
        .collect::<Vec<_>>();
    let min = latencies.iter().copied().min();
    let max = latencies.iter().copied().max();
    let avg = (!latencies.is_empty()).then(|| {
        latencies
            .iter()
            .copied()
            .fold(Duration::ZERO, |acc, value| acc + value)
            / (latencies.len() as u32)
    });
    let errors = if received == 0 {
        vec![format!(
            "{} ping did not receive any reply",
            config.method.as_str()
        )]
    } else {
        Vec::new()
    };

    Ok(PingReport {
        metadata: PingMetadata {
            schema_version: crate::model::REPORT_SCHEMA_VERSION,
            version: env!("CARGO_PKG_VERSION").to_string(),
            target,
            method: config.method,
            port: config.port,
            count: config.count,
            generated_at: Utc::now(),
            total: Some(started.elapsed()),
        },
        replies,
        summary: PingSummary {
            transmitted: config.count,
            received,
            packet_loss_percent: ((config.count - received) as f64 / config.count as f64) * 100.0,
            min,
            avg,
            max,
        },
        errors,
    })
}

async fn run_udp_ping(target: &Target, config: &PingConfig) -> Vec<PingReply> {
    let port = config.port.unwrap_or(33435);
    let mut replies = Vec::with_capacity(config.count as usize);
    for seq in 1..=config.count {
        let local = bind_addr(target.address);
        let started = std::time::Instant::now();
        let reply = match async {
            let socket = tokio::net::UdpSocket::bind(local).await?;
            socket
                .connect(SocketAddr::new(target.address, port))
                .await?;
            socket.send(&[0]).await?;
            let mut buf = [0_u8; 64];
            match timeout(config.timeout, socket.recv(&mut buf)).await {
                Ok(Ok(_)) => Ok(PingReply {
                    seq,
                    success: true,
                    outcome: "udp-response".to_string(),
                    latency: Some(started.elapsed()),
                    ttl_hint: None,
                    mac_address: None,
                }),
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    Ok(PingReply {
                        seq,
                        success: true,
                        outcome: "port-unreachable".to_string(),
                        latency: Some(started.elapsed()),
                        ttl_hint: None,
                        mac_address: None,
                    })
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "udp ping timed out",
                )),
            }
        }
        .await
        {
            Ok(reply) => reply,
            Err(error) => PingReply {
                seq,
                success: false,
                outcome: error.to_string(),
                latency: None,
                ttl_hint: None,
                mac_address: None,
            },
        };
        log_ping_reply(
            seq,
            reply.latency,
            reply.ttl_hint,
            reply.success,
            target.address,
        );
        replies.push(reply);
        if seq != config.count && !config.interval.is_zero() {
            tokio::time::sleep(config.interval).await;
        }
    }
    replies
}

async fn run_tcp_ping(target: &Target, config: &PingConfig) -> Vec<PingReply> {
    let port = config.port.unwrap_or(80);
    let mut replies = Vec::with_capacity(config.count as usize);
    for seq in 1..=config.count {
        let started = std::time::Instant::now();
        let reply = match timeout(
            config.timeout,
            tokio::net::TcpStream::connect(SocketAddr::new(target.address, port)),
        )
        .await
        {
            Ok(Ok(_)) => PingReply {
                seq,
                success: true,
                outcome: "connect-open".to_string(),
                latency: Some(started.elapsed()),
                ttl_hint: None,
                mac_address: None,
            },
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => PingReply {
                seq,
                success: true,
                outcome: "connection-refused".to_string(),
                latency: Some(started.elapsed()),
                ttl_hint: None,
                mac_address: None,
            },
            Ok(Err(error)) => PingReply {
                seq,
                success: false,
                outcome: error.to_string(),
                latency: None,
                ttl_hint: None,
                mac_address: None,
            },
            Err(_) => PingReply {
                seq,
                success: false,
                outcome: "tcp ping timed out".to_string(),
                latency: None,
                ttl_hint: None,
                mac_address: None,
            },
        };
        log_ping_reply(
            seq,
            reply.latency,
            reply.ttl_hint,
            reply.success,
            target.address,
        );
        replies.push(reply);
        if seq != config.count && !config.interval.is_zero() {
            tokio::time::sleep(config.interval).await;
        }
    }
    replies
}

async fn run_quic_ping(target: &Target, config: &PingConfig) -> Vec<PingReply> {
    let port = config.port.unwrap_or(443);
    let connector = SocketConnector;
    let mut replies = Vec::with_capacity(config.count as usize);
    for seq in 1..=config.count {
        let reply = match connector
            .connect(
                target.address,
                port,
                Transport::Quic,
                config.timeout,
                None,
                target.hostname.as_deref(),
            )
            .await
        {
            Ok(outcome) => PingReply {
                seq,
                success: true,
                outcome: "quic-handshake".to_string(),
                latency: Some(outcome.latency),
                ttl_hint: None,
                mac_address: None,
            },
            Err(error) => PingReply {
                seq,
                success: false,
                outcome: error.to_string(),
                latency: None,
                ttl_hint: None,
                mac_address: None,
            },
        };
        log_ping_reply(
            seq,
            reply.latency,
            reply.ttl_hint,
            reply.success,
            target.address,
        );
        replies.push(reply);
        if seq != config.count && !config.interval.is_zero() {
            tokio::time::sleep(config.interval).await;
        }
    }
    replies
}

async fn run_icmp_ping(target: &Target, config: &PingConfig) -> Result<Vec<PingReply>> {
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

    let packet = build_icmp_packet(&interface, target.address)?;
    let parse_option = capture_parse_option(&interface);
    let mut replies = Vec::with_capacity(config.count as usize);

    for seq in 1..=config.count {
        let started = std::time::Instant::now();
        poll_fn(|cx| tx.poll_send(cx, &packet))
            .await
            .map_err(std::io::Error::other)?;

        let mut reply = PingReply {
            seq,
            success: false,
            outcome: "icmp ping timed out".to_string(),
            latency: None,
            ttl_hint: None,
            mac_address: None,
        };

        while started.elapsed() < config.timeout {
            let remaining = config.timeout.saturating_sub(started.elapsed());
            match timeout(remaining, rx.next()).await {
                Ok(Some(Ok(frame_bytes))) => {
                    let Some(frame) = Frame::from_buf(&frame_bytes, parse_option.clone()) else {
                        continue;
                    };
                    if let Some((ttl_hint, mac_address)) = parse_icmp_reply(target.address, &frame)
                    {
                        reply = PingReply {
                            seq,
                            success: true,
                            outcome: "echo-reply".to_string(),
                            latency: Some(started.elapsed()),
                            ttl_hint,
                            mac_address,
                        };
                        break;
                    }
                }
                Ok(Some(Err(error))) => {
                    reply.outcome = error.to_string();
                    break;
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }

        log_ping_reply(
            seq,
            reply.latency,
            reply.ttl_hint,
            reply.success,
            target.address,
        );
        replies.push(reply);
        if seq != config.count && !config.interval.is_zero() {
            tokio::time::sleep(config.interval).await;
        }
    }

    Ok(replies)
}

fn parse_icmp_reply(address: IpAddr, frame: &Frame) -> Option<(Option<u8>, Option<String>)> {
    let ip = frame.ip.as_ref()?;
    let mac = frame.datalink.as_ref().and_then(|datalink| {
        datalink
            .ethernet
            .as_ref()
            .map(|ethernet| ethernet.source.to_string())
    });
    if let Some(ipv4) = &ip.ipv4 {
        if IpAddr::V4(ipv4.source) != address {
            return None;
        }
        let icmp = ip.icmp.as_ref()?;
        if icmp.icmp_type == IcmpType::EchoReply {
            return Some((Some(ipv4.ttl), mac));
        }
    }
    if let Some(ipv6) = &ip.ipv6 {
        if IpAddr::V6(ipv6.source) != address {
            return None;
        }
        let icmpv6 = ip.icmpv6.as_ref()?;
        if icmpv6.icmpv6_type == Icmpv6Type::EchoReply {
            return Some((Some(ipv6.hop_limit), mac));
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

fn bind_addr(address: IpAddr) -> SocketAddr {
    match address {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
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

fn build_icmp_packet(interface: &netdev::Interface, dst_ip: IpAddr) -> Result<Vec<u8>> {
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
    let src_ip = match dst_ip {
        IpAddr::V4(_) => interface
            .ipv4
            .first()
            .map(|ip| IpAddr::V4(ip.addr()))
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        IpAddr::V6(_) => interface
            .ipv6
            .first()
            .map(|ip| IpAddr::V6(ip.addr()))
            .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
    };
    let ip_only = interface.is_tun() || interface.is_loopback();

    let ip_packet = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let icmp = IcmpPacketBuilder::new(src, dst)
                .echo_fields(0x4e52, 1)
                .build()?;
            Ipv4PacketBuilder::new()
                .source(src)
                .destination(dst)
                .protocol(IpNextProtocol::Icmp)
                .flags(Ipv4Flags::DontFragment)
                .payload(icmp.to_bytes())
                .build()?
                .to_bytes()
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let icmp = Icmpv6PacketBuilder::new(src, dst)
                .echo_fields(0x4e52, 1)
                .build()?;
            Ipv6PacketBuilder::new()
                .source(src)
                .destination(dst)
                .next_header(IpNextProtocol::Icmpv6)
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

fn log_ping_reply(
    seq: u32,
    latency: Option<Duration>,
    ttl_hint: Option<u8>,
    success: bool,
    src: IpAddr,
) {
    let src = if success {
        src.to_string()
    } else {
        "*".to_string()
    };
    let rtt = latency
        .map(|value| format!("{}ms", value.as_millis()))
        .unwrap_or_else(|| "-".to_string());
    let ttl = ttl_hint
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    info!("#{} Reply from {} TTL: {} RTT: {}", seq, src, ttl, rtt);
}
