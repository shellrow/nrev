use anyhow::Result;
use crate::trace::{TraceResult, TraceSetting};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use futures::stream::StreamExt;
use futures::future::poll_fn;
use netdev::MacAddr;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::icmp::IcmpType;
use nex::packet::icmpv6::Icmpv6Type;
use crate::endpoint::NodeType;
use crate::probe::ProbeStatus;
use crate::{probe::ProbeResult, protocol::Protocol};
use nex::datalink::async_io::{async_channel, AsyncChannel};
use tracing_indicatif::span_ext::IndicatifSpanExt;

/// Run a UDP traceroute based on the provided trace settings.
pub async fn run_udp_trace(setting: &TraceSetting) -> Result<TraceResult> {
    let mut result = TraceResult::new();
    result.protocol = Protocol::Udp;

    let interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => return Err(anyhow::anyhow!("Interface not found")),
    };
    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(setting.receive_timeout),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };

    let AsyncChannel::Ethernet(mut tx, mut rx) = async_channel(&interface, config)?
    else {
        unreachable!();
    };

    let mut responses: Vec<ProbeResult> = Vec::new();

    let mut parse_option: ParseOption = ParseOption::default();
    if interface.is_tun() || (cfg!(any(target_os = "macos", target_os = "ios")) && interface.is_loopback()) {
        let payload_offset = if interface.is_loopback() { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }

    let header_span = tracing::info_span!("trace");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message(&format!("trace ({})", setting.dst_ip));
    header_span.pb_set_length(setting.hop_limit as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();

    let mut dst_reached: bool = false;
    let start_time = Instant::now();
    for seq_ttl in 1..setting.hop_limit {
        let udp_packet = crate::packet::udp::build_udp_trace_packet(&interface, &setting, seq_ttl);
        let send_time = Instant::now();
        match poll_fn(|cx| tx.poll_send(cx, &udp_packet)).await {
            Ok(_) => {
            },
            Err(e) => eprintln!("Failed to send packet: {}", e),
        }
        loop {
            match tokio::time::timeout(setting.receive_timeout, rx.next()).await {
                Ok(Some(Ok(packet))) => {
                    let rtt = send_time.elapsed();
                    let frame = match Frame::from_buf(&packet, parse_option.clone()) {
                        Some(frame) => frame,
                        None => {
                            eprintln!("Failed to parse packet: {:?}", packet);
                            continue;
                        }
                    };
                    let mut mac_addr: MacAddr = MacAddr::zero();
                    if let Some(datalink_layer) = &frame.datalink {
                        // Ethernet
                        if let Some(ethernet_header) = &datalink_layer.ethernet {
                            mac_addr = ethernet_header.source;
                        }
                    }
                    if let Some(ip_layer) = &frame.ip {
                        // IPv4
                        if let Some(ipv4_header) = &ip_layer.ipv4 {
                            // IPv4 ICMP
                            if let Some(icmp_header) = &ip_layer.icmp {
                                match icmp_header.icmp_type {
                                    IcmpType::TimeExceeded => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl as u32,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V4(ipv4_header.source),
                                            host_name: None,
                                            port_number: None,
                                            port_status: None,
                                            ttl: ipv4_header.ttl,
                                            hop: crate::util::ip::initial_ttl(ipv4_header.ttl)
                                                - ipv4_header.ttl,
                                            rtt: rtt,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::Udp,
                                            node_type: if seq_ttl == 1 {
                                                NodeType::Gateway
                                            } else {
                                                NodeType::Hop
                                            },
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        tracing::info!("#{} Reply from {}, RTT={:?} TTL={} Type={}", seq_ttl, ipv4_header.source, rtt, ipv4_header.ttl, probe_result.node_type.as_str());
                                        responses.push(probe_result);
                                        header_span.pb_inc(1);
                                        break;
                                    }
                                    IcmpType::DestinationUnreachable => {
                                        if IpAddr::V4(ipv4_header.source) == setting.dst_ip {
                                            let probe_result: ProbeResult = ProbeResult {
                                                seq: seq_ttl as u32,
                                                mac_addr: mac_addr,
                                                ip_addr: setting.dst_ip,
                                                host_name: setting.dst_hostname.clone(),
                                                port_number: None,
                                                port_status: None,
                                                ttl: ipv4_header.ttl,
                                                hop: crate::util::ip::initial_ttl(ipv4_header.ttl)
                                                    - ipv4_header.ttl,
                                                rtt: rtt,
                                                probe_status: ProbeStatus::new(),
                                                protocol: Protocol::Udp,
                                                node_type: NodeType::Destination,
                                                sent_packet_size: udp_packet.len(),
                                                received_packet_size: packet.len(),
                                            };
                                            tracing::info!("#{} Reply from {}, RTT={:?} TTL={} Type={}", seq_ttl, ipv4_header.source, rtt, ipv4_header.ttl, probe_result.node_type.as_str());
                                            responses.push(probe_result);
                                            header_span.pb_inc(1);
                                            dst_reached = true;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        // IPv6
                        if let Some(ipv6_header) = &ip_layer.ipv6 {
                            // ICMPv6
                            if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                                match icmpv6_header.icmpv6_type {
                                    Icmpv6Type::TimeExceeded => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl as u32,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V6(ipv6_header.source),
                                            host_name: None,
                                            port_number: None,
                                            port_status: None,
                                            ttl: ipv6_header.hop_limit,
                                            hop: crate::util::ip::initial_ttl(ipv6_header.hop_limit)
                                                - ipv6_header.hop_limit,
                                            rtt: rtt,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::Udp,
                                            node_type: if seq_ttl == 1 {
                                                NodeType::Gateway
                                            } else {
                                                NodeType::Hop
                                            },
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        tracing::info!("#{} Reply from {}, RTT={:?} TTL={} Type={}", seq_ttl, ipv6_header.source, rtt, ipv6_header.hop_limit, probe_result.node_type.as_str());
                                        responses.push(probe_result);
                                        header_span.pb_inc(1);
                                        break;
                                    },
                                    Icmpv6Type::DestinationUnreachable => {
                                        if IpAddr::V6(ipv6_header.source) == setting.dst_ip {
                                            let probe_result: ProbeResult = ProbeResult {
                                                seq: seq_ttl as u32,
                                                mac_addr: mac_addr,
                                                ip_addr: setting.dst_ip,
                                                host_name: setting.dst_hostname.clone(),
                                                port_number: None,
                                                port_status: None,
                                                ttl: ipv6_header.hop_limit,
                                                hop: crate::util::ip::initial_ttl(ipv6_header.hop_limit)
                                                    - ipv6_header.hop_limit,
                                                rtt: rtt,
                                                probe_status: ProbeStatus::new(),
                                                protocol: Protocol::Udp,
                                                node_type: NodeType::Destination,
                                                sent_packet_size: udp_packet.len(),
                                                received_packet_size: packet.len(),
                                            };
                                            tracing::info!("#{} Reply from {}, RTT={:?} TTL={} Type={}", seq_ttl, ipv6_header.source, rtt, ipv6_header.hop_limit, probe_result.node_type.as_str());
                                            responses.push(probe_result);
                                            header_span.pb_inc(1);
                                            dst_reached = true;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                },
                Ok(Some(Err(e))) => {
                    tracing::error!("Failed to receive packet: {}", e);
                    header_span.pb_inc(1);
                    break;
                },
                Ok(None) => {
                    tracing::error!("Channel closed");
                    header_span.pb_inc(1);
                    break;
                },
                Err(_) => {
                    tracing::error!("Request timeout for seq {}", seq_ttl as u32);
                    let probe_result = ProbeResult::timeout(
                        seq_ttl as u32,
                        setting.dst_ip,
                        setting.dst_hostname.clone(),
                        Protocol::Udp,
                        udp_packet.len(),
                    );
                    responses.push(probe_result);

                    header_span.pb_inc(1);
                    break;
                }
            }

            let elapsed_time: Duration = send_time.elapsed();
            if elapsed_time > setting.receive_timeout {
                tracing::error!("Request timeout for seq {}", seq_ttl as u32);
                let probe_result = ProbeResult::timeout(
                    seq_ttl as u32,
                    setting.dst_ip,
                    setting.dst_hostname.clone(),
                    Protocol::Udp,
                    udp_packet.len(),
                );
                responses.push(probe_result);

                header_span.pb_inc(1);
                break;
            }
        }
        if dst_reached {
            break;
        }
        if !setting.send_rate.is_zero() && seq_ttl < setting.hop_limit {
            tokio::time::sleep(setting.send_rate).await;
        }
    }

    // Finish header span
    drop(header_span);

    let elapsed_time = start_time.elapsed();
    result.probe_status = ProbeStatus::new();
    result.elapsed_time = elapsed_time;
    result.nodes = responses;
    result.protocol = Protocol::Udp;

    Ok(result)
}
