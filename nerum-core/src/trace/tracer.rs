use crate::ping::result::TracerouteResult;
use crate::probe::{ProbeResult, ProbeStatus};
use crate::host::{PortStatus, NodeType};
use crate::packet::setting::PacketBuildSetting;
use crate::protocol::Protocol;
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use netdev::Interface;
use nex::datalink::{FrameReceiver, FrameSender};
use nex::net::mac::MacAddr;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::icmp::IcmpType;
use nex::packet::icmpv6::Icmpv6Type;

use super::setting::TraceSetting;

/// Tracer structure.
///
/// Supports UDP Traceroute.
#[derive(Clone, Debug)]
pub struct Tracer {
    /// Probe Setting
    pub probe_setting: TraceSetting,
    /// Sender for progress messaging
    tx: Arc<Mutex<Sender<ProbeResult>>>,
    /// Receiver for progress messaging
    rx: Arc<Mutex<Receiver<ProbeResult>>>,
}

impl Tracer {
    /// Create new Tracer instance with setting
    pub fn new(setting: TraceSetting) -> Result<Tracer, String> {
        // Check interface
        if crate::interface::get_interface_by_index(setting.if_index).is_none() {
            return Err(format!(
                "Tracer::new: unable to get interface. index: {}",
                setting.if_index
            ));
        }
        let (tx, rx) = channel();
        let tracer = Tracer {
            probe_setting: setting,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        };
        return Ok(tracer);
    }
    /// Run traceroute
    pub fn trace(&self) -> Result<TracerouteResult, String> {
        run_traceroute(&self.probe_setting, &self.tx)
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<ProbeResult>>> {
        self.rx.clone()
    }
}

fn run_traceroute(
    setting: &TraceSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> Result<TracerouteResult, String> {
    let interface: Interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => {
            return Err(format!(
                "run_traceroute: unable to get interface by index {}",
                setting.if_index
            ))
        }
    };
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
    // Create a channel to send/receive packet
    let (mut tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("run_traceroute: unable to create channel".to_string()),
        Err(e) => return Err(format!("run_traceroute: unable to create channel: {}", e)),
    };
    match setting.protocol {
        crate::protocol::Protocol::ICMP => Err("ICMP traceroute is not supported".to_string()),
        crate::protocol::Protocol::TCP => Err("TCP traceroute is not supported".to_string()),
        crate::protocol::Protocol::UDP => {
            let result = udp_trace(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
        _ => {
            return Err("run_ping: unsupported protocol".to_string());
        }
    }
}

pub fn udp_trace(
    tx: &mut Box<dyn FrameSender>,
    rx: &mut Box<dyn FrameReceiver>,
    setting: &TraceSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> TracerouteResult {
    let mut result = TracerouteResult::new();
    result.protocol = Protocol::UDP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.tunnel {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::time::get_sysdate();
    let start_time = Instant::now();
    let mut responses: Vec<ProbeResult> = Vec::new();
    let mut dst_reached: bool = false;
    for seq_ttl in 1..setting.hop_limit {
        let packet_setting: PacketBuildSetting = PacketBuildSetting::from_trace_setting(setting, seq_ttl);
        let udp_packet: Vec<u8> = crate::packet::udp::build_udp_packet(packet_setting.clone());
        //let udp_packet: Vec<u8> = crate::packet::udp::build_udp_packet(setting.clone(), Some(seq_ttl));
        let send_time = Instant::now();
        match tx.send(&udp_packet) {
            Some(_) => {}
            None => {},
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    // Datalink
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
                            if IpAddr::V4(ipv4_header.destination) != packet_setting.src_ip {
                                continue;
                            }
                            // ICMP
                            if let Some(icmp_header) = &ip_layer.icmp {
                                match icmp_header.icmp_type {
                                    IcmpType::TimeExceeded => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl as u32,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V4(ipv4_header.source),
                                            host_name: ipv4_header.source.to_string(),
                                            port_number: None,
                                            port_status: None,
                                            ttl: ipv4_header.ttl,
                                            hop: crate::ip::guess_initial_ttl(ipv4_header.ttl)
                                                - ipv4_header.ttl,
                                            rtt: recv_time,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::UDP,
                                            node_type: if seq_ttl == 1 {
                                                NodeType::DefaultGateway
                                            } else {
                                                NodeType::Relay
                                            },
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        responses.push(probe_result.clone());
                                        match msg_tx.lock() {
                                            Ok(lr) => match lr.send(probe_result) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        break;
                                    }
                                    IcmpType::DestinationUnreachable => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl as u32,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V4(ipv4_header.source),
                                            host_name: ipv4_header.source.to_string(),
                                            port_number: Some(setting.dst_port),
                                            port_status: Some(PortStatus::Closed),
                                            ttl: ipv4_header.ttl,
                                            hop: crate::ip::guess_initial_ttl(ipv4_header.ttl)
                                                - ipv4_header.ttl,
                                            rtt: recv_time,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::UDP,
                                            node_type: NodeType::Destination,
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        responses.push(probe_result.clone());
                                        match msg_tx.lock() {
                                            Ok(lr) => match lr.send(probe_result) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        dst_reached = true;
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        // IPv6
                        if let Some(ipv6_header) = &ip_layer.ipv6 {
                            if IpAddr::V6(ipv6_header.destination) != packet_setting.src_ip {
                                continue;
                            }
                            // ICMPv6
                            if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                                match icmpv6_header.icmpv6_type {
                                    Icmpv6Type::TimeExceeded => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl as u32,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V6(ipv6_header.source),
                                            host_name: ipv6_header.source.to_string(),
                                            port_number: None,
                                            port_status: None,
                                            ttl: ipv6_header.hop_limit,
                                            hop: crate::ip::guess_initial_ttl(
                                                ipv6_header.hop_limit,
                                            ) - ipv6_header.hop_limit,
                                            rtt: recv_time,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::UDP,
                                            node_type: if seq_ttl == 1 {
                                                NodeType::DefaultGateway
                                            } else {
                                                NodeType::Relay
                                            },
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        responses.push(probe_result.clone());
                                        match msg_tx.lock() {
                                            Ok(lr) => match lr.send(probe_result) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        break;
                                    }
                                    Icmpv6Type::DestinationUnreachable => {
                                        let probe_result: ProbeResult = ProbeResult {
                                            seq: seq_ttl as u32,
                                            mac_addr: mac_addr,
                                            ip_addr: IpAddr::V6(ipv6_header.source),
                                            host_name: ipv6_header.source.to_string(),
                                            port_number: Some(setting.dst_port),
                                            port_status: Some(PortStatus::Closed),
                                            ttl: ipv6_header.hop_limit,
                                            hop: crate::ip::guess_initial_ttl(
                                                ipv6_header.hop_limit,
                                            ) - ipv6_header.hop_limit,
                                            rtt: recv_time,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::UDP,
                                            node_type: NodeType::Destination,
                                            sent_packet_size: udp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        responses.push(probe_result.clone());
                                        match msg_tx.lock() {
                                            Ok(lr) => match lr.send(probe_result) {
                                                Ok(_) => {}
                                                Err(_) => {}
                                            },
                                            Err(_) => {}
                                        }
                                        dst_reached = true;
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    let probe_result = ProbeResult::trace_timeout(
                        seq_ttl as u32,
                        Protocol::UDP,
                        udp_packet.len(),
                        NodeType::Relay,
                    );
                    responses.push(probe_result.clone());
                    match msg_tx.lock() {
                        Ok(lr) => match lr.send(probe_result) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    }
                    break;
                }
            }
            let wait_time: Duration = Instant::now().duration_since(send_time);
            if wait_time > setting.receive_timeout {
                let probe_result = ProbeResult::trace_timeout(
                    seq_ttl as u32,
                    Protocol::UDP,
                    udp_packet.len(),
                    NodeType::Relay,
                );
                responses.push(probe_result.clone());
                match msg_tx.lock() {
                    Ok(lr) => match lr.send(probe_result) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
                break;
            }
        }
        if dst_reached {
            break;
        }
        if seq_ttl < setting.hop_limit {
            std::thread::sleep(setting.send_rate);
        }
    }
    let probe_time = Instant::now().duration_since(start_time);
    result.end_time = crate::sys::time::get_sysdate();
    result.elapsed_time = probe_time;
    result.nodes = responses;
    result.probe_status = ProbeStatus::new();
    result
}
