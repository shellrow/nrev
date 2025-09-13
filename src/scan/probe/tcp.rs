use futures::stream::{self, StreamExt};
use futures::future::poll_fn;
use netdev::{Interface, MacAddr};
use nex::datalink::async_io::{async_channel, AsyncChannel, AsyncRawSender};
use nex::packet::frame::Frame;
use nex::packet::ip::IpNextProtocol;
use nex::packet::tcp::TcpFlags;
use nex::socket::tcp::{AsyncTcpSocket, TcpConfig};
use tracing_indicatif::span_ext::IndicatifSpanExt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use std::collections::{BTreeMap, HashMap, HashSet};
use anyhow::Result;
use tokio::sync::mpsc;

use crate::capture::pcap::PacketCaptureOptions;
use crate::cli::{PortScanMethod};
use crate::endpoint::{Endpoint, EndpointResult, OsGuess, Port, PortResult, PortState, ServiceInfo, TransportProtocol};
use crate::output::ScanResult;
use crate::probe::ProbeSetting;

/// Try to connect to the given ports on the target endpoint using TCP protocol.
/// Concurrency specifies the number of concurrent connection attempts.
pub async fn try_connect_ports(
    target: Endpoint,
    concurrency: usize,
    timeout: Duration,
) -> Result<EndpointResult> {
    let (ch_tx, mut ch_rx) = mpsc::unbounded_channel::<PortResult>();
    let header_span = tracing::info_span!("tcp_connect_scan");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message(&format!("TCP PortScan ({})", target.ip));
    header_span.pb_set_length(target.ports.len() as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();

    let span_rx = header_span.clone();
    let recv_task = tokio::spawn(async move {
        let mut open_ports: BTreeMap<Port, PortResult> = BTreeMap::new();
        while let Some(port_result) = ch_rx.recv().await {
            open_ports.insert(port_result.port.clone(), port_result);
            // Update progress bar
            span_rx.pb_inc(1);
        }
        open_ports
    });

    let prod = stream::iter(target.socket_addrs(TransportProtocol::Tcp)).for_each_concurrent(concurrency, move |socket_addr| {
        let ch_tx = ch_tx.clone();
        async move {
            let cfg = if socket_addr.is_ipv4() {
                TcpConfig::v4_stream()
            } else {
                TcpConfig::v6_stream()
            };
            let socket = AsyncTcpSocket::from_config(&cfg).unwrap();
            let mut port_result = PortResult {
                port: Port::new(socket_addr.port(), TransportProtocol::Tcp),
                state: PortState::Closed,
                service: ServiceInfo::default(),
                rtt_ms: None,
            };
            match socket.connect_timeout(socket_addr, timeout).await {
                Ok(mut stream) => {
                    port_result.state = PortState::Open;
                    match stream.shutdown().await {
                        Ok(_) => {}
                        Err(_) => {}
                    }
                }
                Err(_) => {}
            }
            let _ = ch_tx.send(port_result);
        }
    });
    let prod_task = tokio::spawn(prod);
    let (results_res, _prod_res) = tokio::join!(recv_task, prod_task);
    let open_ports = results_res?;
    // Finish header span
    drop(header_span);
    Ok(EndpointResult {
        ip: target.ip,
        hostname: target.hostname,
        ports: open_ports,
        mac_addr: target.mac_addr,
        vendor_name: None,
        os: OsGuess::default(),
        tags: target.tags,
        cpes: Vec::new(),
    })
}

/// Run a TCP connect scan based on the provided probe settings.
pub async fn run_connect_scan(
    setting: ProbeSetting,
) -> Result<ScanResult> {
    let start_time = std::time::Instant::now();
    let mut tasks = vec![];
    for target in setting.target_endpoints {
        tasks.push(tokio::spawn(async move {
            let host = try_connect_ports(
                target,
                setting.port_concurrency,
                setting.connect_timeout,
            )
            .await;
            host
        }));
    }
    let mut endpoints: Vec<EndpointResult> = vec![];
    for task in tasks {
        match task.await {
            Ok(endpoint_result) => {
                match endpoint_result {
                    Ok(endpoint) => {
                        endpoints.push(endpoint);
                    }
                    Err(e) => {
                        tracing::error!("error: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("error: {}", e);
            }
        }
    }
    let mut result = ScanResult::new();
    result.endpoints = endpoints;
    result.scan_time = start_time.elapsed();
    result.fingerprints = Vec::new();
    Ok(result)
}

/// Send TCP SYN packets for port scanning.
pub async fn send_portscan_packets(
    tx: &mut Box<dyn AsyncRawSender>,
    interface: &Interface,
    scan_setting: &ProbeSetting,
) {
    let mut sent: usize = 0;
    for target in &scan_setting.target_endpoints {
        let header_span = tracing::info_span!("tcp_syn_scan");
        header_span.pb_set_style(&crate::output::progress::get_progress_style());
        header_span.pb_set_message(&format!("PortScan ({})", target.ip));
        header_span.pb_set_length(target.ports.len() as u64);
        header_span.pb_set_position(0);
        header_span.pb_start();
        
        for port in &target.ports {
            let packet =
                crate::packet::tcp::build_tcp_syn_packet(&interface, target.ip, port.number, false);

            // Send a packet using poll_fn.
            match poll_fn(|cx| tx.poll_send(cx, &packet)).await {
                Ok(_) => {
                    if !scan_setting.send_rate.is_zero() && sent < 64 {
                        tokio::time::sleep(scan_setting.send_rate).await;
                    }
                    sent += 1;
                }
                Err(e) => eprintln!("Failed to send packet: {}", e),
            }
            header_span.pb_inc(1);
        }
        drop(header_span);
    }
}

/// Send TCP SYN packets for host scanning.
pub async fn send_hostscan_packets(
    tx: &mut Box<dyn AsyncRawSender>,
    interface: &Interface,
    scan_setting: &ProbeSetting,
) {
    let header_span = tracing::info_span!("tcp_syn_host_scan");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message("HostScan");
    header_span.pb_set_length(scan_setting.target_endpoints.len() as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();
    
    for target in &scan_setting.target_endpoints {
        for port in &target.ports {
            let packet =
                crate::packet::tcp::build_tcp_syn_packet(&interface, target.ip, port.number, false);

            // Send a packet using poll_fn.
            match poll_fn(|cx| tx.poll_send(cx, &packet)).await {
                Ok(_) => {
                    if !scan_setting.send_rate.is_zero() {
                        tokio::time::sleep(scan_setting.send_rate).await;
                    }
                }
                Err(e) => eprintln!("Failed to send packet: {}", e),
            }
        }
        header_span.pb_inc(1);
    }
    drop(header_span);
}

/// Run a TCP SYN scan based on the provided probe settings.
pub async fn run_syn_scan(
    setting: ProbeSetting,
) -> Result<ScanResult> {
    let interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => return Err(anyhow::anyhow!("Interface not found")),
    };
    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(setting.wait_time),
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

    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        interface_name: interface.name.clone(),
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        capture_timeout: setting.task_timeout,
        read_timeout: setting.wait_time,
        promiscuous: false,
        receive_undefined: false,
        tunnel: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    for endpoint in setting.target_endpoints.clone() {
        capture_options.src_ips.insert(endpoint.ip);
        capture_options.src_ports.extend(endpoint.ports.iter().map(|p| p.number));
    }
    capture_options.ip_protocols.insert(IpNextProtocol::Tcp);

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();

    let capture_handle: tokio::task::JoinHandle<_> = tokio::spawn(async move {
        crate::capture::pcap::start_capture(
            &mut rx,
            capture_options,
            ready_tx,
            &mut stop_rx,
        )
        .await
    });

    // Wait for listener to start
    let _ = ready_rx;
    let start_time = std::time::Instant::now();
    // Send probe packets
    send_portscan_packets(&mut tx, &interface, &setting).await;
    tokio::time::sleep(setting.wait_time).await;
    // Stop pcap
    let _ = stop_tx.send(());
    let frames = capture_handle.await.unwrap();
    let dns_map = setting.get_dns_map();
    let mut result = parse_portscan_result(frames, &interface, &dns_map);
    result.scan_time = start_time.elapsed();
    Ok(result)
}

/// Run a TCP port scan using the specified probe settings and method.
pub async fn run_port_scan(
    setting: ProbeSetting,
    method: PortScanMethod
) -> Result<ScanResult> {
    match method {
        PortScanMethod::Connect => {
            return run_connect_scan(setting).await;
        }
        PortScanMethod::Syn => {
            return run_syn_scan(setting).await;
        }
    }
}

/// Run a TCP host scan based on the provided probe settings.
pub async fn run_host_scan(setting: ProbeSetting) -> Result<ScanResult> {
    let interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => return Err(anyhow::anyhow!("Interface not found")),
    };
    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(setting.wait_time),
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

    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        interface_name: interface.name.clone(),
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        capture_timeout: setting.task_timeout,
        read_timeout: setting.wait_time,
        promiscuous: false,
        receive_undefined: false,
        tunnel: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    for endpoint in &setting.target_endpoints {
        capture_options.src_ips.insert(endpoint.ip);
        capture_options.src_ports.extend(endpoint.ports.iter().map(|p| p.number));
    }
    capture_options.ip_protocols.insert(IpNextProtocol::Tcp);

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();

    let capture_handle: tokio::task::JoinHandle<_> = tokio::spawn(async move {
        crate::capture::pcap::start_capture(
            &mut rx,
            capture_options,
            ready_tx,
            &mut stop_rx,
        )
        .await
    });

    // Wait for listener to start
    let _ = ready_rx;
    let start_time = std::time::Instant::now();
    // Send probe packets
    send_hostscan_packets(&mut tx, &interface, &setting).await;
    tokio::time::sleep(setting.wait_time).await;
    // Stop pcap
    let _ = stop_tx.send(());
    let frames = capture_handle.await.unwrap();
    let dns_map = setting.get_dns_map();
    let mut result = parse_hostscan_result(frames, &interface, &dns_map);
    result.scan_time = start_time.elapsed();
    Ok(result)
}

/// Parse port scan results from captured packets.
fn parse_portscan_result(
    packets: Vec<Frame>,
    iface: &Interface,
    dns_map: &HashMap<IpAddr, String>,
) -> ScanResult {
    let mut result: ScanResult = ScanResult::new();
    let mut socket_set: HashSet<SocketAddr> = HashSet::new();
    let mut endpoint_map: HashMap<IpAddr, EndpointResult> = HashMap::new();
    for p in packets {
        if p.ip.is_none() || p.transport.is_none() {
            continue;
        }
        let mac_addr: MacAddr;
        if let Some(datalink) = &p.datalink {
            if let Some(ethernet_frame) = &datalink.ethernet {
                if ethernet_frame.destination != iface.mac_addr.unwrap_or(MacAddr::zero()) {
                    continue;
                }
                mac_addr = ethernet_frame.source;
            } else {
                mac_addr = MacAddr::zero();
            }
        } else {
            mac_addr = MacAddr::zero();
        }
        let ip_addr: IpAddr;
        let ttl: u8;
        let port: PortResult;
        if let Some(ip) = &p.ip {
            if let Some(ipv4_packet) = &ip.ipv4 {
                ip_addr = IpAddr::V4(ipv4_packet.source);
                ttl = ipv4_packet.ttl;
            } else if let Some(ipv6_packet) = &ip.ipv6 {
                ip_addr = IpAddr::V6(ipv6_packet.source);
                ttl = ipv6_packet.hop_limit;
            } else {
                continue;
            }
        } else {
            continue;
        }
        if let Some(transport) = &p.transport {
            if let Some(tcp_packet) = &transport.tcp {
                if socket_set.contains(&SocketAddr::new(ip_addr,tcp_packet.source)) {
                    continue;
                }
                let f = tcp_packet.flags;
                if (f & TcpFlags::RST) != 0 {
                    port = PortResult {
                        port: Port::new(tcp_packet.source, TransportProtocol::Tcp),
                        state: PortState::Closed,
                        service: ServiceInfo::default(),
                        rtt_ms: None,
                    };
                } else if (f & (TcpFlags::SYN | TcpFlags::ACK)) == (TcpFlags::SYN | TcpFlags::ACK) {
                    port = PortResult {
                        port: Port::new(tcp_packet.source, TransportProtocol::Tcp),
                        state: PortState::Open,
                        service: ServiceInfo::default(),
                        rtt_ms: None,
                    };
                } else {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            continue;
        }
        endpoint_map
            .entry(ip_addr)
            .or_insert(EndpointResult {
                ip: ip_addr,
                hostname: dns_map.get(&ip_addr).cloned(),
                ports: BTreeMap::new(),
                mac_addr: Some(mac_addr),
                vendor_name: None,
                os: OsGuess::default().with_ttl_observed(ttl),
                tags: Vec::new(),
                cpes: Vec::new(),
            })
            .ports
            .insert(port.port.clone(), port.clone());

        result.fingerprints.push(p.clone());
        socket_set.insert(SocketAddr::new(ip_addr, port.port.number));

    }
    for (ip, endpoint) in endpoint_map {
        let mut ep = EndpointResult::new(ip);
        ep.hostname = endpoint.hostname;
        ep.mac_addr = endpoint.mac_addr;
        ep.vendor_name = endpoint.vendor_name;
        ep.os = endpoint.os;
        ep.tags = endpoint.tags;
        for (_port, port_result) in endpoint.ports {
            ep.upsert_port(port_result);
        }
        result.endpoints.push(ep);
    }
    result
}

/// Parse host scan results from captured packets.
fn parse_hostscan_result(
    packets: Vec<Frame>,
    iface: &Interface,
    dns_map: &HashMap<IpAddr, String>,
) -> ScanResult {
    let oui_db = crate::db::oui::oui_db();
    let if_ipv4_set: HashSet<Ipv4Addr> = iface.ipv4_addrs().into_iter().collect();
    let if_ipv6_set: HashSet<Ipv6Addr> = iface.ipv6_addrs().into_iter().collect();
    let mut result: ScanResult = ScanResult::new();
    let mut socket_set: HashSet<SocketAddr> = HashSet::new();
    let mut endpoint_map: HashMap<IpAddr, EndpointResult> = HashMap::new();
    for p in packets {
        if p.ip.is_none() || p.transport.is_none() {
            continue;
        }
        let mut mac_addr: MacAddr;
        if let Some(datalink) = &p.datalink {
            if let Some(ethernet_frame) = &datalink.ethernet {
                if ethernet_frame.destination != iface.mac_addr.unwrap_or(MacAddr::zero()) {
                    continue;
                }
                mac_addr = ethernet_frame.source;
            } else {
                mac_addr = MacAddr::zero();
            }
        } else {
            mac_addr = MacAddr::zero();
        }
        let ip_addr: IpAddr;
        let ttl: u8;
        let port: PortResult;
        if let Some(ip) = &p.ip {
            if let Some(ipv4_packet) = &ip.ipv4 {
                if if_ipv4_set.contains(&ipv4_packet.source) {
                    mac_addr = iface.mac_addr.unwrap_or(MacAddr::zero());
                    ttl = crate::util::ip::initial_ttl(ipv4_packet.ttl);
                }else{
                    ttl = ipv4_packet.ttl;
                }
                ip_addr = IpAddr::V4(ipv4_packet.source);
            } else if let Some(ipv6_packet) = &ip.ipv6 {
                if if_ipv6_set.contains(&ipv6_packet.source) {
                    mac_addr = iface.mac_addr.unwrap_or(MacAddr::zero());
                    ttl = crate::util::ip::initial_ttl(ipv6_packet.hop_limit);
                }else {
                    ttl = ipv6_packet.hop_limit;
                }
                ip_addr = IpAddr::V6(ipv6_packet.source);
            } else {
                continue;
            }
        } else {
            continue;
        }
        if let Some(transport) = &p.transport {
            if let Some(tcp_packet) = &transport.tcp {
                if socket_set.contains(&SocketAddr::new(ip_addr,tcp_packet.source)) {
                    continue;
                }
                let f = tcp_packet.flags;
                if (f & (TcpFlags::SYN | TcpFlags::ACK)) == (TcpFlags::SYN | TcpFlags::ACK) {
                    port = PortResult {
                        port: Port::new(tcp_packet.source, TransportProtocol::Tcp),
                        state: PortState::Open,
                        service: ServiceInfo::default(),
                        rtt_ms: None,
                    };
                } else {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            continue;
        }

        let vendor_name_opt: Option<String>;
        if let Some(oui) = oui_db.lookup_mac(&mac_addr) {
            if let Some(vendor_detail) = &oui.vendor_detail {
                vendor_name_opt = Some(vendor_detail.clone());
            } else {
                vendor_name_opt = Some(oui.vendor.clone());
            }
        } else {
            vendor_name_opt = None;
        }

        let mut os_guess = OsGuess::default().with_ttl_observed(ttl);
        let mut cpes: Vec<String> = Vec::new();

        match crate::os::match_tcpip_signatures(&p) {
            Some(os_match) => {
                os_guess.family = Some(os_match.family);
                os_guess.confidence = Some(os_match.confidence as f32);
                os_guess.ttl_observed = Some(ttl);
                cpes = os_match.cpes;
            }
            None => {
                tracing::debug!("No matching OS found");
            }
        }

        endpoint_map
            .entry(ip_addr)
            .or_insert(EndpointResult {
                ip: ip_addr,
                hostname: dns_map.get(&ip_addr).cloned(),
                ports: BTreeMap::new(),
                mac_addr: Some(mac_addr),
                vendor_name: vendor_name_opt,
                os: os_guess,
                tags: Vec::new(),
                cpes: cpes,
            })
            .ports
            .insert(port.port.clone(), port.clone());

        result.fingerprints.push(p.clone());
        socket_set.insert(SocketAddr::new(ip_addr, port.port.number));

    }
    for (ip, endpoint) in endpoint_map {
        let mut ep = EndpointResult::new(ip);
        ep.hostname = endpoint.hostname;
        ep.mac_addr = endpoint.mac_addr;
        ep.vendor_name = endpoint.vendor_name;
        ep.os = endpoint.os;
        ep.cpes = endpoint.cpes;
        ep.tags = endpoint.tags;
        for (_port, port_result) in endpoint.ports {
            ep.upsert_port(port_result);
        }
        result.endpoints.push(ep);
    }
    result
}
