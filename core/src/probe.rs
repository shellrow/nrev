use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use std::sync::mpsc;
use std::thread;

use crate::option;
use crate::result;
use crate::sys;
use crate::model;
use crate::db;
use crate::define;

pub fn run_port_scan(opt: option::PortScanOption) -> netscan::result::ScanResult {
    let mut port_scanner: netscan::scanner::PortScanner = netscan::scanner::PortScanner::new(opt.src_ip).unwrap();
    for target in opt.targets {
        let dst: netscan::host::HostInfo = netscan::host::HostInfo::new_with_ip_addr(target.ip_addr)
            .with_ports(target.ports.clone())
            .with_host_name(target.host_name.clone());
        port_scanner.scan_setting.add_target(dst);
    }
    port_scanner.scan_setting.scan_type = opt.scan_type.to_netscan_type();
    port_scanner.scan_setting.set_timeout(opt.timeout);
    port_scanner.scan_setting.set_wait_time(opt.wait_time);
    port_scanner.scan_setting.set_send_rate(opt.send_rate);

    let ns_scan_result: netscan::result::ScanResult = port_scanner.sync_scan();
    ns_scan_result
}

pub async fn run_async_port_scan(opt: option::PortScanOption) -> netscan::result::ScanResult {
    let mut port_scanner: netscan::scanner::PortScanner = netscan::scanner::PortScanner::new(opt.src_ip).unwrap();
    for target in opt.targets {
        let dst: netscan::host::HostInfo = netscan::host::HostInfo::new_with_ip_addr(target.ip_addr)
            .with_ports(target.ports.clone())
            .with_host_name(target.host_name.clone());
        port_scanner.scan_setting.add_target(dst);
    }
    port_scanner.scan_setting.scan_type = opt.scan_type.to_netscan_type();
    port_scanner.scan_setting.set_timeout(opt.timeout);
    port_scanner.scan_setting.set_wait_time(opt.wait_time);
    port_scanner.scan_setting.set_send_rate(opt.send_rate);

    let ns_scan_result: netscan::result::ScanResult = async_io::block_on(async { port_scanner.scan().await });
    ns_scan_result
}

pub fn run_service_detection(hosts: Vec<model::Host>) -> HashMap<IpAddr, HashMap<u16, String>> {
    let mut map: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    let port_db: netscan::service::PortDatabase = netscan::service::PortDatabase {
        payload_map: HashMap::new(),
        http_ports: db::get_http_ports(),
        https_ports: db::get_https_ports(),
    };
    for host in hosts {
        let mut service_detector = netscan::service::ServiceDetector::new();
        service_detector.set_dst_ip(host.ip_addr);
        service_detector.set_dst_name(host.host_name.clone());
        service_detector.set_ports(host.get_open_ports());
        let service_map: HashMap<u16, String> = service_detector.detect(Some(port_db.clone()));
        map.insert(host.ip_addr, service_map);
    }
    map
}

pub fn run_os_fingerprinting(src_ip: IpAddr, target_hosts: Vec<model::Host>) -> Vec<netscan::os::ProbeResult> {
    let mut fingerprinter = netscan::os::Fingerprinter::new(src_ip).unwrap();
    for host in target_hosts {
        let closed_port: u16 = if host.get_closed_ports().len() > 0 {
            host.get_closed_ports()[0]
        } else {
            0
        };
        let probe_target: netscan::os::ProbeTarget = netscan::os::ProbeTarget {
            ip_addr: host.ip_addr,
            open_tcp_ports: host.get_open_ports(),
            closed_tcp_port: closed_port,
            open_udp_port: 0,
            closed_udp_port: 33455,
        };
        fingerprinter.add_probe_target(probe_target);
    }
    fingerprinter.add_probe_type(netscan::os::ProbeType::IcmpEchoProbe);
    fingerprinter.add_probe_type(netscan::os::ProbeType::IcmpUnreachableProbe);
    fingerprinter.add_probe_type(netscan::os::ProbeType::TcpSynAckProbe);
    fingerprinter.add_probe_type(netscan::os::ProbeType::TcpRstAckProbe);
    fingerprinter.add_probe_type(netscan::os::ProbeType::TcpEcnProbe);
    let probe_results: Vec<netscan::os::ProbeResult> = fingerprinter.probe();
    probe_results
}

pub async fn run_service_scan(opt: option::PortScanOption, msg_tx: &mpsc::Sender<String>) -> result::PortScanResult {
    let mut scan_result: result::PortScanResult = result::PortScanResult::new();
    scan_result.probe_id = sys::get_probe_id();
    scan_result.command_type = option::CommandType::PortScan;
    scan_result.protocol = opt.protocol;
    scan_result.scan_type = opt.scan_type;
    scan_result.start_time = sys::get_sysdate();

    let start_time: Instant = Instant::now();
    // Run port scan
    match msg_tx.send(String::from(define::MESSAGE_START_PORTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    let ns_scan_result: netscan::result::ScanResult = if opt.async_scan {
        run_async_port_scan(opt.clone()).await
    } else {
        run_port_scan(opt.clone())
    };
    match msg_tx.send(String::from(define::MESSAGE_END_PORTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    // Run service detection
    let mut service_map: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    if opt.service_detection {
        match msg_tx.send(String::from(define::MESSAGE_START_SERVICEDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
        let mut hosts: Vec<model::Host> = Vec::new();
        for scanned_host in &ns_scan_result.hosts {
            let mut host: model::Host = model::Host::new();
            host.ip_addr = scanned_host.ip_addr;
            host.host_name = scanned_host.host_name.clone();
            for open_port in scanned_host.get_open_ports() {
                host.add_open_port(open_port, String::new());
            }
            hosts.push(host);
        }
        service_map = run_service_detection(hosts);
        match msg_tx.send(String::from(define::MESSAGE_END_SERVICEDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    // Run OS fingerprinting
    let mut os_probe_results: Vec<netscan::os::ProbeResult> = Vec::new();
    if opt.os_detection {
        match msg_tx.send(String::from(define::MESSAGE_START_OSDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
        let mut hosts: Vec<model::Host> = Vec::new();
        for scanned_host in &ns_scan_result.hosts {
            let mut host: model::Host = model::Host::new();
            host.ip_addr = scanned_host.ip_addr;
            host.host_name = scanned_host.host_name.clone();
            for port in &scanned_host.ports {
                match port.status {
                    netscan::host::PortStatus::Open => {
                        host.add_open_port(port.port, String::new());
                    },
                    netscan::host::PortStatus::Closed => {
                        host.add_closed_port(port.port);
                    },
                    _ => {},
                }
            }
            hosts.push(host);
        }
        os_probe_results = run_os_fingerprinting(opt.src_ip, hosts);
        match msg_tx.send(String::from(define::MESSAGE_END_OSDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    scan_result.end_time = sys::get_sysdate();
    scan_result.elapsed_time = start_time.elapsed().as_millis() as u64;

    // Get master data
    let tcp_map: HashMap<u16, String> = db::get_tcp_map();

    // Arp (only for local network)
    let mut arp_targets: Vec<IpAddr> = vec![];
    let mut mac_map: HashMap<IpAddr, String> = HashMap::new(); 
    let mut oui_db: HashMap<String, String> = HashMap::new();
    for host in &ns_scan_result.hosts {
        if crate::ip::in_same_network(opt.src_ip, host.ip_addr) {
            arp_targets.push(host.ip_addr);
        }
    }
    if arp_targets.len() > 0 {
        mac_map = crate::ip::get_mac_addresses(arp_targets, opt.src_ip);
        oui_db = db::get_oui_detail_map();
    }

    // Set results
    match msg_tx.send(String::from(define::MESSAGE_START_CHECK_RESULTS)) {
        Ok(_) => {}
        Err(_) => {}
    }
    for scanned_host in ns_scan_result.hosts {
        let mut node_info: model::NodeInfo = model::NodeInfo::new();
        node_info.ip_addr = scanned_host.ip_addr;
        node_info.host_name = scanned_host.host_name.clone();
        node_info.node_type = model::NodeType::Destination;
        
        for port in scanned_host.ports {
            let mut service_info: model::ServiceInfo = model::ServiceInfo::new();
            service_info.port_number = port.port;
            match port.status {
                netscan::host::PortStatus::Open => {
                    service_info.port_status = model::PortStatus::Open;
                },
                netscan::host::PortStatus::Closed => {
                    service_info.port_status = model::PortStatus::Closed;
                },
                _ => {},
            }
            service_info.service_name = tcp_map.get(&port.port).unwrap_or(&String::new()).clone();

            if service_map.contains_key(&scanned_host.ip_addr) {
                if let Some(service_version) = service_map.get(&scanned_host.ip_addr).unwrap().get(&port.port) {
                    service_info.service_version = service_version.clone();
                }
            }
            node_info.services.push(service_info);
        }

        node_info.ttl = scanned_host.ttl;

        node_info.mac_addr = mac_map.get(&scanned_host.ip_addr).unwrap_or(&String::new()).clone();
        node_info.vendor_info = if let Some(mac) = mac_map.get(&scanned_host.ip_addr) {
            if mac.len() > 16 {
                let prefix8 = mac[0..8].to_uppercase();
                oui_db
                    .get(&prefix8)
                    .unwrap_or(&String::new())
                    .to_string()
            } else {
                oui_db.get(mac).unwrap_or(&String::new()).to_string()
            }
        } else {
            String::new()
        };
        
        let mut os_fingerprint: model::OsFingerprint = model::OsFingerprint::new();
        for os_probe_result in &os_probe_results {
            if os_probe_result.ip_addr == scanned_host.ip_addr {
                if let Some(syn_ack_result) = &os_probe_result.tcp_syn_ack_result {
                    if syn_ack_result.fingerprints.len() > 0 {
                        os_fingerprint = db::verify_os_fingerprint(syn_ack_result.fingerprints[0].clone());
                    }
                }else {
                    if let Some(ecn_result) = &os_probe_result.tcp_ecn_result {
                        if ecn_result.fingerprints.len() > 0 {
                            os_fingerprint = db::verify_os_fingerprint(ecn_result.fingerprints[0].clone());
                        }
                    }
                }
            }
        }

        node_info.cpe = os_fingerprint.cpe;
        node_info.os_name = os_fingerprint.os_name;
        
        scan_result.nodes.push(node_info);
    }
    match msg_tx.send(String::from(define::MESSAGE_END_CHECK_RESULTS)) {
        Ok(_) => {}
        Err(_) => {}
    }
    scan_result.probe_status = result::ProbeStatus::Done;
    scan_result
}

pub fn run_host_scan(opt: option::HostScanOption) -> netscan::result::ScanResult {
    let mut host_scanner = netscan::scanner::HostScanner::new(opt.src_ip).unwrap();
    for target in opt.targets {
        let dst: netscan::host::HostInfo = netscan::host::HostInfo::new_with_ip_addr(target.ip_addr)
            .with_ports(target.ports.clone())
            .with_host_name(target.host_name.clone());
        host_scanner.scan_setting.add_target(dst);
    }
    host_scanner.scan_setting.scan_type = opt.scan_type.to_netscan_type();
    host_scanner.scan_setting.set_timeout(opt.timeout);
    host_scanner.scan_setting.set_wait_time(opt.wait_time);
    host_scanner.scan_setting.set_send_rate(opt.send_rate);

    let ns_scan_result: netscan::result::ScanResult = host_scanner.sync_scan();
    ns_scan_result
}

pub async fn run_async_host_scan(opt: option::HostScanOption) -> netscan::result::ScanResult  {
    let mut host_scanner = netscan::scanner::HostScanner::new(opt.src_ip).unwrap();
    for target in opt.targets {
        let dst: netscan::host::HostInfo = netscan::host::HostInfo::new_with_ip_addr(target.ip_addr)
            .with_ports(target.ports.clone())
            .with_host_name(target.host_name.clone());
        host_scanner.scan_setting.add_target(dst);
    }
    host_scanner.scan_setting.scan_type = opt.scan_type.to_netscan_type();
    host_scanner.scan_setting.set_timeout(opt.timeout);
    host_scanner.scan_setting.set_wait_time(opt.wait_time);
    host_scanner.scan_setting.set_send_rate(opt.send_rate);

    let ns_scan_result: netscan::result::ScanResult = async_io::block_on(async { host_scanner.scan().await });
    ns_scan_result
}

pub async fn run_node_scan(opt: option::HostScanOption, msg_tx: &mpsc::Sender<String>) -> result::HostScanResult {
    let mut scan_result: result::HostScanResult = result::HostScanResult::new();
    scan_result.probe_id = sys::get_probe_id();
    scan_result.command_type = option::CommandType::HostScan;
    scan_result.protocol = opt.protocol;
    scan_result.scan_type = opt.scan_type;
    scan_result.start_time = sys::get_sysdate();
    let start_time: Instant = Instant::now();

    // Run host scan
    match msg_tx.send(String::from(define::MESSAGE_START_HOSTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    let ns_scan_result: netscan::result::ScanResult = if opt.async_scan {
        run_async_host_scan(opt.clone()).await
    } else {
        run_host_scan(opt.clone())
    };
    match msg_tx.send(String::from(define::MESSAGE_END_HOSTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }

    // lookup
    match msg_tx.send(String::from(define::MESSAGE_START_LOOKUP)) {
        Ok(_) => {}
        Err(_) => {}
    }
    // DNS lookup
    let mut lookup_target_ips: Vec<IpAddr> = vec![];
    let mut dns_map: HashMap<IpAddr, String> = HashMap::new();
    for host in &ns_scan_result.hosts {
        if host.host_name.is_empty() || host.host_name == host.ip_addr.to_string() {
            lookup_target_ips.push(host.ip_addr);
        }else{
            dns_map.insert(host.ip_addr, host.host_name.clone());
        }
    }
    let resolved_map: HashMap<IpAddr, String> = crate::dns::lookup_ips(lookup_target_ips);
    for (ip, host_name) in resolved_map {
        if host_name.is_empty() {
            dns_map.insert(ip, ip.to_string());
        }else{
            dns_map.insert(ip, host_name);
        }
    }
    // Arp (only for local network)
    let mut arp_targets: Vec<IpAddr> = vec![];
    let mut mac_map: HashMap<IpAddr, String> = HashMap::new(); 
    let mut oui_db: HashMap<String, String> = HashMap::new();
    for host in &ns_scan_result.hosts {
        if crate::ip::in_same_network(opt.src_ip, host.ip_addr) {
            arp_targets.push(host.ip_addr);
        }
    }
    if arp_targets.len() > 0 {
        mac_map = crate::ip::get_mac_addresses(arp_targets, opt.src_ip);
        oui_db = db::get_oui_detail_map();
    }
    match msg_tx.send(String::from(define::MESSAGE_END_LOOKUP)) {
        Ok(_) => {}
        Err(_) => {}
    }

    scan_result.end_time = sys::get_sysdate();
    scan_result.elapsed_time = start_time.elapsed().as_millis() as u64;

    // Set results
    match msg_tx.send(String::from(define::MESSAGE_START_CHECK_RESULTS)) {
        Ok(_) => {}
        Err(_) => {}
    }
    for scanned_host in ns_scan_result.hosts {
        let mut node_info: model::NodeInfo = model::NodeInfo::new();
        node_info.ip_addr = scanned_host.ip_addr;
        node_info.host_name = dns_map.get(&scanned_host.ip_addr).unwrap_or(&scanned_host.ip_addr.to_string()).clone();
        node_info.node_type = model::NodeType::Destination;
        
        for port in scanned_host.ports {
            let mut service_info: model::ServiceInfo = model::ServiceInfo::new();
            service_info.port_number = port.port;
            match port.status {
                netscan::host::PortStatus::Open => {
                    service_info.port_status = model::PortStatus::Open;
                },
                netscan::host::PortStatus::Closed => {
                    service_info.port_status = model::PortStatus::Closed;
                },
                _ => {},
            }
            node_info.services.push(service_info);
        }

        node_info.ttl = scanned_host.ttl;

        node_info.mac_addr = mac_map.get(&scanned_host.ip_addr).unwrap_or(&String::new()).clone();
        node_info.vendor_info = if let Some(mac) = mac_map.get(&scanned_host.ip_addr) {
            if mac.len() > 16 {
                let prefix8 = mac[0..8].to_uppercase();
                oui_db
                    .get(&prefix8)
                    .unwrap_or(&String::new())
                    .to_string()
            } else {
                oui_db.get(mac).unwrap_or(&String::new()).to_string()
            }
        } else {
            String::new()
        };

        let mut os_fingerprint: model::OsFingerprint = model::OsFingerprint::new();
        for fingerprint in &ns_scan_result.fingerprints {
            if fingerprint.ip_fingerprint.source_ip == scanned_host.ip_addr {
                os_fingerprint = db::verify_os_fingerprint(fingerprint.clone());
            }
        }
        node_info.cpe = os_fingerprint.cpe;
        node_info.os_name = os_fingerprint.os_name;

        scan_result.nodes.push(node_info);
    }
    match msg_tx.send(String::from(define::MESSAGE_END_CHECK_RESULTS)) {
        Ok(_) => {}
        Err(_) => {}
    }
    scan_result.probe_status = result::ProbeStatus::Done;
    return scan_result;
}

pub fn run_ping(opt: option::PingOption, msg_tx: &mpsc::Sender<String>) -> result::PingResult {
    let mut ping_result = result::PingResult::new();
    ping_result.probe_id = sys::get_probe_id();
    ping_result.command_type = option::CommandType::Ping;
    ping_result.protocol = opt.protocol;
    ping_result.start_time = sys::get_sysdate();
    let port: Option<u16> = if opt.target.ports.len() > 0 {
        Some(opt.target.ports[0])
    } else {
        None
    };
    let start_time: Instant = Instant::now();
    let mut pinger: tracert::ping::Pinger = tracert::ping::Pinger::new(opt.target.ip_addr).unwrap();
    match opt.protocol {
        option::IpNextLevelProtocol::ICMPv4 => {
            pinger.set_protocol(tracert::protocol::Protocol::Icmpv4);
        }
        option::IpNextLevelProtocol::ICMPv6 => {
            pinger.set_protocol(tracert::protocol::Protocol::Icmpv6);
        }
        option::IpNextLevelProtocol::TCP => {
            pinger.set_protocol(tracert::protocol::Protocol::Tcp);
            pinger.dst_port = port.unwrap_or(80);
        }
        option::IpNextLevelProtocol::UDP => {
            pinger.set_protocol(tracert::protocol::Protocol::Udp);
            pinger.dst_port = port.unwrap_or(33435);
        }
    }
    pinger.count = opt.count;
    pinger.set_ping_timeout(opt.timeout);
    let rx = pinger.get_progress_receiver();
    let handle = thread::spawn(move || pinger.ping());
    while let Ok(node) = rx.lock().unwrap().recv() {
        match msg_tx.send(format!(
            "[{}] SEQ:{} IP:{} TTL:{:?} HOP:{:?} RTT:{:?}",
            opt.protocol.name(),
            node.seq,
            node.ip_addr,
            node.ttl.unwrap_or(0),
            node.hop.unwrap_or(0),
            node.rtt
        )) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let tr_ping_result: tracert::ping::PingResult = handle.join().unwrap().unwrap();
    ping_result.end_time = sys::get_sysdate();
    ping_result.elapsed_time = start_time.elapsed().as_millis() as u64;
    ping_result.probe_status = result::ProbeStatus::Done;
    ping_result.stat.probe_time = tr_ping_result.probe_time.as_millis() as u64;
    ping_result.stat.transmitted_count = tr_ping_result.results.len();
    ping_result.stat.received_count = tr_ping_result.results.len();
    let mut rtt_vec: Vec<u128> = vec![];
    for node in tr_ping_result.results {
        let mut ping_response: result::PingResponse = result::PingResponse::new();
        ping_response.seq = node.seq;
        ping_response.protocol = opt.protocol.name();
        ping_response.ip_addr = node.ip_addr;
        ping_response.host_name = node.host_name.clone();
        ping_response.port_number = port;
        ping_response.ttl = node.ttl.unwrap_or(0);
        ping_response.hop = node.hop.unwrap_or(0);
        ping_response.rtt = node.rtt.as_micros() as u64;
        ping_response.node_type = model::NodeType::from_tracert_type(node.node_type);
        rtt_vec.push(node.rtt.as_micros());
        ping_result.stat.responses.push(ping_response);
    }
    let min: u128;
    let max: u128;
    let avg: u128 = (rtt_vec.iter().sum::<u128>() as usize / rtt_vec.len()) as u128;
    match rtt_vec.iter().min() {
        Some(n) => min = *n,
        None => unreachable!(),
    }
    match rtt_vec.iter().max() {
        Some(n) => max = *n,
        None => unreachable!(),
    }
    ping_result.stat.min = min as u64;
    ping_result.stat.max = max as u64;
    ping_result.stat.avg = avg as u64;
    ping_result
}

pub fn run_traceroute(opt: option::TracerouteOption, msg_tx: &mpsc::Sender<String>) -> result::TracerouteResult {
    let mut trace_result = result::TracerouteResult::new();
    trace_result.probe_id = sys::get_probe_id();
    trace_result.command_type = option::CommandType::Ping;
    trace_result.protocol = opt.protocol;
    trace_result.start_time = sys::get_sysdate();
    let start_time: Instant = Instant::now();

    let mut tracer: tracert::trace::Tracer = tracert::trace::Tracer::new(opt.target.ip_addr).unwrap();
    tracer.set_trace_timeout(opt.timeout);
    let rx = tracer.get_progress_receiver();
    let handle = thread::spawn(move || tracer.trace());
    while let Ok(node) = rx.lock().unwrap().recv() {
        match msg_tx.send(format!(
            "SEQ:{} IP:{} HOP:{:?} RTT:{:?}",
            node.seq,
            node.ip_addr,
            node.hop.unwrap_or(0),
            node.rtt
        )) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let tr_trace_result: tracert::trace::TraceResult = handle.join().unwrap().unwrap();
    trace_result.end_time = sys::get_sysdate();
    trace_result.elapsed_time = start_time.elapsed().as_millis() as u64;
    trace_result.probe_status = result::ProbeStatus::Done;
    for node in tr_trace_result.nodes {
        let mut trace_response: result::PingResponse = result::PingResponse::new();
        trace_response.seq = node.seq;
        trace_response.ip_addr = node.ip_addr;
        trace_response.host_name = node.host_name.clone();
        trace_response.ttl = node.ttl.unwrap_or(0);
        trace_response.hop = node.hop.unwrap_or(0);
        trace_response.rtt = node.rtt.as_micros() as u64;
        trace_response.node_type = model::NodeType::from_tracert_type(node.node_type);
        trace_result.nodes.push(trace_response);
    }
    trace_result
}

pub fn run_domain_scan(opt: option::DomainScanOption, msg_tx: &mpsc::Sender<String>) -> result::DomainScanResult {
    let mut domain_result = result::DomainScanResult::new();
    domain_result.probe_id = sys::get_probe_id();
    domain_result.command_type = option::CommandType::DomainScan;
    domain_result.protocol = option::IpNextLevelProtocol::UDP;
    domain_result.start_time = sys::get_sysdate();
    let start_time: Instant = Instant::now();
    let mut domain_scanner = match domainscan::scanner::DomainScanner::new() {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    domain_scanner.set_base_domain(opt.base_domain.clone());
    if opt.words.len() > 0 {
        for w in opt.words {
            domain_scanner.add_word(w);
        }
    }else{
        for d in db::get_subdomain() {
            domain_scanner.add_word(d);
        }
    }
    domain_scanner.set_timeout(opt.timeout);
    match msg_tx.send(String::from(define::MESSAGE_START_DOMAINSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    let rx = domain_scanner.get_progress_receiver();
    let rt: tokio::runtime::Runtime = tokio::runtime::Runtime::new().unwrap();
    let handle = thread::spawn(move || rt.block_on(async { domain_scanner.scan().await }));
    while let Ok(domain) = rx.lock().unwrap().recv() {
        match msg_tx.send(domain) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let domain_scan_result: domainscan::result::DomainScanResult = handle.join().unwrap();
    match msg_tx.send(String::from(define::MESSAGE_END_DOMAINSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    domain_result.end_time = sys::get_sysdate();
    domain_result.elapsed_time = start_time.elapsed().as_millis() as u64;
    domain_result.probe_status = result::ProbeStatus::Done;
    let mut domains: Vec<result::Domain> = vec![];
    for domain in domain_scan_result.domains {
        domains.push(result::Domain {
            domain_name: domain.domain_name,
            ips: domain.ips,
        });
    }
    domain_result.base_domain = opt.base_domain;
    domain_result.domains = domains;
    domain_result
}
