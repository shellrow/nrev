use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use clap::ArgMatches;
use enmap_core::option;
use enmap_core::network;
use enmap_core::option::Protocol;
use enmap_core::option::TargetInfo;
use super::define;
use super::validator;
use super::db;
use super::process;

fn get_default_option() -> option::ScanOption {
    let mut opt = option::ScanOption::new();
    opt.src_port = define::DEFAULT_SRC_PORT;
    match default_net::get_default_interface() {
        Ok(interface) => {
            opt.interface_index = interface.index;
            opt.interface_name = interface.name;
            if interface.ipv4.len() > 0 {
                opt.src_ip = IpAddr::V4(interface.ipv4[0].addr);
            }else{
                if interface.ipv6.len() > 0 {
                    opt.src_ip = IpAddr::V6(interface.ipv6[0].addr);
                }
            }
        },
        Err(_) => {},
    }
    if process::privileged() {
        opt.port_scan_type = option::ScanType::TcpSynScan;
    }else{
        opt.port_scan_type = option::ScanType::TcpConnectScan;
        opt.async_scan = true;
    }
    opt
}

pub fn parse_args(matches: ArgMatches) -> option::ScanOption {
    let mut opt = get_default_option();
    // Mode
    if matches.contains_id("port") {
        opt.command_type = option::CommandType::PortScan;
        let target: &str = matches.value_of("port").unwrap();
        let socketaddr_vec: Vec<&str> = target.split(":").collect();
        let host: String = socketaddr_vec[0].to_string();
        let mut target_info: TargetInfo = TargetInfo::new();
        if validator::is_ipaddr(host.clone()) {
            target_info.ip_addr = host.parse::<IpAddr>().unwrap();
        }else {
            match dns_lookup::lookup_host(&host) {
                Ok(addrs) => {
                    for addr in addrs {
                        if addr.is_ipv4() {
                            target_info.ip_addr = addr;
                            target_info.host_name = host.clone();
                            break;
                        }
                    }
                },
                Err(_) => {},
            }
        }
        if socketaddr_vec.len() > 1 {
            let port_opt = socketaddr_vec[1].to_string();
            if port_opt.contains("-") {
                let range: Vec<&str> = port_opt.split("-").collect();
                let s: u16 = match range[0].parse::<u16>() {
                    Ok(s) => s,
                    Err(_) => 0,
                };
                let e: u16 = match range[1].parse::<u16>() {
                    Ok(e) => e,
                    Err(_) => 0,
                };
                if s != 0 && e != 0 && s < e {
                    target_info.set_dst_ports_from_range(s, e);
                }
            }else if port_opt.contains(",") {
                target_info.set_dst_ports_from_csv(port_opt);
            }
        }else{
            opt.default_scan = true;
            target_info.ports = db::get_default_ports();
        }
        opt.targets.push(target_info);
        opt.tcp_map = db::get_tcp_map();
    }else if matches.contains_id("host") {
        opt.command_type = option::CommandType::HostScan;
        opt.protocol = option::Protocol::ICMPv4;
        opt.host_scan_type = option::ScanType::IcmpPingScan;
        let target: &str = matches.value_of("host").unwrap();
        let target_vec: Vec<&str> = target.split("/").collect();
        if validator::is_ipaddr(target_vec[0].to_string()) || validator::is_socketaddr(target_vec[0].to_string()) {
            let mut port :u16 = 80;
            let ip_addr: IpAddr = if validator::is_socketaddr(target_vec[0].to_string()) {
                let socket_addr = SocketAddr::from_str(target_vec[0]).unwrap();
                port = socket_addr.port();
                socket_addr.ip()
            }else{
                IpAddr::from_str(target_vec[0]).unwrap() 
            };
            let nw_addr: String = match network::get_network_address(ip_addr) {
                Ok(nw_addr) => nw_addr,
                Err(e) => {
                    print!("{}", e);
                    std::process::exit(0);
                },
            };
            // network
            if target.contains("/") {
                let nw_vec: Vec<&str> = target.split("/").collect();
                let prefix_len: u8 = match nw_vec[0].parse::<u8>() {
                    Ok(prefix_len) => prefix_len,
                    Err(_) => 24,
                };
                opt.set_dst_hosts_from_na(nw_addr, prefix_len, Some(port));
            }else{
                opt.set_dst_hosts_from_na(nw_addr, 24, Some(port));
            }
        }else{
            // list
            match validator::validate_filepath(target) {
                Ok(_) => {
                    opt.set_dst_hosts_from_list(target.to_string());
                },
                Err(_) => {
                    let ip_vec: Vec<&str> = target.split(",").collect();
                    for ip_str in ip_vec {
                        match IpAddr::from_str(&ip_str) {
                            Ok(ip) => {
                                opt.targets.push(TargetInfo::new_with_socket(ip, 80));
                            },
                            Err(_) => {
                                if let Some(ip) = network::lookup_host_name(ip_str.to_string()) {
                                    opt.targets.push(TargetInfo::new_with_socket(ip, 80));
                                }
                            },
                        }
                    }
                },
            }
        }
    }else if matches.contains_id("ping") {
        opt.command_type = option::CommandType::Ping;
        opt.protocol = Protocol::ICMPv4;
        let target: &str = matches.value_of("ping").unwrap();
        match target.parse::<IpAddr>(){
            Ok(ip) => {
                opt.targets.push(TargetInfo::new_with_ip_addr(ip));
            },
            Err(_) => {
                match SocketAddr::from_str(&target) {
                    Ok(socket_addr) => {
                        opt.targets.push(TargetInfo::new_with_socket(socket_addr.ip(), socket_addr.port()));
                    },
                    Err(_) => {
                        match dns_lookup::lookup_host(target) {
                            Ok(ips) => {
                                for ip in ips {
                                    if ip.is_ipv4() {
                                        opt.targets.push(TargetInfo::new_with_ip_addr(ip));
                                        break;
                                    }
                                }
                            },
                            Err(_) => {},
                        }
                    },
                }
            },
        }
    }else if matches.contains_id("trace") {
        opt.command_type = option::CommandType::Traceroute;
        opt.protocol = Protocol::UDP;
        let target: &str = matches.value_of("trace").unwrap();
        match target.parse::<IpAddr>(){
            Ok(ip) => {
                opt.targets.push(TargetInfo::new_with_ip_addr(ip));
            },
            Err(_) => {
                match dns_lookup::lookup_host(target) {
                    Ok(ips) => {
                        for ip in ips {
                            if ip.is_ipv4() {
                                opt.targets.push(TargetInfo::new_with_ip_addr(ip));
                                break;
                            }
                        }
                    },
                    Err(_) => {},
                }
            },
        }
    }else if matches.contains_id("domain") {
        opt.command_type = option::CommandType::DomainScan;
        opt.protocol = Protocol::UDP;
        let base_domain: &str = matches.value_of("domain").unwrap();
        opt.targets.push(TargetInfo::new_with_base_domain(base_domain.to_string()));
    }else if matches.contains_id("batch") {
        opt.command_type = option::CommandType::BatchScan;
    }else if matches.contains_id("passive") {
        opt.command_type = option::CommandType::PassiveScan;
    }
    // Flags
    if matches.contains_id("interface") {
        let v_interface: String = matches.get_one::<String>("interface").unwrap().to_string();
        if let Some(interface) = enmap_core::network::get_interface_by_name(v_interface){
            opt.interface_index = interface.index;
            opt.interface_name = interface.name;
            if interface.ipv4.len() > 0 {
                opt.src_ip = IpAddr::V4(interface.ipv4[0].addr);
            }else{
                if interface.ipv6.len() > 0 {
                    opt.src_ip = IpAddr::V6(interface.ipv6[0].addr);
                }
            }
        }
    }
    if matches.contains_id("source") {
        let v_src_ip: String = matches.get_one::<String>("source").unwrap().to_string();
        match v_src_ip.parse::<IpAddr>() {
            Ok(ip_addr) => {
                opt.src_ip = ip_addr;
            },
            Err(_) => {},
        }
    }
    if matches.contains_id("protocol") {
        let v_protocol: String = matches.get_one::<String>("protocol").unwrap().to_string();
        if v_protocol == "TCP" || v_protocol == "tcp" {
            opt.protocol = Protocol::TCP;   
            opt.host_scan_type = option::ScanType::TcpPingScan;
        }else if v_protocol == "UDP" || v_protocol == "udp" {
            opt.protocol = Protocol::UDP;
            opt.host_scan_type = option::ScanType::UdpPingScan;
        }else if v_protocol == "ICMPv4" || v_protocol == "icmpv4" || v_protocol == "ICMP" || v_protocol == "icmp" {
            opt.protocol = Protocol::ICMPv4;
            opt.host_scan_type = option::ScanType::IcmpPingScan;
        }else if v_protocol == "ICMPv6" || v_protocol == "icmpv6" {
            opt.protocol = Protocol::ICMPv6;
            opt.host_scan_type = option::ScanType::IcmpPingScan;
        }
    }
    if matches.contains_id("maxhop") {
        let v_maxhop: String = matches.get_one::<String>("maxhop").unwrap().to_string();
        match v_maxhop.parse::<u8>() {
            Ok(maxhop) => {
                opt.max_hop = maxhop;
            },
            Err(_) => {},
        }
    }
    if matches.contains_id("scantype") {
        let v_scantype: String = matches.get_one::<String>("scantype").unwrap().to_string();
        if v_scantype == "SYN" || v_scantype == "syn" {
            opt.port_scan_type = option::ScanType::TcpSynScan;   
        }else if v_scantype == "CONNECT" || v_scantype == "connect" {
            opt.port_scan_type = option::ScanType::TcpConnectScan;
        }else if v_scantype == "ICMPv4" || v_scantype == "icmpv4" {
            opt.host_scan_type = option::ScanType::IcmpPingScan;
        }else if v_scantype == "ICMPv6" || v_scantype == "icmpv6" {
            opt.host_scan_type = option::ScanType::IcmpPingScan;
        }else if v_scantype == "TCP" || v_scantype == "tcp" {
            opt.host_scan_type = option::ScanType::TcpPingScan;
        }else if v_scantype == "UDP" || v_scantype == "udp" {
            opt.host_scan_type = option::ScanType::UdpPingScan;
        }
    }
    if matches.contains_id("timeout") {
        let v_timeout: u64 = matches.get_one::<String>("timeout").unwrap().parse::<u64>().unwrap();
        opt.timeout = Duration::from_millis(v_timeout);
    }
    if matches.contains_id("waittime") {
        let v_waittime: u64 = matches.get_one::<String>("waittime").unwrap().parse::<u64>().unwrap();
        opt.wait_time = Duration::from_millis(v_waittime);
    }
    if matches.contains_id("rate") {
        let v_rate: u64 = matches.get_one::<String>("rate").unwrap().parse::<u64>().unwrap();
        opt.send_rate = Duration::from_millis(v_rate);
    }
    if matches.contains_id("count") {
        let v_count: u32 = matches.get_one::<String>("count").unwrap().parse::<u32>().unwrap();
        opt.count = v_count;
    }
    if matches.contains_id("service") {
        opt.service_detection = true;
        opt.http_ports = db::get_http_ports();
        opt.https_ports = db::get_https_ports();
    }
    if matches.contains_id("os") {
        opt.os_detection = true;
        opt.tcp_fingerprints = db::get_tcp_fingerprints(); 
    }
    if matches.contains_id("async") {
        opt.async_scan = true;
    }
    if matches.contains_id("list") {
        let v_list: String = matches.get_one::<String>("list").unwrap().to_string();
        opt.use_wordlist = true;
        opt.wordlist_path = v_list;
    }
    if matches.contains_id("config") {
        let v_config: String = matches.get_one::<String>("config").unwrap().to_string();
        opt.use_config = true;
        opt.config_path = v_config;     
    }
    if matches.contains_id("save") {
        let v_save: String = matches.get_one::<String>("save").unwrap().to_string();
        opt.save_file_path = v_save;
    }
    if matches.contains_id("acceptinvalidcerts") {
        opt.accept_invalid_certs = true;
    }

    opt

}
