use std::net::IpAddr;
use serde::{Serialize, Deserialize};
use enmap_core::option::{TargetInfo, ScanOption, CommandType, ScanType, Protocol};
use enmap_core::validator;
use enmap_core::network;

use crate::db;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortArg {
    target_host: String,
    port_option: String,
    ports: Vec<u16>,
    scan_type: String,
    async_flag: bool,
    service_detection_flag: bool,
    os_detection_flag: bool,
    save_flag: bool,
}

impl PortArg {
/*     pub fn new() -> PortArg {
        PortArg {
            target_host: String::new(),
            port_option: String::new(),
            ports: vec![],
            scan_type: String::new(),
            async_flag: false,
            service_detection_flag: false,
            os_detection_flag: false,
            save_flag: false,
        }
    } */
    pub fn to_scan_option(&self) -> enmap_core::option::ScanOption {
        let mut opt: ScanOption = ScanOption::default();
        opt.command_type = CommandType::PortScan;
        opt.tcp_map = db::get_tcp_map();
        let ip_addr: IpAddr;
        if validator::is_ipaddr(self.target_host.clone()) {
            ip_addr = self.target_host.parse::<IpAddr>().unwrap();
        }else{
            match network::lookup_host_name(self.target_host.clone()) {
                Some(ip) => {
                    ip_addr = ip;
                },
                None => {
                    return opt;
                }
            }
        }
        let mut target: TargetInfo = TargetInfo::new_with_ip_addr(ip_addr);
        if self.port_option == String::from("well_known") {
            target.ports = db::get_wellknown_ports();
        }else if self.port_option == String::from("custom_list") {
            target.ports = self.ports.clone();
        }else{
            target.ports = db::get_default_ports();
            opt.default_scan = true;
        }
        if self.async_flag {
            opt.async_scan = true;
        }
        if self.service_detection_flag {
            opt.service_detection = true;
            opt.http_ports = db::get_http_ports();
            opt.https_ports = db::get_https_ports();
        }
        if self.os_detection_flag {
            opt.os_detection = true;
            opt.tcp_fingerprints = db::get_tcp_fingerprints(); 
        }
        opt.targets.push(target);
        opt
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostArg {
    network_address: String,
    prefix_len: u8,
    protocol: String,
    port: u16,
    target_hosts: Vec<String>,
    scan_type: String,
    async_flag: bool,
    dsn_lookup_flag: bool,
    os_detection_flag: bool,
    save_flag: bool,
}

impl HostArg {
/*     pub fn new() -> HostArg {
        HostArg {
            network_address: String::new(),
            prefix_len: 24,
            protocol: Protocol::ICMPv4.name(),
            port: 0,
            target_hosts: vec![],
            scan_type: String::new(),
            async_flag: false,
            dsn_lookup_flag: false,
            os_detection_flag: false,
            save_flag: false,
        }
    } */
    pub fn to_scan_option(&self) -> enmap_core::option::ScanOption {
        let mut opt: ScanOption = ScanOption::default();
        opt.command_type = CommandType::HostScan;
        if self.protocol == Protocol::TCP.name() {
            opt.protocol = Protocol::TCP;
            opt.host_scan_type = ScanType::TcpPingScan;
        }else{
            opt.protocol = Protocol::ICMPv4;
            opt.host_scan_type = ScanType::IcmpPingScan;
        }
        opt.async_scan = self.async_flag;
        opt.oui_map = db::get_oui_map();
        opt.ttl_map = db::get_os_ttl();
        if self.scan_type == String::from("custom_list") {
            for host in &self.target_hosts {
                match host.parse::<IpAddr>(){
                    Ok(ip_addr) => {
                        if self.port == 0 {
                            opt.targets.push(TargetInfo::new_with_socket(ip_addr, 80));
                        }else{
                            opt.targets.push(TargetInfo::new_with_socket(ip_addr, self.port));
                        }
                    },
                    Err(_) => {},
                }
            }
        } else {
            if self.port == 0 {
                opt.set_dst_hosts_from_na(self.network_address.clone(), self.prefix_len, Some(80));
            }else{
                opt.set_dst_hosts_from_na(self.network_address.clone(), self.prefix_len, Some(self.port));
            }
        }
        opt
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingArg {
    target_host: String,
    protocol: String,
    port: u16,
    count: u32,
    os_detection_flag: bool,
    save_flag: bool,
}

impl PingArg {
    pub fn to_scan_option(&self) -> enmap_core::option::ScanOption {
        let mut opt: ScanOption = ScanOption::default();
        opt.command_type = CommandType::Ping;
        // TODO: IPv6 support
        let target_ip: IpAddr = match self.target_host.parse::<IpAddr>(){
                                    Ok(ip) => {
                                        ip
                                    },
                                    Err(_) => {
                                        match network::lookup_host_name(self.target_host.clone()) {
                                            Some(ip) => {
                                                ip
                                            },
                                            None => {
                                                return opt;
                                            }
                                        }
                                    },
                                };
        if self.protocol == Protocol::TCP.name() {
            opt.protocol = Protocol::TCP;
            opt.targets.push(TargetInfo::new_with_socket(target_ip, self.port));
        } else if self.protocol == Protocol::UDP.name() {
            opt.protocol = Protocol::UDP;
            opt.targets.push(TargetInfo::new_with_socket(target_ip, 33435));
        } else {
            opt.protocol = Protocol::ICMPv4;
            opt.targets.push(TargetInfo::new_with_ip_addr(target_ip));
        }
        opt.count = self.count;
        opt
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TracerouteArg {
    target_host: String,
    max_hop: u8,
    timeout: u64,
    os_detection_flag: bool,
    save_flag: bool,
}

impl TracerouteArg {
    pub fn to_scan_option(&self) -> enmap_core::option::ScanOption {
        let mut opt: ScanOption = ScanOption::default();
        opt.command_type = CommandType::Traceroute;
        opt.set_timeout_from_milis(self.timeout);
        // TODO: IPv6 support
        let target_ip: IpAddr = match self.target_host.parse::<IpAddr>(){
                                    Ok(ip) => {
                                        ip
                                    },
                                    Err(_) => {
                                        match network::lookup_host_name(self.target_host.clone()) {
                                            Some(ip) => {
                                                ip
                                            },
                                            None => {
                                                return opt;
                                            }
                                        }
                                    },
                                };
        opt.targets.push(TargetInfo::new_with_ip_addr(target_ip));
        opt.protocol = Protocol::UDP;
        opt.max_hop = self.max_hop;
        opt
    }
}
