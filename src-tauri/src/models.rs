use std::net::IpAddr;
use serde::{Serialize, Deserialize};
use crate::option::{TargetInfo, ScanOption, CommandType, ScanType, Protocol};
use crate::validator;
use crate::network;
use crate::dataset;

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
    pub fn to_scan_option(&self) -> crate::option::ScanOption {
        let mut opt: ScanOption = ScanOption::default();
        opt.command_type = CommandType::PortScan;
        opt.tcp_map = dataset::get_tcp_map();
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
            target.ports = dataset::get_wellknown_ports();
        }else if self.port_option == String::from("custom_list") {
            target.ports = self.ports.clone();
        }else{
            target.ports = dataset::get_default_ports();
            opt.default_scan = true;
        }
        if self.async_flag {
            opt.async_scan = true;
        }
        if self.service_detection_flag {
            opt.service_detection = true;
            opt.http_ports = dataset::get_http_ports();
            opt.https_ports = dataset::get_https_ports();
        }
        if self.os_detection_flag {
            opt.os_detection = true;
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
    pub fn to_scan_option(&self) -> crate::option::ScanOption {
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
        opt.oui_map = dataset::get_oui_detail_map();
        opt.ttl_map = dataset::get_os_ttl();
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
    pub fn to_scan_option(&self) -> crate::option::ScanOption {
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
    pub fn to_scan_option(&self) -> crate::option::ScanOption {
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogSearchArg {
    pub target_host: String,
    pub probe_types: Vec<String>,
    pub start_date: String,
    pub end_date: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
    pub friendly_name: String,
    pub description: String,
    pub if_type: String,
    pub mac_addr: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateway_mac_addr: String,
    pub gateway_ip_addr: String,
}

impl NetworkInterface {
    pub fn new() -> NetworkInterface {
        NetworkInterface {
            index: 0,
            name: String::new(),
            friendly_name: String::new(),
            description: String::new(),
            if_type: String::new(),
            mac_addr: String::new(),
            ipv4: vec![],
            ipv6: vec![],
            gateway_mac_addr: String::new(),
            gateway_ip_addr: String::new(),
        }
    }
}
