use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use serde::{Serialize, Deserialize};
use rand::seq::SliceRandom;
use xenet::packet::ip::IpNextLevelProtocol;
use crate::validator;
use rushmap_core::option::{PortScanOption, PortScanType, HostScanOption, HostScanType, PingOption, TracerouteOption, TargetInfo};
use rushmap_core::db;
use rushmap_core::dns;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortArg {
    target_host: String,
    port_option: String,
    ports: Vec<u16>,
    scan_type: String,
    async_flag: bool,
    service_detection_flag: bool,
    os_detection_flag: bool,
    randomize_flag: bool,
    save_flag: bool,
}

impl PortArg {
    pub async fn to_scan_option(&self) -> PortScanOption {
        let ip_addr: IpAddr;
        if validator::is_ipaddr(self.target_host.clone()) {
            ip_addr = self.target_host.parse::<IpAddr>().unwrap();
        }else{
            match dns::lookup_host_name_async(self.target_host.clone()).await {
                Some(ip) => {
                    ip_addr = ip;
                },
                None => {
                    ip_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
                }
            }
        }
        let mut opt: PortScanOption = PortScanOption::default(ip_addr);
        // Network Interface
        let selected_interface_index = crate::db::get_selected_interface_index();
        if selected_interface_index != 0 && selected_interface_index != opt.interface_index {
            if let Some(selected_interface) = rushmap_core::interface::get_interface_by_index(selected_interface_index) {
                opt.interface_index = selected_interface.index;
                opt.interface_name = selected_interface.name.clone();
                match ip_addr {
                    IpAddr::V4(_) => {
                        if selected_interface.ipv4.len() > 0 {
                            opt.src_ip = IpAddr::V4(selected_interface.ipv4[0].addr);
                        }
                    }
                    IpAddr::V6(_) => {
                        for ip in selected_interface.ipv6 {
                            if rushmap_core::ip::is_global_addr(ip_addr) {
                                if xenet::net::ipnet::is_global_ipv6(&ip.addr) {
                                    opt.src_ip = IpAddr::V6(ip.addr);
                                    break;
                                }
                            }else {
                                opt.src_ip = IpAddr::V6(ip.addr);
                                break;
                            }
                        }
                    }
                }
            }
        }
        let mut target: TargetInfo = TargetInfo::new_with_ip_addr(ip_addr).with_host_name(self.target_host.clone());

        if self.port_option == String::from("well_known") {
            target.ports = db::get_wellknown_ports();
        }else if self.port_option == String::from("custom_list") {
            target.ports = self.ports.clone();
        }else{
            target.ports = db::get_default_ports();
        }
        opt.targets.push(target);

        if self.scan_type == PortScanType::TcpConnectScan.id() {
            opt.scan_type = PortScanType::TcpConnectScan;
        }else{
            opt.scan_type = PortScanType::TcpSynScan;
        }
        opt.async_scan = self.async_flag;
        if self.service_detection_flag {
            opt.service_detection = true;
        }
        opt.os_detection = self.os_detection_flag;
        if self.randomize_flag {
            // Randomize targets by default
            let mut rng = rand::thread_rng();
            for target in opt.targets.iter_mut() {
                target.ports.shuffle(&mut rng);
            }
            opt.targets.shuffle(&mut rng);
        }
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
    randomize_flag: bool,
    save_flag: bool,
}

impl HostArg {
    pub fn to_scan_option(&self) -> HostScanOption {
        let mut opt: HostScanOption = HostScanOption::default();
        // Network Interface
        let selected_interface_index = crate::db::get_selected_interface_index();
        if selected_interface_index != 0 && selected_interface_index != opt.interface_index {
            if let Some(selected_interface) = rushmap_core::interface::get_interface_by_index(selected_interface_index) {
                opt.interface_index = selected_interface.index;
                opt.interface_name = selected_interface.name.clone();
                if selected_interface.ipv4.len() > 0 {
                    opt.src_ip = IpAddr::V4(selected_interface.ipv4[0].addr);
                } else {
                    if selected_interface.ipv6.len() > 0 {
                        opt.src_ip = IpAddr::V6(selected_interface.ipv6[0].addr);
                    }
                }
            }
        }
        if self.protocol.to_uppercase() == IpNextLevelProtocol::Icmp.as_str().to_uppercase() {
            opt.protocol = IpNextLevelProtocol::Icmp;
            opt.scan_type = HostScanType::IcmpPingScan;
        } else if self.protocol.to_uppercase() == IpNextLevelProtocol::Icmpv6.as_str().to_uppercase() {
            opt.protocol = IpNextLevelProtocol::Icmpv6;
            opt.scan_type = HostScanType::IcmpPingScan;
        } else if self.protocol.to_uppercase() == IpNextLevelProtocol::Tcp.as_str().to_uppercase() {
            opt.protocol = IpNextLevelProtocol::Tcp;
            opt.scan_type = HostScanType::TcpPingScan;
        } else if self.protocol.to_uppercase() == IpNextLevelProtocol::Udp.as_str().to_uppercase() {
            opt.protocol = IpNextLevelProtocol::Udp;
            opt.scan_type = HostScanType::UdpPingScan;
        }else{
            opt.protocol = IpNextLevelProtocol::Icmp;
            opt.scan_type = HostScanType::IcmpPingScan;
        }
        opt.async_scan = self.async_flag;
        if self.target_hosts.len() > 0 {
            match self.target_hosts[0].parse::<IpAddr>(){
                Ok(ip_addr) => {
                    if rushmap_core::ip::is_global_addr(ip_addr) && opt.scan_type == HostScanType::IcmpPingScan {
                        opt.wait_time = Duration::from_millis(1000);
                    }
                },
                Err(_) => {},
            }
        }
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
                opt.set_hosts_from_na(self.network_address.clone(), self.prefix_len, Some(80));
            }else{
                opt.set_hosts_from_na(self.network_address.clone(), self.prefix_len, Some(self.port));
            }
        }
        if self.randomize_flag {
            // Randomize targets by default
            let mut rng = rand::thread_rng();
            opt.targets.shuffle(&mut rng);
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
    pub async fn to_scan_option(&self) -> PingOption {
        let target_ip: IpAddr = match self.target_host.parse::<IpAddr>(){
                                    Ok(ip) => {
                                        ip
                                    },
                                    Err(_) => {
                                        match dns::lookup_host_name_async(self.target_host.clone()).await {
                                            Some(ip) => {
                                                ip
                                            },
                                            None => {
                                                IpAddr::V4(Ipv4Addr::LOCALHOST)
                                            }
                                        }
                                    },
                                };
        let mut opt: PingOption = PingOption::default(target_ip, 4);
        // Network Interface
        let selected_interface_index = crate::db::get_selected_interface_index();
        if selected_interface_index != 0 && selected_interface_index != opt.interface_index {
            if let Some(selected_interface) = rushmap_core::interface::get_interface_by_index(selected_interface_index) {
                opt.interface_index = selected_interface.index;
                opt.interface_name = selected_interface.name.clone();
                match target_ip {
                    IpAddr::V4(_) => {
                        if selected_interface.ipv4.len() > 0 {
                            opt.src_ip = IpAddr::V4(selected_interface.ipv4[0].addr);
                        }
                    }
                    IpAddr::V6(_) => {
                        for ip in selected_interface.ipv6 {
                            if rushmap_core::ip::is_global_addr(target_ip) {
                                if xenet::net::ipnet::is_global_ipv6(&ip.addr) {
                                    opt.src_ip = IpAddr::V6(ip.addr);
                                    break;
                                }
                            }else {
                                opt.src_ip = IpAddr::V6(ip.addr);
                                break;
                            }
                        }
                    }
                }
            }
        }
        if self.protocol.to_uppercase() == IpNextLevelProtocol::Icmp.as_str().to_uppercase() {
            opt.protocol = IpNextLevelProtocol::Icmp;
        } else if self.protocol.to_uppercase() == IpNextLevelProtocol::Icmpv6.as_str().to_uppercase() {
            opt.protocol = IpNextLevelProtocol::Icmpv6;
        } else if self.protocol.to_uppercase() == IpNextLevelProtocol::Tcp.as_str().to_uppercase() {
            opt.protocol = IpNextLevelProtocol::Tcp;
        } else if self.protocol.to_uppercase() == IpNextLevelProtocol::Udp.as_str().to_uppercase() {
            opt.protocol = IpNextLevelProtocol::Udp;
        }

        if opt.protocol == IpNextLevelProtocol::Tcp {
            opt.target = TargetInfo::new_with_socket(target_ip, self.port).with_ip_lookup_async().await;
        }else{
            opt.target = TargetInfo::new_with_ip_lookup_async(target_ip).await;
        }
        opt.count = self.count as u8;
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
    pub async fn to_scan_option(&self) -> TracerouteOption {
        let target_ip: IpAddr = match self.target_host.parse::<IpAddr>(){
                                    Ok(ip) => {
                                        ip
                                    },
                                    Err(_) => {
                                        match dns::lookup_host_name_async(self.target_host.clone()).await {
                                            Some(ip) => {
                                                ip
                                            },
                                            None => {
                                                IpAddr::V4(Ipv4Addr::LOCALHOST)
                                            }
                                        }
                                    },
                                };
        let mut opt: TracerouteOption = TracerouteOption::default(target_ip);
        // Network Interface
        let selected_interface_index = crate::db::get_selected_interface_index();
        if selected_interface_index != 0 && selected_interface_index != opt.interface_index {
            if let Some(selected_interface) = rushmap_core::interface::get_interface_by_index(selected_interface_index) {
                opt.interface_index = selected_interface.index;
                opt.interface_name = selected_interface.name.clone();
                match target_ip {
                    IpAddr::V4(_) => {
                        if selected_interface.ipv4.len() > 0 {
                            opt.src_ip = IpAddr::V4(selected_interface.ipv4[0].addr);
                        }
                    }
                    IpAddr::V6(_) => {
                        for ip in selected_interface.ipv6 {
                            if rushmap_core::ip::is_global_addr(target_ip) {
                                if xenet::net::ipnet::is_global_ipv6(&ip.addr) {
                                    opt.src_ip = IpAddr::V6(ip.addr);
                                    break;
                                }
                            }else {
                                opt.src_ip = IpAddr::V6(ip.addr);
                                break;
                            }
                        }
                    }
                }
            }
        }
        opt.timeout = Duration::from_millis(self.timeout);
        opt.target = TargetInfo::new_with_ip_addr(target_ip).with_host_name(self.target_host.clone());
        opt.protocol = IpNextLevelProtocol::Udp;
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
pub struct AppInfo {
    pub name: String,
    pub description: String,
    pub version: String,
    pub release_date: String,
    pub repository: String,
}

impl AppInfo {
    pub fn new() -> AppInfo {
        AppInfo {
            name: crate::define::APP_NAME.to_string(),
            description: crate::define::APP_DESCRIPTION.to_string(),
            version: crate::define::APP_VERSION.to_string(),
            release_date: crate::define::APP_RELEASE_DATE.to_string(),
            repository: crate::define::APP_REPOSITORY.to_string(),
        }
    }
}
