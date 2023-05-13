use std::collections::HashMap;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};
use ipnet::Ipv4Net;
use serde::{Serialize, Deserialize};
use crate::process;
use crate::sys;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum CommandType {
    PortScan,
    HostScan,
    Ping,
    Traceroute,
    DomainScan
}

impl CommandType {
    pub fn id(&self) -> String {
        match *self {
            CommandType::PortScan => String::from("port_scan"),
            CommandType::HostScan => String::from("host_scan"),
            CommandType::Ping => String::from("ping"),
            CommandType::Traceroute => String::from("traceroute"),
            CommandType::DomainScan => String::from("domain_scan"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMPv4,
    ICMPv6,
}

impl Protocol {
    pub fn id(&self) -> String {
        match *self {
            Protocol::TCP => String::from("TCP"),
            Protocol::UDP => String::from("UDP"),
            Protocol::ICMPv4 => String::from("ICMPv4"),
            Protocol::ICMPv6 => String::from("ICMPv6"),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            Protocol::TCP => String::from("TCP"),
            Protocol::UDP => String::from("UDP"),
            Protocol::ICMPv4 => String::from("ICMPv4"),
            Protocol::ICMPv6 => String::from("ICMPv6"),
        }
    }
}

/// Scan Type 
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum ScanType {
    /// Default fast port scan type.
    /// 
    /// Send TCP packet with SYN flag to the target ports and check response.
    TcpSynScan,
    /// Attempt TCP connection and check port status.
    /// 
    /// Slow but can be run without administrator privileges.
    TcpConnectScan,
    /// Default host scan type.
    /// 
    /// Send ICMP echo request and check response.
    IcmpPingScan,
    /// Perform host scan for a specific service.
    /// 
    /// Send TCP packets with SYN flag to a specific port and check response.
    TcpPingScan,
    UdpPingScan,
}

impl ScanType {
    pub fn to_netscan_type(&self) -> netscan::setting::ScanType {
        match *self {
            ScanType::TcpSynScan => netscan::setting::ScanType::TcpSynScan,
            ScanType::TcpConnectScan => netscan::setting::ScanType::TcpConnectScan,
            ScanType::IcmpPingScan => netscan::setting::ScanType::IcmpPingScan,
            ScanType::TcpPingScan => netscan::setting::ScanType::TcpPingScan,
            ScanType::UdpPingScan => netscan::setting::ScanType::UdpPingScan,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetInfo {
    pub ip_addr: IpAddr,
    pub host_name: String,
    pub ports: Vec<u16>,
    pub base_uri: String,
    pub base_domain: String,
}

impl TargetInfo {
    pub fn new_with_ip_addr(ip_addr: IpAddr) -> TargetInfo {
        TargetInfo {
            ip_addr: ip_addr,
            host_name: String::new(),
            ports: vec![],
            base_uri: String::new(),
            base_domain: String::new(),
        }
    }
    pub fn new_with_socket(ip_addr: IpAddr, port: u16) -> TargetInfo {
        TargetInfo {
            ip_addr: ip_addr,
            host_name: String::new(),
            ports: vec![port],
            base_uri: String::new(),
            base_domain: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanOption {
    pub command_type: CommandType,
    pub interface_index: u32,
    pub interface_name: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub targets: Vec<TargetInfo>,
    pub protocol: Protocol,
    pub max_hop: u8,
    pub host_scan_type: ScanType,
    pub port_scan_type: ScanType,
    pub ping_type: Protocol,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub count: u32,
    pub default_scan: bool,
    pub service_detection: bool,
    pub os_detection: bool,
    pub async_scan: bool,
    pub use_wordlist: bool,
    pub use_content: bool,
    pub use_config: bool,
    pub accept_invalid_certs: bool,
    pub wordlist_path: String,
    pub content_path: String,
    pub config_path: String,
    pub request_method: String,
    pub data_provider: String,
    pub save_file_path: String,
    pub http_ports: Vec<u16>,
    pub https_ports: Vec<u16>,
    pub tcp_map: HashMap<u16, String>,
    pub oui_map: HashMap<String, String>,
    pub ttl_map: HashMap<u8, String>,
}

impl ScanOption {
    pub fn new() -> ScanOption {
        ScanOption{
            command_type: CommandType::PortScan,
            interface_index: u32::MIN,
            interface_name: String::new(),
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: u16::MIN,
            targets: vec![],
            protocol: Protocol::TCP,
            max_hop: 64,
            host_scan_type: ScanType::IcmpPingScan,
            port_scan_type: ScanType::TcpConnectScan,
            ping_type: Protocol::ICMPv4,
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(0),
            count: 4,
            default_scan: true,
            service_detection: false,
            os_detection: false,
            async_scan: true,
            use_wordlist: false,
            use_content: false,
            use_config: false,
            accept_invalid_certs: false,
            wordlist_path: String::new(),
            content_path: String::new(),
            config_path: String::new(),
            request_method: String::new(),
            data_provider: String::new(),
            save_file_path: String::new(),
            http_ports: vec![],
            https_ports: vec![],
            tcp_map: HashMap::new(),
            oui_map: HashMap::new(),
            ttl_map: HashMap::new(),
        }
    }
    pub fn default() -> ScanOption {
        let mut opt = ScanOption::new();
        opt.src_port = 53443;
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
            opt.port_scan_type = ScanType::TcpSynScan;
            if sys::get_os_type() == "windows" {
                opt.async_scan = false;
            }
        }else{
            opt.port_scan_type = ScanType::TcpConnectScan;
            opt.async_scan = true;
        }
        opt
    }
    pub fn set_dst_hosts_from_na(&mut self, v: String, prefix_len: u8, port: Option<u16>) {
        match v.parse::<IpAddr>(){
            Ok(addr) => {
                match addr {
                    IpAddr::V4(ipv4_addr) => {
                        let net: Ipv4Net = Ipv4Net::new(ipv4_addr, prefix_len).unwrap();
                        let nw_addr = Ipv4Net::new(net.network(), prefix_len).unwrap();
                        let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
                        for host in hosts {
                            if let Some(p) = port {
                                self.targets.push(TargetInfo::new_with_socket(IpAddr::V4(host), p));
                            }else{
                                self.targets.push(TargetInfo::new_with_socket(IpAddr::V4(host), 80));
                            }
                        }
                    },
                    IpAddr::V6(_) => {},
                }
            },
            Err(_) =>{},
        }
        //TODO: add v6 support
    }
    pub fn set_timeout_from_milis(&mut self, timeout: u64) {
        self.timeout = Duration::from_millis(timeout);
    }
}
