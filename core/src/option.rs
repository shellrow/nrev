use std::{net::{IpAddr, Ipv4Addr}, time::Duration};
use serde::{Deserialize, Serialize};
use ipnet::Ipv4Net;

use crate::{define, db, util, dns, interface, process, sys};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum CommandType {
    PortScan,
    HostScan,
    Ping,
    Traceroute,
    DomainScan,
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
    pub fn name(&self) -> String {
        match *self {
            CommandType::PortScan => String::from("Port scan"),
            CommandType::HostScan => String::from("Host scan"),
            CommandType::Ping => String::from("Ping"),
            CommandType::Traceroute => String::from("Traceroute"),
            CommandType::DomainScan => String::from("Domain scan"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum IpNextLevelProtocol {
    TCP,
    UDP,
    ICMPv4,
    ICMPv6,
}

impl IpNextLevelProtocol {
    pub fn id(&self) -> String {
        match *self {
            IpNextLevelProtocol::TCP => String::from("tcp"),
            IpNextLevelProtocol::UDP => String::from("udp"),
            IpNextLevelProtocol::ICMPv4 => String::from("icmpv4"),
            IpNextLevelProtocol::ICMPv6 => String::from("icmpv6"),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            IpNextLevelProtocol::TCP => String::from("TCP"),
            IpNextLevelProtocol::UDP => String::from("UDP"),
            IpNextLevelProtocol::ICMPv4 => String::from("ICMPv4"),
            IpNextLevelProtocol::ICMPv6 => String::from("ICMPv6"),
        }
    }
}

/// Target Host Information
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TargetInfo {
    pub ip_addr: IpAddr,
    pub host_name: String,
    pub ports: Vec<u16>,
}

impl TargetInfo {
    pub fn new() -> Self {
        TargetInfo {
            ip_addr: IpAddr::from([0, 0, 0, 0]),
            host_name: String::new(),
            ports: Vec::new(),
        }
    }
    pub fn new_with_ip_addr(ip_addr: IpAddr) -> Self {
        TargetInfo {
            ip_addr: ip_addr,
            host_name: String::new(),
            ports: Vec::new(),
        }
    }
    pub fn new_with_ip_lookup(ip_addr: IpAddr) -> Self {
        TargetInfo {
            ip_addr: ip_addr,
            host_name: dns::lookup_ip_addr(ip_addr.to_string()),
            ports: Vec::new(),
        }
    }
    pub async fn new_with_ip_lookup_async(ip_addr: IpAddr) -> Self {
        TargetInfo {
            ip_addr: ip_addr,
            host_name: dns::lookup_ip_addr_async(ip_addr.to_string()).await,
            ports: Vec::new(),
        }
    }
    pub fn new_with_socket(ip_addr: IpAddr, port: u16) -> Self {
        TargetInfo {
            ip_addr: ip_addr,
            host_name: String::new(),
            ports: vec![port],
        }
    }
    pub fn with_host_name(&mut self, host_name: String) -> TargetInfo {
        self.host_name = host_name;
        self.clone()
    }
    pub fn with_ip_lookup(&mut self) -> TargetInfo {
        self.host_name = dns::lookup_ip_addr(self.ip_addr.to_string());
        self.clone()
    }
    pub async fn with_ip_lookup_async(&mut self) -> TargetInfo {
        self.host_name = dns::lookup_ip_addr_async(self.ip_addr.to_string()).await;
        self.clone()
    }
    pub fn set_ports_from_range(&mut self, start: u16, end: u16) {
        self.ports = (start..=end).collect();
    }
    pub fn set_ports_from_option(&mut self, option: PortListOption){
        match option {
            PortListOption::Default => {
                self.ports = db::get_default_ports();
            },
            PortListOption::All => {
                self.ports = (1..=65535).collect();
            },
            PortListOption::Wellknown => {
                self.ports = db::get_wellknown_ports();
            },
            _ => {},
        }
    }
    pub fn set_ports_from_list(&mut self, file_path: String) {
        match util::read_port_list(file_path) {
            Ok(ports) => {
                self.ports = ports;
            },
            Err(_) => {},
        }
    }
    pub fn set_ports_from_csv(&mut self, csv: String) {
        let port_list: Vec<&str> = csv.trim().split(",").collect();
        let mut ports: Vec<u16> = Vec::new();
        for port in port_list {
            match port.parse::<u16>() {
                Ok(p) => {
                    ports.push(p);
                }
                Err(_) => {}
            }
        }
        self.ports = ports;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum PortScanType {
    TcpSynScan,
    TcpConnectScan,   
}

impl PortScanType {
    pub fn id(&self) -> String {
        match *self {
            PortScanType::TcpSynScan => String::from("tcp_syn_scan"),
            PortScanType::TcpConnectScan => String::from("tcp_connect_scan"),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            PortScanType::TcpSynScan => String::from("TCP SYN Scan"),
            PortScanType::TcpConnectScan => String::from("TCP Connect Scan"),
        }
    }
    pub fn arg_name(&self) -> String {
        match *self {
            PortScanType::TcpSynScan => String::from("syn"),
            PortScanType::TcpConnectScan => String::from("connect"),
        }
    }
    pub fn to_netscan_type(&self) -> netscan::setting::ScanType {
        match *self {
            PortScanType::TcpSynScan => netscan::setting::ScanType::TcpSynScan,
            PortScanType::TcpConnectScan => netscan::setting::ScanType::TcpConnectScan,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum HostScanType {
    IcmpPingScan,
    TcpPingScan,
    UdpPingScan,
}

impl HostScanType {
    pub fn id(&self) -> String {
        match *self {
            HostScanType::IcmpPingScan => String::from("icmp_ping_scan"),
            HostScanType::TcpPingScan => String::from("tcp_ping_scan"),
            HostScanType::UdpPingScan => String::from("udp_ping_scan"),
        }
    }
    pub fn name(&self) -> String {
        match *self {
            HostScanType::IcmpPingScan => String::from("ICMP Ping Scan"),
            HostScanType::TcpPingScan => String::from("TCP Ping Scan"),
            HostScanType::UdpPingScan => String::from("UDP Ping Scan"),
        }
    }
    pub fn arg_name(&self) -> String {
        match *self {
            HostScanType::IcmpPingScan => String::from("icmp"),
            HostScanType::TcpPingScan => String::from("tcp"),
            HostScanType::UdpPingScan => String::from("udp"),
        }
    }
    pub fn to_netscan_type(&self) -> netscan::setting::ScanType {
        match *self {
            HostScanType::IcmpPingScan => netscan::setting::ScanType::IcmpPingScan,
            HostScanType::TcpPingScan => netscan::setting::ScanType::TcpPingScan,
            HostScanType::UdpPingScan => netscan::setting::ScanType::UdpPingScan,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum PortListOption {
    Default,
    All,
    Wellknown,
    Custom,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum HostListOption {
    Network,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortScanOption {
    pub interface_index: u32,
    pub interface_name: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub targets: Vec<TargetInfo>,
    pub scan_type: PortScanType,
    pub protocol: IpNextLevelProtocol,
    pub concurrency: usize,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub async_scan: bool,
    pub service_detection: bool,
    pub os_detection: bool,
    pub list_file_path: String,
    pub save_file_path: String,
    pub json_output: bool,
    pub accept_invalid_certs: bool,
}

impl PortScanOption {
    pub fn new() -> Self {
        PortScanOption {
            interface_index: 0,
            interface_name: String::new(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: define::DEFAULT_SRC_PORT,
            targets: Vec::new(),
            scan_type: PortScanType::TcpSynScan,
            protocol: IpNextLevelProtocol::TCP,
            concurrency: define::DEFAULT_PORTS_CONCURRENCY,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            wait_time: Duration::from_millis(define::DEFAULT_WAIT_TIME),
            send_rate: Duration::from_millis(define::DEFAULT_SEND_RATE),
            async_scan: false,
            service_detection: false,
            os_detection: false,
            list_file_path: String::new(),
            save_file_path: String::new(),
            json_output: false,
            accept_invalid_certs: false,
        }
    }
    pub fn default() -> Self {
        let interface: interface::NetworkInterface = interface::NetworkInterface::default();
        let mut opt = PortScanOption {
            interface_index: interface.index,
            interface_name: interface.name,
            src_ip: if interface.ipv4.len() > 0 {
                IpAddr::V4(interface.ipv4[0])
            } else {
                if interface.ipv6.len() > 0 {
                    IpAddr::V6(interface.ipv6[0])
                } else {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                }
            },
            src_port: define::DEFAULT_SRC_PORT,
            targets: Vec::new(),
            scan_type: PortScanType::TcpSynScan,
            protocol: IpNextLevelProtocol::TCP,
            concurrency: define::DEFAULT_PORTS_CONCURRENCY,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            wait_time: Duration::from_millis(define::DEFAULT_WAIT_TIME),
            send_rate: Duration::from_millis(define::DEFAULT_SEND_RATE),
            async_scan: false,
            service_detection: false,
            os_detection: false,
            list_file_path: String::new(),
            save_file_path: String::new(),
            json_output: false,
            accept_invalid_certs: false,
        };
        if process::privileged() {
            opt.scan_type = PortScanType::TcpSynScan;
            if sys::get_os_type() != "windows" {
                opt.async_scan = true;
            }
        } else {
            if sys::get_os_type() == "windows" {
                opt.scan_type = PortScanType::TcpSynScan;
            }else{
                opt.scan_type = PortScanType::TcpConnectScan;
                opt.async_scan = true;
            }
        }
        opt
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostScanOption {
    pub interface_index: u32,
    pub interface_name: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub targets: Vec<TargetInfo>,
    pub scan_type: HostScanType,
    pub protocol: IpNextLevelProtocol,
    pub concurrency: usize,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub async_scan: bool,
    pub list_file_path: String,
    pub save_file_path: String,
    pub json_output: bool,
}

impl HostScanOption {
    pub fn new() -> Self {
        HostScanOption {
            interface_index: 0,
            interface_name: String::new(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: define::DEFAULT_SRC_PORT,
            targets: Vec::new(),
            scan_type: HostScanType::IcmpPingScan,
            protocol: IpNextLevelProtocol::ICMPv4,
            concurrency: define::DEFAULT_HOSTS_CONCURRENCY,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            wait_time: Duration::from_millis(define::DEFAULT_WAIT_TIME),
            send_rate: Duration::from_millis(define::DEFAULT_SEND_RATE),
            async_scan: false,
            list_file_path: String::new(),
            save_file_path: String::new(),
            json_output: false,
        }
    }
    pub fn default() -> Self {
        let interface: interface::NetworkInterface = interface::NetworkInterface::default();
        let src_ip: IpAddr = if interface.ipv4.len() > 0 {
            IpAddr::V4(interface.ipv4[0])
        } else {
            if interface.ipv6.len() > 0 {
                IpAddr::V6(interface.ipv6[0])
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        };
        HostScanOption {
            interface_index: interface.index,
            interface_name: interface.name,
            src_ip: src_ip,
            src_port: define::DEFAULT_SRC_PORT,
            targets: Vec::new(),
            scan_type: HostScanType::IcmpPingScan,
            protocol: if src_ip.is_ipv4() { IpNextLevelProtocol::ICMPv4 } else { IpNextLevelProtocol::ICMPv6 },
            concurrency: define::DEFAULT_HOSTS_CONCURRENCY,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            wait_time: Duration::from_millis(define::DEFAULT_WAIT_TIME),
            send_rate: Duration::from_millis(define::DEFAULT_SEND_RATE),
            async_scan: false,
            list_file_path: String::new(),
            save_file_path: String::new(),
            json_output: false,
        }
    }
    pub fn set_hosts_from_na(&mut self, network_address:String, prefix_len: u8, port: Option<u16>) {
        match network_address.parse::<IpAddr>() {
            Ok(addr) => match addr {
                IpAddr::V4(ipv4_addr) => {
                    let net: Ipv4Net = Ipv4Net::new(ipv4_addr, prefix_len).unwrap();
                    let nw_addr = Ipv4Net::new(net.network(), prefix_len).unwrap();
                    let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
                    for host in hosts {
                        if let Some(p) = port {
                            self.targets
                                .push(TargetInfo::new_with_socket(IpAddr::V4(host), p));
                        } else {
                            self.targets
                                .push(TargetInfo::new_with_socket(IpAddr::V4(host), 80));
                        }
                    }
                }
                IpAddr::V6(_) => {
                    //ICMPv6 network scan is not supported
                },
            },
            Err(_) => {}
        }
    }
    pub fn set_hosts_from_list(&mut self, file_path: String, port: Option<u16>) {
        match util::read_word_list(file_path) {
            Ok(hosts) => {
                for host in hosts {
                    match host.parse::<IpAddr>() {
                        Ok(addr) => {
                            if let Some(p) = port {
                                self.targets
                                    .push(TargetInfo::new_with_socket(addr, p));
                            } else {
                                self.targets
                                    .push(TargetInfo::new_with_socket(addr, 80));
                            }
                        }
                        Err(_) => {
                            // check socket address
                            let socket: Vec<&str> = host.trim().split(":").collect();
                            if socket.len() == 2 {
                                match socket[0].parse::<IpAddr>() {
                                    Ok(addr) => {
                                        match socket[1].parse::<u16>() {
                                            Ok(p) => {
                                                self.targets
                                                    .push(TargetInfo::new_with_socket(addr, p));
                                            }
                                            Err(_) => {}
                                        }
                                    }
                                    Err(_) => {
                                        // Resolve host name
                                        if let Some(ip) = dns::lookup_host_name(socket[0].to_string()) {
                                            match socket[1].parse::<u16>() {
                                                Ok(p) => {
                                                    self.targets
                                                        .push(TargetInfo::new_with_socket(ip, p));
                                                }
                                                Err(_) => {}
                                            }
                                        }
                                    }
                                }
                            }else{
                                // Resolve host name
                                if let Some(ip) = dns::lookup_host_name(host) {
                                    if let Some(p) = port {
                                        self.targets
                                            .push(TargetInfo::new_with_socket(ip, p));
                                    } else {
                                        self.targets
                                            .push(TargetInfo::new_with_socket(ip, 80));
                                    }
                                }
                            }
                        }
                    }
                }
            },
            Err(_) => {},
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingOption {
    pub interface_index: u32,
    pub interface_name: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub target: TargetInfo,
    pub protocol: IpNextLevelProtocol,
    pub count: u8,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub save_file_path: String,
    pub json_output: bool,
}

impl PingOption {
    pub fn new() -> Self {
        PingOption {
            interface_index: 0,
            interface_name: String::new(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: define::DEFAULT_SRC_PORT,
            target: TargetInfo::new(),
            protocol: IpNextLevelProtocol::ICMPv4,
            count: define::DEFAULT_PING_COUNT,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            wait_time: Duration::from_millis(define::DEFAULT_WAIT_TIME),
            send_rate: Duration::from_millis(define::DEFAULT_SEND_RATE),
            save_file_path: String::new(),
            json_output: false,
        }
    }
    pub fn default() -> Self {
        let interface: interface::NetworkInterface = interface::NetworkInterface::default();
        let src_ip: IpAddr = if interface.ipv4.len() > 0 {
            IpAddr::V4(interface.ipv4[0])
        } else {
            if interface.ipv6.len() > 0 {
                IpAddr::V6(interface.ipv6[0])
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        };
        PingOption {
            interface_index: interface.index,
            interface_name: interface.name,
            src_ip: src_ip,
            src_port: define::DEFAULT_SRC_PORT,
            target: TargetInfo::new(),
            protocol: if src_ip.is_ipv4() { IpNextLevelProtocol::ICMPv4 } else { IpNextLevelProtocol::ICMPv6 },
            count: define::DEFAULT_PING_COUNT,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            wait_time: Duration::from_millis(define::DEFAULT_WAIT_TIME),
            send_rate: Duration::from_millis(define::DEFAULT_SEND_RATE),
            save_file_path: String::new(),
            json_output: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TracerouteOption {
    pub interface_index: u32,
    pub interface_name: String,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub target: TargetInfo,
    pub protocol: IpNextLevelProtocol,
    pub max_hop: u8,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub save_file_path: String,
    pub json_output: bool,
}

impl TracerouteOption {
    pub fn new() -> Self {
        TracerouteOption {
            interface_index: 0,
            interface_name: String::new(),
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: define::DEFAULT_SRC_PORT,
            target: TargetInfo::new(),
            protocol: IpNextLevelProtocol::ICMPv4,
            max_hop: define::DEFAULT_MAX_HOP,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            wait_time: Duration::from_millis(define::DEFAULT_WAIT_TIME),
            send_rate: Duration::from_millis(define::DEFAULT_SEND_RATE),
            save_file_path: String::new(),
            json_output: false,
        }
    }
    pub fn default() -> Self {
        let interface: interface::NetworkInterface = interface::NetworkInterface::default();
        let src_ip: IpAddr = if interface.ipv4.len() > 0 {
            IpAddr::V4(interface.ipv4[0])
        } else {
            if interface.ipv6.len() > 0 {
                IpAddr::V6(interface.ipv6[0])
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        };
        TracerouteOption {
            interface_index: interface.index,
            interface_name: interface.name,
            src_ip: src_ip,
            src_port: define::DEFAULT_SRC_PORT,
            target: TargetInfo::new(),
            protocol: if src_ip.is_ipv4() { IpNextLevelProtocol::ICMPv4 } else { IpNextLevelProtocol::ICMPv6 },
            max_hop: define::DEFAULT_MAX_HOP,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            wait_time: Duration::from_millis(define::DEFAULT_WAIT_TIME),
            send_rate: Duration::from_millis(define::DEFAULT_SEND_RATE),
            save_file_path: String::new(),
            json_output: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainScanOption {
    pub base_domain: String,
    pub words: Vec<String>,
    pub concurrency: usize,
    pub protocol: IpNextLevelProtocol,
    pub timeout: Duration,
    pub async_scan: bool,
    pub list_file_path: String,
    pub save_file_path: String,
    pub json_output: bool,
}

impl DomainScanOption {
    pub fn new() -> Self {
        DomainScanOption {
            base_domain: String::new(),
            words: Vec::new(),
            concurrency: define::DEFAULT_HOSTS_CONCURRENCY,
            protocol: IpNextLevelProtocol::UDP,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            async_scan: false,
            list_file_path: String::new(),
            save_file_path: String::new(),
            json_output: false,
        }
    }
    pub fn default() -> Self {
        DomainScanOption {
            base_domain: String::new(),
            words: Vec::new(),
            concurrency: define::DEFAULT_HOSTS_CONCURRENCY,
            protocol: IpNextLevelProtocol::UDP,
            timeout: Duration::from_millis(define::DEFAULT_TIMEOUT),
            async_scan: false,
            list_file_path: String::new(),
            save_file_path: String::new(),
            json_output: false,
        }
    }
    pub fn set_words_from_list(&mut self, file_path: String) {
        match util::read_word_list(file_path) {
            Ok(words) => {
                self.words = words;
            },
            Err(_) => {},
        }
    }
}
