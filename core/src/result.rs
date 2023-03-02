use std::{time::Duration, vec};
use std::net::IpAddr;
use serde::{Serialize, Deserialize};

/// Exit status of probe
#[derive(Clone, Debug ,Serialize, Deserialize)]
pub enum ProbeStatus {
    /// Successfully completed
    Done,
    /// Interrupted by error
    Error,
    /// Execution time exceeds the configured timeout value
    Timeout,
}

impl ProbeStatus {
    pub fn name(&self) -> String {
        match *self {
            ProbeStatus::Done => String::from("Done"),
            ProbeStatus::Error => String::from("Error"),
            ProbeStatus::Timeout => String::from("Timeout"),
        }
    }
}

/// Node type 
#[derive(Clone, Debug ,Serialize, Deserialize)]
pub enum NodeType {
    /// Default gateway
    DefaultGateway,
    /// Relay node
    Relay,
    /// Destination host
    Destination,
}

/// Node structure
#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct Node {
    /// Sequence number
    pub seq: u8,
    /// IP address
    pub ip_addr: IpAddr,
    /// Host name
    pub host_name: String,
    /// Time To Live
    pub ttl: Option<u8>,
    /// Number of hops
    pub hop: Option<u8>,
    /// Node type
    pub node_type: NodeType,
    /// Round Trip Time
    pub rtt: Duration,
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PortInfo {
    pub port_number: u16,
    pub port_status: String,
    pub service_name: String,
    pub service_version: String,
    pub remark: String,
}

impl PortInfo {
    pub fn new() -> PortInfo {
        PortInfo { 
            port_number: 0, 
            port_status: String::new(), 
            service_name: String::new(), 
            service_version: String::new(), 
            remark: String::new(), 
        }
    }
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct HostInfo {
    pub ip_addr: String,
    pub host_name: String,
    pub mac_addr: String,
    pub vendor_info: String,
    pub os_name: String,
    pub cpe: String,
}

impl HostInfo {
    pub fn new() -> HostInfo {
        HostInfo { 
            ip_addr: String::new(), 
            host_name: String::new(), 
            mac_addr: String::new(), 
            vendor_info: String::new(), 
            os_name: String::new(), 
            cpe: String::new() 
        }
    }
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PortScanResult {
    pub ports: Vec<PortInfo>,
    pub host: HostInfo,
    pub port_scan_time: Duration,
    pub service_detection_time: Duration,
    pub os_detection_time: Duration,
    pub total_scan_time: Duration,
}

impl PortScanResult {
    pub fn new() -> PortScanResult {
        PortScanResult { 
            ports: vec![], 
            host: HostInfo::new(), 
            port_scan_time: Duration::from_millis(0), 
            service_detection_time: Duration::from_millis(0), 
            os_detection_time: Duration::from_millis(0), 
            total_scan_time: Duration::from_millis(0),
        }
    }
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct HostScanResult {
    pub hosts: Vec<HostInfo>,
    pub host_scan_time: Duration,
    pub lookup_time: Duration,
    pub total_scan_time: Duration,
}

impl HostScanResult {
    pub fn new() -> HostScanResult {
        HostScanResult { 
            hosts: vec![], 
            host_scan_time: Duration::from_millis(0), 
            lookup_time: Duration::from_millis(0), 
            total_scan_time: Duration::from_millis(0),
        }
    }
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PingResult {
    /// Sequence number
    pub seq: u8,
    /// IP address
    pub ip_addr: IpAddr,
    /// Host name
    pub host_name: String,
    /// Port
    pub port_number: Option<u16>, 
    /// Time To Live
    pub ttl: u8,
    /// Number of hops
    pub hop: u8,
    /// Round Trip Time (microsecond)
    pub rtt: u64,
    /// Status
    pub status: ProbeStatus,
    /// Protocol
    pub protocol: String,
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct PingStat {
    /// Results
    pub ping_results: Vec<PingResult>,
    /// The entire ping probe time (microsecond)
    pub probe_time: u64,
    /// Transmitted packets
    pub transmitted_count: usize,
    /// Received packets
    pub received_count: usize,
    /// Minimum RTT (microsecond)
    pub min: u64,
    /// Avarage RTT (microsecond)
    pub avg: u64,
    /// Maximum RTT (microsecond)
    pub max: u64,
}

impl PingStat {
    pub fn new() -> PingStat {
        PingStat { 
            ping_results: vec![], 
            probe_time: 0, 
            transmitted_count: 0, 
            received_count: 0, 
            min: 0, 
            avg: 0, 
            max: 0 
        }
    }
}

#[derive(Clone, Debug ,Serialize, Deserialize)]
pub struct TraceResult {
    /// Nodes to destination
    pub nodes: Vec<Node>,
    /// Traceroute status
    pub status: ProbeStatus,
    /// The entire traceroute time
    pub probe_time: u64,
}

impl TraceResult {
    pub fn new() -> TraceResult {
        TraceResult {
            nodes:vec![],
            status: ProbeStatus::Done,
            probe_time: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Domain {
    pub domain_name: String,
    pub ips: Vec<IpAddr>,
}

/// Result of domain scan  
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DomainScanResult {
    /// HashMap of domain. 
    /// 
    /// (Domain, IP Addresses)
    pub domains: Vec<Domain>,
    /// Time from start to end of scan.  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ProbeStatus,
}

impl DomainScanResult {
    pub fn new() -> DomainScanResult {
        DomainScanResult {
            domains: vec![], 
            scan_time: Duration::from_millis(0),
            scan_status: ProbeStatus::Done,
        }
    }
}
