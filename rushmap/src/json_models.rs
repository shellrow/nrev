use serde::{Deserialize, Serialize};
use rushmap_core::result::{
    DomainScanResult, HostScanResult, PingResult, PortScanResult, TracerouteResult, PingStat, PingResponse,
};
use rushmap_core::option;
use rushmap_core::db;
use rushmap_core::sys;

// Shared model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonOsInfo {
    pub cpe: String,
    pub os_name: String,
    pub os_vendor: String,
    pub os_family: String,
    pub os_generation: String,
    pub device_type: String,
}

impl JsonOsInfo {
    pub fn new() -> JsonOsInfo {
        JsonOsInfo {
            cpe: String::new(),
            os_name: String::new(),
            os_vendor: String::new(),
            os_family: String::new(),
            os_generation: String::new(),
            device_type: String::new(),
        }
    }
    pub fn from_cpe(cpe: String) -> JsonOsInfo {
        let os_fingerprints = db::get_os_fingerprints();
        for f in os_fingerprints {
            if f.cpe == cpe {
                return JsonOsInfo {
                    cpe: f.cpe,
                    os_name: f.os_name,
                    os_vendor: f.os_vendor,
                    os_family: f.os_family,
                    os_generation: f.os_generation,
                    device_type: f.device_type,
                };
            }
        }
        JsonOsInfo::new()
    }
}

// PortScan JSON model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonPortResult {
    pub port: u16,
    pub port_status: String,
    pub service: String,
    pub service_version: String,
}

impl JsonPortResult {
    pub fn new() -> JsonPortResult {
        JsonPortResult {
            port: 0,
            port_status: String::new(),
            service: String::new(),
            service_version: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonPortScanResult {
    pub probe_id: String,
    pub ip_addr: String,
    pub hostname: String,
    pub protocol: String,
    pub ports: Vec<JsonPortResult>,
    pub os: JsonOsInfo,
    pub issued_at: String,
}

impl JsonPortScanResult {
    pub fn new() -> JsonPortScanResult {
        JsonPortScanResult {
            probe_id: String::new(),
            ip_addr: String::new(),
            hostname: String::new(),
            protocol: String::new(),
            ports: Vec::new(),
            os: JsonOsInfo::new(),
            issued_at: sys::get_sysdate(),
        }
    }
    pub fn from_result(probe_id: String, result: PortScanResult) -> JsonPortScanResult {
        let mut json_result: JsonPortScanResult = JsonPortScanResult::new();
        if result.nodes.len() == 0 {
            return json_result;
        }
        let node = result.nodes[0].clone();
        json_result.probe_id = probe_id;
        json_result.ip_addr = node.ip_addr.to_string();
        json_result.hostname = node.host_name;
        json_result.protocol = option::IpNextLevelProtocol::TCP.name();
        json_result.ports = result
            .nodes[0].services
            .iter()
            .map(|port| {
                let mut json_port = JsonPortResult::new();
                json_port.port = port.port_number;
                json_port.port_status = port.port_status.name().to_lowercase();
                json_port.service = port.service_name.clone();
                json_port.service_version = port.service_version.clone();
                json_port
            })
            .collect();
        json_result.os = JsonOsInfo::from_cpe(node.cpe);
        json_result.issued_at = sys::get_sysdate();
        json_result
    }
}

// HostScan JSON model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonHostResult {
    pub ip_addr: String,
    pub hostname: String,
    pub ttl: u16,
    pub os_info: String,
    pub mac_addr: String,
    pub vendor: String,
}

impl JsonHostResult {
    pub fn new() -> JsonHostResult {
        JsonHostResult {
            ip_addr: String::new(),
            hostname: String::new(),
            ttl: 0,
            os_info: String::new(),
            mac_addr: String::new(),
            vendor: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonHostScanResult {
    pub probe_id: String,
    pub protocol: String,
    pub port: u16,
    pub hosts: Vec<JsonHostResult>,
    pub issued_at: String,
}

impl JsonHostScanResult {
    pub fn new() -> JsonHostScanResult {
        JsonHostScanResult {
            probe_id: String::new(),
            protocol: String::new(),
            port: 0,
            hosts: Vec::new(),
            issued_at: sys::get_sysdate(),
        }
    }
    pub fn from_result(probe_id: String, result: HostScanResult) -> JsonHostScanResult {
        let mut json_result: JsonHostScanResult = JsonHostScanResult::new();
        json_result.probe_id = probe_id;
        json_result.protocol = result.protocol.name();
        json_result.port = 
            if result.nodes.len() > 0 {
                if result.nodes[0].services.len() > 0 {
                    result.nodes[0].services[0].port_number
                }else{
                    0
                }
            }else{
                0
            };
        json_result.hosts = result
            .nodes
            .iter()
            .map(|host| {
                let mut json_host = JsonHostResult::new();
                json_host.ip_addr = host.ip_addr.to_string();
                json_host.hostname = host.host_name.clone();
                json_host.ttl = host.ttl as u16;
                json_host.os_info = host.os_name.clone();
                json_host.mac_addr = host.mac_addr.clone();
                json_host.vendor = host.vendor_info.clone();
                json_host
            })
            .collect();
        json_result.issued_at = sys::get_sysdate();
        json_result
    }
}

// Ping JSON model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonPingResult {
    pub seq: u16,
    pub ttl: u16,
    pub hop: u16,
    pub rtt: u64,
    pub status: String,
}

impl JsonPingResult {
    pub fn new() -> JsonPingResult {
        JsonPingResult {
            seq: 0,
            ttl: 0,
            hop: 0,
            rtt: 0,
            status: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonPingStat {
    pub probe_id: String,
    pub ip_addr: String,
    pub hostname: String,
    pub protocol: String,
    pub port: u16,
    pub min: u64,
    pub avg: u64,
    pub max: u64,
    pub transmitted: u64,
    pub received: u64,
    pub results: Vec<JsonPingResult>,
    pub issued_at: String,
}

impl JsonPingStat {
    pub fn new() -> JsonPingStat {
        JsonPingStat {
            probe_id: String::new(),
            ip_addr: String::new(),
            hostname: String::new(),
            protocol: String::new(),
            port: 0,
            min: 0,
            avg: 0,
            max: 0,
            transmitted: 0,
            received: 0,
            results: Vec::new(),
            issued_at: sys::get_sysdate(),
        }
    }
    pub fn from_result(probe_id: String, result: PingResult) -> JsonPingStat {
        let ping_stat: PingStat = result.stat;
        let mut json_result: JsonPingStat = JsonPingStat::new();
        json_result.probe_id = probe_id;
        json_result.ip_addr = ping_stat.responses[0].ip_addr.to_string();
        json_result.hostname = ping_stat.responses[0].host_name.clone();
        json_result.protocol = result.protocol.name();
        json_result.port = ping_stat.responses[0].port_number.unwrap_or(0);
        json_result.min = ping_stat.min;
        json_result.avg = ping_stat.avg;
        json_result.max = ping_stat.max;
        json_result.transmitted = ping_stat.transmitted_count as u64;
        json_result.received = ping_stat.received_count as u64;
        json_result.results = ping_stat
            .responses
            .iter()
            .map(|ping| {
                let mut json_ping = JsonPingResult::new();
                json_ping.seq = ping.seq as u16;
                json_ping.ttl = ping.ttl as u16;
                json_ping.hop = ping.hop as u16;
                json_ping.rtt = ping.rtt;
                json_ping.status = ping.status.name();
                json_ping
            })
            .collect();
        json_result.issued_at = sys::get_sysdate();
        json_result
    }
}

// Traceroute JSON model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonTracerouteResult {
    pub seq: u16,
    pub ip_addr: String,
    pub hostname: String,
    pub ttl: u16,
    pub hop: u16,
    pub rtt: u64,
}

impl JsonTracerouteResult {
    pub fn new() -> JsonTracerouteResult {
        JsonTracerouteResult {
            seq: 0,
            ip_addr: String::new(),
            hostname: String::new(),
            ttl: 0,
            hop: 0,
            rtt: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonTracerouteStat {
    pub probe_id: String,
    pub ip_addr: String,
    pub hostname: String,
    pub results: Vec<JsonTracerouteResult>,
    pub issued_at: String,
}

impl JsonTracerouteStat {
    pub fn new() -> JsonTracerouteStat {
        JsonTracerouteStat {
            probe_id: String::new(),
            ip_addr: String::new(),
            hostname: String::new(),
            results: Vec::new(),
            issued_at: sys::get_sysdate(),
        }
    }
    pub fn from_result(probe_id: String, result: TracerouteResult) -> JsonTracerouteStat {
        let node: PingResponse = result.nodes[0].clone();
        let mut json_result: JsonTracerouteStat = JsonTracerouteStat::new();
        json_result.probe_id = probe_id;
        json_result.ip_addr = node.ip_addr.to_string();
        json_result.hostname = node.host_name;
        json_result.results = result
            .nodes
            .iter()
            .map(|res| {
                let mut json_trace = JsonTracerouteResult::new();
                json_trace.seq = res.seq as u16;
                json_trace.ip_addr = res.ip_addr.to_string();
                json_trace.hostname = res.host_name.clone();
                json_trace.ttl = res.ttl as u16;
                json_trace.hop = res.hop as u16;
                json_trace.rtt = res.rtt;
                json_trace
            })
            .collect();
        json_result.issued_at = sys::get_sysdate();
        json_result
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonDomain {
    pub domain_name: String,
    pub ips: Vec<String>,
}

impl JsonDomain {
    pub fn new() -> JsonDomain {
        JsonDomain {
            domain_name: String::new(),
            ips: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonDomainScanResult {
    pub probe_id: String,
    pub base_domain: String,
    pub domains: Vec<JsonDomain>,
    pub issued_at: String,
}

impl JsonDomainScanResult {
    pub fn new() -> JsonDomainScanResult {
        JsonDomainScanResult {
            probe_id: String::new(),
            base_domain: String::new(),
            domains: Vec::new(),
            issued_at: sys::get_sysdate(),
        }
    }
    pub fn from_result(probe_id: String, result: DomainScanResult) -> JsonDomainScanResult {
        let mut json_result: JsonDomainScanResult = JsonDomainScanResult::new();
        json_result.probe_id = probe_id;
        json_result.base_domain = result.base_domain.clone();
        json_result.domains = result
            .domains
            .iter()
            .map(|domain| {
                let mut json_domain = JsonDomain::new();
                json_domain.domain_name = domain.domain_name.clone();
                domain.ips.iter().for_each(|ip| {
                    json_domain.ips.push(ip.to_string());
                });
                json_domain
            })
            .collect();
        json_result.issued_at = sys::get_sysdate();
        json_result
    }
}
