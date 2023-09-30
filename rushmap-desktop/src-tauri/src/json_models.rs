use serde::{Deserialize, Serialize};

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
    #[allow(dead_code)]
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
    pub os_cpe: String,
    pub os_name: String,
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
            os_cpe: String::new(),
            os_name: String::new(),
            issued_at: String::new(),
        }
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
            issued_at: String::new(),
        }
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
            issued_at: String::new(),
        }
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
            issued_at: String::new(),
        }
    }
}
