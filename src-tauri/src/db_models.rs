use std::{vec};
use serde::{Deserialize, Serialize};
use rusqlite::{params};
use crate::db;

// DB models
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeType {
    pub probe_type_id: String,
    pub probe_type_name: String,
    pub probe_type_description: String,
}

// DB Models
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProbeResult {
    pub id: u32,
    pub probe_id: String,
    pub probe_type_id: String,
    pub probe_target_addr: String,
    pub probe_target_name: String,
    pub protocol_id: String,
    pub probe_option: Option<String>,
    pub scan_time: Option<u64>,
    pub service_detection_time: Option<u64>,
    pub os_detection_time: Option<u64>,
    pub probe_time: Option<u64>,
    pub transmitted_count: Option<u64>,
    pub received_count: Option<u64>,
    pub min_value: Option<u64>,
    pub avg_value: Option<u64>,
    pub max_value: Option<u64>,
    pub issued_at: String,
}

impl ProbeResult {
    pub fn new() -> ProbeResult {
        ProbeResult {
            id: 0,
            probe_id: String::new(),
            probe_type_id: String::new(),
            probe_target_addr: String::new(),
            probe_target_name: String::new(),
            protocol_id: String::new(),
            probe_option: None,
            scan_time: None,
            service_detection_time: None,
            os_detection_time: None,
            probe_time: None,
            transmitted_count: None,
            received_count: None,
            min_value: None,
            avg_value: None,
            max_value: None,
            issued_at: String::new(),
        }
    }
    pub fn get(probe_id: String) -> ProbeResult {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT id, probe_id, probe_type_id, probe_target_addr, probe_target_name, protocol_id, probe_option, scan_time, service_detection_time, os_detection_time, probe_time, transmitted_count, received_count, min_value, avg_value, max_value, issued_at FROM probe_result WHERE probe_id = ?1").unwrap();
        let mut rows = stmt.query(params![probe_id]).unwrap();
        let mut probe_result = ProbeResult::new();
        while let Some(row) = rows.next().unwrap() {
            probe_result.id = row.get(0).unwrap();
            probe_result.probe_id = row.get(1).unwrap();
            probe_result.probe_type_id = row.get(2).unwrap();
            probe_result.probe_target_addr = row.get(3).unwrap();
            probe_result.probe_target_name = row.get(4).unwrap();
            probe_result.protocol_id = row.get(5).unwrap();
            probe_result.probe_option = row.get(6).unwrap();
            probe_result.scan_time = row.get(7).unwrap();
            probe_result.service_detection_time = row.get(8).unwrap();
            probe_result.os_detection_time = row.get(9).unwrap();
            probe_result.probe_time = row.get(10).unwrap();
            probe_result.transmitted_count = row.get(11).unwrap();
            probe_result.received_count = row.get(12).unwrap();
            probe_result.min_value = row.get(13).unwrap();
            probe_result.avg_value = row.get(14).unwrap();
            probe_result.max_value = row.get(15).unwrap();
            probe_result.issued_at = row.get(16).unwrap();
        }
        probe_result
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PortScanResult {
    pub id: u32,
    pub probe_id: String,
    pub socket_addr: String,
    pub ip_addr: String,
    pub host_name: String,
    pub port: u16,
    pub port_status_id: String,
    pub service_id: String,
    pub service_version: String,
    pub protocol_id: String,
    pub issued_at: String,
}

impl PortScanResult {
    pub fn new() -> PortScanResult {
        PortScanResult {
            id: 0,
            probe_id: String::new(),
            socket_addr: String::new(),
            ip_addr: String::new(),
            host_name: String::new(),
            port: 0,
            port_status_id: String::new(),
            service_id: String::new(),
            service_version: String::new(),
            protocol_id: String::new(),
            issued_at: String::new(),
        }
    }
    pub fn get(probe_id: String) -> Vec<PortScanResult> {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT id, probe_id, socket_addr, ip_addr, host_name, port, port_status_id, protocol_id, service_id, service_version, issued_at FROM port_scan_result WHERE probe_id = ?1").unwrap();
        let mut rows = stmt.query(params![probe_id]).unwrap();
        let mut port_scan_results: Vec<PortScanResult> = Vec::new();
        while let Some(row) = rows.next().unwrap() {
            let mut port_scan_result = PortScanResult::new();
            port_scan_result.id = row.get(0).unwrap();
            port_scan_result.probe_id = row.get(1).unwrap();
            port_scan_result.socket_addr = row.get(2).unwrap();
            port_scan_result.ip_addr = row.get(3).unwrap();
            port_scan_result.host_name = row.get(4).unwrap();
            port_scan_result.port = row.get(5).unwrap();
            port_scan_result.port_status_id = row.get(6).unwrap();
            port_scan_result.service_id = row.get(7).unwrap();
            port_scan_result.service_version = row.get(8).unwrap();
            port_scan_result.protocol_id = row.get(9).unwrap();
            port_scan_result.issued_at = row.get(10).unwrap();
            port_scan_results.push(port_scan_result);
        }
        port_scan_results
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostScanResult {
    pub id: u32,
    pub probe_id: String,
    pub ip_addr: String,
    pub host_name: String,
    pub port: u16,
    pub protocol_id: String,
    pub mac_addr: String,
    pub vendor: String,
    pub os_name: String,
    pub cpe: String,
    pub issued_at: String,
}

impl HostScanResult {
    pub fn new() -> HostScanResult {
        HostScanResult {
            id: 0,
            probe_id: String::new(),
            ip_addr: String::new(),
            host_name: String::new(),
            port: 0,
            protocol_id: String::new(),
            mac_addr: String::new(),
            vendor: String::new(),
            os_name: String::new(),
            cpe: String::new(),
            issued_at: String::new(),
        }
    }
    pub fn get(probe_id: String) -> Vec<HostScanResult> {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT id, probe_id, ip_addr, host_name, port, protocol_id, mac_addr, vendor, os_name, cpe, issued_at FROM host_scan_result WHERE probe_id = ?1").unwrap();
        let mut rows = stmt.query(params![probe_id]).unwrap();
        let mut host_scan_results: Vec<HostScanResult> = Vec::new();
        while let Some(row) = rows.next().unwrap() {
            let mut host_scan_result = HostScanResult::new();
            host_scan_result.id = row.get(0).unwrap();
            host_scan_result.probe_id = row.get(1).unwrap();
            host_scan_result.ip_addr = row.get(2).unwrap();
            host_scan_result.host_name = row.get(3).unwrap();
            host_scan_result.port = row.get(4).unwrap();
            host_scan_result.protocol_id = row.get(5).unwrap();
            host_scan_result.mac_addr = row.get(6).unwrap();
            host_scan_result.vendor = row.get(7).unwrap();
            host_scan_result.os_name = row.get(8).unwrap();
            host_scan_result.cpe = row.get(9).unwrap();
            host_scan_result.issued_at = row.get(10).unwrap();
            host_scan_results.push(host_scan_result);
        }
        host_scan_results
    }
}

#[allow(unused)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PingResult {
    pub id: u32,
    pub probe_id: String,
    pub seq: u16,
    pub ip_addr: String,
    pub host_name: String,
    pub port: u16,
    pub port_status_id: String,
    pub ttl: u16,
    pub hop: u16,
    pub rtt: u64,
    pub issued_at: String,
}

impl PingResult {
    pub fn new() -> PingResult {
        PingResult {
            id: 0,
            probe_id: String::new(),
            seq: 0,
            ip_addr: String::new(),
            host_name: String::new(),
            port: 0,
            port_status_id: String::new(),
            ttl: 0,
            hop: 0,
            rtt: 0,
            issued_at: String::new(),
        }
    }
    pub fn get(probe_id: String) -> Vec<PingResult> {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT id, probe_id, seq, ip_addr, host_name, port, port_status_id, ttl, hop, rtt, issued_at FROM ping_result WHERE probe_id = ?1").unwrap();
        let mut rows = stmt.query(params![probe_id]).unwrap();
        let mut ping_results: Vec<PingResult> = Vec::new();
        while let Some(row) = rows.next().unwrap() {
            let mut ping_result = PingResult::new();
            ping_result.id = row.get(0).unwrap();
            ping_result.probe_id = row.get(1).unwrap();
            ping_result.seq = row.get(2).unwrap();
            ping_result.ip_addr = row.get(3).unwrap();
            ping_result.host_name = row.get(4).unwrap();
            ping_result.port = row.get(5).unwrap();
            ping_result.port_status_id = row.get(6).unwrap();
            ping_result.ttl = row.get(7).unwrap();
            ping_result.hop = row.get(8).unwrap();
            ping_result.rtt = row.get(9).unwrap();
            ping_result.issued_at = row.get(10).unwrap();
            ping_results.push(ping_result);
        }
        ping_results
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TracerouteResult {
    pub id: u32,
    pub probe_id: String,
    pub seq: u16,
    pub ip_addr: String,
    pub host_name: String,
    pub port: u16,
    pub ttl: u16,
    pub hop: u16,
    pub rtt: u64,
    pub issued_at: String,
}

impl TracerouteResult {
    pub fn new() -> TracerouteResult {
        TracerouteResult {
            id: 0,
            probe_id: String::new(),
            seq: 0,
            ip_addr: String::new(),
            host_name: String::new(),
            port: 0,
            ttl: 0,
            hop: 0,
            rtt: 0,
            issued_at: String::new(),
        }
    }
    pub fn get(probe_id: String) -> Vec<TracerouteResult> {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT id, probe_id, seq, ip_addr, host_name, port, ttl, hop, rtt, issued_at FROM traceroute_result WHERE probe_id = ?1").unwrap();
        let mut rows = stmt.query(params![probe_id]).unwrap();
        let mut traceroute_results: Vec<TracerouteResult> = Vec::new();
        while let Some(row) = rows.next().unwrap() {
            let mut traceroute_result = TracerouteResult::new();
            traceroute_result.id = row.get(0).unwrap();
            traceroute_result.probe_id = row.get(1).unwrap();
            traceroute_result.seq = row.get(2).unwrap();
            traceroute_result.ip_addr = row.get(3).unwrap();
            traceroute_result.host_name = row.get(4).unwrap();
            traceroute_result.port = row.get(5).unwrap();
            traceroute_result.ttl = row.get(6).unwrap();
            traceroute_result.hop = row.get(7).unwrap();
            traceroute_result.rtt = row.get(8).unwrap();
            traceroute_result.issued_at = row.get(9).unwrap();
            traceroute_results.push(traceroute_result);
        }
        traceroute_results
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapInfo {
    pub map_id: u32,
    pub map_name: String,
    pub display_order: u32,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapNode {
    pub map_id: u32,
    pub node_id: String,
    pub node_name: String,
    pub ip_addr: String,
    pub host_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapEdge {
    pub map_id: u32,
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub edge_label: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapLayout {
    pub map_id: u32,
    pub node_id: String,
    pub x_value: f32,
    pub y_value: f32
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Oui {
    pub mac_prefix: String,
    pub vendor_name: String,
    pub vendor_name_detail: String,
}

impl Oui {
    pub fn get_oui_list() -> Vec<Oui> {
        let mut oui_list: Vec<Oui> = Vec::new();
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT mac_prefix, vendor_name, vendor_name_detail FROM oui;").unwrap();
        let oui_iter = stmt.query_map(params![], |row| {
            Ok(Oui {
                mac_prefix: row.get(0)?,
                vendor_name: row.get(1)?,
                vendor_name_detail: row.get(2)?,
            })
        }).unwrap();
        for oui in oui_iter {
            oui_list.push(oui.unwrap());
        }
        oui_list
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpService {
    pub port: u16, 
    pub service_name: String, 
    pub service_description: String,   
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpTag {
    pub port: u16,
    pub tag: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpService {
    pub port: u16,
    pub service_name: String,
    pub service_description: String,   
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpTag {
    pub port: u16,
    pub tag: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsFingerprint {
    pub cpe: String,
    pub os_name: String,
    pub os_vendor: String,
    pub os_family: String,
    pub os_generation: String,
    pub device_type: String,
    pub tcp_window_size: u16,
    pub tcp_option_pattern: String,
}

impl OsFingerprint {
    pub fn new() -> OsFingerprint {
        OsFingerprint { 
            cpe: String::new(), 
            os_name: String::new(), 
            os_vendor: String::new(), 
            os_family: String::new(), 
            os_generation: String::new(), 
            device_type: String::new(), 
            tcp_window_size: 0, 
            tcp_option_pattern: String::new() 
        }
    }
    pub fn get(cpe: String) -> OsFingerprint {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT cpe, os_name, os_vendor, os_family, os_generation, device_type, tcp_window_size, tcp_option_pattern FROM os_fingerprint WHERE cpe = ?1").unwrap();
        let mut rows = stmt.query(params![cpe]).unwrap();
        let mut os_fingerprint = OsFingerprint::new();
        while let Some(row) = rows.next().unwrap() {
            os_fingerprint.cpe = row.get(0).unwrap();
            os_fingerprint.os_name = row.get(1).unwrap();
            os_fingerprint.os_vendor = row.get(2).unwrap();
            os_fingerprint.os_family = row.get(3).unwrap();
            os_fingerprint.os_generation = row.get(4).unwrap();
            os_fingerprint.device_type = row.get(5).unwrap();
            os_fingerprint.tcp_window_size = row.get(6).unwrap();
            os_fingerprint.tcp_option_pattern = row.get(7).unwrap();
        }
        os_fingerprint
    } 
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsTtl {
    pub os_family: String,
    pub os_description: String,
    pub initial_ttl: u8,
}

impl OsTtl {
    pub fn new() -> OsTtl {
        OsTtl { os_family: String::new(), os_description: String::new(), initial_ttl: 0 }
    }
}

// Model for frontend
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MapData {
    pub map_info: MapInfo,
    pub nodes: Vec<MapNode>,
    pub edges: Vec<MapEdge>,
    pub layouts: Vec<MapLayout>,
}

impl MapData {
    pub fn new() -> MapData {
        MapData {
            map_info: MapInfo {
                map_id: 0,
                map_name: String::new(),
                display_order: 0,
                created_at: String::new(),
            },
            nodes: vec![],
            edges: vec![],
            layouts: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProbeLog {
    pub id: u32,
    pub probe_id: String,
    pub probe_type_id: String,
    pub probe_type_name: String,
    pub probe_target_addr: String,
    pub probe_target_name: String,
    pub protocol_id: String,
    pub probe_option: Option<String>,
    pub issued_at: String 
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProbeStat {
    pub portscan_count: u32,
    pub hostscan_count: u32,
    pub ping_count: u32,
    pub traceroute_count: u32,
}

impl ProbeStat {
    pub fn new() -> ProbeStat {
        ProbeStat { portscan_count: 0, hostscan_count: 0, ping_count: 0, traceroute_count: 0 }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DataSetItem {
    pub id: String,
    pub name: String,
}
