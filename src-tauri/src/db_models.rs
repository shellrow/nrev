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
