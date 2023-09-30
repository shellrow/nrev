use std::vec;
use serde::{Deserialize, Serialize};
use rusqlite::{params, Transaction};
use crate::db;
use rushmap_core::sys;

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
            issued_at: String::new(),
        }
    }
    pub fn get(probe_id: String) -> ProbeResult {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT id, probe_id, probe_type_id, probe_target_addr, probe_target_name, protocol_id, probe_option, issued_at FROM probe_result WHERE probe_id = ?1").unwrap();
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
            probe_result.issued_at = row.get(7).unwrap();
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
            port_scan_result.protocol_id = row.get(7).unwrap();
            port_scan_result.service_id = row.get(8).unwrap();
            port_scan_result.service_version = row.get(9).unwrap();
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
            host_scan_result.cpe = row.get(9).unwrap_or(String::new());
            host_scan_result.issued_at = row.get(10).unwrap();
            host_scan_results.push(host_scan_result);
        }
        host_scan_results
    }
}

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
pub struct PingStat {
    pub probe_id: String,
    pub ip_addr: String,
    pub host_name: String,
    pub transmitted_count: u64,
    pub received_count: u64,
    pub min_rtt: u64,
    pub avg_rtt: u64,
    pub max_rtt: u64,
    pub issued_at: String,
}

impl PingStat {
    pub fn new() -> PingStat {
        PingStat {
            probe_id: String::new(),
            ip_addr: String::new(),
            host_name: String::new(),
            transmitted_count: 0,
            received_count: 0,
            min_rtt: 0,
            avg_rtt: 0,
            max_rtt: 0,
            issued_at: String::new(),
        }
    }
    pub fn get(probe_id: String) -> PingStat {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT probe_id, ip_addr, host_name, transmitted_count, received_count, min_rtt, avg_rtt, max_rtt, issued_at FROM ping_stat WHERE probe_id = ?1").unwrap();
        let mut rows = stmt.query(params![probe_id]).unwrap();
        let mut ping_stat = PingStat::new();
        while let Some(row) = rows.next().unwrap() {
            ping_stat.probe_id = row.get(0).unwrap();
            ping_stat.ip_addr = row.get(1).unwrap();
            ping_stat.host_name = row.get(2).unwrap();
            ping_stat.transmitted_count = row.get(3).unwrap();
            ping_stat.received_count = row.get(4).unwrap();
            ping_stat.min_rtt = row.get(5).unwrap();
            ping_stat.avg_rtt = row.get(6).unwrap();
            ping_stat.max_rtt = row.get(7).unwrap();
            ping_stat.issued_at = row.get(8).unwrap();
        }
        ping_stat
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TracerouteResult {
    pub id: u32,
    pub probe_id: String,
    pub seq: u16,
    pub ip_addr: String,
    pub host_name: String,
    pub ttl: u16,
    pub hop: u16,
    pub rtt: u64,
    pub node_type: String,
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
            ttl: 0,
            hop: 0,
            rtt: 0,
            node_type: String::new(),
            issued_at: String::new(),
        }
    }
    pub fn get(probe_id: String) -> Vec<TracerouteResult> {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT id, probe_id, seq, ip_addr, host_name, ttl, hop, rtt, node_type, issued_at FROM traceroute_result WHERE probe_id = ?1").unwrap();
        let mut rows = stmt.query(params![probe_id]).unwrap();
        let mut traceroute_results: Vec<TracerouteResult> = Vec::new();
        while let Some(row) = rows.next().unwrap() {
            let mut traceroute_result = TracerouteResult::new();
            traceroute_result.id = row.get(0).unwrap();
            traceroute_result.probe_id = row.get(1).unwrap();
            traceroute_result.seq = row.get(2).unwrap();
            traceroute_result.ip_addr = row.get(3).unwrap();
            traceroute_result.host_name = row.get(4).unwrap();
            traceroute_result.ttl = row.get(5).unwrap();
            traceroute_result.hop = row.get(6).unwrap();
            traceroute_result.rtt = row.get(7).unwrap();
            traceroute_result.node_type = row.get(8).unwrap();
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
pub struct OsTtl {
    pub os_family: String,
    pub os_description: String,
    pub initial_ttl: u8,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserGroup {
    pub group_id: String,
    pub group_name: String,
    pub group_description: String,
    pub created_at: String,
}

impl UserGroup {
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO user_group (group_id, group_name, group_description, created_at) VALUES (?1,?2,?3,?4);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.group_id, self.group_name, self.group_description, self.created_at];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM user_group WHERE group_id = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.group_id];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserTag {
    pub tag_id: String,
    pub tag_name: String,
    pub tag_description: String,
    pub created_at: String,
}

impl UserTag {
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO user_tag (tag_id, tag_name, tag_description, created_at) VALUES (?1,?2,?3,?4);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.tag_id, self.tag_name, self.tag_description, self.created_at];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM user_tag WHERE tag_id = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.tag_id];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserHost {
    pub host_id: String,
    pub ip_addr: String,
    pub host_name: String,
    pub mac_addr: String,
    pub vendor_name: String,
    pub os_name: String,
    pub os_cpe: String,
    pub valid_flag: u32,
}

impl UserHost {  
    pub fn new() -> UserHost {
        UserHost {
            host_id: String::new(),
            ip_addr: String::new(),
            host_name: String::new(),
            mac_addr: String::new(),
            vendor_name: String::new(),
            os_name: String::new(),
            os_cpe: String::new(),
            valid_flag: 0,
        }
    }
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO user_host (host_id, ip_addr, host_name, mac_addr, vendor_name, os_name, os_cpe, valid_flag) VALUES (?1,?2,?3,?4,?5,?6,?7,?8);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id, self.ip_addr, self.host_name, self.mac_addr, self.vendor_name, self.os_name, self.os_cpe, self.valid_flag];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM user_host WHERE host_id = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id];
        tran.execute(sql, params_vec)
    }
    pub fn enable(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "UPDATE user_host SET valid_flag = 1 WHERE host_id = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id];
        tran.execute(sql, params_vec)
    }
    pub fn disable(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "UPDATE user_host SET valid_flag = 0 WHERE host_id = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserService {
    pub host_id: String,
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub service_description: String,
    pub service_cpe: String,
}

impl UserService {    
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO user_service (host_id, port, protocol, service_name, service_description, service_cpe) VALUES (?1,?2,?3,?4,?5,?6);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id, self.port, self.protocol, self.service_name, self.service_description, self.service_cpe];
        tran.execute(sql, params_vec)
    }
    #[allow(dead_code)]
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM user_service WHERE host_id = ?1 AND port = ?2 AND protocol = ?3;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id, self.port, self.protocol];
        tran.execute(sql, params_vec)
    }
    pub fn delete_by_host_id(tran:&Transaction, host_id: String) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM user_service WHERE host_id = ?1;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![host_id];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserHostGroup {
    pub host_id: String,
    pub group_id: String,
}

impl UserHostGroup { 
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO user_host_group (host_id, group_id) VALUES (?1,?2);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id, self.group_id];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM user_host_group WHERE host_id = ?1 AND group_id = ?2;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id, self.group_id];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserHostTag {
    pub host_id: String,
    pub tag_id: String,
}

impl UserHostTag {
    pub fn insert(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "INSERT INTO user_host_tag (host_id, tag_id) VALUES (?1,?2);";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id, self.tag_id];
        tran.execute(sql, params_vec)
    }
    pub fn delete(&self, tran:&Transaction) -> Result<usize,rusqlite::Error> {
        let sql: &str = "DELETE FROM user_host_tag WHERE host_id = ?1 AND tag_id = ?2;";
        let params_vec: &[&dyn rusqlite::ToSql] = params![self.host_id, self.tag_id];
        tran.execute(sql, params_vec)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserServiceTag {
    pub host_id: String,
    pub port: u16,
    pub protocol: String,
    pub tag_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProbeData {
    pub host_id: String,
    pub host: UserHost,
    pub services: Vec<UserService>,
    pub groups: Vec<String>,
    pub tags: Vec<String>,
}

impl UserProbeData {
    pub fn new() -> UserProbeData {
        UserProbeData {
            host_id: String::new(),
            host: UserHost {
                host_id: String::new(),
                ip_addr: String::new(),
                host_name: String::new(),
                mac_addr: String::new(),
                vendor_name: String::new(),
                os_name: String::new(),
                os_cpe: String::new(),
                valid_flag: 0,
            },
            services: vec![],
            groups: vec![],
            tags: vec![],
        }
    }
    pub fn get(host_id: String) -> UserProbeData {
        let mut user_probe_data = UserProbeData::new();
        user_probe_data.host_id = host_id.clone();
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT host_id, ip_addr, host_name, mac_addr, vendor_name, os_name, os_cpe FROM user_host WHERE host_id = ?1").unwrap();
        let mut rows = stmt.query(params![host_id]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            user_probe_data.host.host_id = row.get(0).unwrap();
            user_probe_data.host.ip_addr = row.get(1).unwrap();
            user_probe_data.host.host_name = row.get(2).unwrap();
            user_probe_data.host.mac_addr = row.get(3).unwrap();
            user_probe_data.host.vendor_name = row.get(4).unwrap();
            user_probe_data.host.os_name = row.get(5).unwrap();
            user_probe_data.host.os_cpe = row.get(6).unwrap();
        }
        let mut stmt = conn.prepare("SELECT host_id, port, protocol, service_name, service_description, service_cpe FROM user_service WHERE host_id = ?1").unwrap();
        let mut rows = stmt.query(params![host_id]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            user_probe_data.services.push(UserService {
                host_id: row.get(0).unwrap(),
                port: row.get(1).unwrap(),
                protocol: row.get(2).unwrap(),
                service_name: row.get(3).unwrap(),
                service_description: row.get(4).unwrap(),
                service_cpe: row.get(5).unwrap(),
            });
        }
        let mut stmt = conn.prepare("SELECT group_id FROM user_host_group WHERE host_id = ?1").unwrap();
        let mut rows = stmt.query(params![host_id]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            user_probe_data.groups.push(row.get(0).unwrap());
        }
        let mut stmt = conn.prepare("SELECT tag_id FROM user_host_tag WHERE host_id = ?1").unwrap();
        let mut rows = stmt.query(params![host_id]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            user_probe_data.tags.push(row.get(0).unwrap());
        }
        user_probe_data
    }
    pub fn exists(host_id: String) -> bool {
        let conn = db::connect_db().unwrap();
        let mut stmt = conn.prepare("SELECT host_id FROM user_host WHERE host_id = ?1").unwrap();
        let mut rows = stmt.query(params![host_id]).unwrap();
        if let Some(_row) = rows.next().unwrap() {
            return true;
        }
        false
    }
    pub fn from_port_scan_result(scan_result: rushmap_core::result::PortScanResult) -> UserProbeData {
        let node = scan_result.nodes[0].clone();
        let host_id = 
            if node.host_name.is_empty() {
                sys::get_host_id(node.ip_addr.to_string())
            }else{
                sys::get_host_id(node.host_name.clone())
            };
        let mut user_probe_data = UserProbeData::new();
        user_probe_data.host_id = host_id.clone();
        user_probe_data.host = UserHost {
            host_id: host_id.clone(),
            ip_addr: node.ip_addr.to_string(),
            host_name: node.host_name,
            mac_addr: node.mac_addr,
            vendor_name: node.vendor_info,
            os_name: node.os_name,
            os_cpe: node.cpe,
            valid_flag: 0,
        };
        for service in node.services {
            if service.port_status.name().to_lowercase() != "open".to_owned() {
                continue;
            }
            user_probe_data.services.push(UserService {
                host_id: host_id.clone(),
                port: service.port_number,
                protocol: "TCP".to_owned(),
                service_name: service.service_name,
                service_description: service.service_version,
                service_cpe: String::new(),
            });
        }
        user_probe_data
    }
    pub fn from_host_scan_result(scan_result: rushmap_core::result::HostScanResult) -> Vec<UserProbeData> {
        let mut user_probe_data_list: Vec<UserProbeData> = Vec::new();
        for host in scan_result.nodes {
            let host_id = 
                if host.host_name.is_empty() {
                    sys::get_host_id(host.ip_addr.to_string())
                }else{
                    sys::get_host_id(host.host_name.clone())
                };
            let mut user_probe_data = UserProbeData::new();
            user_probe_data.host_id = host_id.clone();
            user_probe_data.host = UserHost {
                host_id: host_id.clone(),
                ip_addr: host.ip_addr.to_string(),
                host_name: host.host_name,
                mac_addr: host.mac_addr,
                vendor_name: host.vendor_info,
                os_name: host.os_name,
                os_cpe: host.cpe,
                valid_flag: 0,
            };
            if scan_result.protocol == rushmap_core::option::IpNextLevelProtocol::TCP {
                user_probe_data.services.push(UserService {
                    host_id: host_id.clone(),
                    port: host.services[0].port_number,
                    protocol: scan_result.protocol.name(),
                    service_name: String::new(),
                    service_description: String::new(),
                    service_cpe: String::new(),
                });
            }
            user_probe_data_list.push(user_probe_data);
        }
        user_probe_data_list
    }
    pub fn from_ping_result(ping_result: rushmap_core::result::PingResult) -> UserProbeData {
        let host: rushmap_core::result::PingResponse = ping_result.stat.responses[0].clone();
        let host_id = 
            if host.host_name.is_empty() {
                sys::get_host_id(host.ip_addr.to_string())
            }else{
                sys::get_host_id(host.host_name.clone())
            };
        let mut user_probe_data = UserProbeData::new();
        user_probe_data.host_id = host_id.clone();
        user_probe_data.host = UserHost {
            host_id: host_id.clone(),
            ip_addr: host.ip_addr.to_string(),
            host_name: host.host_name,
            mac_addr: String::new(),
            vendor_name: String::new(),
            os_name: String::new(),
            os_cpe: String::new(),
            valid_flag: 0,
        };
        if ping_result.protocol == rushmap_core::option::IpNextLevelProtocol::TCP {
            user_probe_data.services.push(UserService {
                host_id: host_id.clone(),
                port: host.port_number.unwrap_or(0),
                protocol: host.protocol,
                service_name: String::new(),
                service_description: String::new(),
                service_cpe: String::new(),
            });
        }
        user_probe_data
    }
    pub fn from_trace_result(trace_result: rushmap_core::result::TracerouteResult) -> Vec<UserProbeData> {
        let mut user_probe_data_list: Vec<UserProbeData> = Vec::new();
        for node in trace_result.nodes {
            let host_id = 
                if node.host_name.is_empty() {
                    sys::get_host_id(node.ip_addr.to_string())
                }else{
                    sys::get_host_id(node.host_name.clone())
                };
            let mut user_probe_data = UserProbeData::new();
            user_probe_data.host_id = host_id.clone();
            user_probe_data.host = UserHost {
                host_id: host_id.clone(),
                ip_addr: node.ip_addr.to_string(),
                host_name: node.host_name,
                mac_addr: String::new(),
                vendor_name: String::new(),
                os_name: String::new(),
                os_cpe: String::new(),
                valid_flag: 0,
            };
            user_probe_data_list.push(user_probe_data);
        }
        user_probe_data_list
    }
}
