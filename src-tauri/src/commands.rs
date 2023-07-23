use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use tauri::Manager;
use rusqlite::{Connection, Transaction};
use crate::db_models::{self, ProbeLog, DataSetItem, ProbeStat, UserProbeData};
use crate::option::ScanOption;
use crate::result::{PortScanResult, HostScanResult, PingStat, TraceResult};
use crate::{scan, sys};
use crate::network;
use crate::models;
use crate::json_models;

// Commands
#[tauri::command]
pub async fn exec_portscan(opt: models::PortArg) -> PortScanResult {
    let probe_opt: ScanOption = opt.to_scan_option().await;
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, _msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_service_scan(m_probe_opt, &msg_tx).await
        })
    });
    match handle.join() {
        Ok(result) => {
            // DB Insert
            let probe_id = crate::db::get_probe_id();
            let mut conn = crate::db::connect_db().unwrap();
            match crate::db::insert_port_scan_result(&conn, probe_id, result.clone(), String::new()) {
                Ok(_affected_rows) => {},
                Err(e) => {
                    println!("{}", e);
                }
            }
            let user_probe_data = crate::db_models::UserProbeData::from_port_scan_result(result.clone());
            if !UserProbeData::exists(user_probe_data.host_id.clone()) {
                let tran: Transaction = conn.transaction().unwrap();
                match crate::db::save_user_probe_data(&tran, user_probe_data) {
                    Ok(_affected_rows) => {
                        tran.commit().unwrap();
                    },
                    Err(e) => {
                        tran.rollback().unwrap();
                        println!("{}", e);
                    }
                }
            }
            result
        },
        Err(_) => {
            PortScanResult::new()
        }
    }
}

#[tauri::command]
pub async fn exec_hostscan(opt: models::HostArg) -> HostScanResult {
    let probe_opt: ScanOption = opt.to_scan_option();
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, _msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_node_scan(m_probe_opt, &msg_tx).await
        })
    });
    match handle.join() {
        Ok(result) => {
            // DB Insert
            let probe_id = crate::db::get_probe_id();
            let mut conn = crate::db::connect_db().unwrap();
            match crate::db::insert_host_scan_result(&conn, probe_id, result.clone(), String::new()) {
                Ok(_affected_rows) => {},
                Err(e) => {
                    println!("{}", e);
                }
            }
            let user_probe_data: Vec<db_models::UserProbeData> = crate::db_models::UserProbeData::from_host_scan_result(result.clone());
            let tran: Transaction = conn.transaction().unwrap();
            let mut no_error: bool = true;
            for data in user_probe_data {
                if UserProbeData::exists(data.host_id.clone()) {
                    continue;
                }
                match crate::db::save_user_probe_data(&tran, data) {
                    Ok(_affected_rows) => {},
                    Err(e) => {
                        no_error = false;
                        println!("{}", e);
                    }
                }
            }
            if no_error {
                tran.commit().unwrap();
            }else{
                tran.rollback().unwrap();
            }
            result
        },
        Err(_) => {
            HostScanResult::new()
        }
    }
}

#[tauri::command]
pub async fn exec_ping(opt: models::PingArg, app_handle: tauri::AppHandle) -> PingStat {
    let probe_opt: ScanOption = opt.to_scan_option().await;
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_ping(m_probe_opt, &msg_tx)
        })
    });
    //Progress
    while let Ok(msg) = msg_rx.recv() {
        app_handle.emit_all("ping_progress", format!("{}", msg)).unwrap();
    } 
    match handle.join() {
        Ok(result) => {
            // DB Insert
            let probe_id = crate::db::get_probe_id();
            let mut conn = crate::db::connect_db().unwrap();
            match crate::db::insert_ping_result(&conn, probe_id, result.clone(), String::new()) {
                Ok(_affected_rows) => {},
                Err(e) => {
                    println!("{}", e);
                }
            }
            if result.ping_results.len() > 0 {
                let user_probe_data = crate::db_models::UserProbeData::from_ping_result(result.ping_results[0].clone());
                if !UserProbeData::exists(user_probe_data.host_id.clone()) {
                    let tran: Transaction = conn.transaction().unwrap();
                    match crate::db::save_user_probe_data(&tran, user_probe_data) {
                        Ok(_affected_rows) => {
                            tran.commit().unwrap();
                        },
                        Err(e) => {
                            tran.rollback().unwrap();
                            println!("{}", e);
                        }
                    }
                }
            }
            result
        },
        Err(_) => {
            PingStat::new()
        }
    }
}

#[tauri::command]
pub async fn exec_traceroute(opt: models::TracerouteArg, app_handle: tauri::AppHandle) -> TraceResult {
    let probe_opt: ScanOption = opt.to_scan_option().await;
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_traceroute(m_probe_opt, &msg_tx)
        })
    });
    //Progress
    while let Ok(msg) = msg_rx.recv() {
        app_handle.emit_all("trace_progress", format!("{}", msg)).unwrap();
    } 
    match handle.join() {
        Ok(result) => {
            // DB Insert
            let probe_id = crate::db::get_probe_id();
            let mut conn = crate::db::connect_db().unwrap();
            match crate::db::insert_trace_result(&conn, probe_id, result.clone(), String::new()) {
                Ok(_affected_rows) => {},
                Err(e) => {
                    println!("{}", e);
                }
            }
            let user_probe_data: Vec<db_models::UserProbeData> = crate::db_models::UserProbeData::from_trace_result(result.clone());
            let tran: Transaction = conn.transaction().unwrap();
            let mut no_error: bool = true;
            for data in user_probe_data {
                if UserProbeData::exists(data.host_id.clone()) {
                    continue;
                }
                match crate::db::save_user_probe_data(&tran, data) {
                    Ok(_affected_rows) => {},
                    Err(e) => {
                        no_error = false;
                        println!("{}", e);
                    }
                }
            }
            if no_error {
                tran.commit().unwrap();
            }else{
                tran.rollback().unwrap();
            }
            result
        },
        Err(_) => {
            TraceResult::new()
        }
    }
}

#[tauri::command]
pub fn lookup_hostname(hostname: String) -> String {
    if let Some(ip_addr) = network::lookup_host_name(hostname) {
        return ip_addr.to_string();
    }else{
        return String::new();
    }
}

#[tauri::command]
pub fn lookup_ipaddr(ipaddr: String) -> String {
    return network::lookup_ip_addr(ipaddr);
}

#[tauri::command]
pub fn get_probe_log(opt: models::LogSearchArg) -> Vec<ProbeLog> {
    crate::db::get_probe_result(opt.target_host, opt.probe_types, opt.start_date, opt.end_date)
}

#[tauri::command]
pub fn get_probed_hosts() -> Vec<DataSetItem> {
    crate::db::get_probed_hosts()
}

#[tauri::command]
pub fn save_map_data(map_data: crate::db_models::MapData) -> u32 {
    let mut conn = crate::db::connect_db().unwrap();
    match crate::db::save_map_data(&mut conn, map_data) {
        Ok(_affected_rows) => {
            return 0;
        },
        Err(e) => {
            println!("{}", e);
            return 1;
        }
    }
}

#[tauri::command]
pub fn get_map_data(map_id: u32) -> crate::db_models::MapData {
    crate::db::get_map_data(map_id)
}

#[tauri::command]
pub fn get_top_probe_hist() -> Vec<ProbeLog> {
    crate::db::get_top_probe_hist()
}

#[tauri::command]
pub fn get_probe_stat() -> ProbeStat {
    crate::db::get_probe_stat()
}

#[tauri::command]
pub fn get_default_interface() -> crate::models::NetworkInterface {
    crate::network::get_default_interface_model()
}

#[tauri::command]
pub fn get_port_scan_result(probe_id: String) -> json_models::JsonPortScanResult {
    let probe_result: db_models::ProbeResult = db_models::ProbeResult::get(probe_id.clone());
    let host_scan_results: Vec<db_models::HostScanResult> = db_models::HostScanResult::get(probe_id.clone());
    let port_scan_results: Vec<db_models::PortScanResult> = db_models::PortScanResult::get(probe_id);
    let mut result: json_models::JsonPortScanResult = json_models::JsonPortScanResult::new();
    result.probe_id = probe_result.probe_id;
    result.ip_addr = probe_result.probe_target_addr;
    result.hostname = probe_result.probe_target_name;
    result.protocol = probe_result.protocol_id;
    for port in port_scan_results {
        let mut port_result: json_models::JsonPortResult = json_models::JsonPortResult::new();
        port_result.port = port.port;
        port_result.port_status = port.port_status_id;
        port_result.service = port.service_id;
        port_result.service_version = port.service_version;
        result.ports.push(port_result);
    }
    if host_scan_results.len() > 0 {
        let os_fingerprint: db_models::OsFingerprint = db_models::OsFingerprint::get(host_scan_results[0].cpe.clone());
        let mut json_os_fingerprint: json_models::JsonOsInfo = json_models::JsonOsInfo::new();
        json_os_fingerprint.cpe = os_fingerprint.cpe;
        json_os_fingerprint.os_name = os_fingerprint.os_name;
        json_os_fingerprint.os_family = os_fingerprint.os_family;
        json_os_fingerprint.os_generation = os_fingerprint.os_generation;
        json_os_fingerprint.device_type = os_fingerprint.device_type;
        result.os = json_os_fingerprint;
    }
    result.issued_at = probe_result.issued_at;
    result
}

#[tauri::command]
pub fn get_host_scan_result(probe_id: String) -> json_models::JsonHostScanResult {
    let probe_result: db_models::ProbeResult = db_models::ProbeResult::get(probe_id.clone());
    let host_scan_results: Vec<db_models::HostScanResult> = db_models::HostScanResult::get(probe_id);
    let mut result: json_models::JsonHostScanResult = json_models::JsonHostScanResult::new();
    result.probe_id = probe_result.probe_id;
    result.protocol = probe_result.protocol_id;    
    for host_scan_result in host_scan_results {
        let mut host_result: json_models::JsonHostResult = json_models::JsonHostResult::new();
        host_result.ip_addr = host_scan_result.ip_addr;
        host_result.hostname = host_scan_result.host_name;
        host_result.ttl = 0;
        host_result.os_info = host_scan_result.os_name;
        host_result.mac_addr = host_scan_result.mac_addr;
        host_result.vendor = host_scan_result.vendor;
        result.port = host_scan_result.port;
        result.hosts.push(host_result);
    }
    result.issued_at = probe_result.issued_at;
    result
}

#[tauri::command]
pub fn get_ping_stat(probe_id: String) -> json_models::JsonPingStat {
    let probe_result: db_models::ProbeResult = db_models::ProbeResult::get(probe_id.clone());
    let ping_stat: db_models::PingStat = db_models::PingStat::get(probe_id.clone());
    let ping_results: Vec<db_models::PingResult> = db_models::PingResult::get(probe_id);
    let mut result: json_models::JsonPingStat = json_models::JsonPingStat::new();
    result.probe_id = probe_result.probe_id;
    result.ip_addr = probe_result.probe_target_addr;
    result.hostname = probe_result.probe_target_name;
    result.protocol = probe_result.protocol_id;
    result.transmitted = ping_stat.transmitted_count;
    result.received = ping_stat.received_count;
    result.min = ping_stat.min_rtt;
    result.avg = ping_stat.avg_rtt;
    result.max = ping_stat.max_rtt;
    for ping_result in ping_results {
        let mut json_ping_result: json_models::JsonPingResult = json_models::JsonPingResult::new();
        json_ping_result.seq = ping_result.seq;
        json_ping_result.ttl = ping_result.ttl;
        json_ping_result.hop = ping_result.hop;
        json_ping_result.rtt = ping_result.rtt;
        json_ping_result.status = String::from("Done");
        result.port = ping_result.port;
        result.results.push(json_ping_result);
    }
    result.issued_at = probe_result.issued_at;
    result
}

#[tauri::command]
pub fn get_trace_result(probe_id: String) -> json_models::JsonTracerouteStat {
    let probe_result: db_models::ProbeResult = db_models::ProbeResult::get(probe_id.clone());
    let trace_results: Vec<db_models::TracerouteResult> = db_models::TracerouteResult::get(probe_id);
    let mut result: json_models::JsonTracerouteStat = json_models::JsonTracerouteStat::new();
    result.probe_id = probe_result.probe_id;
    result.ip_addr = probe_result.probe_target_addr;
    result.hostname = probe_result.probe_target_name;
    for trace_result in trace_results {
        let mut json_trace_result: json_models::JsonTracerouteResult = json_models::JsonTracerouteResult::new();
        json_trace_result.seq = trace_result.seq;
        json_trace_result.ip_addr = trace_result.ip_addr;
        json_trace_result.hostname = trace_result.host_name;
        json_trace_result.ttl = trace_result.ttl;
        json_trace_result.hop = trace_result.hop;
        json_trace_result.rtt = trace_result.rtt;
        result.results.push(json_trace_result);
    }
    result.issued_at = probe_result.issued_at;
    result
}

#[tauri::command]
pub fn get_os_type() -> String {
    sys::get_os_type()
}

#[tauri::command]
pub fn save_user_group(user_group: Vec<crate::db_models::UserGroup>) -> u32 {
    let mut conn: Connection = match crate::db::connect_db() {
        Ok(c) => c, 
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    };
    let tran: Transaction = conn.transaction().unwrap();
    for group in user_group {
        match group.delete(&tran) {
            Ok(_row_count) => {},
            Err(e) => {
                tran.rollback().unwrap();
                println!("Error: {}", e);
                return 1;
            }
        }
        match group.insert(&tran) {
            Ok(_row_count) => {},
            Err(e) => {
                tran.rollback().unwrap();
                println!("Error: {}", e);
                return 1;
            }
        }
    }
    match tran.commit() {
        Ok(_) => {
            return 0;
        },
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    }
}

#[tauri::command]
pub fn save_user_tag(user_tag: Vec<crate::db_models::UserTag>) -> u32 {
    let mut conn: Connection = match crate::db::connect_db() {
        Ok(c) => c, 
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    };
    let tran: Transaction = conn.transaction().unwrap();
    for tag in user_tag {
        match tag.delete(&tran) {
            Ok(_row_count) => {},
            Err(e) => {
                tran.rollback().unwrap();
                println!("Error: {}", e);
                return 1;
            }
        }
        match tag.insert(&tran) {
            Ok(_row_count) => {},
            Err(e) => {
                tran.rollback().unwrap();
                println!("Error: {}", e);
                return 1;
            }
        }
    }
    match tran.commit() {
        Ok(_) => {
            return 0;
        },
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    }
}

#[tauri::command]
pub fn save_user_probe_data(probe_data: Vec<crate::db_models::UserProbeData>) -> u32 {
    let mut conn: Connection = match crate::db::connect_db() {
        Ok(c) => c, 
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    };
    let tran: Transaction = conn.transaction().unwrap();
    for data in probe_data {
        match crate::db::save_user_probe_data(&tran, data) {
            Ok(_row_count) => {},
            Err(e) => {
                tran.rollback().unwrap();
                println!("Error: {}", e);
                return 1;
            }
        }
    }
    match tran.commit() {
        Ok(_) => {
            return 0;
        },
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    }
}

#[tauri::command]
pub fn get_all_user_probe_data() -> Vec<crate::db_models::UserProbeData> {
    crate::db::get_user_probe_data()
}

#[tauri::command]
pub fn get_user_probe_data(host_id: String) -> crate::db_models::UserProbeData {
    crate::db_models::UserProbeData::get(host_id)
}

#[tauri::command]
pub fn get_user_hosts() -> Vec<crate::db_models::UserHost> {
    crate::db::get_user_hosts()
}

#[tauri::command]
pub fn get_valid_user_hosts() -> Vec<crate::db_models::UserHost> {
    crate::db::get_valid_user_hosts()
}

#[tauri::command]
pub fn enable_user_host(ids: Vec<String>) -> u32 {
    let mut conn: Connection = match crate::db::connect_db() {
        Ok(c) => c, 
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    };
    let tran: Transaction = conn.transaction().unwrap();
    for id in ids {
        let mut host: crate::db_models::UserHost = crate::db_models::UserHost::new();
        host.host_id = id;
        match host.enable(&tran) {
            Ok(_row_count) => {},
            Err(e) => {
                tran.rollback().unwrap();
                println!("Error: {}", e);
                return 1;
            }
        }
    }
    match tran.commit() {
        Ok(_) => {
            return 0;
        },
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    }
}

#[tauri::command]
pub fn disable_user_host(ids: Vec<String>) -> u32 {
    let mut conn: Connection = match crate::db::connect_db() {
        Ok(c) => c, 
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    };
    let tran: Transaction = conn.transaction().unwrap();
    for id in ids {
        let mut host: crate::db_models::UserHost = crate::db_models::UserHost::new();
        host.host_id = id;
        match host.disable(&tran) {
            Ok(_row_count) => {},
            Err(e) => {
                tran.rollback().unwrap();
                println!("Error: {}", e);
                return 1;
            }
        }
    }
    match tran.commit() {
        Ok(_) => {
            return 0;
        },
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    }
}

#[tauri::command]
pub fn delete_user_host(ids: Vec<String>) -> u32 {
    let mut conn: Connection = match crate::db::connect_db() {
        Ok(c) => c, 
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    };
    let tran: Transaction = conn.transaction().unwrap();
    for id in ids {
        let mut host: crate::db_models::UserHost = crate::db_models::UserHost::new();
        host.host_id = id;
        match host.delete(&tran) {
            Ok(_row_count) => {},
            Err(e) => {
                tran.rollback().unwrap();
                println!("Error: {}", e);
                return 1;
            }
        }
    }
    match tran.commit() {
        Ok(_) => {
            return 0;
        },
        Err(e) => {
            println!("Error: {}", e);
            return 1;
        }
    }
}

#[tauri::command]
pub fn get_new_host_id(hostname: String) -> String {
    crate::db::get_host_id(hostname)
}
