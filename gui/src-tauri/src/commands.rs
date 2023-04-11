use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use enmap_core::model::{ProbeLog, DataSetItem, ProbeStat};
use tauri::Manager;
use enmap_core::option::{ScanOption};
use enmap_core::result::{PortScanResult, HostScanResult, PingStat, TraceResult};
use enmap_core::scan;
use enmap_core::network;

use crate::models;

// Test commands
#[tauri::command]
pub fn test_command() {
    println!("I was invoked from JS!");
}

#[tauri::command]
pub fn test_command_arg(invoke_message: String) {
    println!("I was invoked from JS, with this message: {}", invoke_message);
}

#[tauri::command]
pub fn test_command_return() -> String {
    String::from("Hello from Rust!")
}

#[tauri::command]
pub fn test_command_result() -> Result<String, String> {
    // Fail
    //Err("This failed!".into())
    // Success
    Ok("This worked!".into())
}

async fn some_async_function() -> Option<String> {
    Some("response".into())
}

#[tauri::command]
pub async fn test_command_async() {
    let result = some_async_function().await;
    println!("Result: {}", result.unwrap());
}

// Commands
#[tauri::command]
pub async fn exec_portscan(opt: models::PortArg) -> PortScanResult {
    let probe_opt: ScanOption = opt.to_scan_option();
    let m_probe_opt: ScanOption = probe_opt.clone();
    let (msg_tx, _msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_service_scan(m_probe_opt, &msg_tx).await
        })
    });
    let result: PortScanResult = handle.join().unwrap();
    // DB Insert
    let probe_id = enmap_core::db::get_probe_id();
    let conn = enmap_core::db::connect_db().unwrap();
    match enmap_core::db::insert_port_scan_result(&conn, probe_id, result.clone(), String::new()) {
        Ok(_affected_rows) => {},
        Err(e) => {
            println!("{}", e);
        }
    }
    result
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
    let result: HostScanResult = handle.join().unwrap();
    // DB Insert
    let probe_id = enmap_core::db::get_probe_id();
    let conn = enmap_core::db::connect_db().unwrap();
    match enmap_core::db::insert_host_scan_result(&conn, probe_id, result.clone(), String::new()) {
        Ok(_affected_rows) => {},
        Err(e) => {
            println!("{}", e);
        }
    }
    result
}

#[tauri::command]
pub async fn exec_ping(opt: models::PingArg, app_handle: tauri::AppHandle) -> PingStat {
    let probe_opt: ScanOption = opt.to_scan_option();
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
    let result: PingStat = handle.join().unwrap();
    // DB Insert
    let probe_id = enmap_core::db::get_probe_id();
    let conn = enmap_core::db::connect_db().unwrap();
    match enmap_core::db::insert_ping_result(&conn, probe_id, result.clone(), String::new()) {
        Ok(_affected_rows) => {},
        Err(e) => {
            println!("{}", e);
        }
    }
    result
}

#[tauri::command]
pub async fn exec_traceroute(opt: models::TracerouteArg, app_handle: tauri::AppHandle) -> TraceResult {
    let probe_opt: ScanOption = opt.to_scan_option();
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
    let result: TraceResult = handle.join().unwrap();
    // DB Insert
    let probe_id = enmap_core::db::get_probe_id();
    let conn = enmap_core::db::connect_db().unwrap();
    match enmap_core::db::insert_trace_result(&conn, probe_id, result.clone(), String::new()) {
        Ok(_affected_rows) => {},
        Err(e) => {
            println!("{}", e);
        }
    }
    result
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
    enmap_core::db::get_probe_result(opt.target_host, opt.probe_types, opt.start_date, opt.end_date)
}

#[tauri::command]
pub fn get_probed_hosts() -> Vec<DataSetItem> {
    enmap_core::db::get_probed_hosts()
}

#[tauri::command]
pub fn save_map_data(map_data: enmap_core::model::MapData) -> u32 {
    let mut conn = enmap_core::db::connect_db().unwrap();
    match enmap_core::db::save_map_data(&mut conn, map_data) {
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
pub fn get_map_data(map_id: u32) -> enmap_core::model::MapData {
    enmap_core::db::get_map_data(map_id)
}

#[tauri::command]
pub fn get_top_probe_hist() -> Vec<ProbeLog> {
    enmap_core::db::get_top_probe_hist()
}

#[tauri::command]
pub fn get_probe_stat() -> ProbeStat {
    enmap_core::db::get_probe_stat()
}
