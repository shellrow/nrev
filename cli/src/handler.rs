use std::sync::mpsc::{channel ,Sender, Receiver};
use std::thread;
use enmap_core::result::{PingStat, TraceResult};
use enmap_core::{option, scan, result, define};
use indicatif::{ProgressBar, ProgressStyle};
use super::db;
use super::output;

fn get_spinner() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(120);
    let ps: ProgressStyle = ProgressStyle::default_spinner()
        .template("{spinner:.blue} {msg}")
        .tick_strings(&[
            "⠋",
			"⠙",
			"⠹",
			"⠸",
			"⠼",
			"⠴",
			"⠦",
			"⠧",
			"⠇",
			"⠏",
            "✓",
        ]);
    pb.set_style(ps);
    pb
}

pub async fn handle_port_scan(opt: option::ScanOption) {
    let probe_opt: option::ScanOption = opt.clone();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_service_scan(probe_opt, &msg_tx).await
        })
    });
    let mut pb = get_spinner();
    while let Ok(msg) = msg_rx.recv() {
        if msg.contains("START_") || msg.contains("END_") {
            match msg.as_str() {
                define::MESSAGE_START_PORTSCAN => {pb.set_message("Scanning ports ...");},
                define::MESSAGE_END_PORTSCAN => {pb.finish_with_message("Port scan"); pb = get_spinner();},
                define::MESSAGE_START_SERVICEDETECTION => {pb.set_message("Detecting services ...");},
                define::MESSAGE_END_SERVICEDETECTION => {pb.finish_with_message("Service detection"); pb = get_spinner();},
                define::MESSAGE_START_OSDETECTION => {pb.set_message("Detecting OS ...");},
                define::MESSAGE_END_OSDETECTION => {pb.finish_with_message("OS detection"); pb = get_spinner();},
                _ => {},
            }
        }
    }
    pb.finish_and_clear();
    let result: result::PortScanResult = handle.join().unwrap();
    output::show_portscan_result(result.clone());

    // DB Insert
    let probe_id = enmap_core::db::get_probe_id();
    let conn = enmap_core::db::connect_db().unwrap();
    match enmap_core::db::insert_port_scan_result(&conn, probe_id, result.clone(), String::new()) {
        Ok(affected_rows) => {
            println!("{} row(s) affected.", affected_rows);
        },
        Err(e) => {
            println!("{}", e);
        }
    }

    if !opt.save_file_path.is_empty() {
        output::save_json(serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")), opt.save_file_path.clone());
        println!("Probe result saved to: {}", opt.save_file_path);
    }

}

pub async fn handle_host_scan(opt: option::ScanOption) {
    let mut probe_opt: option::ScanOption = opt.clone();
    probe_opt.oui_map = db::get_oui_map();
    probe_opt.ttl_map = db::get_os_ttl();
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let handle = thread::spawn(move|| {
        async_io::block_on(async {
            scan::run_node_scan(probe_opt, &msg_tx).await
        })
    });
    let mut pb = get_spinner();
    while let Ok(msg) = msg_rx.recv() {
        if msg.contains("START_") || msg.contains("END_") {
            match msg.as_str() {
                define::MESSAGE_START_HOSTSCAN => {pb.set_message("Scanning hosts ...");},
                define::MESSAGE_END_HOSTSCAN => {pb.finish_with_message("Host scan"); pb = get_spinner();},
                define::MESSAGE_START_LOOKUP => {pb.set_message("Lookup ...");},
                define::MESSAGE_END_LOOKUP => {pb.finish_with_message("Lookup"); pb = get_spinner();},
                _ => {},
            }
        }
    }
    pb.finish_and_clear();
    let result: result::HostScanResult = handle.join().unwrap();
    output::show_hostscan_result(result.clone());

    // DB Insert
    let probe_id = enmap_core::db::get_probe_id();
    let conn = enmap_core::db::connect_db().unwrap();
    match enmap_core::db::insert_host_scan_result(&conn, probe_id, result.clone(), String::new()) {
        Ok(affected_rows) => {
            println!("{} row(s) affected.", affected_rows);
        },
        Err(e) => {
            println!("{}", e);
        }
    }

    if !opt.save_file_path.is_empty() {
        output::save_json(serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")), opt.save_file_path.clone());
        println!("Probe result saved to: {}", opt.save_file_path);
    }

}

pub fn handle_ping(opt: option::ScanOption) {    
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let ping_opt: option::ScanOption = opt.clone();
    let handle = thread::spawn(move||{
        scan::run_ping(ping_opt, &msg_tx)
    });
    while let Ok(msg) = msg_rx.recv() {
        println!("{}", msg);
    }
    let result: PingStat = handle.join().unwrap();
    output::show_ping_result(result.clone());

    // DB Insert
    let probe_id = enmap_core::db::get_probe_id();
    let conn = enmap_core::db::connect_db().unwrap();
    match enmap_core::db::insert_ping_result(&conn, probe_id, result.clone(), String::new()) {
        Ok(affected_rows) => {
            println!("{} row(s) affected.", affected_rows);
        },
        Err(e) => {
            println!("{}", e);
        }
    }

    if !opt.save_file_path.is_empty() {
        output::save_json(serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")), opt.save_file_path.clone());
        println!("Probe result saved to: {}", opt.save_file_path);
    }

}

pub fn handle_trace(opt: option::ScanOption) {
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let trace_opt: option::ScanOption = opt.clone();
    let handle = thread::spawn(move||{
        scan::run_traceroute(trace_opt, &msg_tx)
    });
    while let Ok(msg) = msg_rx.recv() {
        println!("{}", msg);
    }
    let result: TraceResult = handle.join().unwrap();
    output::show_trace_result(result.clone());

    // DB Insert
    let probe_id = enmap_core::db::get_probe_id();
    let conn = enmap_core::db::connect_db().unwrap();
    match enmap_core::db::insert_trace_result(&conn, probe_id, result.clone(), String::new()) {
        Ok(affected_rows) => {
            println!("{} row(s) affected.", affected_rows);
        },
        Err(e) => {
            println!("{}", e);
        }
    }

    if !opt.save_file_path.is_empty() {
        output::save_json(serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")), opt.save_file_path.clone());
        println!("Probe result saved to: {}", opt.save_file_path);
    }

}

pub fn handle_domain_scan(opt: option::ScanOption) {
    let (msg_tx, msg_rx): (Sender<String>, Receiver<String>) = channel();
    let probe_opt: option::ScanOption = opt.clone();
    let handle = thread::spawn(move||{
        scan::run_domain_scan(probe_opt, &msg_tx)
    });
    let mut pb = get_spinner();
    while let Ok(msg) = msg_rx.recv() {
        if msg.contains("START_") || msg.contains("END_") {
            match msg.as_str() {
                define::MESSAGE_START_DOMAINSCAN => {pb.set_message("Scanning domains ...");},
                define::MESSAGE_END_DOMAINSCAN => {pb.finish_with_message("Domain scan"); pb = get_spinner();},
                _ => {},
            }
        }
    }
    pb.finish_and_clear();
    let result: result::DomainScanResult = handle.join().unwrap();
    output::show_domainscan_result(result.clone());

    if !opt.save_file_path.is_empty() {
        output::save_json(serde_json::to_string_pretty(&result).unwrap_or(String::from("Serialize Error")), opt.save_file_path.clone());
        println!("Probe result saved to: {}", opt.save_file_path);
    }

}
