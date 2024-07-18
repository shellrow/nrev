use clap::ArgMatches;
use indicatif::ProgressBar;
use ipnet::Ipv4Net;
use crate::host::Host;
use crate::json::host::HostScanResult;
use crate::scan::result::ScanResult;
use crate::scan::scanner::HostScanner;
use crate::scan::setting::{HostScanSetting, HostScanType};
use netdev::Interface;
use comfy_table::presets::NOTHING;
use comfy_table::{Cell, CellAlignment, ContentArrangement, Table};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use crate::output;

pub fn handle_hostscan(args: &ArgMatches) {
    output::log_with_time("Initiating host scan...", "INFO");
    let host_args = match args.subcommand_matches("host") {
        Some(matches) => matches,
        None => return,
    };
    let target: String = match host_args.get_one::<String>("target") {
        Some(target) => target.to_owned(),
        None => return,
    };
    let scan_type: HostScanType = match host_args.get_one::<String>("protocol") {
        Some(protocol) => HostScanType::from_str(protocol),
        None => HostScanType::IcmpPingScan,
    };
    let timeout = match host_args.get_one::<u64>("timeout") {
        Some(timeout) => Duration::from_millis(*timeout),
        None => Duration::from_millis(10000),
    };
    let port: u16 = match host_args.get_one::<u16>("port") {
        Some(port) => *port,
        None => 80 as u16,
    };
    let default_waittime: Duration = Duration::from_millis(200);
    let wait_time = match host_args.get_one::<u64>("waittime") {
        Some(wait_time) => Duration::from_millis(*wait_time),
        None => default_waittime,
    };
    let send_rate = match host_args.get_one::<u64>("rate") {
        Some(send_rate) => Duration::from_millis(*send_rate),
        None => Duration::from_millis(0),
    };
    let target_ips: Vec<IpAddr> = match Ipv4Net::from_str(&target) {
        Ok(ipv4net) => {
            // convert hosts to Vec<IpAddr>
            ipv4net.hosts().map(|x| IpAddr::V4(x)).collect()
        }
        Err(_) => {
            match Ipv4Addr::from_str(&target) {
                Ok(ip_addr) => {
                    Ipv4Net::new(ip_addr, 24).unwrap().hosts().map(|x| IpAddr::V4(x)).collect()
                }
                Err(_) => {
                    // Check if target is host-list file
                    match std::fs::read_to_string(&target) {
                        Ok(hosts) => {
                            let mut ips: Vec<IpAddr> = Vec::new();
                            for host in hosts.lines() {
                                let host = host.trim();
                                if host.is_empty() {
                                    continue;
                                }
                                match IpAddr::from_str(host) {
                                    Ok(ip) => ips.push(ip),
                                    Err(_) => continue,
                                }
                            }
                            ips
                        }
                        Err(_) => vec![],
                    }
                }
            }
        },
    };
    // Add scan target
    let mut targets: Vec<Host> = Vec::new();
    for ip in target_ips {
        let host: Host = Host::new(ip, String::new()).with_ports(vec![port]);
        targets.push(host);
    }
    let interface: Interface = if let Some(if_name) = args.get_one::<String>("interface") {
        match crate::interface::get_interface_by_name(if_name.to_string()) {
            Some(iface) => iface,
            None => return,
        }
    }else{
        match netdev::get_default_interface() {
            Ok(iface) => iface,
            Err(_) => return,
        }
    };
    let mut scan_setting = HostScanSetting::default()
    .set_if_index(interface.index)
    .set_scan_type(scan_type)
    .set_targets(targets)
    .set_timeout(timeout)
    .set_wait_time(wait_time)
    .set_send_rate(send_rate);
    // Print options
    print_option(&target, &scan_setting, &interface);
    if !host_args.get_flag("random") {        
        scan_setting.randomize_ports();
        scan_setting.randomize_hosts();
    }
    println!("[Progress]");
    // Display progress with indicatif
    let bar = ProgressBar::new(scan_setting.targets.len() as u64);
    //bar.enable_steady_tick(120);
    bar.set_style(output::get_progress_style());
    bar.set_position(0);
    bar.set_message("HostScan");
    let host_scanner = HostScanner::new(scan_setting);
    let rx = host_scanner.get_progress_receiver();
    // Run scan
    let handle = thread::spawn(move || host_scanner.scan());
    // Print progress
    while let Ok(_host) = rx.lock().unwrap().recv() {
        bar.inc(1);
    }
    let mut hostscan_result: ScanResult = handle.join().unwrap();
    bar.finish_with_message(format!("HostScan ({:?})", hostscan_result.scan_time));
    if hostscan_result.hosts.len() == 0 {
        output::log_with_time("No results found", "INFO");
        return;
    }
    hostscan_result.sort_ports();
    hostscan_result.sort_hosts();
    let os_family_map: HashMap<IpAddr, String> = crate::db::get_fingerprint_map(&hostscan_result.fingerprints);
    for host in &mut hostscan_result.hosts {
        host.os_family = os_family_map.get(&host.ip_addr).unwrap_or(&String::new()).to_string();
    }
    let result: HostScanResult = HostScanResult::from_scan_result(&hostscan_result);
    // Print results
    if args.get_flag("json") {
        let json_result = serde_json::to_string_pretty(&result).unwrap();
        println!("{}", json_result);
    }else {
        show_hostscan_result(&result);
    }
    output::log_with_time("Scan completed", "INFO");
    match args.get_one::<PathBuf>("save") {
        Some(file_path) => {
            match crate::fs::save_text(file_path, serde_json::to_string_pretty(&result).unwrap()) {
                Ok(_) => {
                    output::log_with_time(&format!("Saved to {}", file_path.to_string_lossy()), "INFO");
                },
                Err(e) => {
                    output::log_with_time(&format!("Failed to save: {}", e), "ERROR");
                },
            }
        },
        None => {},
    }
}

fn print_option(target: &str, setting: &HostScanSetting, interface: &Interface) {
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic);
    
    table.add_row(vec![
        Cell::new("Protocol").set_alignment(CellAlignment::Left),
        Cell::new(setting.protocol.to_str()).set_alignment(CellAlignment::Left),
    ]);
    table.add_row(vec![
        Cell::new("ScanType").set_alignment(CellAlignment::Left),
        Cell::new(setting.scan_type.to_str()).set_alignment(CellAlignment::Left),
    ]);
    table.add_row(vec![
        Cell::new("InterfaceName").set_alignment(CellAlignment::Left),
        Cell::new(&interface.name).set_alignment(CellAlignment::Left),
    ]);
    table.add_row(vec![
        Cell::new("Timeout").set_alignment(CellAlignment::Left),
        Cell::new(format!("{:?}", setting.timeout)).set_alignment(CellAlignment::Left),
    ]);
    table.add_row(vec![
        Cell::new("WaitTime").set_alignment(CellAlignment::Left),
        Cell::new(format!("{:?}", setting.wait_time)).set_alignment(CellAlignment::Left),
    ]);
    table.add_row(vec![
        Cell::new("SendRate").set_alignment(CellAlignment::Left),
        Cell::new(format!("{:?}", setting.send_rate)).set_alignment(CellAlignment::Left),
    ]);
    println!("[Options]");
    println!("{}", table);

    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic);
    
    match Ipv4Net::from_str(&target) {
        Ok(ipv4net) => {
            table.add_row(vec![
                Cell::new("Network").set_alignment(CellAlignment::Left),
                Cell::new(ipv4net.to_string()).set_alignment(CellAlignment::Left),
            ]);
        }
        Err(_) => {
            match Ipv4Addr::from_str(&target) {
                Ok(ip_addr) => {
                    let net = Ipv4Net::new(ip_addr, 24).unwrap();
                    table.add_row(vec![
                        Cell::new("Network").set_alignment(CellAlignment::Left),
                        Cell::new(net.to_string()).set_alignment(CellAlignment::Left),
                    ]);
                }
                Err(_) => {
                    table.add_row(vec![
                        Cell::new("List").set_alignment(CellAlignment::Left),
                        Cell::new(target).set_alignment(CellAlignment::Left),
                    ]);
                }
            }
        },
    }
    println!("[Target]");
    println!("{}", table);
}

fn show_hostscan_result(hostscan_result: &HostScanResult) {
    let oui_map: HashMap<String, String> = crate::db::get_oui_detail_map();
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["IP Address", "Host Name", "TTL","OS Family", "MAC Address", "Vendor Name"]);
    
    for host in &hostscan_result.hosts {
        if crate::ip::is_global_addr(&host.ip_addr) {
            table.add_row(vec![
                Cell::new(&host.ip_addr.to_string()).set_alignment(CellAlignment::Left),
                Cell::new(&host.hostname).set_alignment(CellAlignment::Left),
                Cell::new(&host.ttl).set_alignment(CellAlignment::Left),
                Cell::new(&host.os_family).set_alignment(CellAlignment::Left),
                Cell::new("-").set_alignment(CellAlignment::Left),
                Cell::new("-").set_alignment(CellAlignment::Left),
            ]);
        }else{
            let vendor_name = if host.mac_addr.address().len() > 16 {
                let prefix8 = host.mac_addr.address()[0..8].to_uppercase();
                oui_map.get(&prefix8).unwrap_or(&String::new()).to_string()
            } else {
                oui_map.get(&host.mac_addr.address()).unwrap_or(&String::new()).to_string()
            };
            table.add_row(vec![
                Cell::new(&host.ip_addr.to_string()).set_alignment(CellAlignment::Left),
                Cell::new(&host.hostname).set_alignment(CellAlignment::Left),
                Cell::new(&host.ttl).set_alignment(CellAlignment::Left),
                Cell::new(&host.os_family).set_alignment(CellAlignment::Left),
                Cell::new(&host.mac_addr.to_string()).set_alignment(CellAlignment::Left),
                Cell::new(vendor_name).set_alignment(CellAlignment::Left),
            ]);
        }
    }
    println!();
    println!("[Up Hosts]");
    println!("{}", table);
}