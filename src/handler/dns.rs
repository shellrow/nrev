use std::path::PathBuf;
use std::{thread, time::Duration};
use crate::db;
use comfy_table::presets::NOTHING;
use comfy_table::{Cell, CellAlignment, ContentArrangement, Table};
use clap::ArgMatches;
use indicatif::ProgressBar;
use crate::dns::{result::DomainScanResult, scanner::DomainScanner};
use tokio::runtime::Runtime;

use crate::output;

pub fn handle_subdomain_scan(args: &ArgMatches) {
    output::log_with_time("Initiating subdomain scan...", "INFO");
    let host_args = match args.subcommand_matches("subdomain") {
        Some(matches) => matches,
        None => return,
    };
    let target: String = match host_args.get_one::<String>("target") {
        Some(target) => target.to_owned(),
        None => return,
    };
    let timeout = match host_args.get_one::<u64>("timeout") {
        Some(timeout) => Duration::from_millis(*timeout),
        None => Duration::from_secs(30),
    };
    
    let word_list: Vec<String> = match host_args.get_one::<PathBuf>("wordlist") {
        Some(file_path) => {
            match std::fs::read_to_string(&file_path) {
                Ok(contents) => {
                    let mut word_list: Vec<String> = Vec::new();
                    for word in contents.lines() {
                        let word = word.trim();
                        if word.is_empty() {
                            continue;
                        }
                        word_list.push(word.to_owned());
                    }
                    word_list
                }
                Err(_) => vec![],
            }
        },
        None => db::get_subdomain(),
    };
    
    // Display progress with indicatif
    println!("[Progress]");
    let bar = ProgressBar::new(word_list.len() as u64);
    bar.enable_steady_tick(120);
    bar.set_style(output::get_progress_style());
    bar.set_position(0);
    bar.set_message("SubdomainScan");

    let mut domain_scanner = match DomainScanner::new() {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    domain_scanner.set_base_domain(target);
    domain_scanner.word_list = word_list;
    domain_scanner.set_timeout(timeout);
    let rx = domain_scanner.get_progress_receiver();
    let rt = Runtime::new().unwrap();
    // Run scan
    let handle = thread::spawn(move || rt.block_on(async { domain_scanner.scan().await }));
    // Print progress
    while let Ok(_domain) = rx.lock().unwrap().recv() {
        bar.inc(1);
    }
    bar.finish_with_message("SubdomainScan");
    let result: DomainScanResult = handle.join().unwrap();
    // Print results
    if args.get_flag("json") {
        let json_result = serde_json::to_string_pretty(&result).unwrap();
        println!("{}", json_result);
    }else {
        show_domainscan_result(&result);
    }
    output::log_with_time(&format!("Scan completed in {:?}", result.scan_time), "INFO");
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

fn show_domainscan_result(scan_result: &DomainScanResult) {
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Host Name", "IP Address"]);
    println!();
    println!("[Scan Result]");
    for domain in &scan_result.domains {
        table.add_row(vec![
            Cell::new(&domain.domain_name).set_alignment(CellAlignment::Left),
            Cell::new(format!("{:?}", &domain.ips)).set_alignment(CellAlignment::Left),
        ]);
    }
    println!("{}", table);
}
