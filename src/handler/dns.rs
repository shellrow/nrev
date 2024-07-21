use std::path::PathBuf;
use std::{thread, time::Duration};
use crate::db;
use clap::ArgMatches;
use indicatif::ProgressBar;
use crate::dns::{result::DomainScanResult, scanner::DomainScanner};
use tokio::runtime::Runtime;
use termtree::Tree;
use crate::util::tree::node_label;

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

    let mut domain_scanner = match DomainScanner::new() {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    domain_scanner.set_base_domain(target);
    domain_scanner.word_list = word_list;
    domain_scanner.set_timeout(timeout);
    print_option(&domain_scanner);

    // Display progress with indicatif
    println!("[Progress]");
    let bar = ProgressBar::new(domain_scanner.word_list.len() as u64);
    bar.enable_steady_tick(120);
    bar.set_style(output::get_progress_style());
    bar.set_position(0);
    bar.set_message("SubdomainScan");

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

fn print_option(setting: &DomainScanner) {
    println!();
    let mut tree = Tree::new(node_label("SubdomainScan Config", None, None));
    let mut setting_tree = Tree::new(node_label("Settings", None, None));
    setting_tree.push(node_label("Words", Some(&setting.word_list.len().to_string()), None));
    setting_tree.push(node_label("Timeout", Some(&format!("{:?}", setting.timeout)), None));
    setting_tree.push(node_label("Resolve timeout", Some(&format!("{:?}", setting.resolve_timeout)), None));
    setting_tree.push(node_label("Concurrent limit", Some(&setting.concurrent_limit.to_string()), None));
    tree.push(setting_tree);
    let mut target_tree = Tree::new(node_label("Target", None, None));
    target_tree.push(node_label("Domain Name", Some(&setting.base_domain), None));
    tree.push(target_tree);
    println!("{}", tree);
}

fn show_domainscan_result(scan_result: &DomainScanResult) {
    println!();
    let mut tree = Tree::new(node_label("Subdomains", None, None));
    for domain in &scan_result.domains {
        let mut domain_tree = Tree::new(node_label(&domain.domain_name, None, None));
        for ip in &domain.ips {
            if ip.is_ipv4() {
                domain_tree.push(node_label("IPv4", Some(&ip.to_string()), None));
            } else {
                domain_tree.push(node_label("IPv6", Some(&ip.to_string()), None));
            }
        }
        tree.push(domain_tree);
    }
    println!("{}", tree);
}
