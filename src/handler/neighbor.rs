use crate::neighbor::resolver::DeviceResolver;
use crate::neighbor::result::DeviceResolveResult;
use crate::neighbor::setting::AddressResolveSetting;
use crate::output;
use crate::util::tree::node_label;
use clap::ArgMatches;
use netdev::Interface;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use termtree::Tree;

pub fn handle_neighbor_discovery(args: &ArgMatches) {
    let nei_args = match args.subcommand_matches("nei") {
        Some(matches) => matches,
        None => return,
    };
    let target: String = match nei_args.get_one::<String>("target") {
        Some(target) => target.to_owned(),
        None => return,
    };
    let dst_ip: IpAddr = match IpAddr::from_str(&target) {
        Ok(ip_addr) => ip_addr,
        Err(_) => {
            output::log_with_time("Invalid IP Address", "ERROR");
            return;
        }
    };
    match dst_ip {
        IpAddr::V4(_) => {
            output::log_with_time("Initiating ARP...", "INFO");
        }
        IpAddr::V6(_) => {
            output::log_with_time("Initiating NDP...", "INFO");
        }
    }
    let interface: netdev::Interface = if let Some(if_name) = args.get_one::<String>("interface") {
        match crate::interface::get_interface_by_name(if_name.to_string()) {
            Some(iface) => iface,
            None => return,
        }
    } else {
        match netdev::get_default_interface() {
            Ok(iface) => iface,
            Err(_) => return,
        }
    };
    let count: u32 = match nei_args.get_one::<u32>("count") {
        Some(count) => *count,
        None => 1,
    };
    let timeout = match nei_args.get_one::<u64>("timeout") {
        Some(timeout) => Duration::from_millis(*timeout),
        None => Duration::from_secs(30),
    };
    let wait_time = match nei_args.get_one::<u64>("waittime") {
        Some(wait_time) => Duration::from_millis(*wait_time),
        None => Duration::from_secs(1),
    };
    let send_rate = match nei_args.get_one::<u64>("rate") {
        Some(send_rate) => Duration::from_millis(*send_rate),
        None => Duration::from_secs(1),
    };
    let mut setting: AddressResolveSetting = match dst_ip {
        IpAddr::V4(ipv4) => AddressResolveSetting::arp(&interface, ipv4, count).unwrap(),
        IpAddr::V6(ipv6) => AddressResolveSetting::ndp(&interface, ipv6, count).unwrap(),
    };
    setting.probe_timeout = timeout;
    setting.receive_timeout = wait_time;
    setting.send_rate = send_rate;
    print_option(&setting, &interface);
    let resolver: DeviceResolver = DeviceResolver::new(setting).unwrap();
    let rx = resolver.get_progress_receiver();
    let handle = thread::spawn(move || resolver.resolve());
    for r in rx.lock().unwrap().iter() {
        if r.probe_status.kind == crate::probe::ProbeStatusKind::Done {
            output::log_with_time(
                &format!(
                    "{} [{:?}] {} Bytes from MAC:{}, IP:{}, RTT:{:?}",
                    r.seq, r.protocol, r.received_packet_size, r.mac_addr, r.ip_addr, r.rtt
                ),
                "INFO",
            );
        } else {
            output::log_with_time(
                &format!("{} [{:?}] {}", r.seq, r.protocol, r.probe_status.message),
                "ERROR",
            );
        }
    }
    match handle.join() {
        Ok(resolve_result) => match resolve_result {
            Ok(r) => {
                // Print results
                if args.get_flag("json") {
                    let json_result = serde_json::to_string_pretty(&r).unwrap();
                    println!("{}", json_result);
                } else {
                    show_resolve_result(&r);
                }
                match args.get_one::<PathBuf>("save") {
                    Some(file_path) => {
                        match crate::fs::save_text(
                            file_path,
                            serde_json::to_string_pretty(&r).unwrap(),
                        ) {
                            Ok(_) => {
                                output::log_with_time(
                                    &format!("Saved to {}", file_path.to_string_lossy()),
                                    "INFO",
                                );
                            }
                            Err(e) => {
                                output::log_with_time(&format!("Failed to save: {}", e), "ERROR");
                            }
                        }
                    }
                    None => {}
                }
                if r.probe_status.kind == crate::probe::ProbeStatusKind::Done {
                    output::log_with_time("Resolve Success", "INFO");
                } else {
                    output::log_with_time(
                        &format!("Resolve Failed: {}", r.probe_status.message),
                        "ERROR",
                    );
                }
            }
            Err(e) => {
                output::log_with_time(&format!("Resolve Failed: {}", e), "ERROR");
            }
        },
        Err(e) => {
            output::log_with_time(&format!("Resolve Failed: {:?}", e), "ERROR");
        }
    }
}

fn print_option(setting: &AddressResolveSetting, interface: &Interface) {
    if crate::app::is_quiet_mode() {
        return;
    }
    println!();
    // Options
    let mut tree = Tree::new(node_label("NeighborResolve Config", None, None));
    let mut setting_tree = Tree::new(node_label("Settings", None, None));
    setting_tree.push(node_label("Interface", Some(interface.name.as_str()), None));
    setting_tree.push(node_label(
        "Protocol",
        Some(format!("{:?}", setting.protocol).as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "Count",
        Some(setting.count.to_string().as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "Timeout",
        Some(format!("{:?}", setting.probe_timeout).as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "Wait Time",
        Some(format!("{:?}", setting.receive_timeout).as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "Send Rate",
        Some(format!("{:?}", setting.send_rate).as_str()),
        None,
    ));
    tree.push(setting_tree);
    // Target
    let mut target_tree = Tree::new(node_label("Target", None, None));
    target_tree.push(node_label(
        "IP Address",
        Some(setting.dst_ip.to_string().as_str()),
        None,
    ));
    tree.push(target_tree);
    println!("{}", tree);
}

fn show_resolve_result(resolve_result: &DeviceResolveResult) {
    if !crate::app::is_quiet_mode() {
        println!();
    }
    let mut tree = Tree::new(node_label("NeighborResolve Result", None, None));
    // Responses
    let mut responses_tree = Tree::new(node_label("Responses", None, None));
    for response in &resolve_result.results {
        let source_ip_addr: String = if response.ip_addr.to_string() != response.host_name
            && !response.host_name.is_empty()
        {
            format!("{}({})", response.host_name, response.ip_addr)
        } else {
            response.ip_addr.to_string()
        };
        let mut response_tree = Tree::new(node_label(
            "Sequence",
            Some(response.seq.to_string().as_str()),
            None,
        ));
        response_tree.push(node_label(
            "MAC Address",
            Some(&response.mac_addr.address()),
            None,
        ));
        response_tree.push(node_label("IP Address", Some(&source_ip_addr), None));
        response_tree.push(node_label(
            "Protocol",
            Some(format!("{:?}", response.protocol).as_str()),
            None,
        ));
        response_tree.push(node_label(
            "Received Bytes",
            Some(response.received_packet_size.to_string().as_str()),
            None,
        ));
        response_tree.push(node_label(
            "RTT",
            Some(format!("{:?}", response.rtt).as_str()),
            None,
        ));

        responses_tree.push(response_tree);
    }
    tree.push(responses_tree);

    println!("{}", tree);
}
