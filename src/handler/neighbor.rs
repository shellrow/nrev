use clap::ArgMatches;
use crate::neighbor::resolver::DeviceResolver;
use crate::neighbor::setting::AddressResolveSetting;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use crate::output;

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
        Ok(ip_addr) => {
            ip_addr
        },
        Err(_) => {
            output::log_with_time("Invalid IP Address", "ERROR");
            return;
        }
    };
    match dst_ip {
        IpAddr::V4(_) => {
            output::log_with_time("Initiating ARP...", "INFO");
        },
        IpAddr::V6(_) => {
            output::log_with_time("Initiating NDP...", "INFO");
        },
    }
    let interface: netdev::Interface = if let Some(if_name) = args.get_one::<String>("interface") {
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
        IpAddr::V4(ipv4) => {
            AddressResolveSetting::arp(interface, ipv4, count).unwrap()
        },
        IpAddr::V6(ipv6) => {
            AddressResolveSetting::ndp(interface, ipv6, count).unwrap()
        }
    };
    setting.probe_timeout = timeout;
    setting.receive_timeout = wait_time;
    setting.send_rate = send_rate;
    let resolver: DeviceResolver = DeviceResolver::new(setting).unwrap();
    let rx = resolver.get_progress_receiver();
    let handle = thread::spawn(move || resolver.resolve());
    for r in rx.lock().unwrap().iter() {
        if r.probe_status.kind == crate::probe::ProbeStatusKind::Done {
            output::log_with_time(&format!(
                "{} [{:?}] {} Bytes from MAC:{}, IP:{}, RTT:{:?}",
                r.seq, r.protocol, r.received_packet_size, r.mac_addr, r.ip_addr, r.rtt
            ), "INFO");
        }else{
            output::log_with_time(&format!(
                "{} [{:?}] {}",
                r.seq, r.protocol, r.probe_status.message
            ), "ERROR");
        }
    }
    match handle.join() {
        Ok(resolve_result) => match resolve_result {
            Ok(r) => {
                // Print results
                if args.get_flag("json") {
                    let json_result = serde_json::to_string_pretty(&r).unwrap();
                    println!("{}", json_result);
                }
                match args.get_one::<PathBuf>("save") {
                    Some(file_path) => {
                        match crate::fs::save_text(file_path, serde_json::to_string_pretty(&r).unwrap()) {
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
                if r.probe_status.kind == crate::probe::ProbeStatusKind::Done {
                    output::log_with_time("Resolve Success", "INFO");
                }else{
                    output::log_with_time(&format!("Resolve Failed: {}", r.probe_status.message), "ERROR");
                }
            },
            Err(e) => {
                output::log_with_time(&format!("Resolve Failed: {}", e), "ERROR");
            }
        },
        Err(e) => {
            output::log_with_time(&format!("Resolve Failed: {:?}", e), "ERROR");
        }
    }
}
