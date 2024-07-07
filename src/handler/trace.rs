use clap::ArgMatches;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use crate::trace::setting::TraceSetting;
use crate::trace::tracer::Tracer;
use std::thread;
use netdev::Interface;
use std::str::FromStr;
use crate::config::DEFAULT_BASE_TARGET_UDP_PORT;
use crate::output;

pub fn handle_traceroute(args: &ArgMatches) {
    output::log_with_time("Initiating traceroute...", "INFO");
    let trace_args = match args.subcommand_matches("trace") {
        Some(matches) => matches,
        None => return,
    };
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
    let target: String = match trace_args.get_one::<String>("target") {
        Some(target) => target.to_owned(),
        None => return,
    };
    let mut port: u16 = match trace_args.get_one::<u16>("port") {
        Some(port) => *port,
        None => DEFAULT_BASE_TARGET_UDP_PORT,
    };
    let maxhop: u8 = match trace_args.get_one::<u8>("maxhop") {
        Some(maxhop) => *maxhop,
        None => 64,
    };
    let dst_ip: IpAddr = match IpAddr::from_str(&target) {
        Ok(ip_addr) => {
            ip_addr
        },
        Err(_) => {
            match SocketAddr::from_str(&target) {
                Ok(socket_addr) => {
                    port = socket_addr.port();
                    socket_addr.ip()
                },
                Err(_) => {
                    match crate::dns::lookup_host_name(target.clone()) {
                        Some(ip_addr) => {
                            ip_addr
                        },
                        None => {
                            output::log_with_time("Failed to resolve domain", "ERROR");
                            return;
                        }
                    }
                }
            }
        }
    };
    let timeout = match trace_args.get_one::<u64>("timeout") {
        Some(timeout) => Duration::from_millis(*timeout),
        None => Duration::from_secs(30),
    };
    let wait_time = match trace_args.get_one::<u64>("waittime") {
        Some(wait_time) => Duration::from_millis(*wait_time),
        None => Duration::from_secs(1),
    };
    let send_rate = match trace_args.get_one::<u64>("rate") {
        Some(send_rate) => Duration::from_millis(*send_rate),
        None => Duration::from_secs(1),
    };
    let mut setting: TraceSetting = TraceSetting::udp_trace(interface, dst_ip).unwrap();
    setting.dst_hostname = target.split(":").collect::<Vec<&str>>().get(0).unwrap().to_string();
    setting.dst_port = port; 
    setting.hop_limit = maxhop;
    setting.receive_timeout = wait_time;
    setting.probe_timeout = timeout;
    setting.send_rate = send_rate;   
    let tracer: Tracer = Tracer::new(setting).unwrap();
    let rx = tracer.get_progress_receiver();
    let handle = thread::spawn(move || tracer.trace());
    for r in rx.lock().unwrap().iter() {
        if r.probe_status.kind == crate::probe::ProbeStatusKind::Done {
            output::log_with_time(&format!(
                "{} {} Bytes from {}, HOP:{}, TTL:{}, RTT:{:?}, NodeType: {}",
                r.seq, r.received_packet_size, r.ip_addr, r.hop, r.ttl, r.rtt, r.node_type.name()
            ), "INFO");
        }else{
            output::log_with_time(&format!(
                "{} {}",
                r.seq, r.probe_status.message
            ), "ERROR");
        }
    }
    match handle.join() {
        Ok(trace_result) => match trace_result {
            Ok(trace_result) => {
                // Print results
                if args.get_flag("json") {
                    let json_result = serde_json::to_string_pretty(&trace_result).unwrap();
                    println!("{}", json_result);
                }
                output::log_with_time(&format!("Traceroute completed in: {:?}", trace_result.elapsed_time), "INFO");
                match args.get_one::<PathBuf>("save") {
                    Some(file_path) => {
                        match crate::fs::save_text(file_path, serde_json::to_string_pretty(&trace_result).unwrap()) {
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
            Err(e) => println!("{:?}", e),
        },
        Err(e) => println!("{:?}", e),
    }
}
