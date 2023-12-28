use indicatif::{ProgressBar, ProgressStyle};
use rushmap_core::dns;
use xenet::net::interface::Interface;
use xenet::packet::ip::IpNextLevelProtocol;
use std::fs;
use term_table::row::Row;
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table, TableStyle};
use rushmap_core::model::PortStatus;
use rushmap_core::result::{DomainScanResult, HostScanResult, PingResult, PortScanResult, TracerouteResult};
use rushmap_core::option::{PortScanOption, HostScanOption, PingOption, TracerouteOption, CommandType, DomainScanOption};

pub fn get_spinner() -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(120);
    let ps: ProgressStyle = ProgressStyle::default_spinner()
        .template("{spinner:.blue} {msg}")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]);
    pb.set_style(ps);
    pb
}

pub fn show_port_options(opt: PortScanOption) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Options]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe Type", 1, Alignment::Left),
        TableCell::new_with_alignment(CommandType::PortScan.name(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Protocol", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.protocol.as_str().to_uppercase(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Interface Name", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.interface_name, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Source IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.src_ip, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Timeout(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.timeout.as_millis(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("WaitTime(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.wait_time.as_millis(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Type", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.scan_type.name(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Async", 1, Alignment::Left),
        if opt.async_scan {
            TableCell::new_with_alignment("True", 1, Alignment::Left)
        } else {
            TableCell::new_with_alignment("False", 1, Alignment::Left)
        },
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Send Rate(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.send_rate.as_millis(), 1, Alignment::Left),
    ]));
    println!("{}", table.render());

    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Target]");
    println!("────────────────────────────────────────");
    for target in opt.targets {
        if target.ip_addr.to_string() == target.host_name || target.host_name.is_empty() {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
                TableCell::new_with_alignment(target.ip_addr, 1, Alignment::Left),
            ]));
        } else {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
                TableCell::new_with_alignment(target.ip_addr, 1, Alignment::Left),
            ]));
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
                TableCell::new_with_alignment(target.host_name, 1, Alignment::Left),
            ]));
        }
        if target.ports.len() > 10 {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Port", 1, Alignment::Left),
                TableCell::new_with_alignment(
                    format!("{} port(s)", target.ports.len()),
                    1,
                    Alignment::Left,
                ),
            ]));
        } else {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Port", 1, Alignment::Left),
                TableCell::new_with_alignment(
                    format!("{:?} port(s)", target.ports),
                    1,
                    Alignment::Left,
                ),
            ]));
        }
    }
    println!("{}", table.render());
    println!("[Progress]");
    println!("────────────────────────────────────────");
}

pub fn show_host_options(opt: HostScanOption) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Options]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe Type", 1, Alignment::Left),
        TableCell::new_with_alignment(CommandType::HostScan.name(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Protocol", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.protocol.as_str().to_uppercase(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Interface Name", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.interface_name, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Source IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.src_ip, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Timeout(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.timeout.as_millis(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("WaitTime(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.wait_time.as_millis(), 1, Alignment::Left),
    ]));

    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Type", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.scan_type.name(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Async", 1, Alignment::Left),
        if opt.async_scan {
            TableCell::new_with_alignment("True", 1, Alignment::Left)
        } else {
            TableCell::new_with_alignment("False", 1, Alignment::Left)
        },
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Send Rate(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.send_rate.as_millis(), 1, Alignment::Left),
    ]));

    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Target]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Host", 1, Alignment::Left),
        TableCell::new_with_alignment(
            format!("{} host(s)", opt.targets.len()),
            1,
            Alignment::Left,
        ),
    ]));
    if opt.targets.len() > 0 && opt.protocol == IpNextLevelProtocol::Tcp {
        if opt.targets[0].ports.len() > 0 {
            if opt.targets[0].ports[0] > 0 {
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment("Port", 1, Alignment::Left),
                    TableCell::new_with_alignment(
                        opt.targets[0].ports[0].to_string(),
                        1,
                        Alignment::Left,
                    ),
                ]));
            }
        }
    }
    println!("{}", table.render());
    println!("[Progress]");
    println!("────────────────────────────────────────");
}

pub fn show_ping_options(opt: PingOption) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Options]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe Type", 1, Alignment::Left),
        TableCell::new_with_alignment(CommandType::Ping.name(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Protocol", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.protocol.as_str().to_uppercase(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Interface Name", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.interface_name, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Source IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.src_ip, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Timeout(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.timeout.as_millis(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("WaitTime(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.wait_time.as_millis(), 1, Alignment::Left),
    ]));

    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Ping Type", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.protocol.as_str().to_uppercase(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Count", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.count, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Send Rate(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.send_rate.as_millis(), 1, Alignment::Left),
    ]));
    println!("{}", table.render());

    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Target]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.target.ip_addr, 1, Alignment::Left),
    ]));
    if !opt.target.host_name.is_empty() {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
            TableCell::new_with_alignment(opt.target.host_name, 1, Alignment::Left),
        ]));
    }
    if opt.target.ports.len() > 0 && opt.protocol == IpNextLevelProtocol::Tcp {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Port", 1, Alignment::Left),
            TableCell::new_with_alignment(
                opt.target.ports[0].to_string(),
                1,
                Alignment::Left,
            ),
        ]));
    }
    println!("{}", table.render());

    println!("[Progress]");
    println!("────────────────────────────────────────");
}

pub fn show_trace_options(opt: TracerouteOption) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Options]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe Type", 1, Alignment::Left),
        TableCell::new_with_alignment(CommandType::Traceroute.name(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Protocol", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.protocol.as_str().to_uppercase(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Interface Name", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.interface_name, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Source IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.src_ip, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Timeout(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.timeout.as_millis(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("WaitTime(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.wait_time.as_millis(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Max Hop", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.max_hop, 1, Alignment::Left),
    ]));
    println!("{}", table.render());

    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Target]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.target.ip_addr, 1, Alignment::Left),
    ]));
    if !opt.target.host_name.is_empty() {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
            TableCell::new_with_alignment(opt.target.host_name, 1, Alignment::Left),
        ]));
    }
    println!("{}", table.render());

    println!("[Progress]");
    println!("────────────────────────────────────────");
}

pub fn show_domain_options(opt: DomainScanOption) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Options]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe Type", 1, Alignment::Left),
        TableCell::new_with_alignment(CommandType::DomainScan.name(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Protocol", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.protocol.as_str().to_uppercase(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Timeout(ms)", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.timeout.as_millis(), 1, Alignment::Left),
    ]));
    if !opt.list_file_path.is_empty() {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Word List", 1, Alignment::Left),
            TableCell::new_with_alignment(opt.list_file_path, 1, Alignment::Left),
        ]));
    }
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Target]");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Domain", 1, Alignment::Left),
        TableCell::new_with_alignment(opt.base_domain.clone(), 1, Alignment::Left),
    ]));
    if let Some(ip_addr) = dns::lookup_host_name(opt.base_domain) {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
            TableCell::new_with_alignment(ip_addr.to_string(), 1, Alignment::Left),
        ]));
    }
    println!("{}", table.render());
    println!("[Progress]");
    println!("────────────────────────────────────────");
}

pub fn show_portscan_result(result: PortScanResult) {
    if result.nodes.len() == 0 {
        println!("No results found");
        return;
    }
    let node = result.nodes[0].clone();
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!();
    println!("[Host Info]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment(node.ip_addr.to_string(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
        TableCell::new_with_alignment(node.host_name, 1, Alignment::Left),
    ]));
    if !node.mac_addr.is_empty() {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("MAC Address", 1, Alignment::Left),
            TableCell::new_with_alignment(node.mac_addr, 1, Alignment::Left),
        ]));
    }
    if !node.vendor_info.is_empty() {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Vendor Info", 1, Alignment::Left),
            TableCell::new_with_alignment(node.vendor_info, 1, Alignment::Left),
        ]));
    }
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("OS Name", 1, Alignment::Left),
        TableCell::new_with_alignment(node.os_name, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("CPE", 1, Alignment::Left),
        TableCell::new_with_alignment(node.cpe, 1, Alignment::Left),
    ]));
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Port Info]");
    println!("────────────────────────────────────────");
    let port_count: usize = node.services.len();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Number", 1, Alignment::Left),
        TableCell::new_with_alignment("Status", 1, Alignment::Left),
        TableCell::new_with_alignment("Service Name", 1, Alignment::Left),
        TableCell::new_with_alignment("Service Version", 1, Alignment::Left),
    ]));
    for port in node.services {
        if port_count > 10 {
            if port.port_status == PortStatus::Open {
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment(port.port_number, 1, Alignment::Left),
                    TableCell::new_with_alignment(port.port_status.name(), 1, Alignment::Left),
                    TableCell::new_with_alignment(port.service_name, 1, Alignment::Left),
                    TableCell::new_with_alignment(port.service_version, 1, Alignment::Left),
                ]));
            }
        } else {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(port.port_number, 1, Alignment::Left),
                TableCell::new_with_alignment(port.port_status.name(), 1, Alignment::Left),
                TableCell::new_with_alignment(port.service_name, 1, Alignment::Left),
                TableCell::new_with_alignment(port.service_version, 1, Alignment::Left),
            ]));
        }
    }
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Performance]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Total elapsed time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.elapsed_time), 1, Alignment::Left),
    ]));
    println!("{}", table.render());
}

pub fn show_hostscan_result(result: HostScanResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!();
    println!("[Host Scan Result]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
        TableCell::new_with_alignment("TTL", 1, Alignment::Left),
        TableCell::new_with_alignment("OS Info", 1, Alignment::Left),
        TableCell::new_with_alignment("MAC Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Vendor Info", 1, Alignment::Left),
    ]));
    for host in result.nodes {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(host.ip_addr, 1, Alignment::Left),
            TableCell::new_with_alignment(host.host_name, 1, Alignment::Left),
            TableCell::new_with_alignment(host.ttl, 1, Alignment::Left),
            TableCell::new_with_alignment(host.os_name, 1, Alignment::Left),
            TableCell::new_with_alignment(host.mac_addr, 1, Alignment::Left),
            TableCell::new_with_alignment(host.vendor_info, 1, Alignment::Left),
        ]));
    }
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Performance]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Total elapsed time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.elapsed_time), 1, Alignment::Left),
    ]));
    println!("{}", table.render());
}

pub fn show_ping_result(result: PingResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!();
    println!("[Ping Result]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("SEQ", 1, Alignment::Left),
        TableCell::new_with_alignment("Protocol", 1, Alignment::Left),
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
        TableCell::new_with_alignment("Port", 1, Alignment::Left),
        TableCell::new_with_alignment("TTL", 1, Alignment::Left),
        TableCell::new_with_alignment("Hop", 1, Alignment::Left),
        TableCell::new_with_alignment("RTT", 1, Alignment::Left),
    ]));
    for r in result.stat.responses {
        let port_data: String = if let Some(port_number) = r.port_number {
            if r.protocol == IpNextLevelProtocol::Tcp.as_str().to_uppercase() {
                port_number.to_string()
            } else {
                "None".to_string()
            }
        } else {
            "None".to_string()
        };
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(r.seq, 1, Alignment::Left),
            TableCell::new_with_alignment(r.protocol, 1, Alignment::Left),
            TableCell::new_with_alignment(r.ip_addr, 1, Alignment::Left),
            TableCell::new_with_alignment(r.host_name, 1, Alignment::Left),
            TableCell::new_with_alignment(port_data, 1, Alignment::Left),
            TableCell::new_with_alignment(r.ttl, 1, Alignment::Left),
            TableCell::new_with_alignment(r.hop, 1, Alignment::Left),
            TableCell::new_with_alignment(
                format!("{:?}", r.rtt),
                1,
                Alignment::Left,
            ),
        ]));
    }
    println!("{}", table.render());

    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!("[Ping Stat]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Probe Time", 1, Alignment::Left),
        TableCell::new_with_alignment(
            format!("{:?}", result.stat.probe_time),
            1,
            Alignment::Left,
        ),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Transmitted", 1, Alignment::Left),
        TableCell::new_with_alignment(result.stat.transmitted_count, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Received", 1, Alignment::Left),
        TableCell::new_with_alignment(result.stat.received_count, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Loss", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:.2}%", ((1.0 - (result.stat.received_count as f64 / result.stat.transmitted_count as f64)) * 100.0).round()), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Min", 1, Alignment::Left),
        TableCell::new_with_alignment(
            format!("{:?}", result.stat.min),
            1,
            Alignment::Left,
        ),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Avg", 1, Alignment::Left),
        TableCell::new_with_alignment(
            format!("{:?}", result.stat.avg),
            1,
            Alignment::Left,
        ),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Max", 1, Alignment::Left),
        TableCell::new_with_alignment(
            format!("{:?}", result.stat.max),
            1,
            Alignment::Left,
        ),
    ]));
    println!("{}", table.render());
}

pub fn show_trace_result(result: TracerouteResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!();
    println!("[Trace Result]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("SEQ", 1, Alignment::Left),
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
        TableCell::new_with_alignment("Node Type", 1, Alignment::Left),
        TableCell::new_with_alignment("TTL", 1, Alignment::Left),
        TableCell::new_with_alignment("Hop", 1, Alignment::Left),
        TableCell::new_with_alignment("RTT", 1, Alignment::Left),
    ]));
    for node in result.nodes {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(node.seq, 1, Alignment::Left),
            TableCell::new_with_alignment(node.ip_addr, 1, Alignment::Left),
            TableCell::new_with_alignment(node.host_name, 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}", node.node_type), 1, Alignment::Left),
            TableCell::new_with_alignment(
                format!("{:?}", node.ttl),
                1,
                Alignment::Left,
            ),
            TableCell::new_with_alignment(
                format!("{:?}", node.hop),
                1,
                Alignment::Left,
            ),
            TableCell::new_with_alignment(format!("{:?}", node.rtt), 1, Alignment::Left),
        ]));
    }
    println!("{}", table.render());
    println!("[Performance]");
    println!("────────────────────────────────────────");
    println!(
        "Total elapsed time: {:?}",result.elapsed_time);
    println!();
}

pub fn show_domainscan_result(result: DomainScanResult) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!();
    println!("[Scan Result]");
    println!("────────────────────────────────────────");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Domain Name", 1, Alignment::Left),
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
    ]));
    for domain in result.domains {
        for ip in domain.ips {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(domain.domain_name.clone(), 1, Alignment::Left),
                TableCell::new_with_alignment(ip, 1, Alignment::Left),
            ]));
        }
    }
    println!("{}", table.render());
    println!("[Performance]");
    println!("────────────────────────────────────────");
    println!("Total elapsed time: {:?}", result.elapsed_time);
    println!();
}

pub fn save_json(json: String, file_path: String) -> bool {
    match fs::write(file_path, json) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn show_interfaces(interfaces: Vec<Interface>) {
    const INDENT: &str = "    ";
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.style = TableStyle::blank();
    println!();
    println!("[Network Interfaces]");
    println!("────────────────────────────────────────");
    for interface in interfaces {
        println!("{}:", interface.index);
        println!("{}Name: {}", INDENT, interface.name);
        println!("{}Interface Type: {}", INDENT, interface.if_type.name());
        if let Some(mac_addr) = interface.mac_addr {
            println!("{}MAC Address: {}", INDENT, mac_addr.address());
        }
        println!("{}IPv4 Address: {:?}", INDENT, interface.ipv4);
        println!("{}IPv6 Address: {:?}", INDENT, interface.ipv6);
        if let Some(gateway) = interface.gateway {
            println!("{}Gateway:", INDENT);
            println!(
                "{}{}MAC Address: {}",
                INDENT,
                INDENT,
                gateway.mac_addr.address()
            );
            println!("{}{}IP Address: {}", INDENT, INDENT, gateway.ip_addr);
        }
    }
    println!("{}", table.render());
}

pub fn show_interfaces_json(interfaces: Vec<Interface>) {
    match serde_json::to_string_pretty(&interfaces) {
        Ok(json) => {
            println!("{}", json);
        }
        Err(_) => {
            println!("Serialize Error");
        }
    }
}
