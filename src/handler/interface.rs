use std::path::PathBuf;

use clap::ArgMatches;
use netdev::mac::MacAddr;
use netdev::Interface;
use comfy_table::presets::NOTHING;
use comfy_table::{Cell, CellAlignment, ContentArrangement, Table};

use crate::output;

pub fn show_default_interface(args: &ArgMatches) {
    let iface: Interface = match netdev::get_default_interface() {
        Ok(interface) => interface,
        Err(_) => {
            println!("Failed to get default interface");
            return;
        }
    };
    if args.get_flag("json") {
        let json_result = serde_json::to_string_pretty(&iface).unwrap();
        println!("{}", json_result);
    }else {
        show_interface_table(&iface);
    }
    match args.get_one::<PathBuf>("save") {
        Some(file_path) => {
            match crate::fs::save_text(file_path, serde_json::to_string_pretty(&iface).unwrap()) {
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

pub fn show_interfaces(args: &ArgMatches) {
    let interfaces: Vec<Interface> = netdev::get_interfaces();
    if args.get_flag("json") {
        let json_result = serde_json::to_string_pretty(&interfaces).unwrap();
        println!("{}", json_result);
    }else {
        show_interfaces_table(&interfaces);
    }
    match args.get_one::<PathBuf>("save") {
        Some(file_path) => {
            match crate::fs::save_text(file_path, serde_json::to_string_pretty(&interfaces).unwrap()) {
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

pub fn show_interface_table(iface: &Interface) {
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic);
    table.add_row(vec![
        Cell::new(&iface.index).set_alignment(CellAlignment::Left),
        Cell::new("Name").set_alignment(CellAlignment::Left),
        Cell::new(&iface.name).set_alignment(CellAlignment::Left),
    ]);
    table.add_row(vec![
        Cell::new("").set_alignment(CellAlignment::Left),
        Cell::new("MAC").set_alignment(CellAlignment::Left),
        Cell::new(&iface.mac_addr.unwrap_or(MacAddr::zero())).set_alignment(CellAlignment::Left),
    ]);
    table.add_row(vec![
        Cell::new("").set_alignment(CellAlignment::Left),
        Cell::new("IPv4").set_alignment(CellAlignment::Left),
        Cell::new(format!("{:?}",&iface.ipv4)).set_alignment(CellAlignment::Left),
    ]);
    table.add_row(vec![
        Cell::new("").set_alignment(CellAlignment::Left),
        Cell::new("IPv6").set_alignment(CellAlignment::Left),
        Cell::new(format!("{:?}",&iface.ipv6)).set_alignment(CellAlignment::Left),
    ]);
    if let Some(gateway) = &iface.gateway {
        table.add_row(vec![
            Cell::new("").set_alignment(CellAlignment::Left),
            Cell::new("Gateway").set_alignment(CellAlignment::Left),
            Cell::new("").set_alignment(CellAlignment::Left),
        ]);
        table.add_row(vec![
            Cell::new("").set_alignment(CellAlignment::Right),
            Cell::new("IPv4").set_alignment(CellAlignment::Right),
            Cell::new(format!("{:?}",&gateway.ipv4)).set_alignment(CellAlignment::Left),
        ]);
        table.add_row(vec![
            Cell::new("").set_alignment(CellAlignment::Right),
            Cell::new("IPv6").set_alignment(CellAlignment::Right),
            Cell::new(format!("{:?}",&gateway.ipv6)).set_alignment(CellAlignment::Left),
        ]);
        table.add_row(vec![
            Cell::new("").set_alignment(CellAlignment::Right),
            Cell::new("MAC").set_alignment(CellAlignment::Right),
            Cell::new(format!("{}",&gateway.mac_addr)).set_alignment(CellAlignment::Left),
        ]);
    };
    println!();
    println!("[Default Inteface]");
    println!("{}", table);
}

pub fn show_interfaces_table(interfaces: &Vec<Interface>) {
    let mut table = Table::new();
    table
        .load_preset(NOTHING)
        .set_content_arrangement(ContentArrangement::Dynamic);
    for iface in interfaces {
        table.add_row(vec![
            Cell::new(&iface.index).set_alignment(CellAlignment::Left),
            Cell::new("Name").set_alignment(CellAlignment::Left),
            Cell::new(&iface.name).set_alignment(CellAlignment::Left),
        ]);
        table.add_row(vec![
            Cell::new("").set_alignment(CellAlignment::Left),
            Cell::new("MAC").set_alignment(CellAlignment::Left),
            Cell::new(&iface.mac_addr.unwrap_or(MacAddr::zero())).set_alignment(CellAlignment::Left),
        ]);
        table.add_row(vec![
            Cell::new("").set_alignment(CellAlignment::Left),
            Cell::new("IPv4").set_alignment(CellAlignment::Left),
            Cell::new(format!("{:?}",&iface.ipv4)).set_alignment(CellAlignment::Left),
        ]);
        table.add_row(vec![
            Cell::new("").set_alignment(CellAlignment::Left),
            Cell::new("IPv6").set_alignment(CellAlignment::Left),
            Cell::new(format!("{:?}",&iface.ipv6)).set_alignment(CellAlignment::Left),
        ]);
        if let Some(gateway) = &iface.gateway {
            table.add_row(vec![
                Cell::new("").set_alignment(CellAlignment::Left),
                Cell::new("Gateway").set_alignment(CellAlignment::Left),
                Cell::new("").set_alignment(CellAlignment::Left),
            ]);
            table.add_row(vec![
                Cell::new("").set_alignment(CellAlignment::Right),
                Cell::new("IPv4").set_alignment(CellAlignment::Right),
                Cell::new(format!("{:?}",&gateway.ipv4)).set_alignment(CellAlignment::Left),
            ]);
            table.add_row(vec![
                Cell::new("").set_alignment(CellAlignment::Right),
                Cell::new("IPv6").set_alignment(CellAlignment::Right),
                Cell::new(format!("{:?}",&gateway.ipv6)).set_alignment(CellAlignment::Left),
            ]);
            table.add_row(vec![
                Cell::new("").set_alignment(CellAlignment::Right),
                Cell::new("MAC").set_alignment(CellAlignment::Right),
                Cell::new(format!("{}",&gateway.mac_addr)).set_alignment(CellAlignment::Left),
            ]);
        };
    }
    println!();
    println!("[Intefaces]");
    println!("{}", table);
}
