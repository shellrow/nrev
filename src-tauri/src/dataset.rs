use std::collections::HashMap;
use crate::{db, db_models};

pub fn get_oui_detail_map() -> HashMap<String, String> {
    let mut oui_map: HashMap<String, String> = HashMap::new();
    let rs_nscan_oui: Vec<db_models::Oui> = db_models::Oui::get_oui_list();
    for oui in rs_nscan_oui {
        oui_map.insert(oui.mac_prefix, oui.vendor_name_detail);
    }
    oui_map
}

pub fn get_tcp_map() -> HashMap<u16, String> {
    let mut tcp_map: HashMap<u16, String> = HashMap::new();
    let tcp_services: Vec<db_models::TcpService> = db::get_tcp_services();
    for port in tcp_services {
        tcp_map.insert(port.port, port.service_name);
    }
    tcp_map
}

pub fn get_default_ports() -> Vec<u16> {
    let mut default_ports: Vec<u16> = vec![];
    let default_services: Vec<db_models::TcpService> = db::get_default_services();
    for service in default_services {
        default_ports.push(service.port);
    }
    default_ports
}

pub fn get_wellknown_ports() -> Vec<u16> {
    let mut wellknown_ports: Vec<u16> = vec![];
    let wellknown_services: Vec<db_models::TcpService> = db::get_wellknown_services();
    for service in wellknown_services {
        wellknown_ports.push(service.port);
    }
    wellknown_ports
}

pub fn get_http_ports() -> Vec<u16> {
    db::get_http_ports()
}

pub fn get_https_ports() -> Vec<u16> {
    db::get_https_ports()
}

pub fn get_os_ttl() -> HashMap<u8, String> {
    let mut os_ttl_map: HashMap<u8, String> = HashMap::new();
    let os_ttl_list: Vec<db_models::OsTtl> = db::get_os_ttl();
    for os_ttl in os_ttl_list {
        os_ttl_map.insert(os_ttl.initial_ttl, os_ttl.os_description);
    }
    os_ttl_map
}
