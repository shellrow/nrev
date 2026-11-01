use netdev::Interface;
use netdev::MacAddr;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Select a source address with the same family and scope as the destination.
pub(crate) fn source_ip_for(iface: &Interface, destination: IpAddr) -> IpAddr {
    match destination {
        IpAddr::V4(dst) => iface
            .ipv4
            .iter()
            .find(|network| network.contains(&dst))
            .or_else(|| iface.ipv4.first())
            .map(|network| IpAddr::V4(network.addr()))
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        IpAddr::V6(dst) => iface
            .ipv6
            .iter()
            .filter(|network| network.addr().is_unicast_link_local() == dst.is_unicast_link_local())
            .max_by_key(|network| (network.contains(&dst), network.prefix_len()))
            .map(|network| IpAddr::V6(network.addr()))
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
    }
}

/// Get interface information by IP address.
pub fn get_interface_by_ip(ip_addr: IpAddr) -> Option<Interface> {
    for iface in netdev::interface::get_interfaces() {
        for ip in &iface.ipv4 {
            if ip.addr() == ip_addr {
                return Some(iface);
            }
        }
        for ip in &iface.ipv6 {
            if ip.addr() == ip_addr {
                return Some(iface);
            }
        }
    }
    None
}

/// Get interface information by index.
pub fn get_interface_by_index(index: u32) -> Option<Interface> {
    netdev::interface::get_interfaces()
        .into_iter()
        .find(|iface| iface.index == index)
}

/// Get interface information by name.
pub fn get_interface_by_name(name: String) -> Option<Interface> {
    netdev::interface::get_interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
}

/// Get the first IPv4 address of the interface.
pub fn get_interface_ipv4(iface: &Interface) -> Option<Ipv4Addr> {
    iface.ipv4.first().map(|ip| ip.addr())
}

/// Get the first global IPv6 address of the interface.
pub fn get_interface_global_ipv6(iface: &Interface) -> Option<Ipv6Addr> {
    for ip in &iface.ipv6 {
        if nex::net::ip::is_global_ipv6(&ip.addr()) {
            return Some(ip.addr());
        }
    }
    None
}

/// Get the first local IPv6 address of the interface.
pub fn get_interface_local_ipv6(iface: &Interface) -> Option<Ipv6Addr> {
    for ip in &iface.ipv6 {
        if !nex::net::ip::is_global_ipv6(&ip.addr()) {
            return Some(ip.addr());
        }
    }
    None
}

/// Get all IP addresses of the interface as strings.
pub fn get_interface_ips(iface: &Interface) -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();
    for ip in &iface.ipv4 {
        ips.push(ip.addr().to_string());
    }
    for ip in &iface.ipv6 {
        ips.push(ip.addr().to_string());
    }
    ips
}

/// Get all local IP addresses on the specified interface.
pub fn get_local_ips(if_index: u32) -> HashSet<IpAddr> {
    let mut ips: HashSet<IpAddr> = HashSet::new();
    if let Some(interface) = get_interface_by_index(if_index) {
        for ip in &interface.ipv4 {
            ips.insert(IpAddr::V4(ip.addr()));
        }
        for ip in &interface.ipv6 {
            ips.insert(IpAddr::V6(ip.addr()));
        }
    } else {
        tracing::warn!("interface not found for index {}", if_index);
    }
    // localhost IP addresses
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    ips
}

/// Get all local IP addresses on the default interface.
pub fn get_default_local_ips() -> HashSet<IpAddr> {
    let mut ips: HashSet<IpAddr> = HashSet::new();
    // Default interface IP addresses
    match netdev::get_default_interface() {
        Ok(default_interface) => {
            for ip in &default_interface.ipv4 {
                ips.insert(IpAddr::V4(ip.addr()));
            }
            for ip in &default_interface.ipv6 {
                ips.insert(IpAddr::V6(ip.addr()));
            }
        }
        Err(e) => {
            tracing::warn!("failed to get default interface: {}", e);
        }
    }
    // localhost IP addresses
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    ips
}

/// Get all local IP addresses on the specified interface.
pub fn get_interface_local_ips(iface: &Interface) -> HashSet<IpAddr> {
    let mut ips: HashSet<IpAddr> = HashSet::new();
    for ip in &iface.ipv4 {
        ips.insert(IpAddr::V4(ip.addr()));
    }
    for ip in &iface.ipv6 {
        ips.insert(IpAddr::V6(ip.addr()));
    }
    // localhost IP addresses
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    ips
}

/// Get a map of all local IP addresses to their corresponding interface names.
pub fn get_local_ip_map() -> HashMap<IpAddr, String> {
    let mut ip_map: HashMap<IpAddr, String> = HashMap::new();
    for iface in netdev::interface::get_interfaces() {
        for ip in &iface.ipv4 {
            ip_map.insert(IpAddr::V4(ip.addr()), iface.name.clone());
        }
        for ip in &iface.ipv6 {
            ip_map.insert(IpAddr::V6(ip.addr()), iface.name.clone());
        }
    }
    ip_map
}

// get usable interface list
pub fn get_usable_interfaces() -> Vec<Interface> {
    let mut usable_interfaces: Vec<Interface> = Vec::new();
    for iface in netdev::interface::get_interfaces() {
        if iface.is_up() && (!iface.ipv4.is_empty() || !iface.ipv6.is_empty()) {
            usable_interfaces.push(iface);
        }
    }
    usable_interfaces
}

/// Get the MAC address of the interface, or MacAddr::zero() if not available.
pub fn get_interface_macaddr(iface: &Interface) -> MacAddr {
    match &iface.mac_addr {
        Some(mac_addr) => *mac_addr,
        None => MacAddr::zero(),
    }
}

/// Get the MAC address of the gateway, or MacAddr::zero() if not available.
pub fn get_gateway_macaddr(iface: &Interface) -> MacAddr {
    match &iface.gateway {
        Some(gateway) => gateway.mac_addr,
        None => MacAddr::zero(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_source_selection_respects_subnet_and_ipv6_scope() {
        let mut interface = Interface::dummy();
        interface.ipv4 = vec![
            "198.51.100.1/24".parse().unwrap(),
            "192.0.2.1/24".parse().unwrap(),
        ];
        interface.ipv6 = vec![
            "fe80::1/64".parse().unwrap(),
            "2001:db8::1/64".parse().unwrap(),
        ];
        for (destination, expected) in [
            ("192.0.2.2", "192.0.2.1"),
            ("fe80::2", "fe80::1"),
            ("2001:db8::2", "2001:db8::1"),
        ] {
            assert_eq!(
                source_ip_for(&interface, destination.parse().unwrap()),
                expected.parse::<IpAddr>().unwrap()
            );
        }
    }
}
