use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use ipnet::{Ipv4Net, Ipv6Net};
use pnet_packet::{Packet, MutablePacket};

pub fn get_network_address(ip_addr: IpAddr) -> Result<String, String>{
    match ip_addr {
        IpAddr::V4(ipv4_addr) => {
            let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24).unwrap();
            Ok(net.network().to_string())
        },
        IpAddr::V6(ipv6_addr) => {
            let net: Ipv6Net = Ipv6Net::new(ipv6_addr, 24).unwrap();
            Ok(net.network().to_string())
        },
    }
}

pub fn get_mac_through_arp(interface: &pnet_datalink::NetworkInterface, target_ip: Ipv4Addr) -> pnet_datalink::MacAddr {
    let source_ip = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        })
        .unwrap();

    let (mut sender, mut receiver) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = pnet_packet::ethernet::MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(pnet_datalink::MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(pnet_packet::ethernet::EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = pnet_packet::arp::MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(pnet_packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(pnet_packet::ethernet::EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(pnet_packet::arp::ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(pnet_datalink::MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();

    let mut target_mac_addr: pnet_datalink::MacAddr = pnet_datalink::MacAddr::zero();

    for _x in 0..2 {
        let buf = receiver.next().unwrap();
        let arp = pnet_packet::arp::ArpPacket::new(&buf[pnet_packet::ethernet::MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_hw_addr() != interface.mac.unwrap() {
            target_mac_addr = arp.get_sender_hw_addr();
            break;
        }
    }
    return target_mac_addr;
}

pub fn get_mac_addresses(ips: Vec<IpAddr>, src_ip: IpAddr) -> HashMap<IpAddr, String> {
    let mut map : HashMap<IpAddr, String> = HashMap::new();
    if let Some(c_interface) = get_interface_by_ip(src_ip) {
        let interfaces = pnet_datalink::interfaces();
        let iface = interfaces.into_iter().filter(|interface: &pnet_datalink::NetworkInterface| interface.index == c_interface.index).next().expect("Failed to get Interface");
        for ip in ips {
            if !is_global_addr(ip) && in_same_network(src_ip, ip) {
                let mac_addr = get_mac_through_arp(&iface, ip.to_string().parse::<Ipv4Addr>().unwrap()).to_string();
                map.insert(ip, mac_addr);
                /* if mac_addr.len() > 16 {
                    let prefix8 = mac_addr[0..8].to_uppercase();
                    vendor_map.insert(ip.to_string(), (mac_addr, oui_map.get(&prefix8).unwrap_or(&String::from("Unknown")).to_string()));
                }else{
                    vendor_map.insert(ip.to_string(), (mac_addr, String::from("Unknown")));
                } */
            }
        }
    }
    map
}

pub fn is_global_addr(ip_addr: IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ip) => {
            !(ip.is_loopback() || ip.is_private())
        },
        IpAddr::V6(ip) => {
            !(ip.is_loopback() || ((ip.segments()[0] & 0xfe00) == 0xfc00))
        },
    }
}

pub fn in_same_network(src_ip: IpAddr, dst_ip: IpAddr) -> bool {
    let src_ip_nw = match get_network_address(src_ip) {
        Ok(nw) => nw,
        Err(_) => return false,
    };
    let dst_ip_nw = match get_network_address(dst_ip) {
        Ok(nw) => nw,
        Err(_) => return false,
    };
    if src_ip_nw == dst_ip_nw {
        true
    }else{
        false
    }
}

pub fn lookup_host_name(host_name: String) -> Option<IpAddr> {
    let ip_vec: Vec<IpAddr> = dns_lookup::lookup_host(host_name.as_str()).unwrap_or(vec![]);
    let mut ipv6_vec: Vec<IpAddr> = vec![];
    for ip in ip_vec {
        match ip {
            IpAddr::V4(_) => {
                return Some(ip);
            },
            IpAddr::V6(_) => {
                ipv6_vec.push(ip);
            }
        }
    }
    if ipv6_vec.len() > 0 {
        return Some(ipv6_vec[0])
    }else{
        None
    }
}

pub fn lookup_ip_addr(ip_addr: String) -> String {
    let ip_addr: IpAddr = IpAddr::from_str(ip_addr.as_str()).unwrap();
    match dns_lookup::lookup_addr(&ip_addr) {
        Ok(hostname) => {
            return hostname;
        },
        Err(_) => {
            return String::new();
        },
    }
}

pub fn get_interface_by_ip(ip_addr: IpAddr) -> Option<default_net::Interface> {
    for iface in default_net::get_interfaces() {
        match ip_addr {
            IpAddr::V4(ipv4) => {
                for ip in &iface.ipv4 {
                    if ip.addr == ipv4 {
                        return Some(iface);
                    }
                }
            },
            IpAddr::V6(ipv6) => {
                for ip in &iface.ipv6 {
                    if ip.addr == ipv6 {
                        return Some(iface);
                    }
                }   
            },
        }
    }
    return None;
}

pub fn get_interface_by_name(if_name: String) -> Option<default_net::Interface> {
    for iface in default_net::get_interfaces() {
        if iface.name == if_name {
            return Some(iface);
        }
        if let Some(friendly_name) = &iface.friendly_name {
            if friendly_name == &if_name {
                return Some(iface);
            }
        }
    }
    return None;
}
