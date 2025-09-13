pub mod arp;
pub mod ndp;

use serde::{Deserialize, Serialize};
use netdev::mac::MacAddr;
use std::{net::{IpAddr, Ipv4Addr}, time::Duration};

use crate::protocol::Protocol;

/// Result of Neighbor Discovery
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NeighborDiscoveryResult {
    pub mac_addr: MacAddr,
    pub vendor: Option<String>,
    pub ip_addr: IpAddr,
    pub hostname: Option<String>,
    /// Round Trip Time (microsecond)
    pub rtt: Duration,
    /// Protocol
    pub protocol: Protocol,
    pub if_name: String,
    pub if_friendly_name: Option<String>,
    pub if_index: u32,
}

impl NeighborDiscoveryResult {
    /// Construct a new NeighborDiscoveryResult instance
    pub fn new() -> NeighborDiscoveryResult {
        NeighborDiscoveryResult {
            mac_addr: MacAddr::zero(),
            vendor: None,
            ip_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            hostname: None,
            rtt: Duration::from_millis(0),
            protocol: Protocol::Icmp,
            if_name: String::new(),
            if_friendly_name: None,
            if_index: 0,
        }
    }
}

/// Lookup the vendor name for a given MAC address using the OUI database.
pub fn lookup_vendor(mac: &MacAddr) -> Option<String> {
    let oui_db = crate::db::oui::oui_db();
    if let Some(oui) = oui_db.lookup_mac(mac) {
        if let Some(vendor_detail) = &oui.vendor_detail {
            return Some(vendor_detail.clone());
        } else {
            return Some(oui.vendor.clone());
        }
    }
    None
}
