use std::net::Ipv4Addr;
use std::{net::IpAddr, time::Duration};

use netdev::Interface;
use serde::{Deserialize, Serialize};

use crate::protocol::Protocol;
use crate::config::{DEFAULT_BASE_TARGET_UDP_PORT, DEFAULT_HOP_LIMIT};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TraceSetting {
    pub if_index: u32,
    pub dst_hostname: String,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub hop_limit: u8,
    pub protocol: Protocol,
    pub receive_timeout: Duration,
    pub probe_timeout: Duration,
    pub send_rate: Duration,
    pub tunnel: bool,
    pub loopback: bool,
}

impl Default for TraceSetting {
    fn default() -> Self {
        Self {
            if_index: 0,
            dst_hostname: "localhost".to_string(),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: DEFAULT_BASE_TARGET_UDP_PORT,
            hop_limit: DEFAULT_HOP_LIMIT,
            protocol: Protocol::UDP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: false,
            loopback: false,
        }
    }
}

impl TraceSetting {
    pub fn udp_trace(
        interface: &Interface,
        dst_ip_addr: IpAddr
    ) -> Result<TraceSetting, String> {
        let use_tun = interface.is_tun();
        let loopback = interface.is_loopback();

        let setting = TraceSetting {
            if_index: interface.index,
            dst_ip: dst_ip_addr,
            dst_hostname: dst_ip_addr.to_string(),
            dst_port: DEFAULT_BASE_TARGET_UDP_PORT,
            hop_limit: 64,
            protocol: Protocol::UDP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
}
