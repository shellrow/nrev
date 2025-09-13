pub mod probe;

use std::net::Ipv4Addr;
use std::{net::IpAddr, time::Duration};

use netdev::Interface;
use serde::{Deserialize, Serialize};
use anyhow::Result;

use crate::config::default::{DEFAULT_BASE_TARGET_UDP_PORT, DEFAULT_HOP_LIMIT};
use crate::endpoint::Host;
use crate::probe::{ProbeResult, ProbeStatus};
use crate::protocol::Protocol;

/// Settings for traceroute operations.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct TraceSetting {
    pub if_index: u32,
    pub dst_hostname: Option<String>,
    pub dst_ip: IpAddr,
    pub dst_port: Option<u16>,
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
            dst_hostname: None,
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: Some(DEFAULT_BASE_TARGET_UDP_PORT),
            hop_limit: DEFAULT_HOP_LIMIT,
            protocol: Protocol::Udp,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: false,
            loopback: false,
        }
    }
}

impl TraceSetting {
    /// Create a UDP trace setting from the given interface and destination host.
    pub fn udp_trace(interface: &Interface, dst_host: &Host) -> Result<TraceSetting> {
        let use_tun = interface.is_tun();
        let loopback = interface.is_loopback();

        let setting = TraceSetting {
            if_index: interface.index,
            dst_ip: dst_host.ip,
            dst_hostname: dst_host.hostname.clone(),
            dst_port: Some(DEFAULT_BASE_TARGET_UDP_PORT),
            hop_limit: 64,
            protocol: Protocol::Udp,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
}

/// Result of a traceroute operation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TraceResult {
    pub nodes: Vec<ProbeResult>,
    pub probe_status: ProbeStatus,
    pub elapsed_time: Duration,
    pub protocol: Protocol,
}

impl TraceResult {
    /// Create a new empty TraceResult.
    pub fn new() -> TraceResult {
        TraceResult {
            nodes: Vec::new(),
            probe_status: ProbeStatus::new(),
            elapsed_time: Duration::from_millis(0),
            protocol: Protocol::Udp,
        }
    }
}

/// Tracer structure.
///
/// Supports UDP Traceroute.
#[derive(Clone, Debug)]
pub struct Tracer {
    /// Probe Setting
    pub setting: TraceSetting,
}

impl Tracer {
    /// Create a new Tracer instance.
    pub fn new(setting: TraceSetting) -> Self {
        Self { setting }
    }
    /// Run the traceroute based on the specified protocol.
    pub async fn run(&self) -> Result<TraceResult> {
        match self.setting.protocol {
            Protocol::Udp => probe::udp::run_udp_trace(&self.setting).await,
            _ => {
                Err(anyhow::anyhow!("Unsupported protocol"))
            },
        }
    }
}
