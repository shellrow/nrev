pub mod port;
pub mod host;
pub mod ping;

use std::path::PathBuf;

use clap::{command, value_parser, ArgAction, Args, Parser, Subcommand, ValueEnum};

use crate::{config::default::{DEFAULT_BASE_TARGET_UDP_PORT, DEFAULT_PORTS_CONCURRENCY}, endpoint::TransportProtocol, protocol::Protocol};

/// nrev - Fast Network Mapper
#[derive(Parser, Debug)]
#[command(author, version, about = "nrev - Cross-platform Network Mapper\nhttps://github.com/shellrow/nrev", long_about = None)]
pub struct Cli {
    /// Global log level
    #[arg(long, default_value = "info")]
    pub log_level: LogLevel,

    /// Log to file (in addition to stdout)
    #[arg(long, action = ArgAction::SetTrue, default_value_t = false)]
    pub log_file: bool,

    /// Log file path (default: ~/.nrev/logs/nrev.log)
    #[arg(long, value_name = "FILE", value_parser = value_parser!(PathBuf))]
    pub log_file_path: Option<PathBuf>,

    /// Suppress all log output (only errors are shown)
    #[arg(long, action = ArgAction::SetTrue, default_value_t = false)]
    pub quiet: bool,

    /// Save output to file (JSON format)
    #[arg(short, long, value_name = "FILE", value_parser = value_parser!(PathBuf))]
    pub output: Option<PathBuf>,

    /// Suppress stdout console output (only save to file if -o is set)
    #[arg(long, action = ArgAction::SetTrue, default_value_t = false)]
    pub no_stdout: bool,

    /// Subcommands
    #[command(subcommand)]
    pub command: Command,
}

/// Log level
#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// Convert to `tracing::Level`
    pub fn to_level_filter(&self) -> tracing::Level {
        match self {
            LogLevel::Error => tracing::Level::ERROR,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Trace => tracing::Level::TRACE,
        }
    }
}

/// Subcommands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan ports on the target(s) (TCP/QUIC)
    Port(PortScanArgs),

    /// Discover alive hosts (ICMP/UDP/TCP etc.)
    Host(HostScanArgs),

    /// Simple ping (ICMP/UDP/TCP)
    Ping(PingArgs),

    /// Traceroute (UDP)
    Trace(TraceArgs),

    /// Neighbor discovery (ARP/NDP)
    Nei(NeighborArgs),

    /// Subdomain enumeration
    Domain(DomainScanArgs),

    /// Show network interface(s)
    Interface(InterfaceArgs),
}

/// Port scan methods. Default: Connect
#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum PortScanMethod { Connect, Syn }

/// Host scan protocols. Default: ICMP
#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum HostScanProto { Icmp, Udp, Tcp }

impl HostScanProto {
    /// Convert to TransportProtocol (if applicable)
    pub fn to_transport(&self) -> Option<TransportProtocol> {
        match self {
            HostScanProto::Icmp => None,
            HostScanProto::Udp => Some(TransportProtocol::Udp),
            HostScanProto::Tcp => Some(TransportProtocol::Tcp),
        }
    }
    /// Convert to &str
    pub fn as_str(&self) -> &str {
        match self {
            HostScanProto::Icmp => "icmp",
            HostScanProto::Udp => "udp",
            HostScanProto::Tcp => "tcp",
        }
    }
}

/// Traceroute protocol (currently only UDP is supported)
#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
pub enum TraceProto { Udp }

impl TraceProto {
    /// Convert to &str
    pub fn as_str(&self) -> &str {
        match self {
            TraceProto::Udp => "udp",
        }
    }
    /// Convert to Protocol
    pub fn to_protocol(&self) -> Protocol {
        match self {
            TraceProto::Udp => Protocol::Udp,
        }
    }
}

/// Port scan arguments
#[derive(Args, Debug)]
pub struct PortScanArgs {
    /// Target IP or hostname
    #[arg(required = true)]
    pub target: Vec<String>,

    /// Port spec: "top-1000" | "1-1024,80,443" | "22-25"
    #[arg(short, long, default_value = "top-1000")]
    pub ports: String,

    /// Transport to scan (now tcp only; udp/quic later)
    #[arg(long, default_value = "tcp", value_parser = ["tcp","udp","quic"])]
    pub proto: String,

    /// Scanning method (default: connect)
    #[arg(long, value_enum, default_value_t = PortScanMethod::Connect)]
    pub method: PortScanMethod,

    /// Enable service detection (banner/TLS/etc.)
    #[arg(short='s', long, default_value_t = false, action=ArgAction::SetTrue)]
    pub service_detect: bool,

    /// Enable OS fingerprinting
    /// for open ports, send one SYN to collect OS-fingerprint features
    #[arg(short='o', long, default_value_t = false, action=ArgAction::SetTrue)]
    pub os_detect: bool,

    /// Enable QUIC probing on UDP ports (e.g., 443/udp)
    #[arg(long, action=ArgAction::SetTrue)]
    pub quic: bool,

    /// SNI for QUIC/TLS probing (defaults to target name)
    #[arg(long)]
    pub sni: Option<String>,

    /// Network interface name to bind
    #[arg(long)]
    pub interface: Option<String>,

    /// Concurrency (tasks)
    #[arg(long, default_value_t = DEFAULT_PORTS_CONCURRENCY)]
    pub concurrency: usize,

    /// Base connect timeout in ms (auto-adapted by RTT)
    #[arg(long, value_parser = value_parser!(u64).range(1..=10_000))]
    pub connect_timeout_ms: Option<u64>,

    /// Read timeout in ms (auto-adapted by RTT)
    #[arg(long, value_parser = value_parser!(u64).range(1..=10_000))]
    pub read_timeout_ms: Option<u64>,

    /// Wait time after last send (ms)
    #[arg(short='w', long, value_parser = value_parser!(u64).range(10..=5000))]
    pub wait_ms: Option<u64>,

    /// Task timeout in ms
    #[arg(long, default_value_t = 30000, value_parser = value_parser!(u64).range(1..=60_000))]
    pub task_timeout_ms: u64,

    /// Scan ports in user-specified order (default is randomized)
    #[arg(long, action=ArgAction::SetTrue)]
    pub ordered: bool,

    /// Skip initial ping
    #[arg(long, action=ArgAction::SetTrue)]
    pub no_ping: bool,
}

/// Host scan arguments
#[derive(Args, Debug)]
pub struct HostScanArgs {
    /// Targets (CIDR, range, or list).
    #[arg(required = true)]
    pub target: Vec<String>,

    /// Protocol to use (default: ICMP)
    #[arg(long, value_enum, default_value_t = HostScanProto::Icmp)]
    pub proto: HostScanProto,

    /// Port spec: "80" | "80,443" | "22-25"
    #[arg(short, long, default_value = "80")]
    pub ports: String,

    /// Wait time after last send (ms)
    #[arg(short='w', long, default_value_t = 300, value_parser = value_parser!(u64).range(10..=5000))]
    pub wait_ms: u64,

    /// Timeout per probe (ms)
    #[arg(long, default_value_t = 600, value_parser = value_parser!(u64).range(50..=5000))]
    pub timeout_ms: u64,

    /// Network interface name to bind
    #[arg(long)]
    pub interface: Option<String>,

    /// Concurrency (in-flight probes)
    #[arg(long, default_value_t = 512)]
    pub concurrency: usize,

    /// Scan hosts in user-specified order (default is randomized)
    #[arg(long, action=ArgAction::SetTrue)]
    pub ordered: bool,
}

/// Simple ping arguments
#[derive(Args, Debug)]
pub struct PingArgs {
    /// Target IP or hostname
    #[arg(required = true)]
    pub target: String,

    /// Protocol to use (default: ICMP)
    #[arg(long, value_enum, default_value_t = Protocol::Icmp)]
    pub proto: Protocol,

    /// Target port
    #[arg(short, long, default_value_t = 80)]
    pub port: u16,

    /// Number of probes
    #[arg(short, long, default_value_t = 4, value_parser = value_parser!(u32).range(1..=10_000))]
    pub count: u32,

    /// Interval between probes (ms)
    #[arg(short, long, default_value_t = 1000)]
    pub interval_ms: u64,

    /// Per-probe timeout (ms)
    #[arg(long, default_value_t = 1000)]
    pub timeout_ms: u64,

    /// Network interface name to bind
    #[arg(long)]
    pub interface: Option<String>,
}


/// Traceroute arguments
#[derive(Args, Debug)]
pub struct TraceArgs {
    /// Target host or IP
    #[arg(required = true)]
    pub target: String,

    /// Protocol
    #[arg(long, value_enum, default_value_t = TraceProto::Udp)]
    pub proto: TraceProto,

    /// Destination port (for UDP)
    #[arg(long, default_value_t = DEFAULT_BASE_TARGET_UDP_PORT)]
    pub port: u16,

    /// Max TTL/hops
    #[arg(long, default_value_t = 64, value_parser = value_parser!(u8).range(1..=255))]
    pub max_hops: u8,

    /// Interval between probes (ms)
    #[arg(short, long, default_value_t = 1000)]
    pub interval_ms: u64,

    /// Per-hop timeout (ms)
    #[arg(long, default_value_t = 1000)]
    pub timeout_ms: u64,

    /// Network interface name to bind
    #[arg(long)]
    pub interface: Option<String>,
}

/// Neighbor discovery arguments
#[derive(Args, Debug)]
pub struct NeighborArgs {
    /// Target IP (IPv4 -> ARP, IPv6 -> NDP).
    #[arg(required = true)]
    pub target: String,

    /// Network interface name to bind
    #[arg(short='i', long)]
    pub interface: Option<String>,

    /// Timeout waiting for replies (ms)
    #[arg(long, default_value_t = 500)]
    pub timeout_ms: u64,
}

/// Subdomain scan arguments
#[derive(Args, Debug)]
pub struct DomainScanArgs {
    /// Base domain (e.g., example.com)
    #[arg(required = true)]
    pub domain: String,

    /// Wordlist path
    #[arg(short, long)]
    pub wordlist: Option<PathBuf>,

    /// Concurrency
    #[arg(long, default_value_t = 256)]
    pub concurrency: usize,

    /// Total scan timeout (ms)
    #[arg(long, default_value_t = 30000)]
    pub timeout_ms: u64,

    /// Per-lookup timeout (ms)
    #[arg(long, default_value_t = 2000)]
    pub resolve_timeout_ms: u64,
}

/// Network interface arguments
#[derive(Args, Debug)]
pub struct InterfaceArgs {
    /// Show all interfaces
    #[arg(short, long, action=ArgAction::SetTrue)]
    pub all: bool,
}
