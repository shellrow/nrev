use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum, value_parser};

#[derive(Debug, Parser)]
#[command(
    name = "nrev",
    version,
    about = "Observation-first reconnaissance engine"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan ports and collect structured observations.
    Port(Box<ScanArgs>),
    /// Discover reachable hosts with ICMP, UDP, or TCP probes.
    Host(Box<HostArgs>),
    /// Show the built-in and externally loaded probe catalog.
    Probe(ProbeArgs),
    /// Show externally loaded scan recipes.
    Recipe(RecipeArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

impl OutputFormat {
    pub fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ScanTransport {
    Tcp,
    Udp,
    Syn,
    Quic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ProgressMode {
    Auto,
    Quiet,
    Verbose,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum HostDiscoveryMode {
    Icmp,
    Udp,
    Tcp,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Target hosts, IPs, CIDRs, or host:port expressions.
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Port set: top-100, top-1000, well-known, 80,443, 20-25.
    #[arg(short, long, default_value = "top-100")]
    pub ports: String,

    /// Transport to use for scanning and probing.
    #[arg(short = 't', long, value_enum, default_value_t = ScanTransport::Tcp)]
    pub transport: ScanTransport,

    /// Max number of concurrent endpoints.
    #[arg(short = 'c', long, default_value_t = 512)]
    pub concurrency: usize,

    /// Show closed and filtered ports in the human-readable report.
    #[arg(long, action = ArgAction::SetTrue)]
    pub all_states: bool,

    /// Disable progress output.
    #[arg(short = 'q', long, action = ArgAction::SetTrue)]
    pub quiet: bool,

    /// Progress output mode.
    #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
    pub progress: ProgressMode,

    /// Interface name to use for UDP or SYN scanning.
    #[arg(short = 'i', long)]
    pub interface: Option<String>,

    /// Connect timeout in milliseconds. Defaults to adaptive mode when omitted.
    #[arg(long, value_parser = value_parser!(u64).range(50..=30_000))]
    pub connect_timeout_ms: Option<u64>,

    /// Probe timeout in milliseconds.
    #[arg(long, default_value_t = 2000, value_parser = value_parser!(u64).range(50..=30_000))]
    pub probe_timeout_ms: u64,

    /// Max HTTP/HTTPS body preview bytes to inspect for metadata extraction.
    #[arg(long, default_value_t = 4096)]
    pub http_body_preview_bytes: usize,

    /// Retries for connect/probe actions.
    #[arg(long, default_value_t = 0, value_parser = value_parser!(u8).range(0..=5))]
    pub retries: u8,

    /// Optional profile file (JSON or TOML).
    #[arg(short = 'P', long, value_name = "FILE", value_parser = value_parser!(PathBuf))]
    pub profile: Option<PathBuf>,

    /// Optional external data file or directory (JSON or TOML).
    #[arg(short = 'd', long, value_name = "PATH", value_parser = value_parser!(PathBuf))]
    pub data: Option<PathBuf>,

    /// Named scan recipe loaded from external data.
    #[arg(short = 'r', long)]
    pub recipe: Option<String>,

    /// Override the enabled built-in probe ids.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub probes: Vec<String>,

    /// Disable built-in probes and run only externally loaded probes.
    #[arg(long, action = ArgAction::SetTrue)]
    pub no_builtin_probes: bool,

    /// Output format for stdout.
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Write the stable JSON report to a file.
    #[arg(short, long, value_name = "FILE", value_parser = value_parser!(PathBuf))]
    pub output: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct ScanArgSources {
    pub ports: bool,
    pub transport: bool,
    pub concurrency: bool,
    pub all_states: bool,
    pub quiet: bool,
    pub progress: bool,
    pub interface: bool,
    pub connect_timeout_ms: bool,
    pub probe_timeout_ms: bool,
    pub http_body_preview_bytes: bool,
    pub retries: bool,
    pub profile: bool,
    pub data: bool,
    pub recipe: bool,
    pub probes: bool,
    pub no_builtin_probes: bool,
    pub format: bool,
    pub output: bool,
}

#[derive(Debug, Args)]
pub struct HostArgs {
    /// Target hosts, IPs, CIDRs, or @file expressions.
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Discovery method to use.
    #[arg(short = 'm', long, value_enum, default_value_t = HostDiscoveryMode::Icmp)]
    pub method: HostDiscoveryMode,

    /// Port set used by UDP or TCP discovery.
    #[arg(short, long)]
    pub ports: Option<String>,

    /// Max number of concurrent host probes.
    #[arg(short = 'c', long, default_value_t = 512)]
    pub concurrency: usize,

    /// Probe timeout in milliseconds.
    #[arg(short = 't', long, default_value_t = 600, value_parser = value_parser!(u64).range(50..=30_000))]
    pub timeout_ms: u64,

    /// Interface name to use for ICMP or UDP probing.
    #[arg(short = 'i', long)]
    pub interface: Option<String>,

    /// Scan hosts in user-specified order.
    #[arg(long, action = ArgAction::SetTrue)]
    pub ordered: bool,

    /// Show unreachable hosts in the human-readable report.
    #[arg(long, action = ArgAction::SetTrue)]
    pub all_hosts: bool,

    /// Disable progress output.
    #[arg(short = 'q', long, action = ArgAction::SetTrue)]
    pub quiet: bool,

    /// Progress output mode.
    #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
    pub progress: ProgressMode,

    /// Output format for stdout.
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Write the stable JSON report to a file.
    #[arg(short, long, value_name = "FILE", value_parser = value_parser!(PathBuf))]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ProbeArgs {
    /// Optional external data file or directory (JSON or TOML).
    #[arg(short = 'd', long, value_name = "PATH", value_parser = value_parser!(PathBuf))]
    pub data: Option<PathBuf>,

    /// Emit JSON instead of a human-readable list.
    #[arg(short = 'j', long, action = ArgAction::SetTrue)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RecipeArgs {
    /// Optional external data file or directory (JSON or TOML).
    #[arg(short = 'd', long, value_name = "PATH", value_parser = value_parser!(PathBuf))]
    pub data: Option<PathBuf>,

    /// Emit JSON instead of a human-readable list.
    #[arg(short = 'j', long, action = ArgAction::SetTrue)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_command_supports_short_options() {
        let cli = Cli::try_parse_from([
            "nrev",
            "port",
            "example.com",
            "-p",
            "443",
            "-t",
            "udp",
            "-c",
            "64",
            "-q",
            "-i",
            "en0",
            "-P",
            "profile.toml",
            "-d",
            "recipes",
            "-r",
            "web-balanced",
            "-f",
            "json",
            "-o",
            "report.json",
        ])
        .expect("parse port args");

        let Command::Port(args) = cli.command else {
            panic!("expected port command");
        };
        assert_eq!(args.ports, "443");
        assert_eq!(args.transport, ScanTransport::Udp);
        assert_eq!(args.concurrency, 64);
        assert!(args.quiet);
        assert_eq!(args.interface.as_deref(), Some("en0"));
        assert_eq!(
            args.profile.as_deref(),
            Some(PathBuf::from("profile.toml").as_path())
        );
        assert_eq!(
            args.data.as_deref(),
            Some(PathBuf::from("recipes").as_path())
        );
        assert_eq!(args.recipe.as_deref(), Some("web-balanced"));
        assert_eq!(args.format, OutputFormat::Json);
        assert_eq!(
            args.output.as_deref(),
            Some(PathBuf::from("report.json").as_path())
        );
    }

    #[test]
    fn host_command_supports_short_options() {
        let cli = Cli::try_parse_from([
            "nrev",
            "host",
            "192.0.2.0/24",
            "-m",
            "udp",
            "-p",
            "33434",
            "-c",
            "32",
            "-t",
            "1200",
            "-i",
            "en0",
            "-q",
            "-f",
            "json",
            "-o",
            "hosts.json",
        ])
        .expect("parse host args");

        let Command::Host(args) = cli.command else {
            panic!("expected host command");
        };
        assert_eq!(args.method, HostDiscoveryMode::Udp);
        assert_eq!(args.ports.as_deref(), Some("33434"));
        assert_eq!(args.concurrency, 32);
        assert_eq!(args.timeout_ms, 1200);
        assert_eq!(args.interface.as_deref(), Some("en0"));
        assert!(args.quiet);
        assert_eq!(args.format, OutputFormat::Json);
        assert_eq!(
            args.output.as_deref(),
            Some(PathBuf::from("hosts.json").as_path())
        );
    }

    #[test]
    fn catalog_commands_support_short_options() {
        let probe = Cli::try_parse_from(["nrev", "probe", "-d", "data", "-j"]).expect("probe");
        let Command::Probe(args) = probe.command else {
            panic!("expected probe command");
        };
        assert_eq!(args.data.as_deref(), Some(PathBuf::from("data").as_path()));
        assert!(args.json);

        let recipe =
            Cli::try_parse_from(["nrev", "recipe", "-d", "recipes", "-j"]).expect("recipe");
        let Command::Recipe(args) = recipe.command else {
            panic!("expected recipe command");
        };
        assert_eq!(
            args.data.as_deref(),
            Some(PathBuf::from("recipes").as_path())
        );
        assert!(args.json);
    }
}
