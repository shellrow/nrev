use std::{path::Path, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    cli::{
        HostArgs, HostDiscoveryMode, NeighborArgs, NeighborMethod as CliNeighborMethod, PingArgs,
        PingMethod as CliPingMethod, ProgressMode, ScanArgSources, ScanArgs, ScanTransport,
        TraceArgs, TraceMethod as CliTraceMethod,
    },
    data::DataRegistry,
    error::{NrevError, Result},
    model::{HostDiscoveryMethod, NeighborMethod, PingMethod, TraceMethod, Transport},
    target::parse_ports,
};

const DEFAULT_UDP_PROBE_PORT: u16 = 33435;
const DEFAULT_TCP_PROBE_PORT: u16 = 80;
const DEFAULT_QUIC_PROBE_PORT: u16 = 443;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanProfile {
    pub name: String,
    pub ports: Option<String>,
    pub transport: Option<ProfileTransport>,
    pub interface: Option<String>,
    pub concurrency: Option<usize>,
    pub connect_timeout_ms: Option<u64>,
    pub probe_timeout_ms: Option<u64>,
    pub http_body_preview_bytes: Option<usize>,
    pub retries: Option<u8>,
    pub probes: Option<Vec<String>>,
    pub builtin_probes: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanRecipe {
    pub name: String,
    pub description: Option<String>,
    pub ports: Option<String>,
    pub transport: Option<ProfileTransport>,
    pub interface: Option<String>,
    pub concurrency: Option<usize>,
    pub connect_timeout_ms: Option<u64>,
    pub probe_timeout_ms: Option<u64>,
    pub http_body_preview_bytes: Option<usize>,
    pub retries: Option<u8>,
    pub probes: Option<Vec<String>>,
    pub builtin_probes: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub profile_name: String,
    pub recipe_name: Option<String>,
    pub transport: Transport,
    pub interface: Option<String>,
    pub show_all_states: bool,
    pub quiet: bool,
    pub progress_mode: ProgressMode,
    pub default_ports: Vec<u16>,
    pub concurrency: usize,
    pub connect_timeout: Duration,
    pub adaptive_connect_timeout: bool,
    pub probe_timeout: Duration,
    pub http_body_preview_bytes: usize,
    pub retries: u8,
    pub enabled_probes: Vec<String>,
    pub builtin_probes: bool,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct HostConfig {
    pub method: HostDiscoveryMethod,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout: Duration,
    pub interface: Option<String>,
    pub ordered: bool,
    pub show_all_hosts: bool,
    pub quiet: bool,
    pub progress_mode: ProgressMode,
}

#[derive(Clone, Debug)]
pub struct PingConfig {
    pub method: PingMethod,
    pub port: Option<u16>,
    pub count: u32,
    pub interval: Duration,
    pub timeout: Duration,
    pub interface: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TraceConfig {
    pub method: TraceMethod,
    pub port: Option<u16>,
    pub max_hops: u8,
    pub interval: Duration,
    pub timeout: Duration,
    pub interface: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NeighborConfig {
    pub method: Option<NeighborMethod>,
    pub timeout: Duration,
    pub interface: Option<String>,
}

impl ScanConfig {
    pub fn from_scan_args(args: &ScanArgs, registry: &DataRegistry) -> Result<Self> {
        Self::from_scan_args_with_sources(args, registry, &ScanArgSources::default())
    }

    pub fn from_scan_args_with_sources(
        args: &ScanArgs,
        registry: &DataRegistry,
        sources: &ScanArgSources,
    ) -> Result<Self> {
        let profile = if let Some(path) = &args.profile {
            Some(load_profile(path)?)
        } else {
            None
        };
        let recipe = args
            .recipe
            .as_deref()
            .map(|name| {
                registry
                    .recipes
                    .iter()
                    .find(|recipe| recipe.name == name)
                    .cloned()
                    .ok_or_else(|| NrevError::InvalidRecipe(name.to_string()))
            })
            .transpose()?;

        let ports_expr = if sources.ports {
            args.ports.clone()
        } else {
            recipe
                .as_ref()
                .and_then(|r| r.ports.clone())
                .or_else(|| profile.as_ref().and_then(|p| p.ports.clone()))
                .unwrap_or_else(|| args.ports.clone())
        };

        let enabled_probes = if sources.probes || !args.probes.is_empty() {
            args.probes.clone()
        } else if let Some(recipe) = &recipe {
            recipe.probes.clone().unwrap_or_default()
        } else {
            profile
                .as_ref()
                .and_then(|p| p.probes.clone())
                .unwrap_or_default()
        };
        let explicit_connect_timeout = if sources.connect_timeout_ms {
            args.connect_timeout_ms
        } else {
            recipe
                .as_ref()
                .and_then(|r| r.connect_timeout_ms)
                .or_else(|| profile.as_ref().and_then(|p| p.connect_timeout_ms))
                .or(args.connect_timeout_ms)
        };

        Ok(Self {
            profile_name: profile
                .as_ref()
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "default".to_string()),
            recipe_name: recipe.as_ref().map(|r| r.name.clone()),
            transport: if sources.transport {
                args.transport.into()
            } else {
                recipe
                    .as_ref()
                    .and_then(|r| r.transport)
                    .or_else(|| profile.as_ref().and_then(|p| p.transport))
                    .map(Into::into)
                    .unwrap_or_else(|| args.transport.into())
            },
            interface: if sources.interface {
                args.interface.clone()
            } else {
                recipe
                    .as_ref()
                    .and_then(|r| r.interface.clone())
                    .or_else(|| profile.as_ref().and_then(|p| p.interface.clone()))
                    .or_else(|| args.interface.clone())
            },
            show_all_states: args.all_states,
            quiet: args.quiet || args.progress == ProgressMode::Quiet,
            progress_mode: args.progress,
            default_ports: parse_ports(&ports_expr)?,
            concurrency: if sources.concurrency {
                args.concurrency
            } else {
                recipe
                    .as_ref()
                    .and_then(|r| r.concurrency)
                    .or_else(|| profile.as_ref().and_then(|p| p.concurrency))
                    .unwrap_or(args.concurrency)
            },
            connect_timeout: Duration::from_millis(explicit_connect_timeout.unwrap_or(1500)),
            adaptive_connect_timeout: explicit_connect_timeout.is_none(),
            probe_timeout: Duration::from_millis(if sources.probe_timeout_ms {
                args.probe_timeout_ms
            } else {
                recipe
                    .as_ref()
                    .and_then(|r| r.probe_timeout_ms)
                    .or_else(|| profile.as_ref().and_then(|p| p.probe_timeout_ms))
                    .unwrap_or(args.probe_timeout_ms)
            }),
            http_body_preview_bytes: if sources.http_body_preview_bytes {
                args.http_body_preview_bytes
            } else {
                recipe
                    .as_ref()
                    .and_then(|r| r.http_body_preview_bytes)
                    .or_else(|| profile.as_ref().and_then(|p| p.http_body_preview_bytes))
                    .unwrap_or(args.http_body_preview_bytes)
            },
            retries: if sources.retries {
                args.retries
            } else {
                recipe
                    .as_ref()
                    .and_then(|r| r.retries)
                    .or_else(|| profile.as_ref().and_then(|p| p.retries))
                    .unwrap_or(args.retries)
            },
            enabled_probes,
            builtin_probes: if sources.no_builtin_probes {
                !args.no_builtin_probes
            } else {
                recipe
                    .as_ref()
                    .and_then(|r| r.builtin_probes)
                    .or_else(|| profile.as_ref().and_then(|p| p.builtin_probes))
                    .unwrap_or(!args.no_builtin_probes)
            },
            tags: recipe.map(|r| r.tags).unwrap_or_default(),
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileTransport {
    Tcp,
    Udp,
    Syn,
    Quic,
}

impl From<ScanTransport> for Transport {
    fn from(value: ScanTransport) -> Self {
        match value {
            ScanTransport::Tcp => Self::Tcp,
            ScanTransport::Udp => Self::Udp,
            ScanTransport::Syn => Self::Syn,
            ScanTransport::Quic => Self::Quic,
        }
    }
}

impl From<ProfileTransport> for Transport {
    fn from(value: ProfileTransport) -> Self {
        match value {
            ProfileTransport::Tcp => Self::Tcp,
            ProfileTransport::Udp => Self::Udp,
            ProfileTransport::Syn => Self::Syn,
            ProfileTransport::Quic => Self::Quic,
        }
    }
}

impl From<HostDiscoveryMode> for HostDiscoveryMethod {
    fn from(value: HostDiscoveryMode) -> Self {
        match value {
            HostDiscoveryMode::Icmp => Self::Icmp,
            HostDiscoveryMode::Udp => Self::Udp,
            HostDiscoveryMode::Tcp => Self::Tcp,
        }
    }
}

impl From<CliPingMethod> for PingMethod {
    fn from(value: CliPingMethod) -> Self {
        match value {
            CliPingMethod::Icmp => Self::Icmp,
            CliPingMethod::Udp => Self::Udp,
            CliPingMethod::Tcp => Self::Tcp,
            CliPingMethod::Quic => Self::Quic,
        }
    }
}

impl From<CliTraceMethod> for TraceMethod {
    fn from(value: CliTraceMethod) -> Self {
        match value {
            CliTraceMethod::Icmp => Self::Icmp,
            CliTraceMethod::Udp => Self::Udp,
        }
    }
}

impl HostConfig {
    pub fn from_host_args(args: &HostArgs) -> Result<Self> {
        let method: HostDiscoveryMethod = args.method.into();
        let ports = if let Some(ports) = &args.ports {
            parse_ports(ports)?
        } else {
            default_host_ports(method)
        };

        Ok(Self {
            method,
            ports,
            concurrency: args.concurrency,
            timeout: Duration::from_millis(args.timeout_ms),
            interface: args.interface.clone(),
            ordered: args.ordered,
            show_all_hosts: args.all_hosts,
            quiet: args.quiet || args.progress == ProgressMode::Quiet,
            progress_mode: args.progress,
        })
    }
}

impl PingConfig {
    pub fn from_ping_args(args: &PingArgs) -> Self {
        let method: PingMethod = args.method.into();
        let port = match method {
            PingMethod::Icmp => None,
            PingMethod::Udp => Some(args.port.unwrap_or(DEFAULT_UDP_PROBE_PORT)),
            PingMethod::Tcp => Some(args.port.unwrap_or(DEFAULT_TCP_PROBE_PORT)),
            PingMethod::Quic => Some(args.port.unwrap_or(DEFAULT_QUIC_PROBE_PORT)),
        };
        Self {
            method,
            port,
            count: args.count,
            interval: Duration::from_millis(args.interval_ms),
            timeout: Duration::from_millis(args.timeout_ms),
            interface: args.interface.clone(),
        }
    }
}

impl TraceConfig {
    pub fn from_trace_args(args: &TraceArgs) -> Self {
        let method: TraceMethod = args.method.into();
        Self {
            method,
            port: match method {
                TraceMethod::Icmp => None,
                TraceMethod::Udp => Some(args.port.unwrap_or(DEFAULT_UDP_PROBE_PORT)),
            },
            max_hops: args.max_hops,
            interval: Duration::from_millis(args.interval_ms),
            timeout: Duration::from_millis(args.timeout_ms),
            interface: args.interface.clone(),
        }
    }
}

impl NeighborConfig {
    pub fn from_neighbor_args(args: &NeighborArgs) -> Self {
        Self {
            method: match args.method {
                CliNeighborMethod::Auto => None,
                CliNeighborMethod::Arp => Some(NeighborMethod::Arp),
                CliNeighborMethod::Ndp => Some(NeighborMethod::Ndp),
            },
            timeout: Duration::from_millis(args.timeout_ms),
            interface: args.interface.clone(),
        }
    }
}

fn default_host_ports(method: HostDiscoveryMethod) -> Vec<u16> {
    match method {
        HostDiscoveryMethod::Icmp => Vec::new(),
        HostDiscoveryMethod::Udp => vec![33434, 40125],
        HostDiscoveryMethod::Tcp => vec![80, 443],
    }
}

pub fn load_profile(path: &Path) -> Result<ScanProfile> {
    let content = std::fs::read_to_string(path)?;
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => Ok(serde_json::from_str(&content)?),
        Some("toml") => Ok(toml::from_str(&content)?),
        _ => Err(crate::error::NrevError::UnsupportedFileExtension(
            path.to_path_buf(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::DataRegistry;

    #[test]
    fn profile_overrides_defaults() {
        let profile = ScanProfile {
            name: "fast".to_string(),
            ports: Some("443,8443".to_string()),
            transport: Some(ProfileTransport::Tcp),
            interface: None,
            concurrency: Some(10),
            connect_timeout_ms: Some(100),
            probe_timeout_ms: Some(200),
            http_body_preview_bytes: Some(1024),
            retries: Some(2),
            probes: Some(vec!["tls".to_string()]),
            builtin_probes: Some(true),
        };
        let path = std::env::temp_dir().join("nrev-profile.json");
        std::fs::write(&path, serde_json::to_string(&profile).expect("serialize")).expect("write");
        let loaded = load_profile(&path).expect("load profile");
        assert_eq!(loaded.name, "fast");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn recipe_overrides_profile() {
        let args = ScanArgs {
            targets: vec!["127.0.0.1".to_string()],
            ports: "80".to_string(),
            transport: ScanTransport::Tcp,
            concurrency: 512,
            all_states: false,
            quiet: false,
            progress: ProgressMode::Auto,
            interface: None,
            connect_timeout_ms: None,
            probe_timeout_ms: 2000,
            http_body_preview_bytes: 4096,
            retries: 0,
            profile: None,
            data: None,
            recipe: Some("enterprise".to_string()),
            probes: Vec::new(),
            no_builtin_probes: false,
            format: crate::cli::OutputFormat::Human,
            output: None,
        };
        let registry = DataRegistry {
            recipes: vec![ScanRecipe {
                name: "enterprise".to_string(),
                description: None,
                ports: Some("1433,1521".to_string()),
                transport: Some(ProfileTransport::Tcp),
                interface: None,
                concurrency: Some(20),
                connect_timeout_ms: None,
                probe_timeout_ms: None,
                http_body_preview_bytes: None,
                retries: None,
                probes: Some(vec!["mssql-prelogin".to_string(), "oracle-tns".to_string()]),
                builtin_probes: Some(true),
                tags: vec!["enterprise".to_string()],
            }],
            ..DataRegistry::default()
        };
        let config = ScanConfig::from_scan_args(&args, &registry).expect("config");
        assert_eq!(config.default_ports, vec![1433, 1521]);
        assert_eq!(config.tags, vec!["enterprise"]);
    }

    #[test]
    fn explicit_cli_values_override_recipe_defaults() {
        let args = ScanArgs {
            targets: vec!["127.0.0.1".to_string()],
            ports: "443".to_string(),
            transport: ScanTransport::Udp,
            concurrency: 32,
            all_states: false,
            quiet: false,
            progress: ProgressMode::Auto,
            interface: Some("en0".to_string()),
            connect_timeout_ms: Some(250),
            probe_timeout_ms: 900,
            http_body_preview_bytes: 2048,
            retries: 2,
            profile: None,
            data: None,
            recipe: Some("enterprise".to_string()),
            probes: vec!["dns-udp".to_string()],
            no_builtin_probes: true,
            format: crate::cli::OutputFormat::Human,
            output: None,
        };
        let sources = ScanArgSources {
            ports: true,
            transport: true,
            concurrency: true,
            interface: true,
            connect_timeout_ms: true,
            probe_timeout_ms: true,
            http_body_preview_bytes: true,
            retries: true,
            probes: true,
            no_builtin_probes: true,
            ..ScanArgSources::default()
        };
        let registry = DataRegistry {
            recipes: vec![ScanRecipe {
                name: "enterprise".to_string(),
                description: None,
                ports: Some("1433,1521".to_string()),
                transport: Some(ProfileTransport::Tcp),
                interface: Some("en9".to_string()),
                concurrency: Some(20),
                connect_timeout_ms: Some(1000),
                probe_timeout_ms: Some(1200),
                http_body_preview_bytes: Some(512),
                retries: Some(1),
                probes: Some(vec!["mssql-prelogin".to_string()]),
                builtin_probes: Some(true),
                tags: vec!["enterprise".to_string()],
            }],
            ..DataRegistry::default()
        };

        let config =
            ScanConfig::from_scan_args_with_sources(&args, &registry, &sources).expect("config");
        assert_eq!(config.transport, Transport::Udp);
        assert_eq!(config.default_ports, vec![443]);
        assert_eq!(config.concurrency, 32);
        assert_eq!(config.interface.as_deref(), Some("en0"));
        assert_eq!(config.connect_timeout, Duration::from_millis(250));
        assert_eq!(config.probe_timeout, Duration::from_millis(900));
        assert_eq!(config.http_body_preview_bytes, 2048);
        assert_eq!(config.retries, 2);
        assert_eq!(config.enabled_probes, vec!["dns-udp"]);
        assert!(!config.builtin_probes);
    }

    #[test]
    fn supports_quic_transport_from_cli() {
        let args = ScanArgs {
            targets: vec!["example.com".to_string()],
            ports: "443".to_string(),
            transport: ScanTransport::Quic,
            concurrency: 64,
            all_states: false,
            quiet: false,
            progress: ProgressMode::Auto,
            interface: None,
            connect_timeout_ms: None,
            probe_timeout_ms: 1500,
            http_body_preview_bytes: 4096,
            retries: 0,
            profile: None,
            data: None,
            recipe: None,
            probes: Vec::new(),
            no_builtin_probes: false,
            format: crate::cli::OutputFormat::Human,
            output: None,
        };

        let config = ScanConfig::from_scan_args(&args, &DataRegistry::default()).expect("config");
        assert_eq!(config.transport, Transport::Quic);
        assert_eq!(config.default_ports, vec![443]);
    }
}
