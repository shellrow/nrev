use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    net::{IpAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use chrono::Utc;
use futures::{StreamExt, stream};
use ipnet::IpNet;
use rand::seq::SliceRandom;

use crate::{
    config::HostConfig,
    model::{
        HostDiscoveryMethod, HostObservation, HostResult, HostScanMetadata, HostScanReport, Target,
    },
    transport::{icmp_host_probe, icmp_scan_targets, tcp_host_probe, udp_host_probe},
};

pub struct HostDiscoveryExecution {
    pub report: HostScanReport,
    pub discovery_time: Duration,
    pub reachable_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum HostScanEvent {
    DiscoveryStarted {
        target_count: usize,
        method: HostDiscoveryMethod,
    },
    DiscoveryCompleted {
        elapsed: Duration,
    },
}

pub struct HostScanner {
    config: HostConfig,
}

impl HostScanner {
    pub fn new(config: HostConfig) -> Self {
        Self { config }
    }

    pub async fn discover(&self, targets: Vec<Target>) -> Result<HostDiscoveryExecution> {
        self.discover_with_progress(targets, |_| {}).await
    }

    pub async fn discover_with_progress<F>(
        &self,
        mut targets: Vec<Target>,
        mut on_event: F,
    ) -> Result<HostDiscoveryExecution>
    where
        F: FnMut(HostScanEvent),
    {
        if !self.config.ordered {
            let mut rng = rand::rng();
            targets.shuffle(&mut rng);
        }

        on_event(HostScanEvent::DiscoveryStarted {
            target_count: targets.len(),
            method: self.config.method,
        });
        let started = std::time::Instant::now();
        let results = if self.config.method == HostDiscoveryMethod::Icmp {
            discover_targets_icmp(targets, &self.config).await
        } else {
            let concurrency = effective_host_concurrency(&self.config);
            stream::iter(targets.into_iter())
                .map(|target| {
                    let config = self.config.clone();
                    async move { discover_target(target, &config).await }
                })
                .buffer_unordered(concurrency)
                .collect::<Vec<_>>()
                .await
        };
        let discovery_time = started.elapsed();
        on_event(HostScanEvent::DiscoveryCompleted {
            elapsed: discovery_time,
        });

        let reachable_count = results.iter().filter(|target| target.reachable).count();
        Ok(HostDiscoveryExecution {
            report: HostScanReport {
                metadata: HostScanMetadata {
                    schema_version: crate::model::REPORT_SCHEMA_VERSION,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    method: self.config.method,
                    generated_at: Utc::now(),
                    timings: None,
                },
                targets: results,
            },
            discovery_time,
            reachable_count,
        })
    }
}

fn effective_host_concurrency(config: &HostConfig) -> usize {
    match config.method {
        HostDiscoveryMethod::Icmp => 1,
        HostDiscoveryMethod::Udp | HostDiscoveryMethod::Tcp => config.concurrency.max(1),
    }
}

async fn discover_targets_icmp(targets: Vec<Target>, config: &HostConfig) -> Vec<HostResult> {
    let addresses = targets
        .iter()
        .map(|target| target.address)
        .collect::<Vec<_>>();
    match icmp_scan_targets(&addresses, config.timeout, config.interface.as_deref()).await {
        Ok(observations) => targets
            .into_iter()
            .map(|target| match observations.get(&target.address).cloned() {
                Some(observation) => HostResult {
                    target,
                    reachable: true,
                    observations: vec![observation],
                    errors: Vec::new(),
                },
                None => HostResult {
                    target,
                    reachable: false,
                    observations: Vec::new(),
                    errors: vec!["icmp probe timed out".to_string()],
                },
            })
            .collect(),
        Err(error) => targets
            .into_iter()
            .map(|target| HostResult {
                target,
                reachable: false,
                observations: Vec::new(),
                errors: vec![error.to_string()],
            })
            .collect(),
    }
}

async fn discover_target(target: Target, config: &HostConfig) -> HostResult {
    let observations = match config.method {
        HostDiscoveryMethod::Icmp => {
            match icmp_host_probe(target.address, config.timeout, config.interface.as_deref()).await
            {
                Ok(observation) => vec![observation],
                Err(error) => {
                    return HostResult {
                        target,
                        reachable: false,
                        observations: Vec::new(),
                        errors: vec![error.to_string()],
                    };
                }
            }
        }
        HostDiscoveryMethod::Udp => collect_udp_observations(target.address, config).await,
        HostDiscoveryMethod::Tcp => collect_tcp_observations(target.address, config).await,
    };

    if observations.is_empty() {
        HostResult {
            target,
            reachable: false,
            observations: Vec::new(),
            errors: vec![format!("{} probe timed out", config.method.as_str())],
        }
    } else {
        HostResult {
            target,
            reachable: true,
            observations,
            errors: Vec::new(),
        }
    }
}

async fn collect_tcp_observations(address: IpAddr, config: &HostConfig) -> Vec<HostObservation> {
    let results = stream::iter(config.ports.iter().copied())
        .map(|port| async move { tcp_host_probe(address, &[port], config.timeout).await.ok() })
        .buffer_unordered(config.ports.len().clamp(1, 16))
        .collect::<Vec<_>>()
        .await;

    results.into_iter().flatten().collect()
}

async fn collect_udp_observations(address: IpAddr, config: &HostConfig) -> Vec<HostObservation> {
    let results = stream::iter(config.ports.iter().copied())
        .map(|port| async move {
            udp_host_probe(
                address,
                &[port],
                config.timeout,
                config.interface.as_deref(),
            )
            .await
            .ok()
        })
        .buffer_unordered(config.ports.len().clamp(1, 16))
        .collect::<Vec<_>>()
        .await;

    results.into_iter().flatten().collect()
}

#[derive(Debug)]
enum TargetSpec {
    Network(IpNet),
    Address(IpAddr),
    Hostname(String),
}

impl TargetSpec {
    fn parse(raw: &str) -> Self {
        if let Ok(net) = raw.parse::<IpNet>() {
            return Self::Network(net);
        }
        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Self::Address(ip);
        }
        Self::Hostname(raw.to_string())
    }
}

fn canonicalize_for_seen(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn collect_target_tokens(
    inputs: &[String],
    seen_files: &mut HashSet<PathBuf>,
) -> Result<Vec<String>> {
    let mut tokens = Vec::new();

    for raw in inputs {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }

        let (is_file_hint, path_str) = if let Some(stripped) = value.strip_prefix('@') {
            (true, stripped)
        } else {
            (false, value)
        };

        let path = Path::new(path_str);
        if is_file_hint || path.is_file() {
            let canonical = canonicalize_for_seen(path);
            if !seen_files.insert(canonical) {
                continue;
            }

            let text = fs::read_to_string(path)?;
            let nested_inputs = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(ToString::to_string)
                .collect::<Vec<_>>();

            let mut nested = collect_target_tokens(&nested_inputs, seen_files)?;
            tokens.append(&mut nested);
            continue;
        }

        tokens.push(value.to_string());
    }

    Ok(tokens)
}

pub fn resolve_host_targets(inputs: &[String]) -> Result<Vec<Target>> {
    resolve_host_targets_with_limit(inputs, crate::target::DEFAULT_MAX_TARGETS)
}

pub fn resolve_host_targets_with_limit(
    inputs: &[String],
    max_targets: usize,
) -> Result<Vec<Target>> {
    let mut seen_files = HashSet::new();
    let tokens = collect_target_tokens(inputs, &mut seen_files)?;

    let mut by_ip = BTreeMap::new();
    for token in tokens {
        match TargetSpec::parse(&token) {
            TargetSpec::Network(net) => match net {
                IpNet::V4(net) => {
                    for ip in net.hosts() {
                        by_ip.entry(IpAddr::V4(ip)).or_insert(Target {
                            original: token.clone(),
                            hostname: None,
                            address: IpAddr::V4(ip),
                        });
                        ensure_target_limit(&by_ip, &token, max_targets)?;
                    }
                }
                IpNet::V6(net) => {
                    for ip in net.hosts() {
                        by_ip.entry(IpAddr::V6(ip)).or_insert(Target {
                            original: token.clone(),
                            hostname: None,
                            address: IpAddr::V6(ip),
                        });
                        ensure_target_limit(&by_ip, &token, max_targets)?;
                    }
                }
            },
            TargetSpec::Address(ip) => {
                by_ip.entry(ip).or_insert(Target {
                    original: token.clone(),
                    hostname: None,
                    address: ip,
                });
                ensure_target_limit(&by_ip, &token, max_targets)?;
            }
            TargetSpec::Hostname(name) => {
                let socket = format!("{name}:0");
                let mut seen = BTreeSet::new();
                for addr in socket.to_socket_addrs()? {
                    if seen.insert(addr.ip()) {
                        by_ip.entry(addr.ip()).or_insert(Target {
                            original: name.clone(),
                            hostname: Some(name.clone()),
                            address: addr.ip(),
                        });
                        ensure_target_limit(&by_ip, &name, max_targets)?;
                    }
                }
            }
        }
    }

    Ok(by_ip.into_values().collect())
}

fn ensure_target_limit(
    targets: &BTreeMap<IpAddr, Target>,
    input: &str,
    max_targets: usize,
) -> Result<()> {
    if targets.len() > max_targets.max(1) {
        return Err(crate::error::NrevError::TargetLimitExceeded {
            input: input.to_string(),
            limit: max_targets.max(1),
        }
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use tokio::net::{TcpListener, UdpSocket};

    #[test]
    fn resolves_targets_from_file_and_cidr() {
        let path = std::env::temp_dir().join("nrev-host-targets.txt");
        fs::write(&path, "127.0.0.1\n192.168.0.0/30\n").expect("write target file");
        let targets = resolve_host_targets(&[format!("@{}", path.display())]).expect("targets");
        assert!(
            targets
                .iter()
                .any(|target| target.address == "127.0.0.1".parse::<IpAddr>().unwrap())
        );
        assert!(
            targets
                .iter()
                .any(|target| target.address == "192.168.0.1".parse::<IpAddr>().unwrap())
        );
        assert!(
            targets
                .iter()
                .any(|target| target.address == "192.168.0.2".parse::<IpAddr>().unwrap())
        );
        fs::remove_file(path).ok();
    }

    #[test]
    fn rejects_host_expansion_above_limit() {
        let error = resolve_host_targets_with_limit(&["192.0.2.0/29".to_string()], 2)
            .expect_err("target limit");
        assert!(error.to_string().contains("safety limit of 2"));
    }

    #[tokio::test]
    async fn tcp_host_probe_marks_listener_as_reachable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let observation = tcp_host_probe(
            "127.0.0.1".parse().expect("ip"),
            &[port],
            Duration::from_millis(200),
        )
        .await
        .expect("reachable");
        assert_eq!(observation.method, HostDiscoveryMethod::Tcp);
        assert_eq!(observation.port, Some(port));
        task.abort();
    }

    #[tokio::test]
    async fn udp_host_probe_marks_udp_response_as_reachable() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp listener");
        let port = socket.local_addr().expect("addr").port();
        let task = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let (len, peer) = socket.recv_from(&mut buf).await.expect("recv");
            let _ = socket.send_to(&buf[..len], peer).await;
        });

        let observation = udp_host_probe(
            "127.0.0.1".parse().expect("ip"),
            &[port],
            Duration::from_millis(200),
            None,
        )
        .await
        .expect("reachable");
        assert_eq!(observation.method, HostDiscoveryMethod::Udp);
        assert_eq!(observation.port, Some(port));
        task.abort();
    }
}
