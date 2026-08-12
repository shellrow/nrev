use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use ipnet::IpNet;

use crate::{
    error::{NrevError, Result},
    model::Target,
};

pub const DEFAULT_MAX_TARGETS: usize = 65_536;
pub const DEFAULT_MAX_ENDPOINT_ASSIGNMENTS: usize = 1_000_000;
type ResolvedTargets = BTreeMap<(IpAddr, Option<String>), (Target, BTreeSet<u16>)>;

const TOP_100_PORTS_JSON: &str = include_str!("../resources/nrev-top-100-ports.json");
const TOP_1000_PORTS_JSON: &str = include_str!("../resources/nrev-top-1000-ports.json");
const WELL_KNOWN_PORTS_JSON: &str = include_str!("../resources/nrev-well-known-ports.json");

fn top_100_ports() -> &'static Vec<u16> {
    static TOP_100_PORTS: OnceLock<Vec<u16>> = OnceLock::new();
    TOP_100_PORTS.get_or_init(|| {
        serde_json::from_str(TOP_100_PORTS_JSON).expect("embedded top-100 ports must be valid")
    })
}

fn top_1000_ports() -> &'static Vec<u16> {
    static TOP_1000_PORTS: OnceLock<Vec<u16>> = OnceLock::new();
    TOP_1000_PORTS.get_or_init(|| {
        serde_json::from_str(TOP_1000_PORTS_JSON).expect("embedded top-1000 ports must be valid")
    })
}

fn well_known_ports() -> &'static Vec<u16> {
    static WELL_KNOWN_PORTS: OnceLock<Vec<u16>> = OnceLock::new();
    WELL_KNOWN_PORTS.get_or_init(|| {
        serde_json::from_str(WELL_KNOWN_PORTS_JSON)
            .expect("embedded well-known ports must be valid")
    })
}

pub struct TargetResolver {
    default_ports: Vec<u16>,
    max_targets: usize,
    max_endpoint_assignments: usize,
}

impl TargetResolver {
    pub fn new(default_ports: Vec<u16>) -> Self {
        Self {
            default_ports,
            max_targets: DEFAULT_MAX_TARGETS,
            max_endpoint_assignments: DEFAULT_MAX_ENDPOINT_ASSIGNMENTS,
        }
    }

    pub fn with_max_targets(mut self, max_targets: usize) -> Self {
        self.max_targets = max_targets.max(1);
        self
    }

    pub fn with_max_endpoint_assignments(mut self, max_endpoint_assignments: usize) -> Self {
        self.max_endpoint_assignments = max_endpoint_assignments.max(1);
        self
    }

    pub fn resolve(&self, inputs: &[String]) -> Result<Vec<(Target, Vec<u16>)>> {
        let mut seen_files = HashSet::new();
        let tokens = collect_target_tokens(inputs, &mut seen_files)?;
        let mut resolved = ResolvedTargets::new();
        let mut endpoint_assignments = 0usize;
        for input in tokens {
            if let Some((host, port)) = split_host_port(&input) {
                for target in resolve_host(&host)? {
                    insert_target(
                        &mut resolved,
                        target_with_original(target, &input),
                        &[port],
                        &input,
                        self.max_targets,
                        &mut endpoint_assignments,
                        self.max_endpoint_assignments,
                    )?;
                }
                continue;
            }

            if let Ok(network) = input.parse::<IpNet>() {
                match network {
                    IpNet::V4(network) => {
                        for ip in network.hosts() {
                            insert_target(
                                &mut resolved,
                                Target {
                                    original: input.clone(),
                                    hostname: None,
                                    address: IpAddr::V4(ip),
                                },
                                &self.default_ports,
                                &input,
                                self.max_targets,
                                &mut endpoint_assignments,
                                self.max_endpoint_assignments,
                            )?;
                        }
                    }
                    IpNet::V6(network) => {
                        for ip in network.hosts() {
                            insert_target(
                                &mut resolved,
                                Target {
                                    original: input.clone(),
                                    hostname: None,
                                    address: IpAddr::V6(ip),
                                },
                                &self.default_ports,
                                &input,
                                self.max_targets,
                                &mut endpoint_assignments,
                                self.max_endpoint_assignments,
                            )?;
                        }
                    }
                }
                continue;
            }

            for target in resolve_host(&input)? {
                insert_target(
                    &mut resolved,
                    target_with_original(target, &input),
                    &self.default_ports,
                    &input,
                    self.max_targets,
                    &mut endpoint_assignments,
                    self.max_endpoint_assignments,
                )?;
            }
        }

        if resolved.is_empty() {
            return Err(NrevError::ResolutionFailed(inputs.join(",")));
        }

        Ok(resolved
            .into_values()
            .map(|(target, ports)| (target, ports.into_iter().collect()))
            .collect())
    }
}

fn insert_target(
    targets: &mut ResolvedTargets,
    target: Target,
    ports: &[u16],
    input: &str,
    max_targets: usize,
    endpoint_assignments: &mut usize,
    max_endpoint_assignments: usize,
) -> Result<()> {
    let key = (target.address, target.hostname.clone());
    if !targets.contains_key(&key) && targets.len() >= max_targets {
        return Err(NrevError::TargetLimitExceeded {
            input: input.to_string(),
            limit: max_targets,
        });
    }
    let additional_ports = targets
        .get(&key)
        .map(|(_, existing)| ports.iter().filter(|port| !existing.contains(port)).count())
        .unwrap_or_else(|| ports.iter().copied().collect::<BTreeSet<_>>().len());
    if endpoint_assignments.saturating_add(additional_ports) > max_endpoint_assignments {
        return Err(NrevError::EndpointLimitExceeded {
            input: input.to_string(),
            limit: max_endpoint_assignments,
        });
    }
    targets
        .entry(key)
        .or_insert_with(|| (target, BTreeSet::new()))
        .1
        .extend(ports.iter().copied());
    *endpoint_assignments += additional_ports;
    Ok(())
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

fn target_with_original(mut target: Target, original: &str) -> Target {
    target.original = original.to_string();
    target
}

fn resolve_host(input: &str) -> Result<Vec<Target>> {
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(vec![Target {
            original: input.to_string(),
            hostname: None,
            address: ip,
        }]);
    }

    let socket = format!("{input}:0");
    let addrs: Vec<SocketAddr> = socket
        .to_socket_addrs()
        .map_err(|_| NrevError::ResolutionFailed(input.to_string()))?
        .collect();

    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();
    for addr in addrs {
        if seen.insert(addr.ip()) {
            targets.push(Target {
                original: input.to_string(),
                hostname: Some(input.to_string()),
                address: addr.ip(),
            });
        }
    }
    Ok(targets)
}

pub fn parse_ports(input: &str) -> Result<Vec<u16>> {
    if input == "top-100" {
        return Ok(top_100_ports().clone());
    }

    if input == "top-1000" {
        return Ok(top_1000_ports().clone());
    }

    if input == "well-known" {
        return Ok(well_known_ports().clone());
    }

    let mut set = BTreeSet::new();
    for chunk in input.split(',').filter(|part| !part.trim().is_empty()) {
        if let Some((start, end)) = chunk.split_once('-') {
            let start: u16 = start
                .trim()
                .parse()
                .map_err(|_| NrevError::InvalidPortSpec(input.to_string()))?;
            let end: u16 = end
                .trim()
                .parse()
                .map_err(|_| NrevError::InvalidPortSpec(input.to_string()))?;
            if start > end {
                return Err(NrevError::InvalidPortSpec(input.to_string()));
            }
            for port in start..=end {
                set.insert(port);
            }
        } else {
            let port: u16 = chunk
                .trim()
                .parse()
                .map_err(|_| NrevError::InvalidPortSpec(input.to_string()))?;
            set.insert(port);
        }
    }

    if set.is_empty() {
        return Err(NrevError::InvalidPortSpec(input.to_string()));
    }

    Ok(set.into_iter().collect())
}

fn split_host_port(input: &str) -> Option<(String, u16)> {
    if input.matches(':').count() != 1 {
        return None;
    }

    let (host, port) = input.split_once(':')?;
    let port = port.parse().ok()?;
    Some((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn parses_port_ranges() {
        assert_eq!(
            parse_ports("80,443,8000-8002").expect("ports"),
            vec![80, 443, 8000, 8001, 8002]
        );
    }

    #[test]
    fn parses_top_100() {
        let ports = parse_ports("top-100").expect("top-100");
        assert_eq!(ports.len(), 100);
        assert_eq!(ports[0], 21);
        assert!(ports.contains(&443));
        assert!(ports.contains(&3389));
        assert!(!ports.contains(&1));
    }

    #[test]
    fn parses_top_1000() {
        let ports = parse_ports("top-1000").expect("top-1000");
        assert_eq!(ports.len(), 1000);
        assert_eq!(ports[0], 11);
        assert!(ports.contains(&80));
        assert!(ports.contains(&1433));
        assert!(ports.contains(&3389));
    }

    #[test]
    fn parses_well_known_ports() {
        let ports = parse_ports("well-known").expect("well-known");
        assert!(ports.contains(&1));
        assert!(ports.contains(&22));
        assert!(ports.contains(&53));
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
    }

    #[test]
    fn resolves_cidr() {
        let targets = TargetResolver::new(vec![80])
            .resolve(&["192.168.1.0/30".to_string()])
            .expect("targets");
        let addresses: Vec<IpAddr> = targets
            .into_iter()
            .map(|(target, _)| target.address)
            .collect();
        assert_eq!(
            addresses,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))
            ]
        );
    }

    #[test]
    fn merges_duplicate_ip_targets_and_ports() {
        let targets = TargetResolver::new(vec![80])
            .resolve(&[
                "192.0.2.1".to_string(),
                "192.0.2.1:443".to_string(),
                "192.0.2.0/30".to_string(),
            ])
            .expect("targets");

        assert_eq!(targets.len(), 2);
        let (_, ports) = targets
            .iter()
            .find(|(target, _)| target.address == Ipv4Addr::new(192, 0, 2, 1))
            .expect("deduplicated target");
        assert_eq!(ports, &vec![80, 443]);
    }

    #[test]
    fn rejects_target_expansion_above_limit() {
        let error = TargetResolver::new(vec![80])
            .with_max_targets(2)
            .resolve(&["192.0.2.0/29".to_string()])
            .expect_err("target limit");
        assert!(matches!(
            error,
            NrevError::TargetLimitExceeded { limit: 2, .. }
        ));
    }

    #[test]
    fn rejects_endpoint_expansion_above_limit() {
        let error = TargetResolver::new(vec![80, 443])
            .with_max_endpoint_assignments(2)
            .resolve(&["192.0.2.1".to_string(), "192.0.2.2".to_string()])
            .expect_err("endpoint limit");
        assert!(matches!(
            error,
            NrevError::EndpointLimitExceeded { limit: 2, .. }
        ));
    }

    #[test]
    fn resolves_targets_from_file() {
        let path = std::env::temp_dir().join("nrev-port-targets.txt");
        fs::write(&path, "127.0.0.1\n192.168.1.0/30\n").expect("write target file");

        let targets = TargetResolver::new(vec![80])
            .resolve(&[format!("@{}", path.display())])
            .expect("targets");

        assert!(targets.iter().any(|(target, ports)| target.address
            == "127.0.0.1".parse::<IpAddr>().unwrap()
            && ports == &vec![80]));
        assert!(
            targets
                .iter()
                .any(|(target, _)| target.address == "192.168.1.1".parse::<IpAddr>().unwrap())
        );
        assert!(
            targets
                .iter()
                .any(|(target, _)| target.address == "192.168.1.2".parse::<IpAddr>().unwrap())
        );

        fs::remove_file(path).ok();
    }
}
