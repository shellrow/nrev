use std::path::Path;

use termtree::Tree;

use crate::config::ScanRecipe;
use crate::model::{
    EndpointResult, EndpointState, HostResult, HostScanReport, ProbeObservation, ScanReport,
    TlsObservation,
};
use crate::probes::{BuiltinProbeMetadata, ExternalProbeDefinition};

pub fn render_human_scan_report(report: &ScanReport, show_all_states: bool) -> String {
    let mut root = Tree::new("Scan report(s)".to_string());
    let mut rendered_targets = 0usize;

    let mut groups = std::collections::BTreeMap::<String, Vec<&crate::model::TargetReport>>::new();
    for target in &report.targets {
        groups
            .entry(target.target.original.clone())
            .or_default()
            .push(target);
    }

    for (group_label, mut targets) in groups {
        targets.sort_by_key(|target| target.target.address);
        let needs_grouping = targets.len() > 1;

        if needs_grouping {
            let mut group = Tree::new(group_label);
            for target in targets {
                if let Some(target_tree) = render_scan_target_tree(target, show_all_states, true) {
                    group.push(target_tree);
                }
            }

            if group.leaves.is_empty() {
                if show_all_states {
                    group.push(Tree::new("no endpoints".to_string()));
                } else {
                    continue;
                }
            }

            root.push(group);
            rendered_targets += 1;
        } else if let Some(target) = targets.first()
            && let Some(target_tree) = render_scan_target_tree(target, show_all_states, false)
        {
            root.push(target_tree);
            rendered_targets += 1;
        }
    }

    if rendered_targets == 0 {
        root.push(Tree::new(if show_all_states {
            "no endpoints".to_string()
        } else {
            "no open ports".to_string()
        }));
    }

    format!("{root}\n")
}

pub fn write_json_report(report: &ScanReport, path: &Path) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

pub fn render_human_host_report(report: &HostScanReport, show_all_hosts: bool) -> String {
    let mut root = Tree::new("Host report(s)".to_string());

    let visible_targets = report
        .targets
        .iter()
        .filter(|target| show_all_hosts || target.reachable)
        .collect::<Vec<_>>();

    let mut groups = std::collections::BTreeMap::<String, Vec<&HostResult>>::new();
    for target in visible_targets {
        groups
            .entry(target.target.original.clone())
            .or_default()
            .push(target);
    }

    for (group_label, targets) in groups {
        let mut targets = targets;
        targets.sort_by_key(|target| target.target.address);
        let needs_grouping = targets.len() > 1
            || targets
                .iter()
                .any(|target| target.target.original != target.target.address.to_string());
        if needs_grouping {
            let mut group = Tree::new(format!("{group_label} ({})", targets.len()));
            for target in targets {
                group.push(render_host_tree(target));
            }
            root.push(group);
        } else if let Some(target) = targets.first() {
            root.push(render_host_tree(target));
        }
    }

    if root.leaves.is_empty() {
        root.push(Tree::new(if show_all_hosts {
            "no hosts".to_string()
        } else {
            "no reachable hosts".to_string()
        }));
    }

    format!("{root}\n")
}

pub fn write_json_host_report(report: &HostScanReport, path: &Path) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

pub fn render_human_recipe_catalog(recipes: &[ScanRecipe]) -> String {
    let mut root = Tree::new("Recipe(s)".to_string());

    for recipe in recipes {
        let mut node = Tree::new(recipe.name.clone());
        if let Some(description) = &recipe.description {
            node.push(Tree::new(format!("description: {description}")));
        }
        if let Some(transport) = recipe.transport {
            node.push(Tree::new(format!(
                "transport: {}",
                render_recipe_transport(transport)
            )));
        }
        if let Some(ports) = &recipe.ports {
            node.push(Tree::new(format!("ports: {ports}")));
        }
        if let Some(concurrency) = recipe.concurrency {
            node.push(Tree::new(format!("concurrency: {concurrency}")));
        }
        if let Some(timeout_ms) = recipe.connect_timeout_ms {
            node.push(Tree::new(format!("connect-timeout-ms: {timeout_ms}")));
        }
        if let Some(timeout_ms) = recipe.probe_timeout_ms {
            node.push(Tree::new(format!("probe-timeout-ms: {timeout_ms}")));
        }
        if !recipe.tags.is_empty() {
            node.push(Tree::new(format!("tags: {}", recipe.tags.join(", "))));
        }
        if let Some(probes) = &recipe.probes
            && !probes.is_empty()
        {
            node.push(Tree::new(format!("probes: {}", probes.join(", "))));
        }
        root.push(node);
    }

    if root.leaves.is_empty() {
        root.push(Tree::new("no recipes".to_string()));
    }

    format!("{root}\n")
}

pub fn render_human_probe_catalog(
    probes: &[BuiltinProbeMetadata],
    external_probes: &[ExternalProbeDefinition],
) -> String {
    let mut root = Tree::new("Probe(s)".to_string());
    let mut grouped = std::collections::BTreeMap::<&str, Vec<&BuiltinProbeMetadata>>::new();

    for probe in probes {
        grouped.entry(probe.transport).or_default().push(probe);
    }

    for (transport, probes) in grouped {
        let mut transport_node = Tree::new(format!("{transport} ({})", probes.len()));
        for probe in probes {
            let mut probe_node = Tree::new(probe.id.to_string());
            probe_node.push(Tree::new(format!("summary: {}", probe.summary)));
            probe_node.push(Tree::new(format!(
                "ports: {}",
                probe
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
            transport_node.push(probe_node);
        }
        root.push(transport_node);
    }

    if !external_probes.is_empty() {
        let mut external_node = Tree::new(format!("external ({})", external_probes.len()));
        for probe in external_probes {
            let mut probe_node = Tree::new(probe.id.clone());
            probe_node.push(Tree::new(format!("transport: {}", probe.transport)));
            if !probe.ports.is_empty() {
                probe_node.push(Tree::new(format!(
                    "ports: {}",
                    probe
                        .ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            if !probe.expect.is_empty() {
                probe_node.push(Tree::new(format!("expect: {}", probe.expect.join(", "))));
            }
            external_node.push(probe_node);
        }
        root.push(external_node);
    }

    if root.leaves.is_empty() {
        root.push(Tree::new("no probes".to_string()));
    }

    format!("{root}\n")
}

fn render_endpoint_tree(endpoint: &EndpointResult) -> Tree<String> {
    let mut node = Tree::new(format!(
        "{}/{}",
        endpoint.port,
        endpoint.transport.as_str().to_uppercase()
    ));
    node.push(Tree::new(format!(
        "state: {}",
        state_label(&endpoint.state)
    )));
    if endpoint.latency.as_millis() > 0 {
        node.push(Tree::new(format!(
            "latency: {}ms",
            endpoint.latency.as_millis()
        )));
    }
    if let Some(service) = primary_service(endpoint) {
        node.push(Tree::new(format!("service: {service}")));
    }
    if let Some(server) = primary_server(endpoint) {
        node.push(Tree::new(format!("server: {server}")));
    }
    for (label, key) in [
        ("X-Powered-By", "x-powered-by"),
        ("Via", "via"),
        ("X-Cache", "x-cache"),
        ("CF-Cache-Status", "cf-cache-status"),
        ("Alt-Svc", "alt-svc"),
        ("Set-Cookie", "set-cookie"),
        ("Access-Control-Allow-Origin", "access-control-allow-origin"),
        (
            "Access-Control-Allow-Credentials",
            "access-control-allow-credentials",
        ),
        ("title", "title"),
        ("description", "description"),
        ("generator", "generator"),
    ] {
        if let Some(value) = primary_evidence(endpoint, key) {
            node.push(Tree::new(format!("{label}: {}", truncate(&value, 140))));
        }
    }
    if let Some(banner) = primary_banner(endpoint) {
        node.push(Tree::new(format!("banner: {}", truncate(&banner, 140))));
    }
    if let Some(tls) = primary_tls(endpoint) {
        node.push(Tree::new(format!("tls: {tls}")));
    }
    node
}

fn render_scan_target_tree(
    target: &crate::model::TargetReport,
    show_all_states: bool,
    grouped: bool,
) -> Option<Tree<String>> {
    let mut target_tree = Tree::new(render_target_label(target, grouped));
    let visible_endpoints = target
        .endpoints
        .values()
        .filter(|endpoint| show_all_states || endpoint.state == EndpointState::Open)
        .collect::<Vec<_>>();

    for endpoint in visible_endpoints {
        target_tree.push(render_endpoint_tree(endpoint));
    }

    if let Some(fingerprint) = &target.fingerprint {
        target_tree
            .leaves
            .insert(0, render_target_fingerprint_tree(fingerprint));
    }

    if !target.os_guesses.is_empty() {
        let insert_at = usize::from(target.fingerprint.is_some());
        target_tree
            .leaves
            .insert(insert_at, render_target_os_guess_tree(&target.os_guesses));
    }

    if target_tree.leaves.is_empty() {
        if show_all_states {
            target_tree.push(Tree::new("no endpoints".to_string()));
        } else {
            return None;
        }
    }

    Some(target_tree)
}

fn render_target_fingerprint_tree(fingerprint: &crate::model::TcpIpObservation) -> Tree<String> {
    let mut node = Tree::new("fingerprint".to_string());
    node.push(Tree::new(format!(
        "syn_ack_seen: {}",
        fingerprint.syn_ack_seen
    )));
    node.push(Tree::new(format!("rst_seen: {}", fingerprint.rst_seen)));

    if let Some(ttl_hint) = fingerprint.ttl_hint {
        node.push(Tree::new(format!("ttl: {ttl_hint}")));
    }
    if let Some(ttl_class) = fingerprint.ttl_class {
        node.push(Tree::new(format!("ttl_class: {ttl_class}")));
    }
    if let Some(window_size) = fingerprint.window_size {
        node.push(Tree::new(format!("window_size: {window_size}")));
    }
    if let Some(order) = &fingerprint.tcp_option_order {
        node.push(Tree::new(format!("tcp_option_order: {order}")));
    }
    if let Some(mss) = fingerprint.mss {
        node.push(Tree::new(format!("mss: {mss}")));
    }
    if let Some(window_scale) = fingerprint.window_scale {
        node.push(Tree::new(format!("window_scale: {window_scale}")));
    }
    if let Some(sack_permitted) = fingerprint.sack_permitted {
        node.push(Tree::new(format!("sack_permitted: {sack_permitted}")));
    }
    if let Some(timestamps) = fingerprint.timestamps {
        node.push(Tree::new(format!("timestamps: {timestamps}")));
    }

    node
}

fn render_target_os_guess_tree(guesses: &[crate::model::FingerprintMatch]) -> Tree<String> {
    let mut node = Tree::new("os-guess".to_string());
    for guess in guesses {
        node.push(Tree::new(guess.label.clone()));
    }
    node
}

fn render_target_label(target: &crate::model::TargetReport, grouped: bool) -> String {
    let address = target.target.address.to_string();
    if grouped {
        return address;
    }

    match &target.target.hostname {
        Some(hostname) if hostname != &address => format!("{hostname} ({address})"),
        _ if target.target.original != address => format!("{} ({address})", target.target.original),
        _ => address,
    }
}

fn render_host_tree(target: &HostResult) -> Tree<String> {
    let mut node = Tree::new(render_host_target_label(target));
    node.push(Tree::new(format!(
        "state: {}",
        if target.reachable {
            "Reachable"
        } else {
            "Unreachable"
        }
    )));

    for observation in &target.observations {
        let mut parts = vec![
            observation.method.as_str().to_string(),
            observation.outcome.clone(),
        ];
        if let Some(port) = observation.port {
            parts.push(format!("port={port}"));
        }
        if let Some(latency) = observation.latency {
            parts.push(format!("latency={}ms", latency.as_millis()));
        }
        if let Some(ttl_hint) = observation.ttl_hint {
            parts.push(format!("ttl={ttl_hint}"));
        }
        if let Some(mac_address) = &observation.mac_address {
            parts.push(format!("mac={mac_address}"));
        }
        node.push(Tree::new(parts.join(" ")));
    }

    for error in &target.errors {
        node.push(Tree::new(format!("error: {error}")));
    }

    node
}

fn render_host_target_label(target: &HostResult) -> String {
    let address = target.target.address.to_string();
    target.target.hostname.clone().unwrap_or(address)
}

fn render_recipe_transport(transport: crate::config::ProfileTransport) -> &'static str {
    match transport {
        crate::config::ProfileTransport::Tcp => "tcp",
        crate::config::ProfileTransport::Udp => "udp",
        crate::config::ProfileTransport::Syn => "syn",
        crate::config::ProfileTransport::Quic => "quic",
    }
}

fn primary_service(endpoint: &EndpointResult) -> Option<String> {
    endpoint.observations.iter().find_map(|observation| {
        observation
            .service_hint
            .as_ref()
            .map(|service| service.name.clone())
    })
}

fn primary_server(endpoint: &EndpointResult) -> Option<String> {
    primary_evidence(endpoint, "server")
}

fn primary_evidence(endpoint: &EndpointResult, key: &str) -> Option<String> {
    endpoint
        .observations
        .iter()
        .find_map(|observation| evidence_value(observation, key).map(|value| value.to_string()))
}

fn primary_banner(endpoint: &EndpointResult) -> Option<String> {
    endpoint.observations.iter().find_map(|observation| {
        observation
            .banner
            .as_ref()
            .map(|banner| banner.normalized.trim().to_string())
            .filter(|banner| !banner.is_empty())
    })
}

fn primary_tls(endpoint: &EndpointResult) -> Option<String> {
    endpoint
        .observations
        .iter()
        .find_map(|observation| observation.tls.as_ref().map(summarize_tls))
}

fn state_label(state: &EndpointState) -> &'static str {
    match state {
        EndpointState::Open => "Open",
        EndpointState::Closed => "Closed",
        EndpointState::Filtered => "Filtered",
        EndpointState::Unreachable => "Unreachable",
        EndpointState::Error => "Error",
    }
}

fn summarize_tls(tls: &TlsObservation) -> String {
    let mut parts = Vec::new();
    if let Some(protocol) = &tls.negotiated_protocol {
        parts.push(protocol.clone());
    }
    if let Some(cipher) = &tls.cipher_suite {
        parts.push(cipher.clone());
    }
    if let Some(subject) = tls.certificate_subjects.first() {
        parts.push(format!("subject={}", truncate(subject, 48)));
    }
    if parts.is_empty() {
        "observed".to_string()
    } else {
        parts.join(", ")
    }
}

fn truncate(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        value.to_string()
    } else {
        let mut truncated = value.chars().take(limit).collect::<String>();
        truncated.push_str("...");
        truncated
    }
}

fn evidence_value<'a>(observation: &'a ProbeObservation, key: &str) -> Option<&'a str> {
    observation
        .evidence
        .iter()
        .find(|item| item.key == key)
        .map(|item| item.value.as_str())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::model::{
        Banner, Confidence, EndpointResult, HostDiscoveryMethod, HostObservation, HostResult,
        HostScanMetadata, HostScanReport, ProbeObservation, ScanMetadata, ScanReport, ServiceHint,
        Target, TargetReport, Transport,
    };
    use std::{collections::BTreeMap, net::IpAddr, str::FromStr, time::Duration};

    fn sample_report() -> ScanReport {
        let mut endpoints = BTreeMap::new();
        endpoints.insert(
            22,
            EndpointResult {
                port: 22,
                transport: Transport::Syn,
                state: EndpointState::Open,
                latency: Duration::from_millis(10),
                observations: vec![ProbeObservation {
                    probe_id: "ssh".to_string(),
                    service_hint: Some(ServiceHint {
                        name: "ssh".to_string(),
                        confidence: Confidence::High,
                    }),
                    banner: Some(Banner {
                        raw: "SSH-2.0-test".to_string(),
                        normalized: "SSH-2.0-test".to_string(),
                    }),
                    tls: None,
                    tags: Vec::new(),
                    evidence: Vec::new(),
                    confidence: Confidence::High,
                }],
                fingerprint: None,
                fingerprint_matches: Vec::new(),
                errors: Vec::new(),
            },
        );
        endpoints.insert(
            80,
            EndpointResult {
                port: 80,
                transport: Transport::Tcp,
                state: EndpointState::Filtered,
                latency: Duration::default(),
                observations: Vec::new(),
                fingerprint: None,
                fingerprint_matches: Vec::new(),
                errors: Vec::new(),
            },
        );
        ScanReport {
            metadata: ScanMetadata {
                version: "test".to_string(),
                profile: "default".to_string(),
                recipe: None,
                tags: Vec::new(),
                generated_at: Utc::now(),
                timings: None,
            },
            targets: vec![TargetReport {
                target: Target {
                    original: "example".to_string(),
                    hostname: None,
                    address: IpAddr::from_str("127.0.0.1").expect("ip"),
                },
                fingerprint: None,
                fingerprint_matches: Vec::new(),
                os_guesses: Vec::new(),
                endpoints,
            }],
        }
    }

    #[test]
    fn human_output_includes_open_probe_details() {
        let rendered = render_human_scan_report(&sample_report(), false);
        assert!(rendered.contains("22/SYN"));
        assert!(rendered.contains("service: ssh"));
        assert!(rendered.contains("banner: SSH-2.0-test"));
    }

    #[test]
    fn human_output_includes_http_metadata_fields() {
        let mut report = sample_report();
        report.targets[0].endpoints.insert(
            80,
            EndpointResult {
                port: 80,
                transport: Transport::Tcp,
                state: EndpointState::Open,
                latency: Duration::from_millis(15),
                observations: vec![ProbeObservation {
                    probe_id: "http".to_string(),
                    service_hint: Some(ServiceHint {
                        name: "http".to_string(),
                        confidence: Confidence::High,
                    }),
                    banner: Some(Banner {
                        raw: "HTTP/1.1 200 OK".to_string(),
                        normalized: "HTTP/1.1 200 OK".to_string(),
                    }),
                    tls: None,
                    tags: Vec::new(),
                    evidence: vec![
                        crate::model::Evidence {
                            key: "server".to_string(),
                            value: "Apache".to_string(),
                        },
                        crate::model::Evidence {
                            key: "title".to_string(),
                            value: "Example".to_string(),
                        },
                        crate::model::Evidence {
                            key: "x-powered-by".to_string(),
                            value: "PHP".to_string(),
                        },
                    ],
                    confidence: Confidence::High,
                }],
                fingerprint: None,
                fingerprint_matches: Vec::new(),
                errors: Vec::new(),
            },
        );

        let rendered = render_human_scan_report(&report, false);
        assert!(rendered.contains("server: Apache"));
        assert!(rendered.contains("title: Example"));
        assert!(rendered.contains("X-Powered-By: PHP"));
    }

    #[test]
    fn human_output_hides_non_open_by_default() {
        let rendered = render_human_scan_report(&sample_report(), false);
        assert!(!rendered.contains("80/TCP"));
    }

    #[test]
    fn human_output_hides_targets_without_open_ports_by_default() {
        let mut report = sample_report();
        report.targets.push(TargetReport {
            target: Target {
                original: "filtered-only".to_string(),
                hostname: None,
                address: IpAddr::from_str("127.0.0.2").expect("ip"),
            },
            fingerprint: None,
            fingerprint_matches: Vec::new(),
            os_guesses: Vec::new(),
            endpoints: BTreeMap::from([(
                443,
                EndpointResult {
                    port: 443,
                    transport: Transport::Tcp,
                    state: EndpointState::Filtered,
                    latency: Duration::default(),
                    observations: Vec::new(),
                    fingerprint: None,
                    fingerprint_matches: Vec::new(),
                    errors: Vec::new(),
                },
            )]),
        });

        let rendered = render_human_scan_report(&report, false);
        assert!(!rendered.contains("filtered-only"));
    }

    #[test]
    fn human_output_groups_cidr_targets_under_the_original_input() {
        let report = ScanReport {
            metadata: ScanMetadata {
                version: "test".to_string(),
                profile: "default".to_string(),
                recipe: None,
                tags: Vec::new(),
                generated_at: Utc::now(),
                timings: None,
            },
            targets: vec![
                TargetReport {
                    target: Target {
                        original: "192.168.10.0/24".to_string(),
                        hostname: None,
                        address: IpAddr::from_str("192.168.10.101").expect("ip"),
                    },
                    fingerprint: None,
                    fingerprint_matches: Vec::new(),
                    os_guesses: Vec::new(),
                    endpoints: BTreeMap::from([(
                        80,
                        EndpointResult {
                            port: 80,
                            transport: Transport::Tcp,
                            state: EndpointState::Filtered,
                            latency: Duration::default(),
                            observations: Vec::new(),
                            fingerprint: None,
                            fingerprint_matches: Vec::new(),
                            errors: Vec::new(),
                        },
                    )]),
                },
                TargetReport {
                    target: Target {
                        original: "192.168.10.0/24".to_string(),
                        hostname: None,
                        address: IpAddr::from_str("192.168.10.102").expect("ip"),
                    },
                    fingerprint: None,
                    fingerprint_matches: Vec::new(),
                    os_guesses: Vec::new(),
                    endpoints: BTreeMap::from([(
                        443,
                        EndpointResult {
                            port: 443,
                            transport: Transport::Tcp,
                            state: EndpointState::Open,
                            latency: Duration::default(),
                            observations: Vec::new(),
                            fingerprint: None,
                            fingerprint_matches: Vec::new(),
                            errors: Vec::new(),
                        },
                    )]),
                },
            ],
        };

        let rendered = render_human_scan_report(&report, false);
        assert!(rendered.contains("192.168.10.0/24"));
        assert!(rendered.contains("192.168.10.102"));
        assert!(rendered.contains("443/TCP"));
        assert!(!rendered.contains("192.168.10.0/24 (192.168.10.102)"));
        assert!(!rendered.contains("192.168.10.101"));
    }

    #[test]
    fn human_output_shows_non_open_when_requested() {
        let rendered = render_human_scan_report(&sample_report(), true);
        assert!(rendered.contains("80/TCP"));
        assert!(rendered.contains("state: Filtered"));
    }

    #[test]
    fn human_output_renders_raw_fingerprint_and_os_guess_nodes() {
        let mut report = sample_report();
        report.targets[0].fingerprint = Some(crate::model::TcpIpObservation {
            transport: Transport::Syn,
            handshake_observed: true,
            response_observed: true,
            ttl_hint: Some(64),
            ttl_class: Some(64),
            window_size: Some(64240),
            syn_ack_seen: true,
            rst_seen: false,
            tcp_option_order: Some("MSS,SACK,TS,NOP,WS".to_string()),
            tcp_option_set: Some("{MSS,NOP,SACK,TS,WS}".to_string()),
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: Some(true),
            timestamps: Some(true),
        });
        report.targets[0].os_guesses = vec![crate::model::FingerprintMatch {
            label: "Unix-like: Linux / BSD / Darwin".to_string(),
            family: "UnixLike".to_string(),
            confidence: Confidence::Low,
            evidence: Vec::new(),
        }];

        let rendered = render_human_scan_report(&report, false);
        assert!(rendered.contains("fingerprint"));
        assert!(rendered.contains("tcp_option_order: MSS,SACK,TS,NOP,WS"));
        assert!(rendered.contains("os-guess"));
        assert!(rendered.contains("Unix-like: Linux / BSD / Darwin"));
    }

    #[test]
    fn human_host_output_hides_unreachable_by_default() {
        let report = HostScanReport {
            metadata: HostScanMetadata {
                version: "test".to_string(),
                method: HostDiscoveryMethod::Icmp,
                generated_at: Utc::now(),
                timings: None,
            },
            targets: vec![
                HostResult {
                    target: Target {
                        original: "alive".to_string(),
                        hostname: None,
                        address: IpAddr::from_str("192.0.2.10").expect("ip"),
                    },
                    reachable: true,
                    observations: vec![HostObservation {
                        method: HostDiscoveryMethod::Icmp,
                        port: None,
                        outcome: "echo-reply".to_string(),
                        latency: Some(Duration::from_millis(4)),
                        ttl_hint: Some(64),
                        mac_address: Some("00:11:22:33:44:55".to_string()),
                    }],
                    errors: Vec::new(),
                },
                HostResult {
                    target: Target {
                        original: "down".to_string(),
                        hostname: None,
                        address: IpAddr::from_str("192.0.2.11").expect("ip"),
                    },
                    reachable: false,
                    observations: Vec::new(),
                    errors: vec!["timed out".to_string()],
                },
            ],
        };

        let rendered = render_human_host_report(&report, false);
        assert!(rendered.contains("alive"));
        assert!(rendered.contains("192.0.2.10"));
        assert!(rendered.contains("mac=00:11:22:33:44:55"));
        assert!(!rendered.contains("192.0.2.11"));
    }
}
