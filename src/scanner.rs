use std::{collections::BTreeMap, sync::Arc};

use anyhow::Result;
use chrono::Utc;
use futures::{StreamExt, stream};
use rand::seq::SliceRandom;
use tokio::sync::Semaphore;

use crate::{
    config::ScanConfig,
    data::DataRegistry,
    fingerprint::{
        baseline_syn_observation, baseline_tcp_observation, baseline_udp_observation,
        build_platform_match, builtin_os_ttl_classes, match_legacy_os_signatures, match_rules,
        match_ttl_classes,
    },
    model::{EndpointResult, EndpointState, ScanMetadata, ScanReport, TargetReport, Transport},
    probes::{ProbeContext, select_builtin_probes},
    service_db::apply_legacy_service_signatures,
    transport::{
        Connector, ProbeConnection, SynPortStatus, estimate_tcp_rtt, syn_scan_target,
        syn_scan_targets,
    },
};

const MAX_TCP_CONNECT_INFLIGHT_PER_TARGET: usize = 128;

pub struct Scanner<C> {
    config: ScanConfig,
    registry: DataRegistry,
    connector: C,
}

pub struct ScanExecution {
    pub report: ScanReport,
    pub transport_scan_time: std::time::Duration,
    pub followup_probe_time: std::time::Duration,
    pub open_endpoint_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum ScanEvent {
    TransportScanStarted {
        target_count: usize,
        port_count: usize,
        transport: Transport,
    },
    TransportScanCompleted {
        elapsed: std::time::Duration,
    },
    FollowupProbesStarted {
        open_endpoint_count: usize,
    },
    FollowupProbesCompleted {
        elapsed: std::time::Duration,
    },
}

struct TargetPhaseResult {
    target: crate::model::Target,
    endpoints: BTreeMap<u16, EndpointResult>,
    open_ports: Vec<u16>,
    reusable_connections: BTreeMap<u16, ProbeConnection>,
}

struct FollowupResult {
    observations: Vec<crate::model::ProbeObservation>,
    errors: Vec<String>,
}

struct TransportEndpointScan {
    endpoint: EndpointResult,
    reusable_connection: Option<ProbeConnection>,
}

impl<C> Scanner<C>
where
    C: Connector,
{
    pub fn new(config: ScanConfig, registry: DataRegistry, connector: C) -> Self {
        Self {
            config,
            registry,
            connector,
        }
    }

    pub async fn scan(
        &self,
        targets: Vec<(crate::model::Target, Vec<u16>)>,
    ) -> Result<ScanExecution> {
        self.scan_with_progress(targets, |_| {}).await
    }

    pub async fn scan_with_progress<F>(
        &self,
        targets: Vec<(crate::model::Target, Vec<u16>)>,
        mut on_event: F,
    ) -> Result<ScanExecution>
    where
        F: FnMut(ScanEvent),
    {
        let mut targets = targets;
        let mut rng = rand::rng();
        targets.shuffle(&mut rng);
        for (_, ports) in &mut targets {
            ports.shuffle(&mut rng);
        }

        let connector = self.connector.clone();
        let config = self.config.clone();
        let registry = self.registry.clone();
        let target_count = targets.len();
        let port_count = targets.iter().map(|(_, ports)| ports.len()).sum();
        let target_concurrency = effective_target_concurrency(&config, target_count);

        on_event(ScanEvent::TransportScanStarted {
            target_count,
            port_count,
            transport: config.transport,
        });
        let transport_started = std::time::Instant::now();
        let transport_phase = if config.transport == Transport::Syn {
            scan_syn_transport_phase(targets, &config).await
        } else {
            stream::iter(targets.into_iter())
                .map(|(target, ports)| {
                    let connector = connector.clone();
                    let config = config.clone();
                    async move {
                        scan_target_phase(
                            target,
                            ports,
                            &config,
                            connector,
                            target_concurrency,
                            target_count,
                        )
                        .await
                    }
                })
                .buffer_unordered(target_concurrency)
                .collect::<Vec<_>>()
                .await
        };
        let transport_scan_time = transport_started.elapsed();
        on_event(ScanEvent::TransportScanCompleted {
            elapsed: transport_scan_time,
        });

        let open_endpoint_count = transport_phase
            .iter()
            .map(|phase| phase.open_ports.len())
            .sum();

        let followup_started = std::time::Instant::now();
        if open_endpoint_count > 0 {
            on_event(ScanEvent::FollowupProbesStarted {
                open_endpoint_count,
            });
        }
        let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
        let target_reports =
            stream::iter(transport_phase.into_iter())
                .map(|phase| {
                    let connector = connector.clone();
                    let config = config.clone();
                    let registry = registry.clone();
                    let semaphore = semaphore.clone();
                    async move {
                        run_followup_phase(phase, &config, &registry, connector, semaphore).await
                    }
                })
                .buffer_unordered(target_concurrency)
                .collect::<Vec<_>>()
                .await;
        let followup_probe_time = followup_started.elapsed();
        if open_endpoint_count > 0 {
            on_event(ScanEvent::FollowupProbesCompleted {
                elapsed: followup_probe_time,
            });
        }

        Ok(ScanExecution {
            report: ScanReport {
                metadata: ScanMetadata {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    profile: self.config.profile_name.clone(),
                    recipe: self.config.recipe_name.clone(),
                    tags: self.config.tags.clone(),
                    generated_at: Utc::now(),
                    timings: None,
                },
                targets: target_reports,
            },
            transport_scan_time,
            followup_probe_time,
            open_endpoint_count,
        })
    }
}

async fn scan_target_phase<C: Connector>(
    target: crate::model::Target,
    ports: Vec<u16>,
    config: &ScanConfig,
    connector: C,
    target_concurrency: usize,
    scan_target_count: usize,
) -> TargetPhaseResult {
    let mut target_config = config.clone();
    if target_config.adaptive_connect_timeout {
        target_config.connect_timeout =
            adaptive_connect_timeout_for_target(config, &target, &ports, scan_target_count).await;
    }

    if target_config.transport == Transport::Syn {
        return scan_syn_target_phase(target, ports, &target_config, connector).await;
    }

    let endpoint_concurrency = effective_transport_concurrency(&target_config, target_concurrency);
    let endpoint_results = stream::iter(ports.into_iter())
        .map(|port| {
            let connector = connector.clone();
            let config = target_config.clone();
            let target = target.clone();
            async move { scan_transport_endpoint(target, port, &config, connector).await }
        })
        .buffer_unordered(endpoint_concurrency)
        .collect::<Vec<_>>()
        .await;

    let mut endpoints = BTreeMap::new();
    let mut open_ports = Vec::new();
    let mut reusable_connections = BTreeMap::new();
    for result in endpoint_results {
        if result.endpoint.state == EndpointState::Open {
            open_ports.push(result.endpoint.port);
        }
        if let Some(connection) = result.reusable_connection {
            reusable_connections.insert(result.endpoint.port, connection);
        }
        endpoints.insert(result.endpoint.port, result.endpoint);
    }

    TargetPhaseResult {
        target,
        endpoints,
        open_ports,
        reusable_connections,
    }
}

async fn adaptive_connect_timeout_for_target(
    config: &ScanConfig,
    target: &crate::model::Target,
    ports: &[u16],
    scan_target_count: usize,
) -> std::time::Duration {
    if config.transport != Transport::Tcp {
        return config.connect_timeout;
    }
    let probe_ports = select_rtt_probe_ports(ports);
    let fallback_timeout =
        derive_connect_timeout(std::time::Duration::from_millis(200), scan_target_count);
    estimate_tcp_rtt(
        target.address,
        &probe_ports,
        std::time::Duration::from_millis(250),
    )
    .await
    .map(|rtt| derive_connect_timeout(rtt, scan_target_count))
    .unwrap_or(fallback_timeout)
}

fn derive_connect_timeout(
    rtt: std::time::Duration,
    scan_target_count: usize,
) -> std::time::Duration {
    let adapted = (rtt.as_millis() as f64 * 1.5) as u64;
    let floor_ms = if scan_target_count > 1 { 150 } else { 50 };
    std::time::Duration::from_millis(adapted.clamp(floor_ms, 5000))
}

fn select_rtt_probe_ports(ports: &[u16]) -> Vec<u16> {
    const PREFERRED_PORTS: &[u16] = &[
        80, 443, 22, 21, 445, 3389, 139, 135, 1433, 25, 110, 995, 993, 8080, 8443, 3306, 5432,
        6379, 5985, 5900,
    ];

    let mut selected = Vec::new();
    for port in PREFERRED_PORTS {
        if ports.contains(port) && !selected.contains(port) {
            selected.push(*port);
        }
    }
    for port in ports.iter().copied().take(16) {
        if !selected.contains(&port) {
            selected.push(port);
        }
    }
    selected
}

async fn scan_syn_target_phase<C: Connector>(
    target: crate::model::Target,
    ports: Vec<u16>,
    config: &ScanConfig,
    _connector: C,
) -> TargetPhaseResult {
    let mut endpoints = BTreeMap::new();
    let mut open_ports = Vec::new();
    let syn_results = syn_scan_target(
        target.address,
        &ports,
        config.connect_timeout,
        config.interface.as_deref(),
    )
    .await;

    match syn_results {
        Ok(results) => {
            for port in ports {
                let endpoint = match results.get(&port) {
                    Some(SynPortStatus::Open(observation)) => {
                        open_ports.push(port);
                        let mut fingerprint = baseline_syn_observation(
                            true,
                            observation.syn_ack_seen,
                            observation.rst_seen,
                            observation.ttl_hint,
                            observation.window_size,
                        );
                        apply_syn_observation_details(&mut fingerprint, observation);
                        EndpointResult {
                            port,
                            transport: Transport::Syn,
                            state: EndpointState::Open,
                            latency: std::time::Duration::default(),
                            observations: Vec::new(),
                            fingerprint: Some(fingerprint),
                            fingerprint_matches: Vec::new(),
                            errors: Vec::new(),
                        }
                    }
                    Some(SynPortStatus::Closed(observation)) => {
                        let fingerprint = if let Some(observation) = observation {
                            let mut fingerprint = baseline_syn_observation(
                                true,
                                observation.syn_ack_seen,
                                observation.rst_seen,
                                observation.ttl_hint,
                                observation.window_size,
                            );
                            apply_syn_observation_details(&mut fingerprint, observation);
                            fingerprint
                        } else {
                            baseline_syn_observation(false, false, true, None, None)
                        };
                        EndpointResult {
                            port,
                            transport: Transport::Syn,
                            state: EndpointState::Closed,
                            latency: std::time::Duration::default(),
                            observations: Vec::new(),
                            fingerprint: Some(fingerprint),
                            fingerprint_matches: Vec::new(),
                            errors: Vec::new(),
                        }
                    }
                    Some(SynPortStatus::Filtered) | None => EndpointResult {
                        port,
                        transport: Transport::Syn,
                        state: EndpointState::Filtered,
                        latency: std::time::Duration::default(),
                        observations: Vec::new(),
                        fingerprint: Some(baseline_syn_observation(
                            false, false, false, None, None,
                        )),
                        fingerprint_matches: Vec::new(),
                        errors: Vec::new(),
                    },
                };
                endpoints.insert(port, endpoint);
            }
        }
        Err(error) => {
            for port in ports {
                endpoints.insert(
                    port,
                    EndpointResult {
                        port,
                        transport: Transport::Syn,
                        state: EndpointState::Error,
                        latency: std::time::Duration::default(),
                        observations: Vec::new(),
                        fingerprint: Some(baseline_syn_observation(
                            false, false, false, None, None,
                        )),
                        fingerprint_matches: Vec::new(),
                        errors: vec![error.to_string()],
                    },
                );
            }
        }
    }

    TargetPhaseResult {
        target,
        endpoints,
        open_ports,
        reusable_connections: BTreeMap::new(),
    }
}

async fn scan_transport_endpoint<C: Connector>(
    target: crate::model::Target,
    port: u16,
    config: &ScanConfig,
    connector: C,
) -> TransportEndpointScan {
    let mut errors = Vec::new();
    let mut last_error = None;

    for _attempt in 0..=config.retries {
        match connector
            .connect(
                target.address,
                port,
                config.transport,
                config.connect_timeout,
                config.interface.as_deref(),
                target
                    .hostname
                    .as_deref()
                    .or(Some(target.original.as_str())),
            )
            .await
        {
            Ok(outcome) => {
                let state = classify_open_state(config.transport, &outcome.connection);
                let fingerprint = build_fingerprint(config.transport, &outcome.connection, false);
                let reusable_connection = if state == EndpointState::Open
                    && matches!(
                        config.transport,
                        Transport::Tcp | Transport::Udp | Transport::Quic
                    ) {
                    Some(outcome.connection)
                } else {
                    None
                };

                return TransportEndpointScan {
                    endpoint: EndpointResult {
                        port,
                        transport: config.transport,
                        state,
                        latency: outcome.latency,
                        observations: Vec::new(),
                        fingerprint: Some(fingerprint),
                        fingerprint_matches: Vec::new(),
                        errors,
                    },
                    reusable_connection,
                };
            }
            Err(error) => last_error = Some(error),
        }
    }

    let state = classify_error(config.transport, last_error.as_ref());
    if let Some(error) = last_error {
        errors.push(error.to_string());
    }

    TransportEndpointScan {
        endpoint: EndpointResult {
            port,
            transport: config.transport,
            state,
            latency: std::time::Duration::default(),
            observations: Vec::new(),
            fingerprint: Some(build_closed_fingerprint(config.transport)),
            fingerprint_matches: Vec::new(),
            errors,
        },
        reusable_connection: None,
    }
}

async fn run_followup_phase<C: Connector>(
    phase: TargetPhaseResult,
    config: &ScanConfig,
    registry: &DataRegistry,
    connector: C,
    semaphore: Arc<Semaphore>,
) -> TargetReport {
    let target = phase.target;
    let mut endpoints = phase.endpoints;
    let mut reusable_connections = phase.reusable_connections;

    if !phase.open_ports.is_empty() {
        let followups = stream::iter(phase.open_ports.into_iter())
            .map(|port| {
                let target = target.clone();
                let config = config.clone();
                let registry = registry.clone();
                let connector = connector.clone();
                let semaphore = semaphore.clone();
                let reusable_connection = reusable_connections.remove(&port);
                async move {
                    let _permit = semaphore.acquire_owned().await.expect("semaphore");
                    (
                        port,
                        collect_followup_observations(
                            &target,
                            port,
                            &config,
                            &registry,
                            connector,
                            reusable_connection,
                        )
                        .await,
                    )
                }
            })
            .buffer_unordered(config.concurrency.max(1))
            .collect::<Vec<_>>()
            .await;

        for (port, followup) in followups {
            if let Some(endpoint) = endpoints.get_mut(&port) {
                endpoint.observations = followup.observations;
                endpoint.errors.extend(followup.errors);
                if let Some(fingerprint) = endpoint.fingerprint.as_mut() {
                    fingerprint.response_observed = !endpoint.observations.is_empty();
                    endpoint.fingerprint_matches =
                        collect_fingerprint_matches(fingerprint, registry);
                }
            }
        }
    }

    for endpoint in endpoints.values_mut() {
        let _ = endpoint;
    }

    let (target_fingerprint, stack_matches) =
        collect_target_fingerprint(&endpoints, registry, config.transport);
    let target_fingerprint_matches =
        merge_platform_matches(stack_matches, collect_target_service_matches(&endpoints));

    if config.transport == Transport::Syn {
        for endpoint in endpoints.values_mut() {
            endpoint.fingerprint_matches.clear();
        }
    }

    TargetReport {
        target,
        fingerprint: target_fingerprint,
        fingerprint_matches: Vec::new(),
        os_guesses: target_fingerprint_matches,
        endpoints,
    }
}

async fn collect_followup_observations<C: Connector>(
    target: &crate::model::Target,
    port: u16,
    config: &ScanConfig,
    registry: &DataRegistry,
    connector: C,
    reusable_connection: Option<ProbeConnection>,
) -> FollowupResult {
    let mut observations = Vec::new();
    let mut errors = Vec::new();
    let followup_transport = probe_transport(config.transport);
    let host = target.hostname.as_deref().unwrap_or(&target.original);
    let mut reusable_connection = reusable_connection;

    if config.builtin_probes {
        for probe in select_builtin_probes(port, followup_transport, &config.enabled_probes) {
            let connection = if let Some(connection) = reusable_connection.take() {
                Ok(connection)
            } else {
                connector
                    .connect(
                        target.address,
                        port,
                        followup_transport,
                        config.connect_timeout,
                        config.interface.as_deref(),
                        target
                            .hostname
                            .as_deref()
                            .or(Some(target.original.as_str())),
                    )
                    .await
                    .map(|outcome| outcome.connection)
            };

            match connection {
                Ok(probe_connection) => {
                    if let Ok(observation) = probe
                        .execute(
                            probe_connection,
                            ProbeContext {
                                host,
                                port,
                                timeout: config.probe_timeout,
                                http_body_preview_bytes: config.http_body_preview_bytes,
                            },
                        )
                        .await
                    {
                        let stop = should_stop_after_observation(&observation);
                        observations.push(observation);
                        if stop {
                            break;
                        }
                    }
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
    }

    for probe in registry
        .external_probes
        .iter()
        .filter(|probe| probe.matches(port, followup_transport))
    {
        let connection = if let Some(connection) = reusable_connection.take() {
            Ok(connection)
        } else {
            connector
                .connect(
                    target.address,
                    port,
                    followup_transport,
                    config.connect_timeout,
                    config.interface.as_deref(),
                    target
                        .hostname
                        .as_deref()
                        .or(Some(target.original.as_str())),
                )
                .await
                .map(|outcome| outcome.connection)
        };

        match connection {
            Ok(probe_connection) => {
                if let Ok(observation) = probe.execute(probe_connection, config.probe_timeout).await
                {
                    observations.push(observation);
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
    }

    FollowupResult {
        observations: {
            let mut observations = observations;
            for observation in &mut observations {
                apply_legacy_service_signatures(observation, &registry.service_signatures);
            }
            observations
        },
        errors,
    }
}

fn build_fingerprint(
    transport: Transport,
    connection: &ProbeConnection,
    response_observed: bool,
) -> crate::model::TcpIpObservation {
    match transport {
        Transport::Tcp => {
            let mut fingerprint = baseline_tcp_observation();
            fingerprint.response_observed = response_observed;
            fingerprint.syn_ack_seen = matches!(connection, ProbeConnection::Tcp(_));
            fingerprint
        }
        Transport::Udp => baseline_udp_observation(response_observed),
        Transport::Quic => {
            let mut fingerprint = baseline_udp_observation(response_observed);
            fingerprint.transport = Transport::Quic;
            fingerprint.handshake_observed = true;
            fingerprint
        }
        Transport::Syn => match connection {
            ProbeConnection::Syn(observation) => {
                let mut fingerprint = baseline_syn_observation(
                    true,
                    observation.syn_ack_seen,
                    observation.rst_seen,
                    observation.ttl_hint,
                    observation.window_size,
                );
                apply_syn_observation_details(&mut fingerprint, observation);
                fingerprint
            }
            _ => baseline_syn_observation(false, false, false, None, None),
        },
    }
}

fn build_closed_fingerprint(transport: Transport) -> crate::model::TcpIpObservation {
    match transport {
        Transport::Tcp => {
            let mut fingerprint = baseline_tcp_observation();
            fingerprint.handshake_observed = false;
            fingerprint
        }
        Transport::Udp => baseline_udp_observation(false),
        Transport::Quic => {
            let mut fingerprint = baseline_udp_observation(false);
            fingerprint.transport = Transport::Quic;
            fingerprint
        }
        Transport::Syn => baseline_syn_observation(false, false, false, None, None),
    }
}

fn collect_fingerprint_matches(
    fingerprint: &crate::model::TcpIpObservation,
    registry: &DataRegistry,
) -> Vec<crate::model::FingerprintMatch> {
    let mut matches = match_rules(fingerprint, &registry.fingerprint_rules);
    matches.extend(match_ttl_classes(fingerprint, &builtin_os_ttl_classes()));
    matches.extend(match_ttl_classes(fingerprint, &registry.os_ttl_classes));
    matches.extend(match_legacy_os_signatures(
        fingerprint,
        &registry.os_signatures,
    ));
    matches
}

fn apply_syn_observation_details(
    fingerprint: &mut crate::model::TcpIpObservation,
    observation: &crate::transport::SynAckObservation,
) {
    fingerprint.ttl_class = observation.ttl_class;
    fingerprint.tcp_option_order = observation.tcp_option_order.clone();
    fingerprint.tcp_option_set = observation.tcp_option_set.clone();
    fingerprint.mss = observation.mss;
    fingerprint.window_scale = observation.window_scale;
    fingerprint.sack_permitted = observation.sack_permitted;
    fingerprint.timestamps = observation.timestamps;
}

fn collect_target_fingerprint(
    endpoints: &BTreeMap<u16, EndpointResult>,
    registry: &DataRegistry,
    transport: Transport,
) -> (
    Option<crate::model::TcpIpObservation>,
    Vec<crate::model::FingerprintMatch>,
) {
    if transport != Transport::Syn {
        return (None, Vec::new());
    }

    let best = endpoints
        .values()
        .filter_map(|endpoint| endpoint.fingerprint.as_ref())
        .max_by_key(|fingerprint| fingerprint_rank(fingerprint))
        .cloned();

    let matches = best
        .as_ref()
        .map(|fingerprint| collect_fingerprint_matches(fingerprint, registry))
        .unwrap_or_default();

    (best, matches)
}

fn collect_target_service_matches(
    endpoints: &BTreeMap<u16, EndpointResult>,
) -> Vec<crate::model::FingerprintMatch> {
    endpoints
        .values()
        .flat_map(|endpoint| endpoint.observations.iter())
        .filter_map(|observation| {
            let cpes = observation
                .evidence
                .iter()
                .filter(|item| item.key == "cpe")
                .map(|item| item.value.clone())
                .collect::<Vec<_>>();
            if cpes.is_empty() {
                return None;
            }
            let evidence = observation
                .evidence
                .iter()
                .filter(|item| item.key == "service_signature" || item.key == "cpe")
                .cloned()
                .collect::<Vec<_>>();
            build_platform_match(&cpes, observation.confidence.clone(), evidence)
        })
        .collect()
}

fn merge_platform_matches(
    primary: Vec<crate::model::FingerprintMatch>,
    secondary: Vec<crate::model::FingerprintMatch>,
) -> Vec<crate::model::FingerprintMatch> {
    let preferred = preferred_service_families(&secondary);
    let mut merged = Vec::new();
    for item in primary
        .into_iter()
        .filter(|item| stack_match_is_compatible(item, &preferred))
        .chain(secondary)
    {
        insert_platform_match(&mut merged, item);
    }
    suppress_generic_matches(merged)
}

fn insert_platform_match(
    merged: &mut Vec<crate::model::FingerprintMatch>,
    candidate: crate::model::FingerprintMatch,
) {
    if let Some(index) = merged
        .iter()
        .position(|item| item.family == candidate.family || item.label == candidate.label)
    {
        if confidence_rank(&candidate.confidence) > confidence_rank(&merged[index].confidence) {
            merged[index] = candidate;
        }
        return;
    }

    let candidate_root = family_root(&candidate.family);
    if candidate_root.is_some() {
        if let Some(root) = candidate_root
            && let Some(index) = merged
                .iter()
                .position(|item| family_root(&item.family) == Some(root))
        {
            let existing_is_generic = merged[index].family == root;
            let candidate_is_generic = candidate.family == root;
            if existing_is_generic && !candidate_is_generic {
                merged[index] = candidate;
            } else if !existing_is_generic
                && !candidate_is_generic
                && confidence_rank(&candidate.confidence)
                    > confidence_rank(&merged[index].confidence)
            {
                merged[index] = candidate;
            }
            return;
        }
    }

    merged.push(candidate);
}

fn preferred_service_families(matches: &[crate::model::FingerprintMatch]) -> Vec<String> {
    matches
        .iter()
        .filter(|item| {
            item.evidence
                .iter()
                .any(|evidence| evidence.key == "service_signature")
        })
        .map(|item| item.family.clone())
        .collect()
}

fn stack_match_is_compatible(
    candidate: &crate::model::FingerprintMatch,
    preferred: &[String],
) -> bool {
    if preferred.is_empty() {
        return true;
    }

    if is_ttl_class_match(candidate) {
        return true;
    }

    preferred
        .iter()
        .any(|family| families_are_compatible(&candidate.family, family))
}

fn families_are_compatible(candidate: &str, preferred: &str) -> bool {
    if candidate == preferred {
        return true;
    }

    match (family_root(candidate), family_root(preferred)) {
        (Some(left), Some(right)) => left == right,
        (Some(root), None) => root == preferred,
        (None, Some(root)) => candidate == root,
        (None, None) => false,
    }
}

fn suppress_generic_matches(
    matches: Vec<crate::model::FingerprintMatch>,
) -> Vec<crate::model::FingerprintMatch> {
    let has_specific_platform = matches
        .iter()
        .any(|item| is_specific_platform_match(item) && !is_ttl_class_match(item));

    matches
        .into_iter()
        .filter(|item| !has_specific_platform || !is_ttl_class_match(item))
        .collect()
}

fn family_root(family: &str) -> Option<&str> {
    match family {
        "apple" | "apple:mac_os" | "apple:iphone_os" => Some("apple"),
        "linux" | "linux:linux_kernel" | "google:android" => Some("linux"),
        "bsd" | "openbsd:openbsd" | "freebsd:freebsd" | "netbsd:netbsd" => Some("bsd"),
        _ => None,
    }
}

fn is_ttl_class_match(candidate: &crate::model::FingerprintMatch) -> bool {
    candidate
        .evidence
        .iter()
        .any(|item| item.key == "source" && item.value == "builtin-ttl-class")
}

fn is_specific_platform_match(candidate: &crate::model::FingerprintMatch) -> bool {
    candidate.family.contains(':')
        || matches!(
            candidate.family.as_str(),
            "apple" | "linux" | "bsd" | "microsoft:windows" | "nintendo" | "playstation"
        )
}

fn confidence_rank(confidence: &crate::model::Confidence) -> u8 {
    match confidence {
        crate::model::Confidence::Low => 0,
        crate::model::Confidence::Medium => 1,
        crate::model::Confidence::High => 2,
    }
}

fn fingerprint_rank(fingerprint: &crate::model::TcpIpObservation) -> usize {
    usize::from(fingerprint.ttl_hint.is_some())
        + usize::from(fingerprint.window_size.is_some())
        + usize::from(fingerprint.tcp_option_order.is_some())
        + usize::from(fingerprint.tcp_option_set.is_some())
        + usize::from(fingerprint.mss.is_some())
        + usize::from(fingerprint.window_scale.is_some())
        + usize::from(fingerprint.sack_permitted.is_some())
        + usize::from(fingerprint.timestamps.is_some())
        + usize::from(fingerprint.syn_ack_seen)
}

fn classify_open_state(transport: Transport, connection: &ProbeConnection) -> EndpointState {
    match transport {
        Transport::Tcp => EndpointState::Open,
        Transport::Syn => EndpointState::Open,
        Transport::Quic => EndpointState::Open,
        Transport::Udp => match connection {
            ProbeConnection::Udp(_) => EndpointState::Open,
            _ => EndpointState::Filtered,
        },
    }
}

fn classify_error(transport: Transport, error: Option<&std::io::Error>) -> EndpointState {
    match (transport, error.map(|err| err.kind())) {
        (Transport::Syn, Some(std::io::ErrorKind::ConnectionRefused)) => EndpointState::Closed,
        (Transport::Syn, Some(std::io::ErrorKind::TimedOut)) => EndpointState::Filtered,
        (Transport::Udp, Some(std::io::ErrorKind::ConnectionRefused)) => EndpointState::Closed,
        (Transport::Udp, Some(std::io::ErrorKind::TimedOut)) => EndpointState::Filtered,
        (Transport::Quic, Some(std::io::ErrorKind::ConnectionRefused)) => EndpointState::Closed,
        (Transport::Quic, Some(std::io::ErrorKind::TimedOut)) => EndpointState::Filtered,
        (_, Some(std::io::ErrorKind::ConnectionRefused)) => EndpointState::Closed,
        (_, Some(std::io::ErrorKind::TimedOut)) => EndpointState::Filtered,
        (
            _,
            Some(
                std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::NetworkUnreachable,
            ),
        ) => EndpointState::Unreachable,
        (_, Some(_)) => EndpointState::Error,
        (_, None) => EndpointState::Error,
    }
}

fn probe_transport(transport: Transport) -> Transport {
    match transport {
        Transport::Syn => Transport::Tcp,
        other => other,
    }
}

async fn scan_syn_transport_phase(
    targets: Vec<(crate::model::Target, Vec<u16>)>,
    config: &ScanConfig,
) -> Vec<TargetPhaseResult> {
    let syn_inputs = targets
        .iter()
        .map(|(target, ports)| (target.address, ports.clone()))
        .collect::<Vec<_>>();
    let syn_results = syn_scan_targets(
        &syn_inputs,
        config.connect_timeout,
        config.interface.as_deref(),
    )
    .await;

    targets
        .into_iter()
        .map(|(target, ports)| {
            let mut endpoints = BTreeMap::new();
            let mut open_ports = Vec::new();

            match &syn_results {
                Ok(results_by_host) => {
                    let results = results_by_host.get(&target.address);
                    for port in ports {
                        let endpoint = match results.and_then(|result| result.get(&port)) {
                            Some(SynPortStatus::Open(observation)) => {
                                open_ports.push(port);
                                let mut fingerprint = baseline_syn_observation(
                                    true,
                                    observation.syn_ack_seen,
                                    observation.rst_seen,
                                    observation.ttl_hint,
                                    observation.window_size,
                                );
                                apply_syn_observation_details(&mut fingerprint, observation);
                                EndpointResult {
                                    port,
                                    transport: Transport::Syn,
                                    state: EndpointState::Open,
                                    latency: std::time::Duration::default(),
                                    observations: Vec::new(),
                                    fingerprint: Some(fingerprint),
                                    fingerprint_matches: Vec::new(),
                                    errors: Vec::new(),
                                }
                            }
                            Some(SynPortStatus::Closed(observation)) => {
                                let fingerprint = if let Some(observation) = observation {
                                    let mut fingerprint = baseline_syn_observation(
                                        true,
                                        observation.syn_ack_seen,
                                        observation.rst_seen,
                                        observation.ttl_hint,
                                        observation.window_size,
                                    );
                                    apply_syn_observation_details(&mut fingerprint, observation);
                                    fingerprint
                                } else {
                                    baseline_syn_observation(false, false, true, None, None)
                                };
                                EndpointResult {
                                    port,
                                    transport: Transport::Syn,
                                    state: EndpointState::Closed,
                                    latency: std::time::Duration::default(),
                                    observations: Vec::new(),
                                    fingerprint: Some(fingerprint),
                                    fingerprint_matches: Vec::new(),
                                    errors: Vec::new(),
                                }
                            }
                            Some(SynPortStatus::Filtered) | None => EndpointResult {
                                port,
                                transport: Transport::Syn,
                                state: EndpointState::Filtered,
                                latency: std::time::Duration::default(),
                                observations: Vec::new(),
                                fingerprint: Some(baseline_syn_observation(
                                    false, false, false, None, None,
                                )),
                                fingerprint_matches: Vec::new(),
                                errors: Vec::new(),
                            },
                        };
                        endpoints.insert(port, endpoint);
                    }
                }
                Err(error) => {
                    for port in ports {
                        endpoints.insert(
                            port,
                            EndpointResult {
                                port,
                                transport: Transport::Syn,
                                state: EndpointState::Error,
                                latency: std::time::Duration::default(),
                                observations: Vec::new(),
                                fingerprint: Some(baseline_syn_observation(
                                    false, false, false, None, None,
                                )),
                                fingerprint_matches: Vec::new(),
                                errors: vec![error.to_string()],
                            },
                        );
                    }
                }
            }

            TargetPhaseResult {
                target,
                endpoints,
                open_ports,
                reusable_connections: BTreeMap::new(),
            }
        })
        .collect()
}

fn effective_target_concurrency(config: &ScanConfig, target_count: usize) -> usize {
    config.concurrency.max(1).min(target_count.max(1))
}

fn effective_transport_concurrency(config: &ScanConfig, target_concurrency: usize) -> usize {
    let requested = config.concurrency.max(1);
    let per_target_budget = (requested / target_concurrency.max(1)).max(1);
    match config.transport {
        // Large single-host connect bursts can starve the local TCP stack and cause
        // ports to be missed before a SYN is even emitted. Keep TCP connect scans
        // bounded per target for stable coverage.
        Transport::Tcp | Transport::Quic => {
            per_target_budget.min(MAX_TCP_CONNECT_INFLIGHT_PER_TARGET)
        }
        Transport::Udp | Transport::Syn => per_target_budget,
    }
}

fn should_stop_after_observation(observation: &crate::model::ProbeObservation) -> bool {
    observation.service_hint.as_ref().is_some_and(|hint| {
        matches!(hint.confidence, crate::model::Confidence::High)
            && matches!(
                observation.probe_id.as_str(),
                "http"
                    | "ssh"
                    | "ftp"
                    | "smtp"
                    | "pop3"
                    | "imap"
                    | "telnet"
                    | "mysql"
                    | "postgresql"
                    | "redis"
                    | "memcached"
                    | "mqtt"
                    | "smb"
                    | "rdp"
                    | "mssql-prelogin"
                    | "oracle-tns"
                    | "dns-tcp"
                    | "dns-udp"
                    | "ntp"
                    | "quic"
            )
    })
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::Arc,
        time::{Duration, Instant},
    };

    use async_trait::async_trait;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        sync::Mutex,
    };

    use super::*;
    use crate::{
        config::ScanConfig,
        data::DataRegistry,
        model::{Confidence, Evidence, FingerprintMatch, Target, Transport},
        transport::{ConnectOutcome, Connector, ProbeConnection},
    };

    #[derive(Clone, Default)]
    struct TestConnector;

    #[async_trait]
    impl Connector for TestConnector {
        async fn connect(
            &self,
            address: IpAddr,
            port: u16,
            _transport: Transport,
            timeout_window: Duration,
            _interface_name: Option<&str>,
            _server_name: Option<&str>,
        ) -> std::io::Result<ConnectOutcome> {
            crate::transport::SocketConnector
                .connect(address, port, Transport::Tcp, timeout_window, None, None)
                .await
        }
    }

    #[tokio::test]
    async fn scan_flow_marks_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local addr");
        let task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.write_all(b"SSH-2.0-test\r\n").await;
            }
        });

        let config = ScanConfig {
            profile_name: "test".to_string(),
            recipe_name: None,
            transport: Transport::Tcp,
            interface: None,
            show_all_states: false,
            quiet: false,
            progress_mode: crate::cli::ProgressMode::Auto,
            default_ports: vec![address.port()],
            concurrency: 4,
            connect_timeout: Duration::from_secs(1),
            adaptive_connect_timeout: false,
            probe_timeout: Duration::from_secs(1),
            http_body_preview_bytes: 4096,
            retries: 0,
            enabled_probes: vec!["ssh".to_string()],
            builtin_probes: true,
            tags: Vec::new(),
        };
        let scanner = Scanner::new(config, DataRegistry::default(), TestConnector);
        let execution = scanner
            .scan(vec![(
                Target {
                    original: "127.0.0.1".to_string(),
                    hostname: None,
                    address: address.ip(),
                },
                vec![address.port()],
            )])
            .await
            .expect("scan");

        let endpoint = execution.report.targets[0]
            .endpoints
            .get(&address.port())
            .expect("endpoint");
        assert_eq!(endpoint.state, EndpointState::Open);
        assert!(
            endpoint
                .fingerprint
                .as_ref()
                .is_some_and(|fp| fp.handshake_observed)
        );
        task.await.expect("server");
    }

    #[derive(Clone, Default)]
    struct SlowConnector;

    #[async_trait]
    impl Connector for SlowConnector {
        async fn connect(
            &self,
            _address: IpAddr,
            _port: u16,
            _transport: Transport,
            _timeout_window: Duration,
            _interface_name: Option<&str>,
            _server_name: Option<&str>,
        ) -> std::io::Result<ConnectOutcome> {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let accept_task = tokio::spawn(async move {
                let _ = listener.accept().await;
            });
            let stream = TcpStream::connect(address).await?;
            let _ = accept_task.await;
            Ok(ConnectOutcome {
                connection: ProbeConnection::Tcp(stream),
                latency: Duration::from_millis(50),
            })
        }
    }

    #[tokio::test]
    async fn connect_scan_runs_ports_concurrently() {
        let config = ScanConfig {
            profile_name: "test".to_string(),
            recipe_name: None,
            transport: Transport::Tcp,
            interface: None,
            show_all_states: false,
            quiet: false,
            progress_mode: crate::cli::ProgressMode::Auto,
            default_ports: vec![1, 2, 3, 4],
            concurrency: 4,
            connect_timeout: Duration::from_secs(1),
            adaptive_connect_timeout: false,
            probe_timeout: Duration::from_millis(1),
            http_body_preview_bytes: 4096,
            retries: 0,
            enabled_probes: Vec::new(),
            builtin_probes: false,
            tags: Vec::new(),
        };
        let scanner = Scanner::new(config, DataRegistry::default(), SlowConnector);
        let start = Instant::now();
        let execution = scanner
            .scan(vec![(
                Target {
                    original: "127.0.0.1".to_string(),
                    hostname: None,
                    address: "127.0.0.1".parse().expect("ip"),
                },
                vec![1, 2, 3, 4],
            )])
            .await
            .expect("scan");

        assert_eq!(execution.report.targets[0].endpoints.len(), 4);
        assert!(start.elapsed() < Duration::from_millis(180));
    }

    #[derive(Clone)]
    struct CountingConnector {
        active: Arc<Mutex<usize>>,
        peak: Arc<Mutex<usize>>,
    }

    #[async_trait]
    impl Connector for CountingConnector {
        async fn connect(
            &self,
            _address: IpAddr,
            _port: u16,
            _transport: Transport,
            _timeout_window: Duration,
            _interface_name: Option<&str>,
            _server_name: Option<&str>,
        ) -> std::io::Result<ConnectOutcome> {
            {
                let mut active = self.active.lock().await;
                *active += 1;
                let mut peak = self.peak.lock().await;
                *peak = (*peak).max(*active);
            }

            tokio::time::sleep(Duration::from_millis(25)).await;

            {
                let mut active = self.active.lock().await;
                *active -= 1;
            }

            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "simulated timeout",
            ))
        }
    }

    #[tokio::test]
    async fn tcp_connect_scan_caps_per_target_inflight_work() {
        let connector = CountingConnector {
            active: Arc::new(Mutex::new(0)),
            peak: Arc::new(Mutex::new(0)),
        };
        let peak = connector.peak.clone();
        let config = ScanConfig {
            profile_name: "test".to_string(),
            recipe_name: None,
            transport: Transport::Tcp,
            interface: None,
            show_all_states: false,
            quiet: false,
            progress_mode: crate::cli::ProgressMode::Auto,
            default_ports: (1..=300).collect(),
            concurrency: 512,
            connect_timeout: Duration::from_secs(1),
            adaptive_connect_timeout: false,
            probe_timeout: Duration::from_millis(1),
            http_body_preview_bytes: 4096,
            retries: 0,
            enabled_probes: Vec::new(),
            builtin_probes: false,
            tags: Vec::new(),
        };
        let scanner = Scanner::new(config, DataRegistry::default(), connector);
        let _ = scanner
            .scan(vec![(
                Target {
                    original: "127.0.0.1".to_string(),
                    hostname: None,
                    address: "127.0.0.1".parse().expect("ip"),
                },
                (1..=300).collect(),
            )])
            .await
            .expect("scan");

        assert!(
            *peak.lock().await <= MAX_TCP_CONNECT_INFLIGHT_PER_TARGET,
            "observed peak inflight work exceeded cap"
        );
    }

    #[tokio::test]
    async fn tcp_connect_scan_respects_global_concurrency_across_targets() {
        let connector = CountingConnector {
            active: Arc::new(Mutex::new(0)),
            peak: Arc::new(Mutex::new(0)),
        };
        let peak = connector.peak.clone();
        let config = ScanConfig {
            profile_name: "test".to_string(),
            recipe_name: None,
            transport: Transport::Tcp,
            interface: None,
            show_all_states: false,
            quiet: false,
            progress_mode: crate::cli::ProgressMode::Auto,
            default_ports: (1..=20).collect(),
            concurrency: 16,
            connect_timeout: Duration::from_secs(1),
            adaptive_connect_timeout: false,
            probe_timeout: Duration::from_millis(1),
            http_body_preview_bytes: 4096,
            retries: 0,
            enabled_probes: Vec::new(),
            builtin_probes: false,
            tags: Vec::new(),
        };
        let scanner = Scanner::new(config, DataRegistry::default(), connector);
        let targets = (1..=8)
            .map(|octet| {
                (
                    Target {
                        original: format!("127.0.0.{octet}"),
                        hostname: None,
                        address: format!("127.0.0.{octet}").parse().expect("ip"),
                    },
                    (1..=20).collect(),
                )
            })
            .collect();

        let _ = scanner.scan(targets).await.expect("scan");

        assert!(
            *peak.lock().await <= 16,
            "observed peak inflight work exceeded requested global concurrency"
        );
    }

    #[test]
    fn adaptive_timeout_uses_safer_floor_for_multi_target_scans() {
        assert_eq!(
            derive_connect_timeout(Duration::from_millis(10), 1),
            Duration::from_millis(50)
        );
        assert_eq!(
            derive_connect_timeout(Duration::from_millis(10), 32),
            Duration::from_millis(150)
        );
    }

    #[test]
    fn service_matches_filter_conflicting_stack_matches() {
        let merged = merge_platform_matches(
            vec![
                FingerprintMatch {
                    label: "Unix-like: Linux / BSD / Darwin".to_string(),
                    family: "UnixLike".to_string(),
                    confidence: Confidence::Low,
                    evidence: vec![Evidence {
                        key: "source".to_string(),
                        value: "builtin-ttl-class".to_string(),
                    }],
                },
                FingerprintMatch {
                    label: "MikroTik RouterOS".to_string(),
                    family: "mikrotik:routeros".to_string(),
                    confidence: Confidence::High,
                    evidence: Vec::new(),
                },
                FingerprintMatch {
                    label: "Linux".to_string(),
                    family: "linux:linux_kernel".to_string(),
                    confidence: Confidence::Medium,
                    evidence: Vec::new(),
                },
            ],
            vec![FingerprintMatch {
                label: "Linux".to_string(),
                family: "linux:linux_kernel".to_string(),
                confidence: Confidence::High,
                evidence: vec![Evidence {
                    key: "service_signature".to_string(),
                    value: "http:tcp:null".to_string(),
                }],
            }],
        );

        let families = merged
            .iter()
            .map(|item| item.family.as_str())
            .collect::<Vec<_>>();
        assert_eq!(families, vec!["linux:linux_kernel"]);
    }

    #[test]
    fn service_matches_filter_conflicting_windows_stack_matches() {
        let merged = merge_platform_matches(
            vec![
                FingerprintMatch {
                    label: "Microsoft Windows family".to_string(),
                    family: "Windows".to_string(),
                    confidence: Confidence::Low,
                    evidence: vec![Evidence {
                        key: "source".to_string(),
                        value: "builtin-ttl-class".to_string(),
                    }],
                },
                FingerprintMatch {
                    label: "Microsoft Windows".to_string(),
                    family: "microsoft:windows".to_string(),
                    confidence: Confidence::Medium,
                    evidence: Vec::new(),
                },
                FingerprintMatch {
                    label: "PlayStation".to_string(),
                    family: "playstation".to_string(),
                    confidence: Confidence::Medium,
                    evidence: Vec::new(),
                },
                FingerprintMatch {
                    label: "Comware".to_string(),
                    family: "comware".to_string(),
                    confidence: Confidence::Medium,
                    evidence: Vec::new(),
                },
            ],
            vec![FingerprintMatch {
                label: "Microsoft Windows".to_string(),
                family: "microsoft:windows".to_string(),
                confidence: Confidence::High,
                evidence: vec![Evidence {
                    key: "service_signature".to_string(),
                    value: "http:tcp:null".to_string(),
                }],
            }],
        );

        let families = merged
            .iter()
            .map(|item| item.family.as_str())
            .collect::<Vec<_>>();
        assert_eq!(families, vec!["microsoft:windows"]);
    }
}
