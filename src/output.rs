use std::{io::Write, path::Path};

use serde::Serialize;
use termtree::Tree;

use crate::config::ScanRecipe;
use crate::model::{
    EndpointResult, EndpointState, HostResult, HostScanReport, NeighborReport, PingReport,
    ScanReport, TlsObservation, TraceReport,
};
use crate::probes::{BuiltinProbeMetadata, ExternalProbeDefinition};
use crate::technology::{
    EndpointInventory, EvidenceRef, HostInventory, Inventory, OperatingSystem,
};

fn render_safe_tree(mut tree: Tree<String>) -> String {
    fn sanitize(tree: &mut Tree<String>) {
        let escape = |c: char| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        };
        if tree.root.chars().any(escape) {
            let mut label = String::with_capacity(tree.root.len());
            for c in tree.root.chars() {
                if escape(c) {
                    label.extend(c.escape_default());
                } else {
                    label.push(c);
                }
            }
            tree.root = label;
        }
        for leaf in &mut tree.leaves {
            sanitize(leaf);
        }
    }
    sanitize(&mut tree);
    format!("{tree}\n")
}

pub fn render_inventory(inventory: &crate::technology::Inventory) -> String {
    let mut root = inventory_root(inventory);
    for host in &inventory.hosts {
        let mut host_tree = Tree::new(host.address.to_string());
        append_os(&mut host_tree, &host.operating_system, true);
        for ep in &host.endpoints {
            let mut endpoint = Tree::new(format!(
                "{}/{} ({}, identity {})",
                ep.port,
                ep.transport.as_str(),
                state_label(&ep.state),
                ep.identity_status
            ));
            if ep.latency_ms > 0 {
                endpoint.push(Tree::new(format!("Latency: {}ms", ep.latency_ms)));
            }
            for error in &ep.errors {
                endpoint.push(Tree::new(format!("Collection error: {error}")));
            }
            append_identification(
                &mut endpoint,
                ep,
                true,
                inventory.advisory_records.is_some(),
                false,
            );
            if ep.collection_errors > ep.errors.len() {
                endpoint.push(Tree::new(format!(
                    "Collection errors: {}",
                    ep.collection_errors
                )));
            }
            host_tree.push(endpoint);
        }
        root.push(host_tree);
    }
    render_safe_tree(root)
}

fn inventory_root(inventory: &Inventory) -> Tree<String> {
    let mut root = Tree::new(format!(
        "Technology inventory (NKDB {})",
        inventory.knowledge_revision
    ));
    if let Some(count) = inventory.advisory_records {
        root.push(Tree::new(format!(
            "Advisory review: {count} supplied records"
        )));
    }
    if let Some(c) = &inventory.nvd_coverage {
        root.push(Tree::new(format!("NVD snapshot {}: page offset {}, {} of {} CVEs, {} imported, {} skipped by status, {} unsupported configurations, {} outside catalog",
            c.timestamp, c.start_index, c.page_records, c.total_results, c.imported, c.skipped_status, c.skipped_configuration, c.outside_catalog)));
    }
    root
}

fn append_os(host_tree: &mut Tree<String>, os: &OperatingSystem, detailed: bool) {
    let status = os.status.replace('_', " ");
    let label = match &os.family {
        Some(family) => format!("{family} ({status})"),
        None => status,
    };
    host_tree.push(Tree::new(format!("OS: {label}")));
    if !detailed {
        return;
    }
    for matched in &os.stack_matches {
        let location = matched
            .port
            .map_or_else(|| "host fingerprint".into(), |p| format!("TCP port {p}"));
        host_tree.push(Tree::new(format!(
            "{} stack on {location} ({})",
            matched.family, matched.profile
        )));
    }
}

fn append_identification(
    endpoint: &mut Tree<String>,
    ep: &EndpointInventory,
    detailed: bool,
    reviewed: bool,
    has_raw: bool,
) {
    if let Some(note) = ep.external_identity_note {
        endpoint.push(Tree::new(format!(
            "External identity withheld: {}",
            note.replace('_', " ")
        )));
    }
    for service in &ep.services {
        endpoint.push(Tree::new(format!(
            "Service: {} ({})",
            service.name,
            service.basis.replace('_', " ")
        )));
    }
    for platform in &ep.service_platforms {
        endpoint.push(Tree::new(
            format!(
                "Service platform: {} {}",
                platform.environment,
                platform.declared_release.as_deref().unwrap_or("")
            )
            .trim_end()
            .to_string(),
        ));
    }
    for t in &ep.technologies {
        let mut product = Tree::new(format!(
            "{} {} ({}, {:?} version)",
            t.id,
            t.version.as_deref().unwrap_or("?"),
            t.role,
            t.version_status
        ));
        if reviewed {
            product.push(Tree::new(format!(
                "Advisory review: {}",
                t.advisory_status.replace('_', " ")
            )));
        }
        for d in t.declarations.iter().filter(|_| detailed) {
            let at = match &d.evidence {
                EvidenceRef::Probe {
                    observation,
                    probe,
                    field,
                } => format!("observation {observation}, {probe}.{field}"),
                EvidenceRef::Nmap { host, port, cpe } => {
                    format!("Nmap host {host}, port entry {port}, CPE {cpe}")
                }
            };
            product.push(Tree::new(format!(
                "{at} ({})",
                d.version.as_deref().unwrap_or("version unavailable")
            )));
        }
        endpoint.push(product);
    }
    for fact in ep.observed.iter().chain(&ep.review) {
        if has_raw
            && matches!(
                fact.name,
                "http.title"
                    | "http.server_product"
                    | "tls.cipher_suite"
                    | "tls.alpn"
                    | "http.via_header"
            )
        {
            continue;
        }
        endpoint.push(Tree::new(format!("{}: {}", fact.name, fact.value)));
    }
    for candidate in &ep.advisory_candidates {
        let mut item = Tree::new(format!(
            "{} on {} (potential, {})",
            candidate.id, candidate.product, candidate.applicability
        ));
        if let Some(config) = &candidate.configuration {
            item.push(Tree::new(format!(
                "{} = {} ({})",
                config.requirement.fact, config.requirement.equals, config.status
            )));
        }
        if let Some(condition) = &candidate.condition {
            item.push(Tree::new(condition.clone()));
        }
        item.push(Tree::new(candidate.review.to_owned()));
        item.push(Tree::new(candidate.source.clone()));
        endpoint.push(item);
    }
}

/// Render the raw scan without loading a technology catalog.
pub fn render_human_scan_report(report: &ScanReport, show_all_states: bool) -> String {
    render_port_report(report, show_all_states, None, false)
}

/// Render observations and their inventory together. The inventory must be
/// derived from the same report with its targets in the original order.
pub fn render_port_report(
    report: &ScanReport,
    show_all_states: bool,
    inventory: Option<&Inventory>,
    detailed: bool,
) -> String {
    let mut root = match inventory {
        Some(inv) if detailed => inventory_root(inv),
        _ => Tree::new("Scan report(s)".to_string()),
    };
    let mut rendered_targets = 0usize;

    let mut groups = std::collections::BTreeMap::<&str, Vec<usize>>::new();
    for (index, target) in report.targets.iter().enumerate() {
        groups
            .entry(&target.target.original)
            .or_default()
            .push(index);
    }
    if !show_all_states {
        let mut totals = std::collections::BTreeMap::new();
        for ep in report
            .targets
            .iter()
            .flat_map(|target| target.endpoints.values())
        {
            if matches!(
                ep.state,
                EndpointState::Closed | EndpointState::Filtered | EndpointState::Unreachable
            ) {
                *totals.entry(state_label(&ep.state)).or_insert(0usize) += 1;
            }
        }
        if !totals.is_empty() {
            let counts = totals
                .into_iter()
                .map(|(state, count)| format!("{count} {state}"))
                .collect::<Vec<_>>()
                .join(", ");
            root.push(Tree::new(format!(
                "Native port states: {counts} (use --all-states for details)"
            )));
        }
    }
    for (label, mut indices) in groups {
        indices.sort_by_key(|&i| report.targets[i].target.address);
        let grouped = indices.len() > 1;
        let mut group = Tree::new(label.to_owned());
        for i in indices {
            let target = &report.targets[i];
            let host_inventory = inventory.and_then(|inv| inv.hosts.get(i)).filter(|h| {
                h.address == target.target.address && h.hostname == target.target.hostname
            });
            if let Some(node) = render_scan_target_tree(
                target,
                show_all_states,
                grouped,
                report.identification.as_ref(),
                host_inventory,
                detailed,
                inventory.is_some_and(|inv| inv.advisory_records.is_some()),
            ) {
                if grouped {
                    group.push(node);
                } else {
                    root.push(node);
                }
                rendered_targets += 1;
            }
        }
        if grouped && !group.leaves.is_empty() {
            root.push(group);
        }
    }
    if rendered_targets == 0 {
        let message = if show_all_states {
            "no endpoints"
        } else {
            "no open ports"
        };
        root.push(Tree::new(match report.targets.as_slice() {
            [target] => format!("{}: {message}", render_target_label(target, false)),
            _ => message.to_string(),
        }));
    }

    if let Some(details) = &report.identification {
        if details.requests.is_empty() && details.hosts.is_empty() && details.complete {
            root.push(Tree::new("no candidate endpoints".to_string()));
        }
        for warning in &details.warnings {
            root.push(Tree::new(format!("Nmap warning: {warning}")));
        }
        if details.failures.is_empty()
            && let Some(error) = &details.error
        {
            root.push(Tree::new(format!("Nmap error: {error}")));
        }
    }
    render_safe_tree(root)
}

pub fn write_json_report(report: &ScanReport, path: &Path) -> anyhow::Result<()> {
    write_json_atomically(report, path)
}

pub fn filtered_scan_report(report: &ScanReport, show_all_states: bool) -> ScanReport {
    if show_all_states {
        return report.clone();
    }
    let external_candidates: std::collections::BTreeSet<_> = report
        .identification
        .iter()
        .flat_map(|details| &details.hosts)
        .flat_map(|host| {
            host.ports
                .iter()
                .filter(|port| is_visible_external_port(port))
                .map(move |port| (host.ip, port.port, port.protocol.as_str()))
        })
        .collect();
    let targets = report
        .targets
        .iter()
        .map(|target| crate::model::TargetReport {
            target: target.target.clone(),
            fingerprint: target.fingerprint.clone(),
            fingerprint_matches: target.fingerprint_matches.clone(),
            os_guesses: target.os_guesses.clone(),
            endpoints: target
                .endpoints
                .iter()
                .filter(|(_, endpoint)| {
                    is_visible_state(&endpoint.state)
                        || external_candidates.contains(&(
                            target.target.address,
                            endpoint.port,
                            endpoint.transport.wire_protocol(),
                        ))
                })
                .map(|(&port, endpoint)| (port, endpoint.clone()))
                .collect(),
        })
        .collect();
    ScanReport {
        metadata: report.metadata.clone(),
        identification: report.identification.clone(),
        targets,
    }
}

pub fn render_human_host_report(report: &HostScanReport, show_all_hosts: bool) -> String {
    let mut root = Tree::new("Host report(s)".to_string());

    let visible_targets = report
        .targets
        .iter()
        .filter(|target| show_all_hosts || target.reachable || report.targets.len() == 1)
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

    if !show_all_hosts && report.targets.len() > 1 {
        let omitted = report.targets.iter().filter(|host| !host.reachable).count();
        if omitted > 0 {
            root.push(Tree::new(format!(
                "{omitted} unreachable host(s); use --all-hosts for details"
            )));
        }
    }
    if root.leaves.is_empty() {
        root.push(Tree::new(if show_all_hosts {
            "no hosts".to_string()
        } else {
            "no reachable hosts".to_string()
        }));
    }

    render_safe_tree(root)
}

pub fn write_json_host_report(report: &HostScanReport, path: &Path) -> anyhow::Result<()> {
    write_json_atomically(report, path)
}

pub fn filtered_host_report(report: &HostScanReport, show_all_hosts: bool) -> HostScanReport {
    let mut filtered = report.clone();
    if !show_all_hosts {
        filtered.targets.retain(|target| target.reachable);
    }
    filtered
}

fn elapsed_ms(value: std::time::Duration) -> String {
    if !value.is_zero() && value.as_millis() == 0 {
        format!("{:.3}", value.as_secs_f64() * 1000.0)
    } else {
        value.as_millis().to_string()
    }
}

pub fn render_human_ping_report(report: &PingReport) -> String {
    let target = &report.metadata.target;
    let label = match &target.hostname {
        Some(hostname) => format!("{hostname} ({})", target.address),
        None => target.address.to_string(),
    };
    let mut root = Tree::new(format!(
        "Ping {} via {}",
        label,
        report.metadata.method.as_str().to_uppercase()
    ));
    if let Some(port) = report.metadata.port {
        root.push(Tree::new(format!("port: {port}")));
    }
    for reply in &report.replies {
        let label = if reply.success {
            format!("#{} {}", reply.seq, report.metadata.target.address)
        } else {
            format!("#{} *", reply.seq)
        };
        let mut node = Tree::new(label);
        node.push(Tree::new(format!("outcome: {}", reply.outcome)));
        if let Some(mac) = &reply.mac_address {
            node.push(Tree::new(format!("MAC: {mac}")));
        }
        if let Some(latency) = reply.latency {
            node.push(Tree::new(format!("RTT: {}ms", elapsed_ms(latency))));
        }
        if let Some(ttl_hint) = reply.ttl_hint {
            node.push(Tree::new(format!("TTL: {ttl_hint}")));
        }
        root.push(node);
    }
    let mut summary = format!(
        "summary: tx={} rx={} loss={:.1}%",
        report.summary.transmitted, report.summary.received, report.summary.packet_loss_percent,
    );
    if let (Some(min), Some(avg), Some(max)) =
        (report.summary.min, report.summary.avg, report.summary.max)
    {
        summary.push_str(&format!(
            " min/avg/max={}/{}/{}ms",
            elapsed_ms(min),
            elapsed_ms(avg),
            elapsed_ms(max)
        ));
    }
    root.push(Tree::new(summary));
    if !report.errors.is_empty() {
        for error in &report.errors {
            root.push(Tree::new(format!("error: {error}")));
        }
    }
    render_safe_tree(root)
}

pub fn write_json_ping_report(report: &PingReport, path: &Path) -> anyhow::Result<()> {
    write_json_atomically(report, path)
}

pub fn render_human_trace_report(report: &TraceReport) -> String {
    let target = &report.metadata.target;
    let label = match &target.hostname {
        Some(hostname) => format!("{hostname} ({})", target.address),
        None => target.address.to_string(),
    };
    let mut root = Tree::new(format!(
        "Trace {} via {}",
        label,
        report.metadata.method.as_str().to_uppercase()
    ));
    if let Some(port) = report.metadata.port {
        root.push(Tree::new(format!("port: {port}")));
    }
    for hop in &report.hops {
        let label = match hop.responder {
            Some(responder) => format!("#{} {}", hop.ttl, responder),
            None => format!("#{} *", hop.ttl),
        };
        let mut node = Tree::new(label);
        node.push(Tree::new(format!(
            "Type: {}",
            if hop.reached_destination {
                "destination"
            } else if hop.ttl == 1 {
                "gateway"
            } else {
                "hop"
            }
        )));
        node.push(Tree::new(format!("outcome: {}", hop.outcome)));
        if let Some(mac) = &hop.mac_address {
            node.push(Tree::new(format!("MAC: {mac}")));
        }
        if let Some(latency) = hop.latency {
            node.push(Tree::new(format!("RTT: {}ms", elapsed_ms(latency))));
        }
        if let Some(ttl_hint) = hop.ttl_hint {
            node.push(Tree::new(format!("TTL: {ttl_hint}")));
        }
        if hop.reached_destination {
            node.push(Tree::new("destination reached".to_string()));
        }
        root.push(node);
    }
    if !report.errors.is_empty() {
        for error in &report.errors {
            root.push(Tree::new(format!("error: {error}")));
        }
    }
    render_safe_tree(root)
}

pub fn write_json_trace_report(report: &TraceReport, path: &Path) -> anyhow::Result<()> {
    write_json_atomically(report, path)
}

pub fn render_human_neighbor_report(report: &NeighborReport) -> String {
    let target = &report.metadata.target;
    let label = match &target.hostname {
        Some(hostname) => format!("{hostname} ({})", target.address),
        None => target.address.to_string(),
    };
    let mut root = Tree::new(format!(
        "Neighbor {} via {}",
        label,
        report.metadata.method.as_str().to_uppercase()
    ));
    if let Some(result) = &report.result {
        root.push(Tree::new(format!("resolved-ip: {}", result.resolved_ip)));
        root.push(Tree::new(format!("mac: {}", result.mac_address)));
        root.push(Tree::new(format!(
            "latency: {}ms",
            elapsed_ms(result.latency)
        )));
        let mut interface = format!(
            "interface: {} (index {})",
            result.interface_name, result.interface_index
        );
        if let Some(name) = &result.interface_friendly_name
            && name != &result.interface_name
        {
            interface.push_str(&format!(" {name}"));
        }
        root.push(Tree::new(interface));
    } else {
        root.push(Tree::new("no neighbor information".to_string()));
    }
    if !report.errors.is_empty() {
        for error in &report.errors {
            root.push(Tree::new(format!("error: {error}")));
        }
    }
    render_safe_tree(root)
}

pub fn write_json_neighbor_report(report: &NeighborReport, path: &Path) -> anyhow::Result<()> {
    write_json_atomically(report, path)
}

fn write_json_atomically<T: Serialize>(value: &T, path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
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

    render_safe_tree(root)
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

    render_safe_tree(root)
}

fn render_endpoint_tree(
    endpoint: &EndpointResult,
    identity: Option<&EndpointInventory>,
    detailed: bool,
    reviewed: bool,
) -> Tree<String> {
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
    if let Some(identity) = identity {
        if identity.identity_status == "conflicting"
            || (detailed && identity.identity_status == "unknown")
        {
            node.push(Tree::new(format!(
                "Product identity: {}",
                identity.identity_status
            )));
        }
        append_identification(&mut node, identity, detailed, reviewed, true);
    }
    let mut seen = std::collections::BTreeSet::new();
    for (index, obs) in endpoint.observations.iter().enumerate() {
        let mut observation = Tree::new(format!("Observation {index} ({})", obs.probe_id));
        let grouped = endpoint.observations.len() > 1 && detailed;
        if grouped {
            seen.clear();
        }
        let mut push = |line: String| {
            if seen.insert(line.clone()) {
                if grouped {
                    observation.push(Tree::new(line));
                } else {
                    node.push(Tree::new(line));
                }
            }
        };
        if let Some(service) = &obs.service_hint
            && !identity.is_some_and(|id| id.services.iter().any(|s| s.name == service.name))
        {
            push(format!("service: {}", service.name));
        }
        for item in &obs.evidence {
            let label = match item.key.as_str() {
                "server" | "title" | "description" | "generator" => item.key.as_str(),
                "location" => "Location",
                "x-powered-by" => "X-Powered-By",
                "via" => "Via",
                "x-cache" => "X-Cache",
                "cf-cache-status" => "CF-Cache-Status",
                "alt-svc" => "Alt-Svc",
                "access-control-allow-origin" => "Access-Control-Allow-Origin",
                "access-control-allow-credentials" => "Access-Control-Allow-Credentials",
                "set-cookie" => { push("Set-Cookie: present".into()); continue; }
                "match" | "open_signal" | "instance" => item.key.as_str(),
                "body_preview" | "status_line" | "default_port" | "response_validated" | "generator_validated" => continue,
                key if detailed && !identity.is_some_and(|id| id.observed.iter().any(|fact| matches!(fact.evidence, EvidenceRef::Probe { observation, field, .. } if observation == index && field == key))) => key,
                _ => continue,
            };
            push(format!("{label}: {}", truncate(&item.value, 160)));
        }
        if let Some(banner) = &obs.banner {
            if banner.raw.starts_with("HTTP/") {
                // Older reports may only contain Location in the captured head.
                if !obs.evidence.iter().any(|e| e.key == "location") {
                    for value in crate::probes::extract_header_values(&banner.raw, "location") {
                        push(format!("Location: {}", truncate(&value, 160)));
                    }
                }
                if let Some(status) = banner.raw.lines().next() {
                    push(format!("banner: {}", truncate(status, 160)));
                }
            } else if !banner.normalized.trim().is_empty() {
                push(format!(
                    "banner: {}",
                    truncate(banner.normalized.trim(), 160)
                ));
            }
        }
        if let Some(tls) = &obs.tls {
            push(format!("tls: {}", summarize_tls(tls)));
            if detailed {
                for issuer in &tls.certificate_issuers {
                    push(format!("Certificate issuer: {}", truncate(issuer, 160)));
                }
                push("Certificate trust: not verified".into());
            }
        }
        if !observation.leaves.is_empty() {
            node.push(observation);
        }
    }
    for error in &endpoint.errors {
        node.push(Tree::new(format!("error: {error}")));
    }
    node
}

fn matches_external_port(endpoint: &EndpointResult, port: &crate::nmap::PortDetails) -> bool {
    endpoint.port == port.port && endpoint.transport.wire_protocol() == port.protocol
}

fn is_visible_external_port(port: &crate::nmap::PortDetails) -> bool {
    matches!(port.state.state.as_str(), "open" | "open|filtered")
}

fn append_external_port(
    node: &mut Tree<String>,
    port: &crate::nmap::PortDetails,
    native: Option<&EndpointResult>,
) {
    if !native.is_some_and(|endpoint| {
        state_label(&endpoint.state).eq_ignore_ascii_case(&port.state.state)
    }) {
        node.push(Tree::new(format!("state: {}", port.state.state)));
    }
    let native_service = native.and_then(primary_service);
    if let Some(reason) = &port.state.reason {
        node.push(Tree::new(format!("reason: {reason}")));
    }
    if let Some(service) = &port.service {
        for (label, value) in [
            ("service", &service.name),
            ("tunnel", &service.tunnel),
            ("product", &service.product),
            ("version", &service.version),
            ("info", &service.extra_info),
            ("hostname", &service.hostname),
            ("OS type", &service.os_type),
            ("device type", &service.device_type),
            ("method", &service.method),
        ] {
            if let Some(value) = value {
                if label == "service"
                    && native_service
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case(value))
                {
                    continue;
                }
                node.push(Tree::new(format!("{label}: {value}")));
            }
        }
        if !service.cpes.is_empty() {
            let mut cpes = Tree::new("cpes".to_string());
            for cpe in &service.cpes {
                cpes.push(Tree::new(cpe.clone()));
            }
            node.push(cpes);
        }
    }
}

fn preferred_os_match(matches: &[crate::nmap::OsMatch]) -> Option<&crate::nmap::OsMatch> {
    fn rank(candidate: &crate::nmap::OsMatch) -> (u8, bool, bool) {
        let general_purpose = !candidate.classes.is_empty()
            && candidate
                .classes
                .iter()
                .all(|class| class.device_type.as_deref() == Some("general purpose"));
        let generic_linux = (candidate.name == "Linux"
            || candidate
                .name
                .strip_prefix("Linux ")
                .is_some_and(|version| version.starts_with(|c: char| c.is_ascii_digit())))
            && (candidate.classes.is_empty() || general_purpose);
        (candidate.accuracy, generic_linux, general_purpose)
    }

    // Preserve source order for equally ranked matches. Accuracy always wins;
    // broader OS descriptions break ties without inferring a distribution.
    matches.iter().fold(None, |best, candidate| match best {
        Some(current) if rank(current) >= rank(candidate) => Some(current),
        _ => Some(candidate),
    })
}

fn render_scan_target_tree(
    target: &crate::model::TargetReport,
    show_all_states: bool,
    grouped: bool,
    identification: Option<&crate::nmap::Identification>,
    inventory: Option<&HostInventory>,
    detailed: bool,
    reviewed: bool,
) -> Option<Tree<String>> {
    let mut target_tree = Tree::new(render_target_label(target, grouped));
    if let Some(inv) = inventory
        && (inv.operating_system.status != "unknown" || (detailed && !inv.endpoints.is_empty()))
    {
        append_os(&mut target_tree, &inv.operating_system, detailed);
    }
    let host = identification.and_then(|details| {
        details
            .hosts
            .iter()
            .find(|host| host.ip == target.target.address)
    });
    let external_ports: std::collections::BTreeMap<_, _> = host
        .into_iter()
        .flat_map(|host| &host.ports)
        .map(|port| ((port.port, port.protocol.as_str()), port))
        .collect();
    for endpoint in target.endpoints.values() {
        let protocol = endpoint.transport.wire_protocol();
        let external = external_ports.get(&(endpoint.port, protocol)).copied();
        if show_all_states
            || is_visible_state(&endpoint.state)
            || endpoint.state == EndpointState::Error
            || external.is_some_and(is_visible_external_port)
        {
            let identity = inventory.and_then(|host| {
                host.endpoints
                    .binary_search_by_key(&endpoint.port, |e| e.port)
                    .ok()
                    .map(|i| &host.endpoints[i])
            });
            let mut node = render_endpoint_tree(endpoint, identity, detailed, reviewed);
            if let Some(port) = external {
                append_external_port(&mut node, port, Some(endpoint));
            }
            target_tree.push(node);
        }
    }
    if let Some(host) = host {
        for port in &host.ports {
            if !target
                .endpoints
                .get(&port.port)
                .is_some_and(|endpoint| matches_external_port(endpoint, port))
                && (show_all_states || is_visible_external_port(port))
            {
                let mut node = Tree::new(format!("{}/{}", port.port, port.protocol.to_uppercase()));
                append_external_port(&mut node, port, None);
                target_tree.push(node);
            }
        }
        for summary in &host.port_summaries {
            let mut node = Tree::new(format!(
                "Nmap port summary: {} port(s): {}",
                summary.count, summary.state
            ));
            for reason in &summary.reasons {
                node.push(Tree::new(format!(
                    "{}: {} port(s)",
                    reason.reason, reason.count
                )));
            }
            target_tree.push(node);
        }
        if let Some(os) = preferred_os_match(&host.os_matches) {
            target_tree.push(Tree::new(format!("OS: {} ({}%)", os.name, os.accuracy)));
        }
    }
    if let Some(details) = identification {
        for failure in &details.failures {
            if failure.ip == target.target.address {
                target_tree.push(Tree::new(format!("Nmap error: {}", failure.error)));
            }
        }
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
        _ if target
            .target
            .original
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|socket| socket.ip() == target.target.address) =>
        {
            address
        }
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
            parts.push(format!("latency={}ms", elapsed_ms(latency)));
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

fn state_label(state: &EndpointState) -> &'static str {
    match state {
        EndpointState::Open => "Open",
        EndpointState::OpenFiltered => "Open|Filtered",
        EndpointState::Closed => "Closed",
        EndpointState::Filtered => "Filtered",
        EndpointState::Unreachable => "Unreachable",
        EndpointState::Error => "Error",
    }
}

fn is_visible_state(state: &EndpointState) -> bool {
    matches!(state, EndpointState::Open | EndpointState::OpenFiltered)
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
    match value.char_indices().nth(limit) {
        Some((end, _)) => format!("{}...", &value[..end]),
        None => value.to_owned(),
    }
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
            identification: None,
            metadata: ScanMetadata {
                schema_version: crate::model::REPORT_SCHEMA_VERSION,
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

    fn identified_report() -> ScanReport {
        let mut report = sample_report();
        report.identification = Some(
            serde_json::from_value(serde_json::json!({
                "source": "nmap", "version": "test", "complete": true, "error": null,
                "hosts": [{
                    "ip": "127.0.0.1",
                    "ports": [
                        {"port": 22, "protocol": "tcp", "state": {"state": "open"},
                         "service": {"name": "ssh", "product": "OpenSSH", "version": "9.9"}},
                        {"port": 80, "protocol": "tcp", "state": {"state": "open"}}
                    ],
                    "os_matches": [{"name": "Linux", "accuracy": 98}]
                }]
            }))
            .unwrap(),
        );
        report
    }

    #[test]
    fn external_identification_merges_into_native_host_and_port_nodes() {
        let report = identified_report();
        let before = serde_json::to_value(&report).unwrap();
        let rendered = render_human_scan_report(&report, false);
        assert_eq!(rendered.matches("127.0.0.1").count(), 1);
        assert_eq!(rendered.matches("22/SYN").count(), 1);
        assert!(!rendered.contains("22/TCP"));
        let ssh = rendered
            .split("22/SYN")
            .nth(1)
            .unwrap()
            .split("80/TCP")
            .next()
            .unwrap();
        assert!(ssh.contains("banner: SSH-2.0-test"));
        assert!(ssh.contains("product: OpenSSH"));
        assert!(ssh.contains("version: 9.9"));
        assert!(rendered.contains("OS: Linux (98%)"));
        // A later external response must not erase the native filtered state.
        let http = rendered.split("80/TCP").nth(1).unwrap();
        assert!(http.contains("state: Filtered"));
        assert!(http.contains("state: open"));
        assert_eq!(before, serde_json::to_value(&report).unwrap());
    }

    #[test]
    fn json_keeps_native_observations_for_externally_open_ports() {
        let mut report = identified_report();
        let filtered = filtered_scan_report(&report, false);
        assert_eq!(
            filtered.targets[0].endpoints[&80].state,
            EndpointState::Filtered
        );
        assert_eq!(filtered.identification, report.identification);
        assert_eq!(report.targets[0].endpoints.len(), 2);

        let port = &mut report.identification.as_mut().unwrap().hosts[0].ports[1];
        port.protocol = "udp".into();
        assert!(
            !filtered_scan_report(&report, false).targets[0]
                .endpoints
                .contains_key(&80)
        );
        report.targets[0].endpoints.get_mut(&80).unwrap().transport = Transport::Quic;
        assert!(
            filtered_scan_report(&report, false).targets[0]
                .endpoints
                .contains_key(&80)
        );
        report.identification.as_mut().unwrap().hosts[0].ip = "127.0.0.2".parse().unwrap();
        assert!(
            !filtered_scan_report(&report, false).targets[0]
                .endpoints
                .contains_key(&80)
        );
    }

    #[test]
    fn merged_fields_prefer_native_values_without_hiding_disagreements() {
        let mut report = identified_report();
        let rendered = render_human_scan_report(&report, false);
        let ssh = rendered
            .split("22/SYN")
            .nth(1)
            .unwrap()
            .split("80/TCP")
            .next()
            .unwrap();
        assert_eq!(ssh.matches("state:").count(), 1);
        assert_eq!(ssh.matches("service:").count(), 1);
        assert!(ssh.contains("state: Open"));
        assert!(ssh.contains("service: ssh"));
        assert!(!rendered.contains("(Nmap)"));

        let endpoint = report.targets[0].endpoints.get_mut(&22).unwrap();
        endpoint.state = EndpointState::OpenFiltered;
        let port = &mut report.identification.as_mut().unwrap().hosts[0].ports[0];
        port.state.state = "open|filtered".into();
        port.service.as_mut().unwrap().name = Some("SSH".into());
        let rendered = render_human_scan_report(&report, false);
        let ssh = rendered
            .split("22/SYN")
            .nth(1)
            .unwrap()
            .split("80/TCP")
            .next()
            .unwrap();
        assert_eq!(ssh.matches("state:").count(), 1);
        assert_eq!(ssh.matches("service:").count(), 1);
        assert!(ssh.contains("state: Open|Filtered"));

        let port = &mut report.identification.as_mut().unwrap().hosts[0].ports[0];
        port.state.state = "closed".into();
        port.service.as_mut().unwrap().name = Some("other".into());
        let rendered = render_human_scan_report(&report, false);
        let ssh = rendered
            .split("22/SYN")
            .nth(1)
            .unwrap()
            .split("80/TCP")
            .next()
            .unwrap();
        assert!(ssh.contains("state: Open|Filtered"));
        assert!(ssh.contains("state: closed"));
        assert!(ssh.contains("service: ssh"));
        assert!(ssh.contains("service: other"));
    }

    #[test]
    fn os_display_selects_one_match_and_prefers_generic_linux_on_accuracy_ties() {
        let mut report = identified_report();
        let matches = &mut report.identification.as_mut().unwrap().hosts[0].os_matches;
        *matches = [
            ("OpenWrt 21.02 (Linux 5.4)", 97),
            ("MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)", 97),
            ("Linux 4.15 - 5.19", 97),
            ("Linux 6.0", 96),
            ("Linux 4.19", 96),
        ]
        .into_iter()
        .map(|(name, accuracy)| crate::nmap::OsMatch {
            name: name.into(),
            accuracy,
            classes: vec![],
        })
        .collect();
        let before = serde_json::to_value(&report).unwrap();
        let rendered = render_human_scan_report(&report, false);
        assert_eq!(rendered.matches("OS:").count(), 1);
        assert!(rendered.contains("OS: Linux 4.15 - 5.19 (97%)"));
        assert!(!rendered.contains("OpenWrt"));
        assert!(!rendered.contains("Linux 6.0"));
        assert_eq!(before, serde_json::to_value(&report).unwrap());

        let matches = &mut report.identification.as_mut().unwrap().hosts[0].os_matches;
        matches[0].accuracy = 98;
        assert_eq!(preferred_os_match(matches).unwrap().name, matches[0].name);
        matches.clear();
        assert!(preferred_os_match(matches).is_none());
    }

    #[test]
    fn external_ports_match_wire_protocol_and_respect_visibility() {
        let mut report = identified_report();
        let ports = &mut report.identification.as_mut().unwrap().hosts[0].ports;
        ports[0].protocol = "udp".into();
        ports[1].state.state = "closed".into();
        let rendered = render_human_scan_report(&report, false);
        assert!(rendered.contains("22/UDP"));
        let native = rendered
            .split("22/SYN")
            .nth(1)
            .unwrap()
            .split("22/UDP")
            .next()
            .unwrap();
        assert!(!native.contains("product:"));
        assert!(!rendered.contains("80/TCP"));
        assert!(render_human_scan_report(&report, true).contains("state: closed"));
        report.targets[0].endpoints.get_mut(&22).unwrap().transport = Transport::Quic;
        let rendered = render_human_scan_report(&report, false);
        assert!(rendered.contains("22/QUIC"));
        assert!(!rendered.contains("22/UDP"));
        assert!(rendered.contains("product: OpenSSH"));
    }

    #[test]
    fn external_failures_and_summaries_remain_under_the_target() {
        let mut report = identified_report();
        report.targets[0].endpoints.clear();
        let details = report.identification.as_mut().unwrap();
        details.hosts[0].ports.clear();
        details.hosts[0]
            .port_summaries
            .push(crate::nmap::PortSummary {
                state: "closed".into(),
                count: 10,
                reasons: vec![],
            });
        let rendered = render_human_scan_report(&report, false);
        assert!(rendered.contains("Nmap port summary: 10 port(s): closed"));
        assert!(rendered.contains("OS: Linux"));
        let details = report.identification.as_mut().unwrap();
        details.hosts.clear();
        details.complete = false;
        details.failures.push(crate::nmap::IdentificationFailure {
            ip: report.targets[0].target.address,
            error: "timed out".into(),
        });
        let rendered = render_human_scan_report(&report, false);
        assert!(rendered.contains("example (127.0.0.1)"));
        assert!(rendered.contains("Nmap error: timed out"));
        assert!(!rendered.contains("no open ports"));
    }

    #[test]
    fn human_output_includes_open_probe_details() {
        let rendered = render_human_scan_report(&sample_report(), false);
        assert!(rendered.contains("22/SYN"));
        assert!(rendered.contains("service: ssh"));
        assert!(rendered.contains("banner: SSH-2.0-test"));
    }

    #[test]
    fn json_report_write_is_complete_and_leaves_no_temporary_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("report.json");
        write_json_report(&sample_report(), &path).expect("write report");

        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read report"))
                .expect("valid JSON report");
        assert_eq!(written["metadata"]["schema_version"], 1);
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("list directory")
                .count(),
            1
        );
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
            identification: None,
            metadata: ScanMetadata {
                schema_version: crate::model::REPORT_SCHEMA_VERSION,
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
                        original: "192.0.2.0/24".to_string(),
                        hostname: None,
                        address: IpAddr::from_str("192.0.2.101").expect("ip"),
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
                        original: "192.0.2.0/24".to_string(),
                        hostname: None,
                        address: IpAddr::from_str("192.0.2.102").expect("ip"),
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
        assert!(rendered.contains("192.0.2.0/24"));
        assert!(rendered.contains("192.0.2.102"));
        assert!(rendered.contains("443/TCP"));
        assert!(!rendered.contains("192.0.2.0/24 (192.0.2.102)"));
        assert!(!rendered.contains("192.0.2.101"));
    }

    #[test]
    fn human_output_shows_non_open_when_requested() {
        let rendered = render_human_scan_report(&sample_report(), true);
        assert!(rendered.contains("80/TCP"));
        assert!(rendered.contains("state: Filtered"));
    }

    #[test]
    fn json_scan_output_hides_non_open_by_default() {
        let report = filtered_scan_report(&sample_report(), false);
        assert_eq!(report.targets[0].endpoints.len(), 1);
        assert_eq!(
            report.targets[0]
                .endpoints
                .get(&22)
                .expect("endpoint")
                .state,
            EndpointState::Open
        );
    }

    #[test]
    fn json_scan_output_keeps_non_open_when_requested() {
        let report = filtered_scan_report(&sample_report(), true);
        assert_eq!(report.targets[0].endpoints.len(), 2);
        assert_eq!(
            report.targets[0]
                .endpoints
                .get(&80)
                .expect("endpoint")
                .state,
            EndpointState::Filtered
        );
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
                schema_version: crate::model::REPORT_SCHEMA_VERSION,
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

    #[test]
    fn json_host_output_hides_unreachable_by_default() {
        let report = HostScanReport {
            metadata: HostScanMetadata {
                schema_version: crate::model::REPORT_SCHEMA_VERSION,
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
                    observations: Vec::new(),
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

        let filtered = filtered_host_report(&report, false);
        assert_eq!(filtered.targets.len(), 1);
        assert_eq!(filtered.targets[0].target.original, "alive");
    }

    #[test]
    fn json_host_output_keeps_unreachable_when_requested() {
        let report = HostScanReport {
            metadata: HostScanMetadata {
                schema_version: crate::model::REPORT_SCHEMA_VERSION,
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
                    observations: Vec::new(),
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

        let filtered = filtered_host_report(&report, true);
        assert_eq!(filtered.targets.len(), 2);
    }
    #[test]
    fn human_output_escapes_terminal_and_direction_controls() {
        let text = render_safe_tree(Tree::new(
            "peer\u{1b}]52;c;secret\u{7}\nforged\u{202e}".into(),
        ));
        assert!(!text.contains('\u{1b}'));
        assert!(!text.contains('\u{7}'));
        assert!(!text.contains('\u{202e}'));
        assert!(text.contains("\\nforged"));
    }
}
