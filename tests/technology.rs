use nrev::{
    model::{Banner, EndpointResult, Evidence, ScanReport, Transport},
    technology::{Advisories, BUILTIN_DATABASE, IdentityStatus, KnowledgeBase, VersionStatus},
};
use serde_json::{Value, json};
use std::{process::Command, sync::LazyLock};

const REPORT: &[u8] = include_bytes!("../samples/inventory/scan.json");
const ADVISORIES: &[u8] = include_bytes!("../samples/inventory/advisories.json");
static DB: LazyLock<KnowledgeBase> = LazyLock::new(|| KnowledgeBase::builtin().unwrap());

fn sample() -> ScanReport {
    serde_json::from_slice(REPORT).unwrap()
}

fn endpoint(report: &mut ScanReport) -> &mut EndpointResult {
    report.targets[0].endpoints.get_mut(&8080).unwrap()
}

fn evidence(key: &str, value: &str) -> Evidence {
    Evidence {
        key: key.into(),
        value: value.into(),
    }
}

fn http(report: &mut ScanReport, server: &str) {
    endpoint(report).observations[0].evidence = vec![
        evidence("status_line", "HTTP/1.1 404 Not Found"),
        evidence("server", server),
    ];
}

fn inventory(report: &ScanReport) -> Value {
    let advisories = Advisories::from_bytes(ADVISORIES, &DB).unwrap();
    serde_json::to_value(DB.inventory(report,Some(&advisories)).unwrap()).unwrap()["hosts"][0]["endpoints"][0].clone()
}

#[test]
fn upstream_bounds_partial_versions_and_packaging() {
    for (server, outcome) in [
        ("nginx/0.6.17", None),
        ("nginx/0.6.18", Some("in_upstream_range")),
        ("nginx/1.20.0", Some("in_upstream_range")),
        ("nginx/1.20.1", None),
        ("nginx/1.20", Some("unknown_version")),
        ("nginx", Some("unknown_version")),
        ("nginx/1.20.0-1ubuntu1", Some("unknown_version")),
        ("nginx/1.20.0 (Ubuntu)", Some("distribution_review")),
    ] {
        let mut report = sample();
        http(&mut report, server);
        let result = inventory(&report);
        assert_eq!(
            result["advisory_candidates"][0]["applicability"].as_str(),
            outcome,
            "{server}"
        );
        if outcome.is_some() {
            let c = &result["advisory_candidates"][0];
            assert_eq!(c["id"], "CVE-2021-23017");
            assert_eq!(c["classification"], "potential");
            assert_eq!(c["fixed"], "1.20.1");
        }
    }
}

#[test]
fn replay_skips_unreliable_fields_and_keeps_roles_separate() {
    let mut report = sample();
    let ep = endpoint(&mut report);
    let obs = &mut ep.observations[0];
    obs.evidence.extend([
        evidence("set-cookie", "secret-value"),
        evidence("body_preview", "nginx/999.0.0"),
        evidence("via", "1.1 private-name"),
    ]);
    let result = DB.identify(ep).unwrap();
    assert_eq!(result.technologies.len(), 2);
    assert_eq!(result.identity_status, "inferred");
    let out = serde_json::to_string(&result).unwrap();
    for value in ["secret-value", "999.0.0", "private-name"] {
        assert!(!out.contains(value));
    }
    assert!(result.observed.iter().any(|f| f.name == "http.via_header"));
    ep.observations[0].evidence[0].value = "FTP/1.0 200 OK".into();
    assert_eq!(DB.identify(ep).unwrap().identity_status, "unknown");
    http(&mut report, "nginx/1.2.3");
    let ep = endpoint(&mut report);
    ep.transport = Transport::Udp;
    assert_eq!(DB.identify(ep).unwrap().identity_status, "unknown");
    ep.transport = Transport::Tcp;
    ep.observations[0].tags.push("external".into());
    assert_eq!(DB.identify(ep).unwrap().identity_status, "unknown");
}

#[test]
fn replay_shows_latency_http_title_and_collection_failure_together() {
    let mut report = sample();
    let ep = endpoint(&mut report);
    ep.latency = std::time::Duration::from_millis(7);
    ep.observations[0].evidence = vec![
        evidence("status_line", "HTTP/1.1 307 Temporary Redirect"),
        evidence("title", "307 Temporary Redirect"),
    ];
    ep.errors.push("tls: TLS error: handshake failed".into());
    let result = DB.inventory(&report, None).unwrap();
    let human = nrev::output::render_inventory(&result);
    for text in [
        "Latency: 7ms",
        "http.title: 307 Temporary Redirect",
        "Collection error: tls: TLS error: handshake failed",
    ] {
        assert!(human.contains(text), "{human}");
    }
    let json = serde_json::to_value(result).unwrap();
    let endpoint = &json["hosts"][0]["endpoints"][0];
    assert_eq!(endpoint["identity_status"], "unknown");
    assert_eq!(endpoint["errors"][0], "tls: TLS error: handshake failed");
}

#[test]
fn uncatalogued_products_remain_attributable_peer_claims() {
    let mut report = sample();
    http(&mut report, "LocalServer/3.2 Runtime/8 (private comment)");
    let result = DB.identify(endpoint(&mut report)).unwrap();
    assert!(result.technologies.is_empty());
    let tokens: Vec<_> = result
        .observed
        .iter()
        .filter(|f| f.name == "http.server_product")
        .map(|f| f.value.as_str())
        .collect();
    assert_eq!(tokens, ["LocalServer/3.2", "Runtime/8"]);
    let ep = endpoint(&mut report);
    ep.observations[0].probe_id = "ssh".into();
    ep.observations[0].banner = Some(nrev::probes::normalize_banner(
        "SSH-2.0-LocalService_4.2 private comment\r\n".into(),
    ));
    let result = DB.identify(ep).unwrap();
    assert!(result.technologies.is_empty());
    assert!(
        result
            .observed
            .iter()
            .any(|f| f.name == "ssh.software" && f.value == "LocalService_4.2")
    );
}

#[test]
fn duplicate_fields_and_duplicate_observations_do_not_confirm_identity() {
    let mut report = sample();
    http(&mut report, "nginx/1.19.0");
    let ep = endpoint(&mut report);
    ep.observations.push(ep.observations[0].clone());
    let out = DB.identify(ep).unwrap();
    assert_eq!(out.technologies.len(), 1);
    assert_eq!(out.technologies[0].identity, IdentityStatus::Inferred);
    ep.observations.truncate(1);
    ep.observations[0]
        .evidence
        .push(evidence("server", "Apache/2.4.62"));
    assert_eq!(DB.identify(ep).unwrap().identity_status, "unknown");
}

#[test]
fn conflicting_versions_and_identities_are_distinct() {
    let mut report = sample();
    http(&mut report, "nginx/1.19.0");
    let ep = endpoint(&mut report);
    let mut other = ep.observations[0].clone();
    other.evidence[1].value = "nginx/1.20.1".into();
    ep.observations.push(other);
    let result = inventory(&report);
    assert_eq!(result["technologies"][0]["version_status"], "conflicting");
    assert!(result["technologies"][0]["version"].is_null());
    assert_eq!(
        result["advisory_candidates"][0]["applicability"],
        "conflicting_versions"
    );
    endpoint(&mut report).observations[1].evidence[1].value = "Apache/2.4.62".into();
    let result = inventory(&report);
    assert_eq!(result["identity_status"], "conflicting");
    assert_eq!(result["technologies"].as_array().unwrap().len(), 2);
    assert!(result.get("advisory_candidates").is_none());
}

#[test]
fn ssh_uses_complete_protocol_line_with_preamble() {
    let mut report = sample();
    let ep = endpoint(&mut report);
    let obs = &mut ep.observations[0];
    obs.probe_id = "ssh".into();
    for (raw, version, status) in [
        (
            "Notice\r\nSSH-2.0-OpenSSH_10.2p10 distro\r\n",
            Some("10.2p10"),
            VersionStatus::Declared,
        ),
        (
            "SSH-2.0-OpenSSH_for_Windows_9.4\r\n",
            Some("9.4"),
            VersionStatus::Partial,
        ),
        ("SSH-2.0-OpenSSH_10.2p1", None, VersionStatus::Missing),
        (
            "SSH-2.0-other OpenSSH_10.2p1\r\n",
            None,
            VersionStatus::Missing,
        ),
    ] {
        ep.observations[0].banner = Some(Banner {
            raw: raw.into(),
            normalized: "untrusted".into(),
        });
        let result = DB.identify(ep).unwrap();
        assert_eq!(
            result
                .technologies
                .first()
                .and_then(|t| t.version.as_deref()),
            version
        );
        if version.is_some() {
            assert_eq!(result.technologies[0].version_status, status);
        }
    }
}

#[test]
fn udp_validation_and_tds_review_are_independent_of_product() {
    let mut report = sample();
    let ep = endpoint(&mut report);
    ep.transport = Transport::Udp;
    let obs = &mut ep.observations[0];
    obs.probe_id = "ntp".into();
    obs.evidence = vec![
        evidence("response_validated", "false"),
        evidence("ntp_stratum", "2"),
    ];
    assert!(DB.identify(ep).unwrap().observed.is_empty());
    ep.observations[0].evidence[0].value = "true".into();
    assert_eq!(DB.identify(ep).unwrap().observed[0].value, "2");
    ep.transport = Transport::Tcp;
    ep.observations[0].probe_id = "mssql-prelogin".into();
    ep.observations[0].evidence = vec![evidence("encryption", "encrypt-not-supported")];
    assert!(DB.identify(ep).unwrap().review.is_empty());
    ep.observations[0]
        .evidence
        .push(evidence("response_validated", "true"));
    let result = DB.identify(ep).unwrap();
    assert!(result.technologies.is_empty());
    assert_eq!(result.review.len(), 1);
}

#[test]
fn external_cpes_join_only_probed_open_wire_endpoint() {
    let mut report = sample();
    http(&mut report, "nginx/1.20.0");
    for (address, port, protocol, method, expected) in [
        ("127.0.0.1", 8080, "tcp", "probed", "conflicting"),
        ("127.0.0.1", 8081, "tcp", "probed", "inferred"),
        ("127.0.0.1", 8080, "udp", "probed", "inferred"),
        ("127.0.0.1", 8080, "tcp", "table", "inferred"),
        ("127.0.0.2", 8080, "tcp", "probed", "inferred"),
    ] {
        report.identification=Some(serde_json::from_value(json!({
            "source":"nmap","version":"fixture","complete":true,"hosts":[{
                "ip":address,"os_matches":[],"ports":[{"port":port,"protocol":protocol,"state":{"state":"open"},
                    "service":{"method":method,"cpes":["cpe:/a:apache:http_server:2.4.63","cpe:/o:vendor:os"]}}]}]
        })).unwrap());
        assert_eq!(inventory(&report)["identity_status"], expected);
    }
}

#[test]
fn corrupt_catalog_advisories_and_report_are_rejected() {
    let mut catalog: Value = serde_json::from_slice(BUILTIN_DATABASE).unwrap();
    let product = catalog["products"][0].clone();
    catalog["products"].as_array_mut().unwrap().push(product);
    assert!(KnowledgeBase::from_bytes(&serde_json::to_vec(&catalog).unwrap()).is_err());
    catalog["products"].as_array_mut().unwrap().pop();
    catalog["products"][0]["signatures"][0]["pattern"] = "[".into();
    assert!(KnowledgeBase::from_bytes(&serde_json::to_vec(&catalog).unwrap()).is_err());
    assert!(KnowledgeBase::from_bytes(b"{}").is_err());
    let mut file: Value = serde_json::from_slice(ADVISORIES).unwrap();
    file["records"][0]["product"] = "cpe:2.3:a:f5:nginx_open_source:*:*:*:*:*:*:*:*".into();
    assert!(Advisories::from_bytes(&serde_json::to_vec(&file).unwrap(), &DB).is_ok());
    for invalid in ["0.6.18", "1.2", "distro", "1.2.3-1", "00.6.18"] {
        file["records"][0]["fixed"] = invalid.into();
        assert!(Advisories::from_bytes(&serde_json::to_vec(&file).unwrap(), &DB).is_err());
    }
    let mut report = sample();
    report.metadata.schema_version = 99;
    assert!(DB.inventory(&report, None).is_err());
    report.metadata.schema_version = 1;
    endpoint(&mut report).port += 1;
    assert!(DB.inventory(&report, None).is_err());
}

#[test]
fn cli_replays_samples_deterministically_and_fails_cleanly() {
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_nrev"))
            .args([
                "inventory",
                "samples/inventory/scan.json",
                "--advisories",
                "samples/inventory/advisories.json",
            ])
            .output()
            .unwrap()
    };
    let result = run();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, run().stdout);
    let inventory: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        inventory["hosts"][0]["endpoints"][0]["advisory_candidates"][0]["id"],
        "CVE-2021-23017"
    );
    let result = Command::new(env!("CARGO_BIN_EXE_nrev"))
        .args(["inventory", "samples/inventory/advisories.json"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
}

#[test]
fn http_subproducts_comments_and_same_exchange_agreement() {
    let mut report = sample();
    http(&mut report, "Apache/2.4.58 (Unix (build)) PHP/8.3.0");
    let ep = endpoint(&mut report);
    ep.observations[0]
        .evidence
        .push(evidence("x-powered-by", "PHP/8.3.0"));
    let detected = DB.identify(ep).unwrap();
    let php = detected
        .technologies
        .iter()
        .find(|t| t.id == "php:php")
        .unwrap();
    assert_eq!(php.declarations.len(), 2);
    assert_eq!(php.confidence, "weak_inference");
    assert_eq!(php.version.as_deref(), Some("8.3.0"));
    assert!(php.declarations.iter().any(|d| d.qualified));
    for server in [
        "(nginx/1.20.0)",
        "nginx/1.20.0 (incomplete",
        "Apache/2.4.58; nginx/1.20.0",
        "nginx/1.20.0 (ok)junk",
    ] {
        http(&mut report, server);
        assert_eq!(
            DB.identify(endpoint(&mut report)).unwrap().identity_status,
            "unknown"
        );
    }
}

#[test]
fn live_inventory_and_replay_agree_after_fragmented_ssh_identification() {
    use std::{io::Write, net::TcpListener, time::Duration};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        peer.write_all(b"Maintenance window\r\nSSH-2.").unwrap();
        std::thread::sleep(Duration::from_millis(10));
        peer.write_all(b"0-OpenSSH_9.2p1\r\n").unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raw.json");
    let out = Command::new(env!("CARGO_BIN_EXE_nrev"))
        .args([
            "port",
            &address.to_string(),
            "--connect-timeout-ms",
            "500",
            "--probes",
            "ssh",
            "--inventory",
            "--format",
            "json",
            "--quiet",
            "--output",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    server.join().unwrap();
    let replay = Command::new(env!("CARGO_BIN_EXE_nrev"))
        .arg("inventory")
        .arg(&path)
        .output()
        .unwrap();
    assert!(replay.status.success());
    assert_eq!(out.stdout, replay.stdout);
    let inventory: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        inventory["hosts"][0]["endpoints"][0]["technologies"][0]["version"],
        "9.2p1"
    );
}

#[test]
fn portable_patch_numbers_use_numeric_ordering() {
    let mut report = sample();
    let obs = &mut endpoint(&mut report).observations[0];
    obs.probe_id = "ssh".into();
    obs.banner = Some(Banner {
        raw: "SSH-2.0-OpenSSH_9.2p10\r\n".into(),
        normalized: String::new(),
    });
    let local=serde_json::to_vec(&json!({"schema":1,"records":[{"id":"LOCAL-1","product":"openbsd:openssh","source":"fixture","introduced":"9.2p2","fixed":"9.2p11"}]})).unwrap();
    let db = Advisories::from_bytes(&local, &DB).unwrap();
    let result = DB.inventory(&report, Some(&db)).unwrap();
    assert_eq!(
        result.hosts[0].endpoints[0].advisory_candidates[0].applicability,
        "in_upstream_range"
    );
}

#[test]
fn oversized_and_duplicate_rules_fail_closed() {
    let mut r = sample();
    let obs = &mut endpoint(&mut r).observations[0];
    obs.evidence = vec![evidence("server", "noise"); 129];
    assert!(DB.inventory(&r, None).is_err());
    let mut db: Value = serde_json::from_slice(BUILTIN_DATABASE).unwrap();
    let rule = db["products"][0]["signatures"][0].clone();
    db["products"][1]["signatures"][0] = rule;
    assert!(KnowledgeBase::from_bytes(&serde_json::to_vec(&db).unwrap()).is_err());
    assert!(KnowledgeBase::from_bytes(&vec![b' '; (256 << 10) + 1]).is_err());
}

#[test]
fn concurrent_replay_with_large_field_index_matches_embedded_result() {
    let mut db: Value = serde_json::from_slice(BUILTIN_DATABASE).unwrap();
    let products = db["products"].as_array_mut().unwrap();
    for n in 0..32 {
        let mut other = products[0].clone();
        other["id"] = format!("fixture:server_{n}").into();
        other["cpe_names"] = json!([]);
        other["signatures"] = json!([{"field":"server","pattern":format!("Example{n}")}]);
        products.push(other);
    }
    let expanded = KnowledgeBase::from_bytes(&serde_json::to_vec(&db).unwrap()).unwrap();
    let mut report = sample();
    let ep = &*endpoint(&mut report);
    let expected = serde_json::to_value(DB.identify(ep).unwrap()).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..50 {
                    assert_eq!(
                        serde_json::to_value(expanded.identify(ep).unwrap()).unwrap(),
                        expected
                    );
                }
            });
        }
    });
}

#[test]
fn replay_accepts_reviewed_catalog_and_rejects_unknown_catalog_schema() {
    let run = |catalog: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_nrev"))
            .args([
                "inventory",
                "samples/inventory/scan.json",
                "--format",
                "human",
                "--knowledge",
            ])
            .arg(catalog)
            .output()
            .unwrap()
    };
    let rendered = run(std::path::Path::new("knowledge/products.json"));
    assert!(rendered.status.success());
    assert!(String::from_utf8_lossy(&rendered.stdout).contains("nginx:nginx"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("future.json");
    let mut file: Value = serde_json::from_slice(BUILTIN_DATABASE).unwrap();
    file["schema"] = 2.into();
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    let refused = run(&path);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
}

#[test]
fn branched_vendor_ranges_preserve_gaps_and_coverage() {
    let db = Advisories::bundled(&DB).unwrap();
    for (version, expected) in [
        ("1.24.9", 0),
        ("1.25.0", 4),
        ("1.25.5", 4),
        ("1.25.6", 0),
        ("1.26.0", 4),
        ("1.26.1", 0),
    ] {
        let mut report = sample();
        http(&mut report, &format!("nginx/{version}"));
        let inv = DB.inventory(&report, Some(&db)).unwrap();
        let ep = &inv.hosts[0].endpoints[0];
        let quic_candidates: Vec<_> = ep
            .advisory_candidates
            .iter()
            .filter(|c| {
                matches!(
                    c.id.as_str(),
                    "CVE-2024-31079" | "CVE-2024-32760" | "CVE-2024-34161" | "CVE-2024-35200"
                )
            })
            .collect();
        assert_eq!(quic_candidates.len(), expected, "{version}");
        for candidate in quic_candidates {
            assert_eq!(
                candidate.configuration.as_ref().unwrap().status,
                "unobserved"
            );
        }
    }
    let unchecked = DB.inventory(&sample(), None).unwrap();
    assert_eq!(unchecked.advisory_records, None);
    assert_eq!(
        unchecked.hosts[0].endpoints[0].technologies[0].advisory_status,
        "not_checked"
    );
    let example = Advisories::from_bytes(ADVISORIES, &DB).unwrap();
    let mut report = sample();
    let inv = DB.inventory(&report, Some(&example)).unwrap();
    assert_eq!(inv.advisory_records, Some(1));
    assert!(
        inv.hosts[0].endpoints[0]
            .technologies
            .iter()
            .any(|t| t.id == "php:php" && t.advisory_status == "no_product_records")
    );
    http(&mut report, "nginx/1.20.1");
    let inv = DB.inventory(&report, Some(&example)).unwrap();
    assert_eq!(
        inv.hosts[0].endpoints[0].technologies[0].advisory_status,
        "outside_supplied_ranges"
    );
}

#[test]
fn bundled_advisories_respect_branch_fixes_and_product_scope() {
    let db = Advisories::bundled(&DB).unwrap();
    for (field, prefix, id, affected, fixed) in [
        (
            "generator",
            "WordPress ",
            "CVE-2026-87902",
            "6.9.8",
            "6.9.9",
        ),
        (
            "generator",
            "WordPress ",
            "CVE-2026-87902",
            "7.1.1",
            "7.1.2",
        ),
        (
            "generator",
            "WordPress ",
            "CVE-2026-119977",
            "7.1.3",
            "7.1.4",
        ),
        (
            "x-powered-by",
            "PHP/",
            "CVE-2026-109618",
            "8.3.35",
            "8.3.36",
        ),
        ("server", "nginx/", "CVE-2026-123007", "1.30.6", "1.30.7"),
        ("server", "nginx/", "CVE-2026-123007", "1.31.8", "1.31.9"),
        ("x-jenkins", "", "CVE-2026-53435", "2.555.2", "2.555.3"),
        ("x-jenkins", "", "CVE-2026-53435", "2.567", "2.568"),
        (
            "dns_version_txt",
            "PowerDNS Authoritative Server ",
            "CVE-2026-73206",
            "5.0.7",
            "5.0.8",
        ),
        (
            "dns_version_txt",
            "PowerDNS Recursor ",
            "CVE-2026-73206",
            "5.4.7",
            "5.4.8",
        ),
    ] {
        for (version, expected) in [(affected, true), (fixed, false)] {
            let mut report = sample();
            let ep = endpoint(&mut report);
            let obs = &mut ep.observations[0];
            let value = format!("{prefix}{version}");
            let status = "HTTP/1.1 200 OK";
            obs.evidence = vec![evidence("status_line", status)];
            match field {
                "dns_version_txt" => {
                    ep.transport = Transport::Udp;
                    obs.probe_id = "dns-udp".into();
                    obs.evidence = vec![
                        evidence("response_validated", "true"),
                        evidence("dns_rcode", "0"),
                        evidence("dns_answers", "1"),
                        evidence(field, &value),
                    ];
                }
                "x-jenkins" => {
                    obs.banner = Some(nrev::probes::normalize_banner(format!(
                        "{status}\r\nX-Jenkins: {value}\r\n\r\n"
                    )));
                }
                _ => {
                    obs.evidence.push(evidence(field, &value));
                    if field == "generator" {
                        obs.evidence.push(evidence("generator_validated", "true"));
                    }
                }
            }
            let inv = DB.inventory(&report, Some(&db)).unwrap();
            let result = &inv.hosts[0].endpoints[0];
            assert_eq!(result.technologies.len(), 1, "{value}");
            assert_eq!(
                result.technologies[0].version.as_deref(),
                Some(version),
                "{value}"
            );
            assert_eq!(
                result
                    .advisory_candidates
                    .iter()
                    .find(|c| c.id == id)
                    .map(|c| c.applicability),
                expected.then_some("in_upstream_range"),
                "{id} {value}"
            );
        }
    }
}

#[test]
fn configuration_receipts_require_a_product_declaration_in_the_same_exchange() {
    let advisories = Advisories::bundled(&DB).unwrap();
    let mut report = sample();
    http(&mut report, "nginx/1.26.0");
    let ep = endpoint(&mut report);
    ep.transport = Transport::Quic;
    let obs = &mut ep.observations[0];
    obs.probe_id = "quic".into();
    obs.tls = Some(serde_json::from_value(json!({
        "negotiated_protocol":"h3","certificate_subjects":[],"certificate_issuers":[],"certificate_validation":"not_performed"
    })).unwrap());
    obs.evidence[0].value = "HTTP/3 200".into();
    let inventory = DB.inventory(&report, Some(&advisories)).unwrap();
    let candidate = inventory.hosts[0].endpoints[0]
        .advisory_candidates
        .iter()
        .find(|c| c.id == "CVE-2024-31079")
        .unwrap();
    assert_eq!(candidate.classification, "potential");
    let receipt = candidate.configuration.as_ref().unwrap();
    assert_eq!(receipt.status, "observed");
    assert!(matches!(
        &receipt.evidence,
        Some(nrev::technology::EvidenceRef::Probe {
            observation: 0,
            field: "status_line",
            ..
        })
    ));
    endpoint(&mut report).observations[0].evidence.truncate(1);
    report.identification = Some(serde_json::from_value(json!({"source":"nmap","version":"fixture","complete":true,
        "hosts":[{"ip":"127.0.0.1","os_matches":[],"ports":[{"port":8080,"protocol":"udp","state":{"state":"open"},"service":{"method":"probed","cpes":["cpe:/a:f5:nginx:1.26.0"]}}]}]})).unwrap());
    let inventory = DB.inventory(&report, Some(&advisories)).unwrap();
    let config = inventory.hosts[0].endpoints[0]
        .advisory_candidates
        .iter()
        .find(|c| c.id == "CVE-2024-31079")
        .unwrap()
        .configuration
        .as_ref()
        .unwrap();
    assert_eq!(config.status, "unobserved");
    assert!(config.evidence.is_none());
}

#[test]
fn malformed_extended_advisories_fail_at_load() {
    let base = json!({"schema":2,"records":[{"id":"TEST-1","product":"nginx:nginx","source":"fixture",
        "ranges":[{"introduced":"1.0.0","last_affected":"1.0.0"}]}]});
    let load = |v: &Value| Advisories::from_bytes(&serde_json::to_vec(v).unwrap(), &DB);
    assert!(load(&base).is_ok());
    for ranges in [
        json!([]),
        json!([{}]),
        json!([{"introduced":"1.0.1","last_affected":"1.0.0"}]),
        json!([{"fixed":"1.0.1","last_affected":"1.0.0"}]),
        json!([{"last_affected":"1.0.1"},{"introduced":"1.0.1"}]),
        json!([{"introduced":"1.0.0"},{"introduced":"1.0.1"}]),
    ] {
        let mut v = base.clone();
        v["records"][0]["ranges"] = ranges;
        assert!(load(&v).is_err());
    }
    for (name, value) in [
        ("fixed", json!("1.0.0")),
        (
            "observed_when",
            json!({"fact":"http.carrier","equals":"smtp"}),
        ),
    ] {
        let mut v = base.clone();
        v["records"][0][name] = value;
        assert!(load(&v).is_err());
    }
    let mut legacy = base;
    legacy["schema"] = 1.into();
    assert!(load(&legacy).is_err());
}

#[test]
fn local_nvd_page_preserves_constraints_and_exposes_skipped_records() {
    let name = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*";
    let supported = json!({"nodes":[{"operator":"OR","cpeMatch":[
        {"vulnerable":true,"criteria":name,"versionStartIncluding":"1.19.0","versionEndIncluding":"1.20.0"},
        {"vulnerable":true,"criteria":"cpe:2.3:o:vendor:os:1:*:*:*:*:*:*:*"}]}]});
    let mut and = supported.clone();
    and["operator"] = "AND".into();
    let mut negated = supported.clone();
    negated["nodes"][0]["negate"] = true.into();
    let mut environment = supported.clone();
    environment["nodes"][0]["cpeMatch"][0]["vulnerable"] = false.into();
    let mut unknown_bound = supported.clone();
    unknown_bound["nodes"][0]["cpeMatch"][0]["otherLimit"] = "1.2.3".into();
    let mut unsupported_version = supported.clone();
    unsupported_version["nodes"][0]["cpeMatch"][0]["versionEndIncluding"] = "1.20".into();
    let mut outside = supported.clone();
    outside["nodes"][0]["cpeMatch"][0]["criteria"] =
        name.replace("f5:nginx", "other:server").into();
    let mut page = json!({"format":"NVD_CVE","version":"2.0","startIndex":8,"totalResults":21,
        "timestamp":"2025-12-01T00:00:00.000", "vulnerabilities":[]});
    for (i, (status, config)) in [
        ("Analyzed", supported.clone()),
        ("Rejected", supported),
        ("Analyzed", and),
        ("Analyzed", negated),
        ("Analyzed", environment),
        ("Analyzed", unknown_bound),
        ("Analyzed", unsupported_version),
        ("Modified", outside),
    ]
    .into_iter()
    .enumerate()
    {
        page["vulnerabilities"].as_array_mut().unwrap().push(json!({"cve":{"id":format!("CVE-2099-{i:04}"),"vulnStatus":status,"configurations":[config]}}));
    }
    let input = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(input.path(), page.to_string()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_nrev"))
        .args(["inventory", "samples/inventory/scan.json", "--nvd"])
        .arg(input.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    let stats = &result["nvd_coverage"];
    assert_eq!(stats["imported"], 1);
    assert_eq!(stats["skipped_status"], 1);
    assert_eq!(stats["skipped_configuration"], 5);
    assert_eq!(stats["outside_catalog"], 1);
    assert_eq!(stats["page_records"], 8);
    assert_eq!(
        result["hosts"][0]["endpoints"][0]["advisory_candidates"][0]["id"],
        "CVE-2099-0000"
    );
    let duplicate = page["vulnerabilities"][0].clone();
    page["vulnerabilities"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(Advisories::from_nvd_bytes(page.to_string().as_bytes(), &DB).is_err());
}

#[test]
fn protocol_facts_survive_an_unknown_product() {
    let mut report = sample();
    let ep = endpoint(&mut report);
    for (probe, raw, key, expected) in [
        (
            "postgresql",
            "[78]",
            "postgresql.ssl_request",
            Some("declined"),
        ),
        (
            "postgresql",
            "[83]",
            "postgresql.ssl_request",
            Some("accepted"),
        ),
        ("postgresql", "[83, 0]", "postgresql.ssl_request", None),
        (
            "memcached",
            "VERSION 1.6.31\r\n",
            "memcached.version",
            Some("1.6.31"),
        ),
        ("memcached", "VERSION 1.6", "memcached.version", None),
        ("redis", "+PONG\r\n", "resp.ping", Some("pong")),
        ("redis", "-ERR +PONG\r\n", "resp.ping", None),
        ("mysql", "8.4.0", "mysql.server_version", Some("8.4.0")),
    ] {
        let obs = &mut ep.observations[0];
        obs.probe_id = probe.into();
        obs.banner = Some(Banner {
            raw: raw.into(),
            normalized: String::new(),
        });
        obs.evidence = vec![evidence(
            if probe == "mysql" {
                "handshake_version"
            } else {
                "response_bytes"
            },
            raw,
        )];
        let inv = DB.identify(ep).unwrap();
        assert!(inv.technologies.is_empty());
        assert_eq!(
            inv.observed
                .iter()
                .find(|f| f.name == key)
                .map(|f| f.value.as_str()),
            expected
        );
    }
}

fn recorded_stack(order: &str, ttl: u8, window: u16) -> nrev::model::TcpIpObservation {
    let mut fp = nrev::fingerprint::baseline_syn_observation(
        true,
        true,
        false,
        Some(ttl),
        Some(window.into()),
    );
    fp.tcp_option_order = Some(order.into());
    fp.window_scale = Some(6);
    fp.mss = Some(1460);
    fp.sack_permitted = Some(true);
    fp.timestamps = order.contains("TS").then_some(true);
    fp
}

#[test]
fn native_platforms_distinguish_stack_environment_and_release() {
    let mut report = sample();
    http(&mut report, "Apache/2.4.62 (Ubuntu 24.04)");
    let ep = endpoint(&mut report);
    ep.transport = Transport::Syn;
    ep.fingerprint = Some(recorded_stack("MSS,SACK,TS,NOP,WS", 58, 65160));
    let result = DB.inventory(&report, None).unwrap();
    let host = &result.hosts[0];
    assert_eq!(host.operating_system.family.as_deref(), Some("linux"));
    assert_eq!(host.operating_system.status, "corroborated_family");
    assert_eq!(
        host.endpoints[0].service_platforms[0]
            .declared_release
            .as_deref(),
        Some("24.04")
    );
    http(&mut report, "Apache/2.4.62 (Win64)");
    let result = DB.inventory(&report, None).unwrap();
    assert_eq!(result.hosts[0].operating_system.status, "conflicting");
    assert!(result.hosts[0].operating_system.family.is_none());
    endpoint(&mut report).fingerprint = None;
    assert_eq!(
        DB.inventory(&report, None).unwrap().hosts[0]
            .operating_system
            .status,
        "service_hint_only"
    );
    http(&mut report, "Apache/2.4.62 (not Ubuntu 24.04)");
    assert_eq!(
        DB.inventory(&report, None).unwrap().hosts[0]
            .operating_system
            .status,
        "unknown"
    );
}

#[test]
fn platform_profiles_consider_every_port_and_withhold_incomplete_matches() {
    let mut report = sample();
    let mac = recorded_stack("MSS,NOP,WS,NOP,NOP,TS,SACK", 64, 65535);
    let windows = recorded_stack("MSS,NOP,WS,NOP,NOP,SACK", 121, 65535);
    let ep = endpoint(&mut report);
    ep.transport = Transport::Syn;
    ep.fingerprint = Some(mac.clone());
    assert_eq!(
        DB.inventory(&report, None).unwrap().hosts[0]
            .operating_system
            .family
            .as_deref(),
        Some("darwin")
    );
    endpoint(&mut report).fingerprint = Some(windows.clone());
    assert_eq!(
        DB.inventory(&report, None).unwrap().hosts[0]
            .operating_system
            .family
            .as_deref(),
        Some("windows")
    );
    let mut second = endpoint(&mut report).clone();
    second.port = 8081;
    second.fingerprint = Some(mac.clone());
    report.targets[0].endpoints.insert(8081, second);
    let inv = DB.inventory(&report, None).unwrap();
    assert_eq!(inv.hosts[0].operating_system.status, "conflicting");
    assert_eq!(inv.hosts[0].operating_system.stack_matches.len(), 2);
    report.targets[0].endpoints.remove(&8081);
    for fp in [
        nrev::model::TcpIpObservation {
            tcp_option_set: Some("{MSS,WS}".into()),
            ..mac.clone()
        },
        nrev::model::TcpIpObservation {
            tcp_option_order: None,
            ..mac.clone()
        },
        nrev::model::TcpIpObservation {
            window_scale: None,
            ..mac.clone()
        },
        nrev::model::TcpIpObservation {
            timestamps: None,
            ..mac.clone()
        },
        nrev::model::TcpIpObservation {
            ttl_hint: Some(1),
            ..mac.clone()
        },
        nrev::model::TcpIpObservation {
            rst_seen: true,
            ..mac.clone()
        },
        nrev::model::TcpIpObservation {
            transport: Transport::Tcp,
            ..mac
        },
    ] {
        endpoint(&mut report).fingerprint = Some(fp);
        assert_eq!(
            DB.inventory(&report, None).unwrap().hosts[0]
                .operating_system
                .status,
            "unknown"
        );
    }
}

#[test]
fn passive_greetings_resolve_protocols_without_trusting_the_port() {
    let mut report = sample();
    for (line, protocol, product) in [
        (
            "* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.",
            Some("imap"),
            Some("dovecot:dovecot"),
        ),
        (
            "+OK Dovecot v2.4.0 ready.",
            Some("pop3"),
            Some("dovecot:dovecot"),
        ),
        (
            "SSH-2.0-OpenSSH_for_Windows_9.5p1",
            Some("ssh"),
            Some("openbsd:openssh"),
        ),
        (
            "220 mail.test ESMTP Postfix 3.2.2",
            Some("smtp"),
            Some("postfix:postfix"),
        ),
        ("220 (vsFTPd 3.0.5)", Some("ftp"), Some("vsftpd:vsftpd")),
        ("220 service ready", None, None),
        ("* OK My Dovecot proxy", Some("imap"), None),
    ] {
        let ep = endpoint(&mut report);
        let obs = &mut ep.observations[0];
        obs.probe_id = "greeting".into();
        obs.service_hint = None;
        obs.banner = Some(Banner {
            raw: format!("{line}\r\n"),
            normalized: String::new(),
        });
        obs.evidence = vec![evidence("greeting", line)];
        let inv = DB.identify(ep).unwrap();
        assert_eq!(inv.services.first().map(|s| s.name.as_str()), protocol);
        assert_eq!(inv.technologies.first().map(|t| t.id.as_str()), product);
        if line.contains("_for_Windows") {
            assert!(inv.technologies[0].declarations[0].qualified);
            assert_eq!(inv.service_platforms[0].environment, "Windows");
        }
        ep.observations[0].banner.as_mut().unwrap().raw = line.into();
        assert!(DB.identify(ep).unwrap().technologies.is_empty());
    }
}

#[test]
fn captured_handshakes_replay_without_an_external_matcher() {
    let report: ScanReport =
        serde_json::from_slice(include_bytes!("../samples/inventory/platforms.json")).unwrap();
    let inventory = DB.inventory(&report, None).unwrap();
    assert_eq!(
        inventory
            .hosts
            .iter()
            .map(|h| h.operating_system.family.as_deref())
            .collect::<Vec<_>>(),
        [
            Some("darwin"),
            Some("linux"),
            Some("windows"),
            Some("windows")
        ]
    );
    for host in &inventory.hosts {
        assert_eq!(host.operating_system.status, "stack_inference");
        assert_eq!(host.operating_system.stack_matches[0].port, Some(8080));
        assert!(host.endpoints[0].services.is_empty());
    }
}

#[test]
fn implicit_greeting_reuses_the_open_connection_on_an_unassigned_port() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket.write_all(b"+OK Dovecot ready.\r\n").unwrap();
        let mut received = [0; 1];
        assert_eq!(socket.read(&mut received).unwrap(), 0);
        listener.set_nonblocking(true).unwrap();
        assert!(listener.accept().is_err());
    });
    let out = Command::new(env!("CARGO_BIN_EXE_nrev"))
        .args([
            "port",
            &address.to_string(),
            "--connect-timeout-ms",
            "500",
            "--inventory",
            "--format",
            "json",
            "--quiet",
            "--nmap-path",
            "missing-test-executable",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        result["hosts"][0]["endpoints"][0]["technologies"][0]["id"],
        "dovecot:dovecot"
    );
    server.join().unwrap();
}

#[tokio::test]
async fn tls_inventory_negotiates_http2_and_retains_headers_on_a_stalled_body() {
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        // Some TLS terminators send a cleartext 400 on this same port.
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("GET / HTTP/1.1"));
        stream
            .get_mut()
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nServer: clear-error\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        drop(stream);
        let (stream, _) = listener.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
            .unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.headers()["range"], "bytes=0-255");
        assert_eq!(request.version(), http::Version::HTTP_2);
        let response = http::Response::builder()
            .status(200)
            .header("server", "nginx/1.26.0")
            .body(())
            .unwrap();
        let _stream = respond.send_response(response, false).unwrap();
        let _ = connection.accept().await;
    });
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_nrev"))
        .args([
            "port",
            "127.0.0.1",
            "--ports",
            &address.port().to_string(),
            "--connect-timeout-ms",
            "500",
            "--probe-timeout-ms",
            "2000",
            "--http-body-preview-bytes",
            "256",
            "--format",
            "json",
            "--quiet",
            "--nmap-path",
            "missing-test-executable",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    let mut report: ScanReport = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.identification.is_none());
    let ep = report.targets[0]
        .endpoints
        .get_mut(&address.port())
        .unwrap();
    assert!(ep.errors.is_empty());
    assert_eq!(ep.observations.len(), 1);
    assert_eq!(
        ep.observations[0].service_hint.as_ref().unwrap().name,
        "https"
    );
    let result = DB.identify(ep).unwrap();
    assert_eq!(result.technologies[0].version.as_deref(), Some("1.26.0"));
    for (name, value) in [
        ("tls.alpn", "h2"),
        ("http.status", "200"),
        ("http.carrier", "tls"),
    ] {
        assert!(
            result
                .observed
                .iter()
                .any(|f| f.name == name && f.value == value)
        );
    }
    ep.observations[0].tls.as_mut().unwrap().negotiated_protocol = Some("http/1.1".into());
    assert!(DB.identify(ep).unwrap().technologies.is_empty());
}

#[test]
fn reviewed_positive_declarations_reach_the_inventory() {
    let cases: Vec<Value> =
        serde_json::from_slice(include_bytes!("../knowledge/review.json")).unwrap();
    for case in cases.iter().filter(|case| case["product"].is_string()) {
        let mut report = sample();
        let ep = endpoint(&mut report);
        let obs = &mut ep.observations[0];
        let field = case["field"].as_str().unwrap();
        let value = case["value"].as_str().unwrap();
        let status = "HTTP/1.1 200 OK";
        obs.evidence = vec![evidence("status_line", status)];
        match field {
            "server" | "server_header" => obs.evidence.push(evidence("server", value)),
            "server_component" => obs
                .evidence
                .push(evidence("server", &format!("Fixture {value}"))),
            "powered_by" => obs.evidence.push(evidence("x-powered-by", value)),
            "generator" => obs.evidence.extend([
                evidence("generator", value),
                evidence("generator_validated", "true"),
            ]),
            "ssh_ident" => {
                obs.probe_id = "ssh".into();
                obs.banner = Some(nrev::probes::normalize_banner(format!("{value}\r\n")));
            }
            "smtp_greeting" | "ftp_greeting" | "imap_greeting" | "pop3_greeting" => {
                obs.probe_id = field.strip_suffix("_greeting").unwrap().into();
                obs.banner = Some(nrev::probes::normalize_banner(format!("{value}\r\n")));
                obs.evidence = vec![evidence("greeting", value)];
            }
            "mysql_version" => {
                obs.probe_id = "mysql".into();
                obs.evidence = vec![evidence("handshake_version", value)];
            }
            "dns_version" => {
                ep.transport = Transport::Udp;
                obs.probe_id = "dns-udp".into();
                obs.evidence = vec![
                    evidence("response_validated", "true"),
                    evidence("dns_rcode", "0"),
                    evidence("dns_answers", "1"),
                    evidence("dns_version_txt", value),
                ];
            }
            _ => {
                let headers = match field {
                    "jenkins_version" => format!("X-Jenkins: {value}"),
                    "influxdb_version" => format!("X-Influxdb-Version: {value}"),
                    "elastic_product" => format!("X-Elastic-Product: {value}"),
                    "github_enterprise_version" => format!("X-GitHub-Enterprise-Version: {value}"),
                    "generator_header" => format!("X-Generator: {value}"),
                    "consul_leader" => format!("X-Consul-Index: 42\r\nX-Consul-KnownLeader: {value}"),
                    "nomad_leader" => format!("X-Nomad-Index: 42\r\nX-Nomad-KnownLeader: {value}"),
                    "kubernetes_flow_control" => "X-Kubernetes-PF-FlowSchema-UID: 46c54f28-a315-4765-8038-f8954cb93e76\r\nX-Kubernetes-PF-PriorityLevel-UID: 77f9772d-41d0-446f-b051-98cef57878a8".into(),
                    _ => panic!("missing observation fixture for {field}"),
                };
                obs.banner = Some(nrev::probes::normalize_banner(format!(
                    "{status}\r\n{headers}\r\n\r\n"
                )));
            }
        }
        let result = DB.identify(ep).unwrap();
        assert_eq!(result.technologies.len(), 1, "{case}");
        let product = &result.technologies[0];
        assert_eq!(product.id, case["product"].as_str().unwrap(), "{case}");
        assert_eq!(
            product.version.as_deref(),
            case["version"].as_str(),
            "{case}"
        );
    }
}

#[test]
fn product_header_replay_requires_complete_unambiguous_evidence() {
    let mut report = sample();
    let ep = endpoint(&mut report);
    ep.observations[0].evidence = vec![evidence("status_line", "HTTP/1.1 200 OK")];
    for raw in [
        "HTTP/1.1 200 OK\r\nX-Jenkins: 2.479",
        "HTTP/1.1 200 OK\r\nX-Jenkins: 2.479\r\nx-jenkins: 2.480\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX-Jenkins: 2.479\r\n continuation\r\n\r\n",
        "HTTP/1.1 200 OK\r\n\r\nX-Jenkins: 2.479\r\n\r\n",
        "HTTP/1.1 404 Not Found\r\nX-Jenkins: 2.479\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX-Consul-Index: 1\r\nX-Nomad-KnownLeader: true\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX-Kubernetes-PF-FlowSchema-UID: redacted\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX-Kubernetes-PF-FlowSchema-UID: 46c54f28-a315-4765-8038-f8954cb93e76\r\nX-Kubernetes-PF-PriorityLevel-UID: 46C54F28-A315-4765-8038-F8954CB93E76\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX-Kubernetes-PF-FlowSchema-UID: 46c54f28-a315-4765-8038-f8954cb93e76\r\nX-Kubernetes-PF-PriorityLevel-UID: 00000000-0000-0000-0000-000000000000\r\n\r\n",
    ] {
        ep.observations[0].banner = Some(nrev::probes::normalize_banner(raw.into()));
        assert!(DB.identify(ep).unwrap().technologies.is_empty(), "{raw}");
    }
    let obs = &mut ep.observations[0];
    obs.banner = Some(nrev::probes::normalize_banner("HTTP/1.1 200 OK\r\nx-jenkins: 2.479\r\nDocker-Distribution-Api-Version: registry/2.0\r\n\r\n".into()));
    let result = DB.identify(ep).unwrap();
    assert_eq!(result.technologies.len(), 1);
    assert_eq!(
        result.technologies[0].version_status,
        VersionStatus::Declared
    );
    assert!(
        result
            .observed
            .iter()
            .any(|v| v.name == "registry.api" && v.value == "registry/2.0")
    );
    ep.observations[0].tags.push("external".into());
    assert!(DB.identify(ep).unwrap().technologies.is_empty());
}
