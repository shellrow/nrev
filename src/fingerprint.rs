use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::model::{Confidence, Evidence, FingerprintMatch, TcpIpObservation, Transport};

const BUILTIN_OS_CLASS_TTL_JSON: &str = include_str!("../resources/nrev-os-class-ttl.json");
const BUILTIN_OS_DB_JSON: &str = include_str!("../resources/nrev-os-db.json");

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintRule {
    pub id: String,
    pub label: String,
    pub family: String,
    #[serde(default)]
    pub transport: Option<TransportRule>,
    #[serde(default)]
    pub handshake_observed: Option<bool>,
    #[serde(default)]
    pub response_observed: Option<bool>,
    #[serde(default)]
    pub ttl_hint: Option<u8>,
    #[serde(default)]
    pub ttl_class: Option<u8>,
    #[serde(default)]
    pub window_size: Option<u32>,
    #[serde(default)]
    pub syn_ack_seen: Option<bool>,
    #[serde(default)]
    pub rst_seen: Option<bool>,
    #[serde(default)]
    pub tcp_option_order: Option<String>,
    #[serde(default)]
    pub tcp_option_set: Option<String>,
    #[serde(default)]
    pub mss: Option<u16>,
    #[serde(default)]
    pub window_scale: Option<u8>,
    #[serde(default)]
    pub sack_permitted: Option<bool>,
    #[serde(default)]
    pub timestamps: Option<bool>,
    #[serde(default = "default_confidence")]
    pub confidence: RuleConfidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OsClassTtl {
    pub os_class: String,
    pub os_description: String,
    pub initial_ttl: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyOsDb {
    #[serde(default)]
    pub signatures: Vec<LegacyOsSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyOsSignature {
    pub signature: LegacyOsSignatureKey,
    #[serde(default)]
    pub cpe: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyOsSignatureKey {
    #[serde(default)]
    pub order_key: Option<String>,
    #[serde(default)]
    pub set_key: Option<String>,
    #[serde(default)]
    pub win_bucket: Option<Vec<u16>>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TransportRule {
    Tcp,
    Udp,
    Syn,
    Quic,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleConfidence {
    Low,
    Medium,
    High,
}

fn default_confidence() -> RuleConfidence {
    RuleConfidence::Medium
}

impl From<RuleConfidence> for Confidence {
    fn from(value: RuleConfidence) -> Self {
        match value {
            RuleConfidence::Low => Self::Low,
            RuleConfidence::Medium => Self::Medium,
            RuleConfidence::High => Self::High,
        }
    }
}

pub fn baseline_tcp_observation() -> TcpIpObservation {
    TcpIpObservation {
        transport: Transport::Tcp,
        handshake_observed: true,
        response_observed: false,
        ttl_hint: None,
        ttl_class: None,
        window_size: None,
        syn_ack_seen: false,
        rst_seen: false,
        tcp_option_order: None,
        tcp_option_set: None,
        mss: None,
        window_scale: None,
        sack_permitted: None,
        timestamps: None,
    }
}

pub fn baseline_udp_observation(response_observed: bool) -> TcpIpObservation {
    TcpIpObservation {
        transport: Transport::Udp,
        handshake_observed: false,
        response_observed,
        ttl_hint: None,
        ttl_class: None,
        window_size: None,
        syn_ack_seen: false,
        rst_seen: false,
        tcp_option_order: None,
        tcp_option_set: None,
        mss: None,
        window_scale: None,
        sack_permitted: None,
        timestamps: None,
    }
}

pub fn baseline_syn_observation(
    response_observed: bool,
    syn_ack_seen: bool,
    rst_seen: bool,
    ttl_hint: Option<u8>,
    window_size: Option<u32>,
) -> TcpIpObservation {
    TcpIpObservation {
        transport: Transport::Syn,
        handshake_observed: response_observed,
        response_observed,
        ttl_hint,
        ttl_class: ttl_hint.map(classify_initial_ttl),
        window_size,
        syn_ack_seen,
        rst_seen,
        tcp_option_order: None,
        tcp_option_set: None,
        mss: None,
        window_scale: None,
        sack_permitted: None,
        timestamps: None,
    }
}

pub fn classify_initial_ttl(ttl: u8) -> u8 {
    match ttl {
        0..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

pub fn builtin_os_ttl_classes() -> Vec<OsClassTtl> {
    serde_json::from_str(BUILTIN_OS_CLASS_TTL_JSON).expect("embedded OS TTL classes must be valid")
}

pub fn builtin_os_signatures() -> Vec<LegacyOsSignature> {
    serde_json::from_str::<LegacyOsDb>(BUILTIN_OS_DB_JSON)
        .expect("embedded OS signature database must be valid")
        .signatures
}

pub fn match_rules(
    observation: &TcpIpObservation,
    rules: &[FingerprintRule],
) -> Vec<FingerprintMatch> {
    rules
        .iter()
        .filter(|rule| rule_matches(observation, rule))
        .map(|rule| FingerprintMatch {
            label: rule.label.clone(),
            family: rule.family.clone(),
            confidence: rule.confidence.into(),
            evidence: build_evidence(observation, rule),
        })
        .collect()
}

fn rule_matches(observation: &TcpIpObservation, rule: &FingerprintRule) -> bool {
    if let Some(transport) = rule.transport {
        let matches_transport = matches!(
            (transport, observation.transport),
            (TransportRule::Tcp, Transport::Tcp)
                | (TransportRule::Udp, Transport::Udp)
                | (TransportRule::Syn, Transport::Syn)
                | (TransportRule::Quic, Transport::Quic)
        );
        if !matches_transport {
            return false;
        }
    }

    optional_bool_match(observation.handshake_observed, rule.handshake_observed)
        && optional_bool_match(observation.response_observed, rule.response_observed)
        && optional_bool_match(observation.syn_ack_seen, rule.syn_ack_seen)
        && optional_bool_match(observation.rst_seen, rule.rst_seen)
        && optional_value_match(observation.ttl_hint, rule.ttl_hint)
        && optional_value_match(observation.ttl_class, rule.ttl_class)
        && optional_value_match(observation.window_size, rule.window_size)
        && optional_string_match(
            observation.tcp_option_order.as_deref(),
            rule.tcp_option_order.as_deref(),
        )
        && optional_string_match(
            observation.tcp_option_set.as_deref(),
            rule.tcp_option_set.as_deref(),
        )
        && optional_value_match(observation.mss, rule.mss)
        && optional_value_match(observation.window_scale, rule.window_scale)
        && optional_optional_bool_match(observation.sack_permitted, rule.sack_permitted)
        && optional_optional_bool_match(observation.timestamps, rule.timestamps)
}

fn optional_bool_match(observed: bool, expected: Option<bool>) -> bool {
    expected.is_none_or(|expected| observed == expected)
}

fn optional_value_match<T>(observed: Option<T>, expected: Option<T>) -> bool
where
    T: Eq + Copy,
{
    expected.is_none_or(|expected| observed == Some(expected))
}

fn optional_string_match(observed: Option<&str>, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| observed == Some(expected))
}

fn optional_optional_bool_match(observed: Option<bool>, expected: Option<bool>) -> bool {
    expected.is_none_or(|expected| observed == Some(expected))
}

fn build_evidence(observation: &TcpIpObservation, rule: &FingerprintRule) -> Vec<Evidence> {
    let mut evidence = vec![
        Evidence {
            key: "rule".to_string(),
            value: rule.id.clone(),
        },
        Evidence {
            key: "transport".to_string(),
            value: observation.transport.as_str().to_string(),
        },
        Evidence {
            key: "handshake_observed".to_string(),
            value: observation.handshake_observed.to_string(),
        },
        Evidence {
            key: "response_observed".to_string(),
            value: observation.response_observed.to_string(),
        },
    ];
    if let Some(ttl_hint) = observation.ttl_hint {
        evidence.push(Evidence {
            key: "ttl_hint".to_string(),
            value: ttl_hint.to_string(),
        });
    }
    if let Some(ttl_class) = observation.ttl_class {
        evidence.push(Evidence {
            key: "ttl_class".to_string(),
            value: ttl_class.to_string(),
        });
    }
    if let Some(window_size) = observation.window_size {
        evidence.push(Evidence {
            key: "window_size".to_string(),
            value: window_size.to_string(),
        });
    }
    if let Some(order) = &observation.tcp_option_order {
        evidence.push(Evidence {
            key: "tcp_option_order".to_string(),
            value: order.clone(),
        });
    }
    if let Some(set_key) = &observation.tcp_option_set {
        evidence.push(Evidence {
            key: "tcp_option_set".to_string(),
            value: set_key.clone(),
        });
    }
    if let Some(mss) = observation.mss {
        evidence.push(Evidence {
            key: "mss".to_string(),
            value: mss.to_string(),
        });
    }
    if let Some(window_scale) = observation.window_scale {
        evidence.push(Evidence {
            key: "window_scale".to_string(),
            value: window_scale.to_string(),
        });
    }
    if let Some(sack_permitted) = observation.sack_permitted {
        evidence.push(Evidence {
            key: "sack_permitted".to_string(),
            value: sack_permitted.to_string(),
        });
    }
    if let Some(timestamps) = observation.timestamps {
        evidence.push(Evidence {
            key: "timestamps".to_string(),
            value: timestamps.to_string(),
        });
    }
    evidence
}

pub fn match_ttl_classes(
    observation: &TcpIpObservation,
    ttl_classes: &[OsClassTtl],
) -> Vec<FingerprintMatch> {
    let Some(ttl_class) = observation.ttl_class else {
        return Vec::new();
    };

    ttl_classes
        .iter()
        .filter(|item| item.initial_ttl == ttl_class)
        .map(|item| FingerprintMatch {
            label: item.os_description.clone(),
            family: item.os_class.clone(),
            confidence: Confidence::Low,
            evidence: vec![
                Evidence {
                    key: "ttl_class".to_string(),
                    value: ttl_class.to_string(),
                },
                Evidence {
                    key: "source".to_string(),
                    value: "builtin-ttl-class".to_string(),
                },
            ],
        })
        .collect()
}

pub fn match_legacy_os_signatures(
    observation: &TcpIpObservation,
    signatures: &[LegacyOsSignature],
) -> Vec<FingerprintMatch> {
    let mut ranked = signatures
        .iter()
        .filter_map(|signature| {
            let (score, matched_on) = score_legacy_os_signature(signature, observation);
            (score > 0).then_some((signature, score, matched_on))
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.1.cmp(&left.1));

    ranked
        .into_iter()
        .take(3)
        .filter_map(|(signature, score, matched_on)| {
            build_platform_match(
                &signature.cpe,
                confidence_from_score(score),
                build_signature_evidence(signature, observation, &matched_on),
            )
            .or_else(|| {
                Some(FingerprintMatch {
                    label: signature_label(signature),
                    family: "os".to_string(),
                    confidence: confidence_from_score(score),
                    evidence: build_signature_evidence(signature, observation, &matched_on),
                })
            })
        })
        .collect()
}

fn build_signature_evidence(
    signature: &LegacyOsSignature,
    observation: &TcpIpObservation,
    matched_on: &[&str],
) -> Vec<Evidence> {
    let mut evidence = matched_on
        .iter()
        .map(|key| Evidence {
            key: "matched_on".to_string(),
            value: (*key).to_string(),
        })
        .collect::<Vec<_>>();
    if let Some(order) = &observation.tcp_option_order {
        evidence.push(Evidence {
            key: "tcp_option_order".to_string(),
            value: order.clone(),
        });
    }
    if let Some(set_key) = &observation.tcp_option_set {
        evidence.push(Evidence {
            key: "tcp_option_set".to_string(),
            value: set_key.clone(),
        });
    }
    if let Some(window_size) = observation.window_size {
        evidence.push(Evidence {
            key: "window_size".to_string(),
            value: window_size.to_string(),
        });
    }
    for cpe in &signature.cpe {
        evidence.push(Evidence {
            key: "cpe".to_string(),
            value: cpe.clone(),
        });
    }
    evidence
}

fn score_legacy_os_signature<'a>(
    signature: &'a LegacyOsSignature,
    observation: &TcpIpObservation,
) -> (u8, Vec<&'a str>) {
    let mut score = 0;
    let mut matched_on = Vec::new();

    if let Some(expected) = signature.signature.order_key.as_deref() {
        match observation.tcp_option_order.as_deref() {
            Some(observed) if expected == observed => {
                score += 60;
                matched_on.push("order_key");
            }
            Some(_) => return (0, Vec::new()),
            None => {}
        }
    }

    if let Some(expected) = signature.signature.set_key.as_deref() {
        match observation.tcp_option_set.as_deref() {
            Some(observed) if tcp_option_sets_equal(expected, observed) => {
                score += 40;
                matched_on.push("set_key");
            }
            Some(_) => return (0, Vec::new()),
            None => {}
        }
    }

    if let Some(buckets) = &signature.signature.win_bucket {
        match observation.window_size {
            Some(window_size)
                if buckets
                    .iter()
                    .any(|bucket| u32::from(*bucket) == window_size) =>
            {
                score += 20;
                matched_on.push("win_bucket");
            }
            Some(_) => return (0, Vec::new()),
            None => {}
        }
    }

    (score, matched_on)
}

fn tcp_option_sets_equal(left: &str, right: &str) -> bool {
    parse_tcp_option_set(left) == parse_tcp_option_set(right)
}

fn parse_tcp_option_set(value: &str) -> BTreeSet<&str> {
    value
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect()
}

fn confidence_from_score(score: u8) -> Confidence {
    match score {
        80..=u8::MAX => Confidence::High,
        40..=79 => Confidence::Medium,
        _ => Confidence::Low,
    }
}

fn signature_label(signature: &LegacyOsSignature) -> String {
    signature
        .cpe
        .first()
        .and_then(|cpe| cpe.strip_prefix("cpe:/"))
        .map(|value| value.replace(':', " "))
        .unwrap_or_else(|| "OS signature".to_string())
}

pub fn build_platform_match(
    cpes: &[String],
    confidence: Confidence,
    mut evidence: Vec<Evidence>,
) -> Option<FingerprintMatch> {
    let family = canonical_platform_family(cpes)?;
    evidence.push(Evidence {
        key: "platform".to_string(),
        value: family.clone(),
    });
    Some(FingerprintMatch {
        label: canonical_platform_label(&family).to_string(),
        family,
        confidence,
        evidence,
    })
}

pub fn canonical_platform_family(cpes: &[String]) -> Option<String> {
    let families = cpes
        .iter()
        .filter_map(|cpe| cpe_family(cpe))
        .collect::<BTreeSet<_>>();

    if families.is_empty() {
        return None;
    }

    let network_specific = [
        "mikrotik:routeros",
        "juniper:junos",
        "cisco:ios_xr",
        "cisco:ios",
        "fortinet:fortios",
        "hp:procurve_switch",
        "comware",
        "zyxel:zynos",
        "arista:eos",
        "ubiquiti",
    ]
    .into_iter()
    .filter(|family| families.contains(*family))
    .collect::<Vec<_>>();
    if network_specific.len() > 1 {
        return Some("network-device".to_string());
    }

    for family in [
        "nintendo",
        "playstation",
        "mikrotik:routeros",
        "juniper:junos",
        "cisco:ios_xr",
        "cisco:ios",
        "fortinet:fortios",
        "hp:procurve_switch",
        "comware",
        "zyxel:zynos",
        "arista:eos",
        "ubiquiti",
    ] {
        if families.contains(family) {
            return Some(family.to_string());
        }
    }

    let has_apple = families.iter().any(|family| family.starts_with("apple"));
    if has_apple {
        let has_mac = families.contains("apple:mac_os");
        let has_mobile = families.contains("apple:iphone_os");
        if has_mac && !has_mobile && families.len() == 1 {
            return Some("apple:mac_os".to_string());
        }
        if has_mobile && !has_mac && families.len() == 1 {
            return Some("apple:iphone_os".to_string());
        }
        return Some("apple".to_string());
    }

    if families.contains("microsoft:windows") {
        return Some("microsoft:windows".to_string());
    }

    let bsd = families
        .iter()
        .filter(|family| {
            matches!(
                **family,
                "openbsd:openbsd" | "freebsd:freebsd" | "netbsd:netbsd"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    if !bsd.is_empty() {
        return if bsd.len() == 1 && families.len() == 1 {
            bsd.first().map(|family| (*family).to_string())
        } else {
            Some("bsd".to_string())
        };
    }

    if families.contains("google:android") {
        return if families.contains("linux:linux_kernel") || families.len() > 1 {
            Some("linux".to_string())
        } else {
            Some("google:android".to_string())
        };
    }

    if families.contains("linux:linux_kernel") {
        return Some("linux:linux_kernel".to_string());
    }

    if families.len() == 1 {
        return families.first().map(|family| (*family).to_string());
    }

    Some("network-device".to_string())
}

pub fn canonical_platform_label(family: &str) -> &'static str {
    match family {
        "apple" => "Apple",
        "apple:mac_os" => "Apple macOS",
        "apple:iphone_os" => "Apple iPhone OS",
        "microsoft:windows" => "Microsoft Windows",
        "linux" => "Linux",
        "linux:linux_kernel" => "Linux",
        "google:android" => "Google Android",
        "bsd" => "BSD",
        "openbsd:openbsd" => "OpenBSD",
        "freebsd:freebsd" => "FreeBSD",
        "netbsd:netbsd" => "NetBSD",
        "nintendo" => "Nintendo",
        "playstation" => "PlayStation",
        "mikrotik:routeros" => "MikroTik RouterOS",
        "juniper:junos" => "Juniper Junos",
        "cisco:ios_xr" => "Cisco IOS XR",
        "cisco:ios" => "Cisco IOS",
        "fortinet:fortios" => "Fortinet FortiOS",
        "hp:procurve_switch" => "HP ProCurve",
        "comware" => "Comware",
        "zyxel:zynos" => "ZyXEL ZyNOS",
        "arista:eos" => "Arista EOS",
        "ubiquiti" => "Ubiquiti",
        "network-device" => "Network device",
        _ => "Platform",
    }
}

fn cpe_family(cpe: &str) -> Option<&'static str> {
    let value = cpe.strip_prefix("cpe:/")?;
    let mut parts = value.split(':');
    let _part = parts.next()?;
    let vendor = parts.next()?;
    let product = parts.next().unwrap_or_default();

    match (vendor, product) {
        ("microsoft", product) if product.starts_with("windows") => Some("microsoft:windows"),
        ("apple", "mac_os") | ("apple", "mac_os_x") | ("apple", "mac_os_x_server") => {
            Some("apple:mac_os")
        }
        ("apple", "iphone_os") | ("apple", "ipados") | ("apple", "tvos") | ("apple", "watchos") => {
            Some("apple:iphone_os")
        }
        ("apple", _) => Some("apple"),
        ("google", "android") => Some("google:android"),
        ("linux", "linux_kernel") => Some("linux:linux_kernel"),
        ("canonical", "ubuntu_linux")
        | ("debian", "debian_linux")
        | ("redhat", "enterprise_linux")
        | ("fedoraproject", "fedora")
        | ("fedoraproject", "fedora_core")
        | ("gentoo", "linux")
        | ("archlinux", "arch_linux") => Some("linux:linux_kernel"),
        ("openbsd", "openbsd") => Some("openbsd:openbsd"),
        ("freebsd", "freebsd") => Some("freebsd:freebsd"),
        ("netbsd", "netbsd") => Some("netbsd:netbsd"),
        ("nintendo", _) => Some("nintendo"),
        ("sony", product) if product.starts_with("playstation") => Some("playstation"),
        ("mikrotik", "routeros") => Some("mikrotik:routeros"),
        ("juniper", "junos") => Some("juniper:junos"),
        ("cisco", "ios_xr") => Some("cisco:ios_xr"),
        ("cisco", "ios") | ("cisco", "ios_xe") | ("cisco", "nx_os") | ("cisco", "san_os") => {
            Some("cisco:ios")
        }
        ("fortinet", "fortios") => Some("fortinet:fortios"),
        ("hp", "procurve_switch_software") => Some("hp:procurve_switch"),
        ("hp", "comware") | ("h3c", "comware") => Some("comware"),
        ("zyxel", "zynos") => Some("zyxel:zynos"),
        ("arista", "eos") => Some("arista:eos"),
        ("ubiquiti", "edgeos") | ("ubiquiti", "airos") | ("ubiquiti", "unifi") => Some("ubiquiti"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rule_on_transport_and_response() {
        let observation = baseline_udp_observation(true);
        let rules = vec![FingerprintRule {
            id: "udp-responder".to_string(),
            label: "UDP responder".to_string(),
            family: "network-device".to_string(),
            transport: Some(TransportRule::Udp),
            handshake_observed: Some(false),
            response_observed: Some(true),
            ttl_hint: None,
            ttl_class: None,
            window_size: None,
            syn_ack_seen: None,
            rst_seen: None,
            tcp_option_order: None,
            tcp_option_set: None,
            mss: None,
            window_scale: None,
            sack_permitted: None,
            timestamps: None,
            confidence: RuleConfidence::Medium,
        }];
        let matches = match_rules(&observation, &rules);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].label, "UDP responder");
    }

    #[test]
    fn canonicalizes_ambiguous_platform_families() {
        assert_eq!(
            canonical_platform_family(&[
                "cpe:/o:apple:iphone_os:17".to_string(),
                "cpe:/o:apple:mac_os_x:14".to_string()
            ]),
            Some("apple".to_string())
        );
        assert_eq!(
            canonical_platform_family(&[
                "cpe:/o:google:android:14".to_string(),
                "cpe:/o:linux:linux_kernel:6".to_string()
            ]),
            Some("linux".to_string())
        );
        assert_eq!(
            canonical_platform_family(&[
                "cpe:/o:microsoft:windows_10".to_string(),
                "cpe:/o:microsoft:windows_11".to_string()
            ]),
            Some("microsoft:windows".to_string())
        );
        assert_eq!(
            canonical_platform_family(&[
                "cpe:/o:freebsd:freebsd:13".to_string(),
                "cpe:/o:netbsd:netbsd:10".to_string()
            ]),
            Some("bsd".to_string())
        );
    }

    #[test]
    fn legacy_os_signature_rejects_window_bucket_mismatch() {
        let signature = LegacyOsSignature {
            signature: LegacyOsSignatureKey {
                order_key: Some("MSS,NOP,WS,SACK,TS".to_string()),
                set_key: Some("{MSS,NOP,SACK,TS,WS}".to_string()),
                win_bucket: Some(vec![65535]),
            },
            cpe: vec!["cpe:/h:sony:playstation_4".to_string()],
        };
        let observation = TcpIpObservation {
            transport: Transport::Syn,
            handshake_observed: true,
            response_observed: true,
            ttl_hint: Some(111),
            ttl_class: Some(128),
            window_size: Some(8192),
            syn_ack_seen: true,
            rst_seen: false,
            tcp_option_order: Some("MSS,NOP,WS,SACK,TS".to_string()),
            tcp_option_set: Some("{MSS,NOP,SACK,TS,WS}".to_string()),
            mss: Some(1420),
            window_scale: Some(8),
            sack_permitted: Some(true),
            timestamps: Some(true),
        };

        assert!(match_legacy_os_signatures(&observation, &[signature]).is_empty());
    }

    #[test]
    fn legacy_os_signature_matches_unordered_set_key() {
        let signature = LegacyOsSignature {
            signature: LegacyOsSignatureKey {
                order_key: Some("MSS,SACK,TS,NOP,WS".to_string()),
                set_key: Some("{MSS,NOP,SACK,TS,WS}".to_string()),
                win_bucket: Some(vec![65160]),
            },
            cpe: vec!["cpe:/o:linux:linux_kernel".to_string()],
        };
        let observation = TcpIpObservation {
            transport: Transport::Syn,
            handshake_observed: true,
            response_observed: true,
            ttl_hint: Some(52),
            ttl_class: Some(64),
            window_size: Some(65160),
            syn_ack_seen: true,
            rst_seen: false,
            tcp_option_order: Some("MSS,SACK,TS,NOP,WS".to_string()),
            tcp_option_set: Some("{MSS,SACK,TS,WS,NOP}".to_string()),
            mss: Some(1420),
            window_scale: Some(7),
            sack_permitted: Some(true),
            timestamps: Some(true),
        };

        let matches = match_legacy_os_signatures(&observation, &[signature]);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].family, "linux:linux_kernel");
        assert_eq!(matches[0].label, "Linux");
    }
}
