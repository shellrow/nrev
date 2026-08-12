use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct Port {
    pub number: u16,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
    Syn,
    Quic,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Syn => "syn",
            Self::Quic => "quic",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointState {
    Open,
    OpenFiltered,
    Closed,
    Filtered,
    Unreachable,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ServiceHint {
    pub name: String,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Banner {
    pub raw: String,
    pub normalized: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TlsObservation {
    pub negotiated_protocol: Option<String>,
    pub cipher_suite: Option<String>,
    pub server_name: Option<String>,
    pub certificate_subjects: Vec<String>,
    pub certificate_issuers: Vec<String>,
    pub certificate_validation: TlsCertificateValidation,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TlsCertificateValidation {
    NotPerformed,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TcpIpObservation {
    pub transport: Transport,
    pub handshake_observed: bool,
    pub response_observed: bool,
    pub ttl_hint: Option<u8>,
    pub ttl_class: Option<u8>,
    pub window_size: Option<u32>,
    pub syn_ack_seen: bool,
    pub rst_seen: bool,
    pub tcp_option_order: Option<String>,
    pub tcp_option_set: Option<String>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: Option<bool>,
    pub timestamps: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct FingerprintMatch {
    pub label: String,
    pub family: String,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Evidence {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ProbeObservation {
    pub probe_id: String,
    pub service_hint: Option<ServiceHint>,
    pub banner: Option<Banner>,
    pub tls: Option<TlsObservation>,
    pub tags: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub confidence: Confidence,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct EndpointResult {
    pub port: u16,
    pub transport: Transport,
    pub state: EndpointState,
    #[serde(with = "duration_ms")]
    pub latency: Duration,
    pub observations: Vec<ProbeObservation>,
    pub fingerprint: Option<TcpIpObservation>,
    pub fingerprint_matches: Vec<FingerprintMatch>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Target {
    pub original: String,
    pub hostname: Option<String>,
    pub address: IpAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TargetReport {
    pub target: Target,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<TcpIpObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fingerprint_matches: Vec<FingerprintMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub os_guesses: Vec<FingerprintMatch>,
    pub endpoints: BTreeMap<u16, EndpointResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ScanMetadata {
    pub schema_version: u32,
    pub version: String,
    pub profile: String,
    pub recipe: Option<String>,
    pub tags: Vec<String>,
    pub generated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<ScanTimings>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ScanReport {
    pub metadata: ScanMetadata,
    pub targets: Vec<TargetReport>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HostDiscoveryMethod {
    Icmp,
    Udp,
    Tcp,
}

impl HostDiscoveryMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PingMethod {
    Icmp,
    Udp,
    Tcp,
    Quic,
}

impl PingMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Quic => "quic",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PingReply {
    pub seq: u32,
    pub success: bool,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none", with = "duration_ms_option")]
    pub latency: Option<Duration>,
    pub ttl_hint: Option<u8>,
    pub mac_address: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PingSummary {
    pub transmitted: u32,
    pub received: u32,
    pub packet_loss_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none", with = "duration_ms_option")]
    pub min: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none", with = "duration_ms_option")]
    pub avg: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none", with = "duration_ms_option")]
    pub max: Option<Duration>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PingMetadata {
    pub schema_version: u32,
    pub version: String,
    pub target: Target,
    pub method: PingMethod,
    pub port: Option<u16>,
    pub count: u32,
    pub generated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none", with = "duration_ms_option")]
    pub total: Option<Duration>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PingReport {
    pub metadata: PingMetadata,
    pub replies: Vec<PingReply>,
    pub summary: PingSummary,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TraceMethod {
    Icmp,
    Udp,
}

impl TraceMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TraceHop {
    pub ttl: u8,
    pub responder: Option<IpAddr>,
    pub outcome: String,
    pub reached_destination: bool,
    #[serde(skip_serializing_if = "Option::is_none", with = "duration_ms_option")]
    pub latency: Option<Duration>,
    pub ttl_hint: Option<u8>,
    pub mac_address: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TraceMetadata {
    pub schema_version: u32,
    pub version: String,
    pub target: Target,
    pub method: TraceMethod,
    pub port: Option<u16>,
    pub max_hops: u8,
    pub generated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none", with = "duration_ms_option")]
    pub total: Option<Duration>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TraceReport {
    pub metadata: TraceMetadata,
    pub hops: Vec<TraceHop>,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NeighborMethod {
    Arp,
    Ndp,
}

impl NeighborMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Ndp => "ndp",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct NeighborMetadata {
    pub schema_version: u32,
    pub version: String,
    pub target: Target,
    pub method: NeighborMethod,
    pub generated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct NeighborResolution {
    pub resolved_ip: IpAddr,
    pub mac_address: String,
    #[serde(with = "duration_ms")]
    pub latency: Duration,
    pub interface_name: String,
    pub interface_friendly_name: Option<String>,
    pub interface_index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct NeighborReport {
    pub metadata: NeighborMetadata,
    pub result: Option<NeighborResolution>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct HostObservation {
    pub method: HostDiscoveryMethod,
    pub port: Option<u16>,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none", with = "duration_ms_option")]
    pub latency: Option<Duration>,
    pub ttl_hint: Option<u8>,
    pub mac_address: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct HostResult {
    pub target: Target,
    pub reachable: bool,
    pub observations: Vec<HostObservation>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct HostScanMetadata {
    pub schema_version: u32,
    pub version: String,
    pub method: HostDiscoveryMethod,
    pub generated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<HostScanTimings>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct HostScanReport {
    pub metadata: HostScanMetadata,
    pub targets: Vec<HostResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ScanTimings {
    #[serde(with = "duration_ms")]
    pub target_resolution: Duration,
    #[serde(with = "duration_ms")]
    pub transport_scan: Duration,
    #[serde(with = "duration_ms")]
    pub followup_probes: Duration,
    #[serde(with = "duration_ms")]
    pub total: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct HostScanTimings {
    #[serde(with = "duration_ms")]
    pub target_resolution: Duration,
    #[serde(with = "duration_ms")]
    pub discovery: Duration,
    #[serde(with = "duration_ms")]
    pub total: Duration,
}

mod duration_ms {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(value.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(value))
    }
}

mod duration_ms_option {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&(value.as_millis() as u64)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<u64>::deserialize(deserializer)?;
        Ok(value.map(Duration::from_millis))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn serializes_duration_as_millis() {
        let endpoint = EndpointResult {
            port: 443,
            transport: Transport::Tcp,
            state: EndpointState::Open,
            latency: Duration::from_millis(123),
            observations: Vec::new(),
            fingerprint: None,
            fingerprint_matches: Vec::new(),
            errors: Vec::new(),
        };
        let value = serde_json::to_value(endpoint).expect("serialize endpoint");
        assert_eq!(value["latency"], 123);
        assert_eq!(value["transport"], "tcp");
        assert_eq!(value["state"], "open");
    }
}
