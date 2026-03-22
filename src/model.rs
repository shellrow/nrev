use std::{collections::BTreeMap, net::IpAddr, time::Duration};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
pub struct Port {
    pub number: u16,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
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
pub enum EndpointState {
    Open,
    Closed,
    Filtered,
    Unreachable,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
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
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TcpIpObservation {
    pub transport: Transport,
    pub handshake_observed: bool,
    pub response_observed: bool,
    pub ttl_hint: Option<u8>,
    pub window_size: Option<u32>,
    pub syn_ack_seen: bool,
    pub rst_seen: bool,
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
    pub endpoints: BTreeMap<u16, EndpointResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct ScanMetadata {
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
    }
}
