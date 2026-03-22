use serde::{Deserialize, Serialize};

use crate::model::{Confidence, Evidence, FingerprintMatch, TcpIpObservation, Transport};

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
    pub window_size: Option<u32>,
    #[serde(default)]
    pub syn_ack_seen: Option<bool>,
    #[serde(default)]
    pub rst_seen: Option<bool>,
    #[serde(default = "default_confidence")]
    pub confidence: RuleConfidence,
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
        window_size: None,
        syn_ack_seen: false,
        rst_seen: false,
    }
}

pub fn baseline_udp_observation(response_observed: bool) -> TcpIpObservation {
    TcpIpObservation {
        transport: Transport::Udp,
        handshake_observed: false,
        response_observed,
        ttl_hint: None,
        window_size: None,
        syn_ack_seen: false,
        rst_seen: false,
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
        window_size,
        syn_ack_seen,
        rst_seen,
    }
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
        && optional_value_match(observation.window_size, rule.window_size)
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
    if let Some(window_size) = observation.window_size {
        evidence.push(Evidence {
            key: "window_size".to_string(),
            value: window_size.to_string(),
        });
    }
    evidence
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
            window_size: None,
            syn_ack_seen: None,
            rst_seen: None,
            confidence: RuleConfidence::Medium,
        }];
        let matches = match_rules(&observation, &rules);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].label, "UDP responder");
    }
}
