use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    fingerprint::canonical_platform_family,
    model::{Confidence, Evidence, ProbeObservation},
};

const BUILTIN_SERVICE_DB_JSON: &str = include_str!("../resources/nrev-service-db.json");

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyServiceDb {
    #[serde(default)]
    pub signatures: Vec<LegacyServiceSignature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyServiceSignature {
    pub probe_id: String,
    pub service: String,
    pub regex: String,
    #[serde(default)]
    pub regex_literal_tokens: Vec<String>,
    #[serde(default)]
    pub cpe: Vec<String>,
}

pub fn builtin_service_signatures() -> Vec<LegacyServiceSignature> {
    serde_json::from_str::<LegacyServiceDb>(BUILTIN_SERVICE_DB_JSON)
        .expect("embedded service signature database must be valid")
        .signatures
}

pub fn apply_legacy_service_signatures(
    observation: &mut ProbeObservation,
    signatures: &[LegacyServiceSignature],
) {
    let Some(service_hint) = &observation.service_hint else {
        return;
    };
    let Some(banner) = &observation.banner else {
        return;
    };

    let banner_text = &banner.normalized;
    let banner_raw = &banner.raw;
    let candidates = signatures.iter().filter(|signature| {
        signature.service == service_hint.name
            && probe_id_matches(&signature.probe_id, &observation.probe_id)
            && literal_tokens_match(&signature.regex_literal_tokens, banner_text)
    });

    for signature in candidates {
        let Ok(regex) = Regex::new(&signature.regex) else {
            continue;
        };
        if !regex.is_match(banner_raw) {
            continue;
        }

        observation.confidence = max_confidence(observation.confidence.clone(), Confidence::High);
        observation.evidence.push(Evidence {
            key: "service_signature".to_string(),
            value: format!("{}:{}", signature.service, signature.probe_id),
        });
        for cpe in &signature.cpe {
            observation.evidence.push(Evidence {
                key: "cpe".to_string(),
                value: cpe.clone(),
            });
        }
        if let Some(platform) = canonical_platform_family(&signature.cpe) {
            observation.evidence.push(Evidence {
                key: "platform".to_string(),
                value: platform,
            });
        }
        break;
    }
}

fn probe_id_matches(signature_probe_id: &str, observation_probe_id: &str) -> bool {
    signature_probe_id == "tcp:null"
        || signature_probe_id == observation_probe_id
        || signature_probe_id.ends_with(observation_probe_id)
}

fn literal_tokens_match(tokens: &[String], banner_text: &str) -> bool {
    tokens.iter().all(|token| banner_text.contains(token))
}

fn max_confidence(left: Confidence, right: Confidence) -> Confidence {
    use Confidence::{High, Low, Medium};

    match (left, right) {
        (High, _) | (_, High) => High,
        (Medium, _) | (_, Medium) => Medium,
        (Low, Low) => Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{Confidence, ProbeObservation, ServiceHint},
        probes::normalize_banner,
    };

    #[test]
    fn matches_raw_banner_regex_and_adds_platform() {
        let mut observation = ProbeObservation {
            probe_id: "http".to_string(),
            service_hint: Some(ServiceHint {
                name: "http".to_string(),
                confidence: Confidence::Medium,
            }),
            banner: Some(normalize_banner(
                "HTTP/1.0 400 Bad Request\r\nServer: doubleTwist Sync (Android)\r\n".to_string(),
            )),
            tls: None,
            tags: Vec::new(),
            evidence: Vec::new(),
            confidence: Confidence::Medium,
        };
        let signatures = vec![LegacyServiceSignature {
            probe_id: "tcp:null".to_string(),
            service: "http".to_string(),
            regex: "doubleTwist Sync \\(Android\\)".to_string(),
            regex_literal_tokens: vec!["doubleTwist Sync (Android)".to_string()],
            cpe: vec![
                "cpe:/o:google:android".to_string(),
                "cpe:/o:linux:linux_kernel".to_string(),
            ],
        }];

        apply_legacy_service_signatures(&mut observation, &signatures);

        assert!(
            observation
                .evidence
                .iter()
                .any(|item| item.key == "platform" && item.value == "linux")
        );
    }
}
