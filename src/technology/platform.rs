//! Family-level assessment of the responding network stack and service environments.
use super::{EndpointInventory, EvidenceRef, KnowledgeBase};
use crate::model::{EndpointState, TargetReport, TcpIpObservation, Transport};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Serialize)]
pub struct ServicePlatform {
    pub family: String,
    pub environment: String,
    pub declared_release: Option<String>,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Serialize)]
pub struct StackMatch {
    /// None refers to the target-level fingerprint in an older report.
    pub port: Option<u16>,
    pub family: String,
    pub profile: String,
    pub source: String,
}

#[derive(Debug, Serialize)]
pub struct OperatingSystem {
    pub status: &'static str,
    /// Family of the responding TCP stack, when the evidence agrees.
    pub family: Option<String>,
    pub stack_matches: Vec<StackMatch>,
    /// Service environment hints are located under the corresponding endpoint.
    pub service_families: Vec<String>,
}

impl KnowledgeBase {
    pub(super) fn operating_system(
        &self,
        target: &TargetReport,
        endpoints: &[EndpointInventory],
    ) -> OperatingSystem {
        let mut stack_matches = Vec::new();
        let mut endpoint_fingerprints = false;
        for (&port, endpoint) in &target.endpoints {
            if let Some(fp) = &endpoint.fingerprint {
                endpoint_fingerprints = true;
                if endpoint.state == EndpointState::Open && endpoint.transport == Transport::Syn {
                    self.stack_matches(fp, Some(port), &mut stack_matches);
                }
            }
        }
        if !endpoint_fingerprints && let Some(fp) = &target.fingerprint {
            self.stack_matches(fp, None, &mut stack_matches);
        }
        let stacks: BTreeSet<_> = stack_matches.iter().map(|s| &s.family).collect();
        let services: BTreeSet<_> = endpoints
            .iter()
            .filter(|ep| ep.state == EndpointState::Open)
            .flat_map(|ep| ep.service_platforms.iter().map(|s| &s.family))
            .collect();
        let families: BTreeSet<_> = stacks.union(&services).collect();
        let (status, family) = if families.len() > 1 {
            ("conflicting", None)
        } else if let Some(family) = stacks.first() {
            (
                if services.is_empty() {
                    "stack_inference"
                } else {
                    "corroborated_family"
                },
                Some((*family).clone()),
            )
        } else if services.is_empty() {
            ("unknown", None)
        } else {
            ("service_hint_only", None)
        };
        OperatingSystem {
            status,
            family,
            service_families: services.into_iter().cloned().collect(),
            stack_matches,
        }
    }

    fn stack_matches(
        &self,
        fp: &TcpIpObservation,
        port: Option<u16>,
        matches: &mut Vec<StackMatch>,
    ) {
        if fp.transport != Transport::Syn
            || !fp.response_observed
            || !fp.handshake_observed
            || !fp.syn_ack_seen
            || fp.rst_seen
            || fp.sack_permitted != Some(true)
            || fp.window_scale.is_none_or(|v| v > 14)
            || matches!(fp.mss, None | Some(0))
            || !fp.window_size.is_some_and(|v| (1..=65535).contains(&v))
        {
            return;
        }
        let (Some(order), Some(ttl)) = (fp.tcp_option_order.as_deref(), fp.ttl_hint) else {
            return;
        };
        let Some(profiles) = self.stack_index.get(order) else {
            return;
        };
        if let Some(set) = &fp.tcp_option_set
            && (set.len() > 128 || !crate::fingerprint::tcp_option_sets_equal(order, set))
        {
            return;
        }
        let has_timestamps = order.split(',').any(|t| t == "TS");
        for &index in profiles {
            let profile = &self.db.stack_profiles[index];
            if profile
                .ttl_class
                .checked_sub(ttl)
                .is_none_or(|hops| hops > 24)
                || fp.ttl_class.is_some_and(|class| class != profile.ttl_class)
                || profile
                    .window
                    .is_some_and(|w| Some(u32::from(w)) != fp.window_size)
                || has_timestamps != fp.timestamps.unwrap_or(false)
            {
                continue;
            }
            matches.push(StackMatch {
                port,
                family: profile.family.clone(),
                profile: profile.id.clone(),
                source: profile.source.clone(),
            });
        }
    }
}
