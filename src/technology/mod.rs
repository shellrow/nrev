//! Deterministic asset inventory derived from recorded nrev probe exchanges.
mod advisory;
mod catalog;
mod external;
pub(crate) mod html;
mod observe;
mod platform;
pub use platform::{OperatingSystem, ServicePlatform, StackMatch};

use crate::model::{EndpointResult, EndpointState, REPORT_SCHEMA_VERSION, ScanReport, Transport};
pub use advisory::{
    Advisories, Candidate, ConditionEvidence, FactCondition, NvdCoverage, VersionRange,
};
use anyhow::{Context, Result, ensure};
use catalog::{Catalog, Field, Index, MAX_FIELD};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub const BUILTIN_DATABASE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/nkdb.json"));

/// Compile once and share between replay workers.
pub struct KnowledgeBase {
    db: Catalog,
    index: Index,
    cpes: BTreeMap<String, usize>,
    stack_index: BTreeMap<String, Vec<usize>>,
    platform_patterns: Vec<regex::Regex>,
    prefilters: BTreeMap<Field, regex::RegexSet>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum EvidenceRef {
    /// Zero-based position in this endpoint's observations array.
    Probe {
        observation: usize,
        probe: String,
        field: &'static str,
    },
    /// Zero-based positions in identification.hosts, ports and service.cpes.
    Nmap {
        host: usize,
        port: usize,
        cpe: usize,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct Declaration {
    pub rule: String,
    pub evidence: EvidenceRef,
    pub version: Option<String>,
    pub qualified: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    Inferred,
    Conflicting,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    Declared,
    Partial,
    Unparsed,
    Missing,
    Conflicting,
}

#[derive(Debug, Serialize)]
pub struct Technology {
    pub id: String,
    pub role: String,
    pub source: String,
    pub cpe_names: Vec<String>,
    pub identity: IdentityStatus,
    pub advisory_status: &'static str,
    /// Product identification always depends on claims made by a remote peer or matcher.
    pub confidence: &'static str,
    pub version_status: VersionStatus,
    pub version: Option<String>,
    pub declarations: Vec<Declaration>,
}

#[derive(Debug, Serialize)]
pub struct Fact {
    pub name: &'static str,
    pub value: String,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Serialize)]
pub struct ServiceEvidence {
    pub name: String,
    pub basis: &'static str,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Serialize)]
pub struct EndpointInventory {
    pub port: u16,
    pub transport: Transport,
    pub state: EndpointState,
    pub collection_errors: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_identity_note: Option<&'static str>,
    pub identity_status: &'static str,
    pub technologies: Vec<Technology>,
    pub services: Vec<ServiceEvidence>,
    pub service_platforms: Vec<ServicePlatform>,
    pub observed: Vec<Fact>,
    pub review: Vec<Fact>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advisory_candidates: Vec<Candidate>,
}

#[derive(Debug, Serialize)]
pub struct HostInventory {
    pub address: IpAddr,
    pub hostname: Option<String>,
    pub operating_system: OperatingSystem,
    pub endpoints: Vec<EndpointInventory>,
}

#[derive(Debug, Serialize)]
pub struct Inventory {
    pub schema: u32,
    pub knowledge_revision: String,
    /// Number of records in the supplied advisory set. None means review was not requested.
    pub advisory_records: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nvd_coverage: Option<NvdCoverage>,
    pub collected_at: DateTime<Utc>,
    pub hosts: Vec<HostInventory>,
}

impl KnowledgeBase {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= catalog::MAX_DATABASE,
            "NKDB exceeds size limit"
        );
        let db: Catalog = serde_json::from_slice(bytes).context("invalid NKDB JSON")?;
        let index = catalog::compile(&db)?;
        let platform_patterns = catalog::compile_platforms(&db)?;
        let mut stack_index = BTreeMap::<String, Vec<usize>>::new();
        for (i, profile) in db.stack_profiles.iter().enumerate() {
            stack_index
                .entry(profile.order.clone())
                .or_default()
                .push(i);
        }
        let mut prefilters = BTreeMap::new();
        for (&field, rules) in &index {
            if rules.len() > 16 {
                let matcher = regex::RegexSetBuilder::new(rules.iter().map(|r| r.regex.as_str()))
                    .unicode(false)
                    .size_limit(4 << 20)
                    .dfa_size_limit(1 << 20)
                    .build()
                    .context("NKDB field matcher exceeds the compilation budget")?;
                prefilters.insert(field, matcher);
            }
        }
        let cpes = db
            .products
            .iter()
            .enumerate()
            .flat_map(|(i, p)| p.cpe_names.iter().map(move |name| (name.clone(), i)))
            .collect();
        Ok(Self {
            cpes,
            stack_index,
            platform_patterns,
            db,
            index,
            prefilters,
        })
    }

    /// Read the research note associated with a product's source key.
    pub fn provenance(&self, source: &str) -> Option<&str> {
        self.db.provenance.get(source).map(String::as_str)
    }

    pub fn builtin() -> Result<Self> {
        Self::from_bytes(BUILTIN_DATABASE)
    }

    /// Evaluate one endpoint. All references point into this endpoint's input record.
    pub fn identify(&self, endpoint: &EndpointResult) -> Result<EndpointInventory> {
        self.evaluate(endpoint, &[])
    }

    fn evaluate(
        &self,
        endpoint: &EndpointResult,
        external: &[(usize, Declaration)],
    ) -> Result<EndpointInventory> {
        let mut groups = BTreeMap::<&str, BTreeMap<usize, Vec<Declaration>>>::new();
        for (product, decl) in external {
            groups
                .entry(&self.db.products[*product].role)
                .or_default()
                .entry(*product)
                .or_default()
                .push(decl.clone());
        }
        let mut observed = Vec::new();
        let mut services = BTreeMap::new();
        let mut service_platforms = Vec::new();
        let mut review = Vec::new();
        ensure!(
            endpoint.observations.len() <= 256,
            "too many observations on endpoint"
        );
        for (i, obs) in endpoint.observations.iter().enumerate() {
            ensure!(
                obs.evidence.len() <= 128,
                "too many evidence fields in observation"
            );
            let reference = |field| EvidenceRef::Probe {
                observation: i,
                probe: obs.probe_id.clone(),
                field,
            };
            let signals = observe::signals(obs, endpoint.transport);
            if let Some((field, key, value)) = signals.platform {
                for (rule, pattern) in self.db.platform_claims.iter().zip(&self.platform_patterns) {
                    if rule.field == field
                        && let Some(captures) = pattern.captures(value)
                    {
                        service_platforms.push(ServicePlatform {
                            family: rule.family.clone(),
                            environment: rule.environment.clone(),
                            declared_release: captures
                                .name("version")
                                .map(|m| m.as_str())
                                .filter(|v| valid_version(v))
                                .map(str::to_owned),
                            evidence: reference(key),
                        });
                    }
                }
            }
            if let Some(hint) = &obs.service_hint
                && hint.name.len() <= 48
                && !hint.name.is_empty()
                && hint
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
            {
                services
                    .entry(hint.name.clone())
                    .or_insert_with(|| ServiceEvidence {
                        name: hint.name.clone(),
                        basis: "probe_hint",
                        evidence: reference("service_hint.name"),
                    });
            }
            for (name, field, v) in signals.facts {
                let protocol = match name {
                    "http.status" => Some(match obs.probe_id.as_str() {
                        "tls" => "https",
                        "quic" => "http3",
                        _ => "http",
                    }),
                    "tls.version" | "tls.cipher_suite" | "tls.alpn" => Some("tls"),
                    "ssh.protocol" => Some("ssh"),
                    "smb.dialect" => Some("smb"),
                    "rdp.security_protocol" => Some("rdp"),
                    "imap.greeting" => Some("imap"),
                    "pop3.greeting" => Some("pop3"),
                    "smtp.starttls" | "smtp.ehlo" => Some("smtp"),
                    "mysql.server_version" => Some("mysql"),
                    "tds.peer_version" | "tds.encryption" => Some("tds"),
                    "ntp.version" => Some("ntp"),
                    "dns.rcode" => Some("dns"),
                    "memcached.version" => Some("memcached"),
                    "postgresql.ssl_request" => Some("postgresql"),
                    "resp.ping" => Some("resp"),
                    _ => None,
                };
                if let Some(name) = protocol
                    && services.get(name).is_none_or(|s| s.basis == "probe_hint")
                {
                    services.insert(
                        name.into(),
                        ServiceEvidence {
                            name: name.into(),
                            basis: "protocol_response",
                            evidence: reference(field),
                        },
                    );
                }
                if name == "tds.encryption" && v == "encrypt-not-supported" {
                    review.push(Fact {
                        name: "review_transport_encryption",
                        value: "The peer reported no TDS encryption support. Check the server transport policy.".into(),
                        evidence: reference(field),
                    });
                }
                observed.push(Fact {
                    name,
                    value: v.to_owned(),
                    evidence: reference(field),
                });
            }
            for (selector, key, value) in signals.declarations {
                let Some(rules) = self.index.get(&selector) else {
                    continue;
                };
                let candidates = self.prefilters.get(&selector).map(|set| set.matches(value));
                for (i, rule) in rules.iter().enumerate() {
                    if candidates.as_ref().is_some_and(|set| !set.matched(i)) {
                        continue;
                    }
                    let Some(c) = rule.regex.captures(value) else {
                        continue;
                    };
                    let p = &self.db.products[rule.product];
                    let version = c.name("version").map(|m| m.as_str());
                    if version.is_some_and(|v| !valid_version(v)) {
                        continue;
                    }
                    if let Some(name) = match selector {
                        Field::FtpGreeting => Some("ftp"),
                        Field::SmtpGreeting => Some("smtp"),
                        _ => None,
                    } && services.get(name).is_none_or(|s| s.basis == "probe_hint")
                    {
                        services.insert(
                            name.into(),
                            ServiceEvidence {
                                name: name.into(),
                                basis: "product_greeting",
                                evidence: reference(key),
                            },
                        );
                    }
                    let declarations = groups
                        .entry(&p.role)
                        .or_default()
                        .entry(rule.product)
                        .or_default();
                    if declarations.last().is_none_or(|d| {
                        d.evidence != reference(key) || d.version.as_deref() != version
                    }) {
                        declarations.push(Declaration {
                            rule: format!("{}#{}", p.id, rule.signature),
                            evidence: reference(key),
                            version: version.map(str::to_owned),
                            qualified: c.name("distribution").is_some()
                                || (matches!(selector, Field::Server | Field::ServerComponent)
                                    && signals.server_comment),
                        });
                    }
                }
            }
        }
        let technologies = self.summarize(groups);
        let identity_status = if technologies.is_empty() {
            "unknown"
        } else if technologies
            .iter()
            .any(|t| t.identity == IdentityStatus::Conflicting)
        {
            "conflicting"
        } else {
            "inferred"
        };
        Ok(EndpointInventory {
            port: endpoint.port,
            transport: endpoint.transport,
            state: endpoint.state.clone(),
            collection_errors: endpoint.errors.len(),
            errors: endpoint
                .errors
                .iter()
                .take(32)
                .map(|e| e.chars().take(512).collect())
                .collect(),
            latency_ms: u64::try_from(endpoint.latency.as_millis()).unwrap_or(u64::MAX),
            external_identity_note: None,
            identity_status,
            technologies,
            services: services.into_values().collect(),
            service_platforms,
            observed,
            review,
            advisory_candidates: Vec::new(),
        })
    }

    fn summarize(
        &self,
        groups: BTreeMap<&str, BTreeMap<usize, Vec<Declaration>>>,
    ) -> Vec<Technology> {
        let mut technologies = Vec::new();
        for (role, products) in groups {
            let conflict = products.len() > 1;
            for (i, declarations) in products {
                let versions: BTreeSet<_> = declarations
                    .iter()
                    .filter_map(|d| d.version.as_deref())
                    .collect();
                let product = &self.db.products[i];
                let version = versions.first().copied().filter(|_| versions.len() == 1);
                let version_status = match version {
                    None if versions.is_empty() => VersionStatus::Missing,
                    None => VersionStatus::Conflicting,
                    Some(v)
                        if advisory::parts(v, product.version_scheme, product.components)
                            .is_some() =>
                    {
                        VersionStatus::Declared
                    }
                    Some(v)
                        if v.split('.').all(|part| {
                            !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
                        }) && (v.split('.').count() < product.components
                            || (product.version_scheme == catalog::Scheme::PortableSsh
                                && v.split('.').count() == product.components)) =>
                    {
                        VersionStatus::Partial
                    }
                    Some(_) => VersionStatus::Unparsed,
                };
                let version = version.filter(|_| !conflict).map(str::to_owned);
                technologies.push(Technology {
                    id: product.id.clone(),
                    source: product.source.clone(),
                    cpe_names: product.cpe_names.clone(),
                    role: role.to_owned(),
                    identity: if conflict {
                        IdentityStatus::Conflicting
                    } else {
                        IdentityStatus::Inferred
                    },
                    advisory_status: "not_checked",
                    confidence: if conflict {
                        "unresolved"
                    } else {
                        "weak_inference"
                    },
                    version_status,
                    version,
                    declarations,
                });
            }
        }
        technologies
    }

    pub fn inventory(
        &self,
        report: &ScanReport,
        advisories: Option<&Advisories>,
    ) -> Result<Inventory> {
        ensure!(
            report.metadata.schema_version == REPORT_SCHEMA_VERSION,
            "unsupported scan report schema"
        );
        let external = self.recorded_cpes(report.identification.as_ref())?;
        let mut duplicates = BTreeSet::new();
        if !external.is_empty() {
            let mut seen = BTreeSet::new();
            for target in &report.targets {
                if !seen.insert(target.target.address) {
                    duplicates.insert(target.target.address);
                }
            }
        }
        let mut hosts = Vec::new();
        let mut candidate_budget = 65536;
        for target in &report.targets {
            let mut endpoints = Vec::new();
            for (&port, ep) in &target.endpoints {
                ensure!(ep.port == port, "endpoint port differs from map key");
                let key = (target.target.address, port, ep.transport.wire_protocol());
                let recorded = external.get(&key);
                let note = if recorded.is_some() && duplicates.contains(&target.target.address) {
                    Some("ambiguous_address")
                } else if recorded.is_some()
                    && !matches!(ep.state, EndpointState::Open | EndpointState::OpenFiltered)
                {
                    Some("port_state_disagreement")
                } else {
                    None
                };
                let mut result = self.evaluate(
                    ep,
                    recorded
                        .filter(|_| note.is_none())
                        .map(Vec::as_slice)
                        .unwrap_or_default(),
                )?;
                result.external_identity_note = note;
                if let Some(db) = advisories {
                    result.advisory_candidates = db.correlate(
                        &mut result.technologies,
                        &result.observed,
                        &mut candidate_budget,
                    )?;
                }
                endpoints.push(result);
            }
            hosts.push(HostInventory {
                address: target.target.address,
                hostname: target.target.hostname.clone(),
                operating_system: self.operating_system(target, &endpoints),
                endpoints,
            });
        }
        Ok(Inventory {
            schema: 1,
            knowledge_revision: self.db.revision.clone(),
            advisory_records: advisories.map(|db| db.record_count),
            nvd_coverage: advisories.and_then(|db| db.nvd.clone()),
            collected_at: report.metadata.generated_at,
            hosts,
        })
    }
}

fn valid_version(value: &str) -> bool {
    value.len() <= 64
        && value.starts_with(|c: char| c.is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+~-".contains(&b))
}
