//! Local, product-indexed advisory review. Input bounds refer to upstream releases.
mod nvd;
pub use nvd::NvdCoverage;

use super::{
    EvidenceRef, Fact, IdentityStatus, KnowledgeBase, Technology, VersionStatus, catalog::Scheme,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema: u32,
    records: Vec<Record>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    product: String,
    source: String,
    introduced: Option<String>,
    fixed: Option<String>,
    condition: Option<String>,
    ranges: Option<Vec<VersionRange>>,
    observed_when: Option<FactCondition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactCondition {
    pub fact: String,
    pub equals: String,
}

impl FactCondition {
    fn validate(&self) -> Result<()> {
        let allowed: &[&str] = match self.fact.as_str() {
            "http.carrier" => &["tls", "quic"],
            "tls.alpn" => &["h3", "h2", "http/1.1"],
            "tls.version" => &["1.2", "1.3"],
            "smtp.starttls" => &["advertised"],
            "tds.encryption" => &[
                "encrypt-on",
                "encrypt-off",
                "encrypt-required",
                "encrypt-not-supported",
            ],
            "postgresql.ssl_request" => &["accepted", "declined"],
            _ => &[],
        };
        ensure!(
            allowed.contains(&self.equals.as_str()),
            "unsupported advisory fact or value"
        );
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct ConditionEvidence {
    pub requirement: FactCondition,
    pub status: &'static str,
    pub evidence: Option<EvidenceRef>,
}

struct Interval {
    low: Option<Vec<u32>>,
    high: Option<Vec<u32>>,
    inclusive: bool,
}

impl Interval {
    fn compile(range: &VersionRange, scheme: Scheme, width: usize) -> Result<Self> {
        let parse =
            |v: &String| parts(v, scheme, width).context("unsupported advisory version bound");
        ensure!(
            range.fixed.is_none() || range.last_affected.is_none(),
            "ambiguous upper bound"
        );
        let low = range.introduced.as_ref().map(parse).transpose()?;
        let high = range
            .fixed
            .as_ref()
            .or(range.last_affected.as_ref())
            .map(parse)
            .transpose()?;
        let inclusive = range.last_affected.is_some();
        ensure!(
            low.is_some() || high.is_some(),
            "advisory range needs a bound"
        );
        ensure!(
            low.as_ref()
                .zip(high.as_ref())
                .is_none_or(|(l, h)| l < h || (inclusive && l == h)),
            "empty or reversed advisory range"
        );
        Ok(Self {
            low,
            high,
            inclusive,
        })
    }

    fn precedes(&self, next: &Self) -> bool {
        self.high
            .as_ref()
            .zip(next.low.as_ref())
            .is_some_and(|(high, low)| high < low || (high == low && !self.inclusive))
    }

    fn contains(&self, version: &[u32]) -> bool {
        self.low.as_deref().is_none_or(|low| version >= low)
            && self
                .high
                .as_deref()
                .is_none_or(|high| version < high || (self.inclusive && version == high))
    }
}

struct Entry {
    record: Record,
    scheme: Scheme,
    width: usize,
    intervals: Vec<Interval>,
}

pub struct Advisories {
    by_product: BTreeMap<String, Vec<Entry>>,
    pub(super) record_count: usize,
    pub(super) nvd: Option<NvdCoverage>,
}

#[derive(Debug, Serialize)]
pub struct Candidate {
    pub id: String,
    pub product: String,
    pub source: String,
    pub classification: &'static str,
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub condition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<VersionRange>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<ConditionEvidence>,
    pub applicability: &'static str,
    pub review: &'static str,
}

pub(super) fn parts(version: &str, scheme: Scheme, width: usize) -> Option<Vec<u32>> {
    fn number(s: &str) -> Option<u32> {
        if s.is_empty()
            || !s.bytes().all(|c| c.is_ascii_digit())
            || (s.len() > 1 && s.starts_with('0'))
        {
            return None;
        }
        s.parse().ok()
    }
    if version.len() > 64 {
        return None;
    }
    let (base, patch) = match scheme {
        Scheme::Numeric | Scheme::OptionalPatch => (version, None),
        Scheme::PortableSsh => {
            let (base, p) = version.split_once('p')?;
            (base, Some(number(p)?))
        }
    };
    let mut components: Vec<_> = base.split('.').map(number).collect::<Option<_>>()?;
    if scheme == Scheme::OptionalPatch && components.len() == 2 {
        components.push(0);
    }
    if components.len() != width {
        return None;
    }
    components.extend(patch);
    Some(components)
}

impl Advisories {
    /// Load the small, offline selection of vendor advisories shipped with nrev.
    pub fn bundled(knowledge: &KnowledgeBase) -> Result<Self> {
        Self::from_bytes(include_bytes!("../../knowledge/advisories.json"), knowledge)
    }

    pub fn from_bytes(bytes: &[u8], knowledge: &KnowledgeBase) -> Result<Self> {
        ensure!(
            bytes.len() <= 4 * 1024 * 1024,
            "advisory file exceeds size limit"
        );
        let file: File = serde_json::from_slice(bytes).context("invalid advisory JSON")?;
        Self::compile(file, knowledge)
    }

    fn compile(file: File, knowledge: &KnowledgeBase) -> Result<Self> {
        ensure!(
            matches!(file.schema, 1 | 2) && file.records.len() <= 8192,
            "unsupported advisory schema or record count"
        );
        let products: BTreeMap<_, _> = knowledge
            .db
            .products
            .iter()
            .flat_map(|p| {
                std::iter::once(&p.id)
                    .chain(&p.cpe_names)
                    .map(move |name| (name.as_str(), p))
            })
            .collect();
        let mut by_product = BTreeMap::<String, Vec<Entry>>::new();
        let mut seen = BTreeSet::new();
        let record_count = file.records.len();
        for record in file.records {
            ensure!(
                !record.id.is_empty()
                    && record.id.len() <= 80
                    && record
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid advisory identifier"
            );
            ensure!(
                !record.source.trim().is_empty()
                    && record.source.len() <= 512
                    && !record.source.chars().any(char::is_control),
                "invalid advisory source"
            );
            ensure!(
                record
                    .condition
                    .as_ref()
                    .is_none_or(|c| !c.trim().is_empty()
                        && c.len() <= 512
                        && !c.chars().any(char::is_control)),
                "invalid advisory condition"
            );
            let product = products
                .get(record.product.as_str())
                .context("advisory names an unknown NKDB product")?;
            ensure!(
                file.schema == 2 || (record.ranges.is_none() && record.observed_when.is_none()),
                "extended advisory fields require schema 2"
            );
            if let Some(requirement) = &record.observed_when {
                requirement.validate()?;
            }
            let legacy = VersionRange {
                introduced: record.introduced.clone(),
                fixed: record.fixed.clone(),
                last_affected: None,
            };
            let ranges = match &record.ranges {
                Some(list) => {
                    ensure!(
                        record.introduced.is_none()
                            && record.fixed.is_none()
                            && (1..=32).contains(&list.len()),
                        "expected one to 32 ranges without top-level bounds"
                    );
                    list.as_slice()
                }
                None => std::slice::from_ref(&legacy),
            };
            let intervals = ranges
                .iter()
                .map(|r| Interval::compile(r, product.version_scheme, product.components))
                .collect::<Result<Vec<_>>>()?;
            for pair in intervals.windows(2) {
                ensure!(
                    pair[0].precedes(&pair[1]),
                    "advisory ranges must be ordered and disjoint"
                );
            }
            ensure!(
                seen.insert((product.id.clone(), record.id.clone())),
                "duplicate product/advisory pair"
            );
            by_product
                .entry(product.id.clone())
                .or_default()
                .push(Entry {
                    record,
                    scheme: product.version_scheme,
                    width: product.components,
                    intervals,
                });
        }
        for records in by_product.values_mut() {
            records.sort_by(|a, b| a.record.id.cmp(&b.record.id));
        }
        Ok(Self {
            by_product,
            record_count,
            nvd: None,
        })
    }

    pub(super) fn correlate(
        &self,
        technologies: &mut [Technology],
        facts: &[Fact],
        budget: &mut usize,
    ) -> Result<Vec<Candidate>> {
        let mut out = Vec::new();
        for t in technologies {
            if t.identity != IdentityStatus::Inferred {
                t.advisory_status = "conflicting_identity";
                continue;
            }
            let Some(records) = self.by_product.get(&t.id) else {
                t.advisory_status = "no_product_records";
                continue;
            };
            t.advisory_status = "outside_supplied_ranges";
            // Scope configuration receipts to exchanges that also declared this product.
            let mut receipts = BTreeMap::new();
            if records.iter().any(|r| r.record.observed_when.is_some()) {
                let exchanges: BTreeSet<_> = t
                    .declarations
                    .iter()
                    .filter_map(|d| match d.evidence {
                        EvidenceRef::Probe { observation, .. } => Some(observation),
                        _ => None,
                    })
                    .collect();
                for fact in facts {
                    if let EvidenceRef::Probe { observation, .. } = fact.evidence
                        && exchanges.contains(&observation)
                    {
                        receipts
                            .entry((fact.name, fact.value.as_str()))
                            .or_insert(&fact.evidence);
                    }
                }
            }
            let product = &records[0];
            let version = t
                .version
                .as_deref()
                .and_then(|v| parts(v, product.scheme, product.width));
            let qualified = t.declarations.iter().any(|d| d.qualified);
            for r in records {
                *budget = budget
                    .checked_sub(r.intervals.len())
                    .context("advisory comparison limit exceeded")?;
                let applicability = if t.version_status == VersionStatus::Conflicting {
                    "conflicting_versions"
                } else if qualified {
                    "distribution_review"
                } else if let Some(v) = &version {
                    if !r.intervals.iter().any(|range| range.contains(v)) {
                        continue;
                    }
                    "in_upstream_range"
                } else {
                    "unknown_version"
                };
                t.advisory_status = "potential_candidates";
                let configuration = r.record.observed_when.as_ref().map(|condition| {
                    let evidence = receipts
                        .get(&(condition.fact.as_str(), condition.equals.as_str()))
                        .copied()
                        .cloned();
                    ConditionEvidence {
                        status: if evidence.is_some() {
                            "observed"
                        } else {
                            "unobserved"
                        },
                        requirement: condition.clone(),
                        evidence,
                    }
                });
                out.push(Candidate {
                    configuration,
                    ranges: r.record.ranges.clone(),
                    id: r.record.id.clone(),
                    product: t.id.clone(),
                    source: r.record.source.clone(),
                    introduced: r.record.introduced.clone(),
                    fixed: r.record.fixed.clone(),
                    condition: r.record.condition.clone(),
                    classification: "potential",
                    applicability,
                    review: "Confirm the installed package, vendor fixes, edition and configuration using the source advisory.",
                });
            }
        }
        Ok(out)
    }
}
