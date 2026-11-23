//! Project simple NVD CPE configurations from a saved API 2.0 response.
use super::{Advisories, File, Interval, KnowledgeBase, Record, VersionRange};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Counts refer to this page of the supplied snapshot.
#[derive(Clone, Debug, Serialize)]
pub struct NvdCoverage {
    pub timestamp: String,
    pub start_index: usize,
    pub total_results: usize,
    pub page_records: usize,
    pub imported: usize,
    pub skipped_status: usize,
    pub skipped_configuration: usize,
    pub outside_catalog: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    format: String,
    version: String,
    timestamp: String,
    start_index: usize,
    total_results: usize,
    vulnerabilities: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    cve: Cve,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cve {
    id: String,
    vuln_status: Option<String>,
    configurations: Option<Value>,
    #[serde(default)]
    cve_tags: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    operator: Option<String>,
    #[serde(default)]
    negate: bool,
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Node {
    operator: String,
    #[serde(default)]
    negate: bool,
    cpe_match: Vec<Criterion>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Criterion {
    vulnerable: bool,
    criteria: String,
    #[serde(rename = "matchCriteriaId")]
    _match_id: Option<String>,
    version_start_including: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

impl Advisories {
    /// Read one local NVD API 2.0 page. Coverage accompanies every resulting inventory.
    pub fn from_nvd_bytes(bytes: &[u8], knowledge: &KnowledgeBase) -> Result<Self> {
        ensure!(bytes.len() <= 8 << 20, "NVD page exceeds size limit");
        let page: Page = serde_json::from_slice(bytes).context("invalid NVD response")?;
        let count = page.vulnerabilities.len();
        ensure!(
            page.format == "NVD_CVE" && page.version == "2.0",
            "unsupported NVD response format"
        );
        ensure!(
            count <= 8192
                && page
                    .start_index
                    .checked_add(count)
                    .is_some_and(|n| n <= page.total_results),
            "invalid NVD page bounds"
        );
        ensure!(
            page.timestamp.len() <= 64
                && (chrono::DateTime::parse_from_rfc3339(&page.timestamp).is_ok()
                    || chrono::NaiveDateTime::parse_from_str(
                        &page.timestamp,
                        "%Y-%m-%dT%H:%M:%S%.f"
                    )
                    .is_ok()),
            "invalid NVD snapshot timestamp"
        );
        let mut coverage = NvdCoverage {
            timestamp: page.timestamp,
            start_index: page.start_index,
            total_results: page.total_results,
            page_records: count,
            imported: 0,
            skipped_status: 0,
            skipped_configuration: 0,
            outside_catalog: 0,
        };
        let mut records = Vec::new();
        let mut ids = BTreeSet::new();
        for Item { cve } in page.vulnerabilities {
            let valid_id = cve
                .id
                .strip_prefix("CVE-")
                .and_then(|v| v.split_once('-'))
                .is_some_and(|(year, n)| {
                    year.len() == 4
                        && (4..=32).contains(&n.len())
                        && year.bytes().chain(n.bytes()).all(|b| b.is_ascii_digit())
                });
            ensure!(
                valid_id && ids.insert(cve.id.clone()),
                "invalid or duplicate NVD CVE ID"
            );
            if !matches!(cve.vuln_status.as_deref(), Some("Analyzed" | "Modified")) {
                coverage.skipped_status += 1;
                continue;
            }
            let Some(entries) = project(cve, knowledge) else {
                coverage.skipped_configuration += 1;
                continue;
            };
            if entries.is_empty() {
                coverage.outside_catalog += 1;
            } else {
                coverage.imported += 1;
                records.extend(entries);
                ensure!(records.len() <= 8192, "too many projected NVD records");
            }
        }
        let mut db = Self::compile(File { schema: 2, records }, knowledge)?;
        db.nvd = Some(coverage);
        Ok(db)
    }
}

fn project(cve: Cve, knowledge: &KnowledgeBase) -> Option<Vec<Record>> {
    if !cve.cve_tags.is_empty() {
        return None;
    }
    let configs: Vec<Configuration> = serde_json::from_value(cve.configurations?).ok()?;
    if configs.is_empty() {
        return None;
    }
    let mut ranges = BTreeMap::<usize, Vec<(Interval, VersionRange)>>::new();
    for config in configs {
        if config.negate
            || config.nodes.is_empty()
            || !(config.operator.as_deref() == Some("OR")
                || (config.nodes.len() == 1 && config.operator.is_none()))
        {
            return None;
        }
        for node in config.nodes {
            if node.negate || node.operator != "OR" || node.cpe_match.is_empty() {
                return None;
            }
            for criterion in node.cpe_match {
                if !criterion.vulnerable {
                    return None;
                }
                let fields: Vec<_> = criterion.criteria.splitn(14, ':').collect();
                if fields.len() != 13 || fields[..2] != ["cpe", "2.3"] {
                    return None;
                }
                if matches!(fields[2], "o" | "h") {
                    continue;
                }
                let (name, version, qualified) =
                    crate::technology::external::parse_name(&criterion.criteria)?;
                let Some(&product) = knowledge.cpes.get(&name) else {
                    continue;
                };
                if qualified
                    || (version.is_none() && fields[5] != "*")
                    || fields[6..].iter().any(|s| *s != "*")
                {
                    return None;
                }
                let mut range = VersionRange {
                    introduced: criterion.version_start_including,
                    fixed: criterion.version_end_excluding,
                    last_affected: criterion.version_end_including,
                };
                if let Some(exact) = version {
                    if range.introduced.is_some()
                        || range.fixed.is_some()
                        || range.last_affected.is_some()
                    {
                        return None;
                    }
                    range.introduced = Some(exact.to_owned());
                    range.last_affected = Some(exact.to_owned());
                }
                let p = &knowledge.db.products[product];
                let interval = Interval::compile(&range, p.version_scheme, p.components).ok()?;
                let list = ranges.entry(product).or_default();
                if list.len() >= 32 {
                    return None;
                }
                list.push((interval, range));
            }
        }
    }
    let mut records = Vec::new();
    for (index, mut entries) in ranges {
        entries.sort_by(|a, b| a.0.low.cmp(&b.0.low));
        entries.dedup_by(|a, b| a.1 == b.1);
        if !entries.windows(2).all(|p| p[0].0.precedes(&p[1].0)) {
            return None;
        }
        records.push(Record {
            id: cve.id.clone(),
            product: knowledge.db.products[index].id.clone(),
            source: format!("https://nvd.nist.gov/vuln/detail/{}", cve.id),
            ranges: Some(entries.into_iter().map(|(_, r)| r).collect()),
            introduced: None,
            fixed: None,
            condition: None,
            observed_when: None,
        });
    }
    Some(records)
}
