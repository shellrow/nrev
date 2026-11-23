// Shared by the build-time validation pipeline and the replay engine.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

pub const SCHEMA: u32 = 1;
pub const MAX_FIELD: usize = 1024;
pub const MAX_DATABASE: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Server,
    ServerComponent,
    ServerHeader,
    PoweredBy,
    JenkinsVersion,
    InfluxdbVersion,
    ElasticProduct,
    GithubEnterpriseVersion,
    GeneratorHeader,
    ConsulLeader,
    NomadLeader,
    KubernetesFlowControl,
    Generator,
    SshIdent,
    SmtpGreeting,
    FtpGreeting,
    MysqlVersion,
    DnsVersion,
    ImapGreeting,
    Pop3Greeting,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub field: Field,
    pub pattern: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    pub id: String,
    pub role: String,
    pub cpe_names: Vec<String>,
    pub source: String,
    pub version_scheme: Scheme,
    pub components: usize,
    pub signatures: Vec<Signature>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Numeric,
    OptionalPatch,
    PortableSsh,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: u32,
    pub revision: String,
    pub products: Vec<Product>,
    pub provenance: BTreeMap<String, String>,
    #[serde(default)]
    pub stack_profiles: Vec<StackProfile>,
    #[serde(default)]
    pub platform_claims: Vec<PlatformClaim>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackProfile {
    pub id: String,
    pub family: String,
    pub order: String,
    pub ttl_class: u8,
    pub window: Option<u16>,
    pub source: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformClaim {
    pub field: Field,
    pub family: String,
    pub environment: String,
    pub pattern: String,
}

pub fn compile_platforms(db: &Catalog) -> Result<Vec<Regex>> {
    ensure!(
        db.stack_profiles.len() <= 128 && db.platform_claims.len() <= 64,
        "too many platform rules"
    );
    let mut ids = BTreeSet::new();
    for r in &db.stack_profiles {
        let options: Vec<_> = r.order.split(',').collect();
        ensure!(
            identifier(&r.id)
                && ids.insert(&r.id)
                && identifier(&r.family)
                && db.provenance.contains_key(&r.source)
                && matches!(r.ttl_class, 64 | 128 | 255)
                && r.window != Some(0)
                && (3..=20).contains(&options.len())
                && ["MSS", "SACK", "WS"].iter().all(|k| options.contains(k))
                && options
                    .iter()
                    .all(|k| matches!(*k, "MSS" | "NOP" | "WS" | "TS" | "SACK")),
            "invalid stack profile"
        );
    }
    db.platform_claims
        .iter()
        .map(|r| {
            ensure!(
                matches!(r.field, Field::Server | Field::SshIdent)
                    && identifier(&r.family)
                    && !r.environment.is_empty()
                    && r.environment.len() <= 64
                    && r.environment
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b' ')
                    && r.pattern.len() <= 512,
                "invalid service platform rule"
            );
            let regex = RegexBuilder::new(&format!(r"\A(?:{})\z", r.pattern))
                .unicode(false)
                .size_limit(128 * 1024)
                .build()?;
            ensure!(
                !regex.is_match("") && regex.capture_names().flatten().all(|n| n == "version"),
                "invalid service platform capture"
            );
            Ok(regex)
        })
        .collect()
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

// Support literal CPE components without globbing or escape sequences.
pub fn cpe_component(value: &str) -> bool {
    value.len() <= 64
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
}

pub struct Rule {
    pub product: usize,
    pub signature: usize,
    pub regex: Regex,
}

pub type Index = BTreeMap<Field, Vec<Rule>>;

pub fn compile(db: &Catalog) -> Result<Index> {
    ensure!(db.schema == SCHEMA, "unsupported NKDB schema");
    ensure!(
        !db.revision.is_empty()
            && db.revision.len() <= 64
            && db
                .revision
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
        "invalid NKDB revision"
    );
    ensure!(
        (1..=256).contains(&db.products.len()),
        "invalid NKDB product count"
    );
    ensure!(
        !db.provenance.is_empty()
            && db.provenance.len() <= 256
            && db.provenance.iter().all(|(k, v)| identifier(k)
                && !v.trim().is_empty()
                && v.len() <= 512
                && !v.chars().any(char::is_control)),
        "invalid NKDB provenance"
    );
    let mut ids = BTreeSet::new();
    let mut cpes = BTreeSet::new();
    let mut patterns = BTreeSet::new();
    let mut index = Index::new();
    for (i, p) in db.products.iter().enumerate() {
        let (vendor, name) = p.id.split_once(':').context("expected vendor:product")?;
        ensure!(
            identifier(vendor)
                && identifier(name)
                && identifier(&p.role)
                && db.provenance.contains_key(&p.source),
            "invalid NKDB identity or metadata"
        );
        ensure!(ids.insert(&p.id), "duplicate NKDB product");
        ensure!(
            (1..=4).contains(&p.components)
                && (p.version_scheme != Scheme::PortableSsh || p.components == 2)
                && (p.version_scheme != Scheme::OptionalPatch || p.components == 3),
            "invalid version width"
        );
        ensure!(
            (1..=8).contains(&p.signatures.len()),
            "invalid signature count"
        );
        ensure!(p.cpe_names.len() <= 8, "too many product aliases");
        for name in &p.cpe_names {
            let fields: Vec<_> = name.split(':').collect();
            ensure!(
                fields.len() == 13
                    && fields[..3] == ["cpe", "2.3", "a"]
                    && cpe_component(fields[3])
                    && cpe_component(fields[4])
                    && fields[5..].iter().all(|v| *v == "*")
                    && cpes.insert(name),
                "invalid or ambiguous CPE product name"
            );
        }
        for (signature, s) in p.signatures.iter().enumerate() {
            ensure!(
                patterns.len() < 256 && patterns.insert((s.field, &s.pattern)),
                "too many or duplicate NKDB signatures"
            );
            ensure!(s.pattern.len() <= 512, "oversized NKDB pattern");
            // Anchor outside the authored expression so alternatives are bounded too.
            let regex = RegexBuilder::new(&format!(r"\A(?:{})\z", s.pattern))
                .unicode(false)
                .size_limit(128 * 1024)
                .dfa_size_limit(64 * 1024)
                .build()
                .with_context(|| format!("invalid signature for {}", p.id))?;
            ensure!(
                !regex.is_match("")
                    && regex
                        .capture_names()
                        .flatten()
                        .all(|n| matches!(n, "version" | "distribution")),
                "invalid NKDB captures"
            );
            index.entry(s.field).or_default().push(Rule {
                product: i,
                signature,
                regex,
            });
        }
    }
    Ok(index)
}
