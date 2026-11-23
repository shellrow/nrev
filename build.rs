#[path = "src/technology/catalog.rs"]
mod catalog;

use anyhow::{Context, Result, ensure};
use catalog::{Catalog, Field, compile};
use serde::Deserialize;
use std::{collections::BTreeSet, fs, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    field: Field,
    value: String,
    product: Option<String>,
    version: Option<String>,
}

fn main() -> Result<()> {
    for file in [
        "knowledge/products.json",
        "knowledge/review.json",
        "src/technology/catalog.rs",
    ] {
        println!("cargo:rerun-if-changed={file}");
    }
    let mut db: Catalog = serde_json::from_slice(&fs::read("knowledge/products.json")?)?;
    db.products.sort_by(|a, b| a.id.cmp(&b.id));
    let index = compile(&db)?;
    catalog::compile_platforms(&db)?;
    let cases: Vec<Case> = serde_json::from_slice(&fs::read("knowledge/review.json")?)?;
    let mut covered = BTreeSet::new();
    let mut negatives = BTreeSet::new();
    for case in cases {
        ensure!(
            case.value.len() <= catalog::MAX_FIELD,
            "oversized review case"
        );
        let rules = index
            .get(&case.field)
            .context("review case has unknown field")?;
        let mut matches = Vec::new();
        for rule in rules {
            if let Some(c) = rule.regex.captures(&case.value) {
                matches.push((
                    Some(db.products[rule.product].id.as_str()),
                    c.name("version").map(|m| m.as_str()),
                ));
                covered.insert((rule.product, rule.signature));
            }
        }
        if case.product.is_none() {
            ensure!(
                case.version.is_none() && matches.is_empty(),
                "negative review failed for {}",
                case.value
            );
            negatives.insert(case.field);
        } else {
            ensure!(
                matches == [(case.product.as_deref(), case.version.as_deref())],
                "ambiguous or incorrect review for {}",
                case.value
            );
        }
    }
    for (field, rules) in index {
        ensure!(
            negatives.contains(&field)
                && rules
                    .iter()
                    .all(|r| covered.contains(&(r.product, r.signature))),
            "incomplete NKDB review for {field:?}"
        );
    }
    let bytes = serde_json::to_vec(&db)?;
    ensure!(bytes.len() <= catalog::MAX_DATABASE, "oversized NKDB");
    let dir = PathBuf::from(std::env::var_os("OUT_DIR").context("missing OUT_DIR")?);
    fs::write(dir.join("nkdb.json"), bytes)?;
    Ok(())
}
