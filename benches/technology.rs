use nrev::{
    model::ScanReport,
    technology::{Advisories, BUILTIN_DATABASE, KnowledgeBase},
};
use serde_json::Value;
use std::{hint::black_box, time::Instant};

fn measure(name: &str, catalog: &[u8], report: &ScanReport) {
    let start = Instant::now();
    for _ in 0..30 {
        black_box(KnowledgeBase::from_bytes(black_box(catalog)).unwrap());
    }
    let load = start.elapsed().as_secs_f64() / 30.0;
    let db = KnowledgeBase::from_bytes(catalog).unwrap();
    let ep = &report.targets[0].endpoints[&8080];
    let mut batches = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        for _ in 0..2000 {
            black_box(db.identify(black_box(ep)).unwrap());
        }
        batches.push(start.elapsed().as_nanos() as u64 / 2000);
    }
    batches.sort_unstable();
    println!(
        "{name}: {} bytes, load {:.3} ms, batch median {} ns/endpoint, batch p95 {} ns/endpoint, {:.0} endpoints/s",
        catalog.len(),
        load * 1000.0,
        batches[25],
        batches[47],
        1e9 / batches[25] as f64
    );
}

fn main() {
    let report: ScanReport =
        serde_json::from_slice(include_bytes!("../samples/inventory/scan.json")).unwrap();
    measure("embedded", BUILTIN_DATABASE, &report);
    let knowledge = KnowledgeBase::builtin().unwrap();
    let advisories = Advisories::bundled(&knowledge).unwrap();
    let mut batches = Vec::new();
    for _ in 0..50 {
        let start = Instant::now();
        for _ in 0..2000 {
            black_box(
                knowledge
                    .inventory(black_box(&report), Some(&advisories))
                    .unwrap(),
            );
        }
        batches.push(start.elapsed().as_nanos() / 2000);
    }
    batches.sort_unstable();
    println!(
        "Full one-endpoint inventory with bundled advisories: batch median {} ns, p95 {} ns",
        batches[25], batches[47]
    );
    let mut db: Value = serde_json::from_slice(BUILTIN_DATABASE).unwrap();
    let products = db["products"].as_array_mut().unwrap();
    for i in products.len()..200 {
        let mut product = products[0].clone();
        product["id"] = format!("bench:product_{i}").into();
        product["cpe_names"] = serde_json::json!([]);
        product["signatures"] =
            serde_json::json!([{"field":"server","pattern":format!("test-{i}")}]);
        products.push(product);
    }
    measure(
        "200 products, same-field distractors",
        &serde_json::to_vec(&db).unwrap(),
        &report,
    );
}
