use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::ScanRecipe,
    error::{NrevError, Result},
    fingerprint::{FingerprintRule, LegacyOsSignature, OsClassTtl},
    probes::{BuiltinProbeCatalog, ExternalProbeDefinition},
    service_db::LegacyServiceSignature,
};

const MAX_EXTERNAL_DATA_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExternalDataFile {
    #[serde(default)]
    pub probes: Vec<ExternalProbeDefinition>,
    #[serde(default)]
    pub fingerprint_rules: Vec<FingerprintRule>,
    #[serde(default)]
    pub os_ttl_classes: Vec<OsClassTtl>,
    #[serde(default)]
    pub os_signatures: Vec<LegacyOsSignature>,
    #[serde(default)]
    pub service_signatures: Vec<LegacyServiceSignature>,
    #[serde(default)]
    pub recipes: Vec<ScanRecipe>,
}

#[derive(Clone, Debug, Default)]
pub struct DataRegistry {
    pub external_probes: Vec<ExternalProbeDefinition>,
    pub fingerprint_rules: Vec<FingerprintRule>,
    pub os_ttl_classes: Vec<OsClassTtl>,
    pub os_signatures: Vec<LegacyOsSignature>,
    pub service_signatures: Vec<LegacyServiceSignature>,
    pub recipes: Vec<ScanRecipe>,
}

impl DataRegistry {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };

        let mut registry = Self::default();
        if path.is_dir() {
            let mut entries: Vec<PathBuf> = fs::read_dir(path)?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .collect();
            entries.sort();
            for entry in entries {
                registry.extend_from_file(&entry)?;
            }
        } else {
            registry.extend_from_file(path)?;
        }
        Ok(registry)
    }

    fn extend_from_file(&mut self, path: &Path) -> Result<()> {
        if fs::metadata(path)?.len() > MAX_EXTERNAL_DATA_FILE_BYTES {
            return Err(NrevError::DataFileTooLarge {
                path: path.to_path_buf(),
                limit_bytes: MAX_EXTERNAL_DATA_FILE_BYTES,
            });
        }
        let content = fs::read_to_string(path)?;
        let file = match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => parse_json_data_file(&content)?,
            Some("toml") => toml::from_str::<ExternalDataFile>(&content)?,
            _ => return Err(NrevError::UnsupportedFileExtension(path.to_path_buf())),
        };
        self.external_probes.extend(file.probes);
        self.fingerprint_rules.extend(file.fingerprint_rules);
        self.os_ttl_classes.extend(file.os_ttl_classes);
        self.os_signatures.extend(file.os_signatures);
        self.service_signatures.extend(file.service_signatures);
        self.recipes.extend(file.recipes);
        Ok(())
    }

    pub fn builtin_catalog(&self) -> BuiltinProbeCatalog {
        BuiltinProbeCatalog::default()
    }

    pub fn recipe_lines(&self) -> Vec<String> {
        self.recipes
            .iter()
            .map(|recipe| {
                let desc = recipe.description.as_deref().unwrap_or("no description");
                format!("{} tags={:?} {}", recipe.name, recipe.tags, desc)
            })
            .collect()
    }
}

fn parse_json_data_file(content: &str) -> Result<ExternalDataFile> {
    let mut value: serde_json::Value = serde_json::from_str(content)?;
    if value.is_array() {
        return Ok(ExternalDataFile {
            os_ttl_classes: serde_json::from_value(value)?,
            ..ExternalDataFile::default()
        });
    }
    let signatures = value
        .as_object_mut()
        .and_then(|object| object.remove("signatures"));
    let mut file: ExternalDataFile = serde_json::from_value(value)?;
    if let Some(signatures) = signatures {
        // Legacy signatures may coexist with probes, rules, and recipes.
        let signatures: Vec<serde_json::Value> = serde_json::from_value(signatures)?;
        for signature in signatures {
            if signature.get("signature").is_some() {
                file.os_signatures.push(serde_json::from_value(signature)?);
            } else {
                file.service_signatures
                    .push(serde_json::from_value(signature)?);
            }
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_external_probe_file() {
        let path = std::env::temp_dir().join("nrev-data.json");
        fs::write(
            &path,
            r#"{"probes":[{"id":"corp-http","transport":"tcp","ports":[8080],"payload":"HEAD / HTTP/1.0\r\n\r\n","expect":["HTTP/"]}],"fingerprint_rules":[{"id":"udp-node","label":"UDP node","family":"network-device","transport":"udp","response_observed":true,"confidence":"medium"}],"recipes":[{"name":"enterprise","description":"Enterprise database sweep","ports":"1433,1521,3306,5432","transport":"tcp","probes":["mssql-prelogin","oracle-tns","mysql","postgresql"],"builtin_probes":true,"tags":["enterprise","database"]}]}"#,
        )
        .expect("write data file");
        let registry = DataRegistry::load(Some(&path)).expect("load registry");
        assert_eq!(registry.external_probes.len(), 1);
        assert_eq!(registry.fingerprint_rules.len(), 1);
        assert_eq!(registry.recipes.len(), 1);
        fs::remove_file(path).ok();
    }

    #[test]
    fn legacy_signature_files_remain_explicitly_loadable() {
        let service = parse_json_data_file(
            r#"{"signatures":[{"probe_id":"ssh","service":"ssh","regex":"^SSH-2.0-","cpe":[]}]}"#,
        )
        .unwrap();
        assert_eq!(service.service_signatures.len(), 1);
        let os =
            parse_json_data_file(r#"{"signatures":[{"signature":{"order_key":"MSS"},"cpe":[]}]}"#)
                .unwrap();
        assert_eq!(os.os_signatures.len(), 1);
    }

    #[test]
    fn default_registry_has_no_identification_database() {
        let registry = DataRegistry::load(None).expect("load registry");
        assert!(registry.os_signatures.is_empty());
        assert!(registry.service_signatures.is_empty());
        assert!(registry.os_ttl_classes.is_empty());
        assert!(!registry.builtin_catalog().probes().is_empty());
    }

    #[test]
    fn rejects_oversized_external_data_before_reading_it() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("oversized.json");
        let file = std::fs::File::create(&path).expect("create sparse data file");
        file.set_len(MAX_EXTERNAL_DATA_FILE_BYTES + 1)
            .expect("resize sparse data file");

        let error = DataRegistry::load(Some(&path)).expect_err("data size limit");
        assert!(matches!(error, NrevError::DataFileTooLarge { .. }));
    }

    #[test]
    fn loads_recipes_from_directory() {
        let dir = std::env::temp_dir().join("nrev-recipe-dir");
        fs::create_dir_all(&dir).expect("create dir");
        fs::write(
            dir.join("web.toml"),
            r#"[[recipes]]
name = "web-balanced"
description = "Web sweep"
ports = "80,443,8080,8443"
transport = "tcp"
probes = ["http", "tls"]
builtin_probes = true
tags = ["web"]
"#,
        )
        .expect("write web recipe");
        fs::write(
            dir.join("quic.toml"),
            r#"[[recipes]]
name = "quic-web"
description = "QUIC sweep"
ports = "443,8443"
transport = "quic"
probes = ["quic"]
builtin_probes = true
tags = ["quic"]
"#,
        )
        .expect("write quic recipe");

        let registry = DataRegistry::load(Some(&dir)).expect("load registry");
        assert_eq!(registry.recipes.len(), 2);
        assert!(
            registry
                .recipes
                .iter()
                .any(|recipe| recipe.name == "web-balanced")
        );
        assert!(
            registry
                .recipes
                .iter()
                .any(|recipe| recipe.name == "quic-web")
        );

        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn loads_mixed_external_data_from_directory() {
        let dir = std::env::temp_dir().join("nrev-external-data-dir");
        fs::create_dir_all(&dir).expect("create dir");
        fs::write(
            dir.join("probes.toml"),
            r#"[[probes]]
id = "corp-http-alt"
transport = "tcp"
ports = [8080]
payload = "GET / HTTP/1.0\r\n\r\n"
expect = ["HTTP/"]
"#,
        )
        .expect("write probe file");
        fs::write(
            dir.join("fingerprints.json"),
            r#"{"fingerprint_rules":[{"id":"udp-responder","label":"UDP responder","family":"service-node","transport":"udp","response_observed":true,"confidence":"medium"}]}"#,
        )
        .expect("write fingerprint file");

        let registry = DataRegistry::load(Some(&dir)).expect("load registry");
        assert_eq!(registry.external_probes.len(), 1);
        assert_eq!(registry.fingerprint_rules.len(), 1);

        fs::remove_dir_all(dir).ok();
    }
    #[test]
    fn malformed_legacy_signatures_are_not_silently_ignored() {
        for json in [
            r#"{"signatures":[{}]}"#,
            r#"{"signatures":null}"#,
            r#"{"signatures":[{"signature":"invalid"}]}"#,
        ] {
            assert!(parse_json_data_file(json).is_err());
        }
    }

    #[test]
    fn mixed_pack_keeps_legacy_signatures_and_modern_sections() {
        let file = parse_json_data_file(
            r#"{
            "probes":[{"id":"custom","transport":"udp","ports":[53],"payload":"test"}],
            "recipes":[{"name":"custom"}],
            "signatures":[
                {"signature":{"order_key":"MSS"},"cpe":["cpe:/o:linux:linux_kernel"]},
                {"probe_id":"ssh","service":"ssh","regex":"^SSH-"}
            ]
        }"#,
        )
        .unwrap();
        assert_eq!(file.probes.len(), 1);
        assert_eq!(file.recipes.len(), 1);
        assert_eq!(file.os_signatures.len(), 1);
        assert_eq!(file.service_signatures.len(), 1);
    }
}
