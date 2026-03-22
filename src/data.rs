use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    config::ScanRecipe,
    error::{NrevError, Result},
    fingerprint::{
        FingerprintRule, LegacyOsDb, LegacyOsSignature, OsClassTtl, builtin_os_signatures,
    },
    probes::{BuiltinProbeCatalog, ExternalProbeDefinition},
    service_db::{LegacyServiceDb, LegacyServiceSignature, builtin_service_signatures},
};

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

#[derive(Clone, Debug)]
pub struct DataRegistry {
    pub external_probes: Vec<ExternalProbeDefinition>,
    pub fingerprint_rules: Vec<FingerprintRule>,
    pub os_ttl_classes: Vec<OsClassTtl>,
    pub os_signatures: Vec<LegacyOsSignature>,
    pub service_signatures: Vec<LegacyServiceSignature>,
    pub recipes: Vec<ScanRecipe>,
}

impl Default for DataRegistry {
    fn default() -> Self {
        Self {
            external_probes: Vec::new(),
            fingerprint_rules: Vec::new(),
            os_ttl_classes: Vec::new(),
            os_signatures: builtin_os_signatures(),
            service_signatures: builtin_service_signatures(),
            recipes: Vec::new(),
        }
    }
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
    if let Ok(file) = serde_json::from_str::<ExternalDataFile>(content) {
        return Ok(file);
    }

    if let Ok(ttl_classes) = serde_json::from_str::<Vec<OsClassTtl>>(content) {
        return Ok(ExternalDataFile {
            os_ttl_classes: ttl_classes,
            ..ExternalDataFile::default()
        });
    }

    if let Ok(db) = serde_json::from_str::<LegacyOsDb>(content)
        && !db.signatures.is_empty()
    {
        return Ok(ExternalDataFile {
            os_signatures: db.signatures,
            ..ExternalDataFile::default()
        });
    }

    if let Ok(db) = serde_json::from_str::<LegacyServiceDb>(content)
        && !db.signatures.is_empty()
    {
        return Ok(ExternalDataFile {
            service_signatures: db.signatures,
            ..ExternalDataFile::default()
        });
    }

    Ok(serde_json::from_str::<ExternalDataFile>(content)?)
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
    fn loads_builtin_registry_by_default() {
        let registry = DataRegistry::load(None).expect("load registry");
        assert!(!registry.os_signatures.is_empty());
        assert!(!registry.service_signatures.is_empty());
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
}
