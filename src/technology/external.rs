//! Join previously recorded, probed application CPEs to their wire endpoints.
use super::{Declaration, EvidenceRef, KnowledgeBase, valid_version};
use crate::nmap::Identification;
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, net::IpAddr};

type EndpointKey<'a> = (IpAddr, u16, &'a str);
pub(super) type ExternalIndex<'a> = BTreeMap<EndpointKey<'a>, Vec<(usize, Declaration)>>;

impl KnowledgeBase {
    pub(super) fn recorded_cpes<'a>(
        &self,
        identification: Option<&'a Identification>,
    ) -> Result<ExternalIndex<'a>> {
        let mut records = ExternalIndex::new();
        let Some(report) = identification.filter(|r| r.source == "nmap") else {
            return Ok(records);
        };
        for (h, host) in report.hosts.iter().enumerate() {
            for (p, port) in host.ports.iter().enumerate() {
                let Some(service) = port
                    .service
                    .as_ref()
                    .filter(|s| s.method.as_deref() == Some("probed"))
                else {
                    continue;
                };
                if port.state.state != "open" || !matches!(port.protocol.as_str(), "tcp" | "udp") {
                    continue;
                }
                for (c, cpe) in service.cpes.iter().enumerate() {
                    let Some((name, version, qualified)) = parse_name(cpe) else {
                        continue;
                    };
                    let Some(&product) = self.cpes.get(&name) else {
                        continue;
                    };
                    let declarations = records
                        .entry((host.ip, port.port, port.protocol.as_str()))
                        .or_default();
                    ensure!(
                        declarations.len() < 256,
                        "too many recorded CPEs on endpoint"
                    );
                    declarations.push((
                        product,
                        Declaration {
                            rule: name,
                            evidence: EvidenceRef::Nmap {
                                host: h,
                                port: p,
                                cpe: c,
                            },
                            version: version.map(str::to_owned),
                            qualified: qualified
                                || service.extra_info.as_deref().is_some_and(|v| !v.is_empty()),
                        },
                    ));
                }
            }
        }
        Ok(records)
    }
}

// Only simple application names are supported. Preserve uncertainty when the
// external matcher specifies update, edition, language or platform constraints.
pub(super) fn parse_name(cpe: &str) -> Option<(String, Option<&str>, bool)> {
    if cpe.len() > 256 {
        return None;
    }
    let (tail, formatted) = cpe
        .strip_prefix("cpe:2.3:a:")
        .map(|s| (s, true))
        .or_else(|| cpe.strip_prefix("cpe:/a:").map(|s| (s, false)))?;
    let parts: Vec<_> = tail.split(':').collect();
    if (formatted && parts.len() != 10) || (!formatted && !(2..=6).contains(&parts.len())) {
        return None;
    }
    if !parts[..2].iter().all(|v| super::catalog::cpe_component(v)) {
        return None;
    }
    let token = parts.get(2).copied().unwrap_or("");
    let version = Some(token).filter(|v| valid_version(v));
    let qualified = (!matches!(token, "" | "*" | "-") && version.is_none())
        || parts.iter().skip(3).any(|v| !matches!(*v, "" | "*"));
    Some((
        format!("cpe:2.3:a:{}:{}:*:*:*:*:*:*:*:*", parts[0], parts[1]),
        version,
        qualified,
    ))
}
