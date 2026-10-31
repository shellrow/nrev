//! Optional detailed identification through Nmap's XML interface.
use crate::model::{EndpointState, TargetReport, Transport};
use anyhow::{Context, Result, ensure};
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

/// Which native scan results may be sent for external identification.
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum IdentificationScope {
    #[default]
    Candidates,
    All,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct IdentificationRequest {
    pub ip: IpAddr,
    pub protocol: String,
    pub ports: Vec<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct IdentificationFailure {
    pub ip: IpAddr,
    pub error: String,
}

/// Select endpoints without adding addresses or ports outside the native scan.
pub fn plan_identification(
    targets: &[TargetReport],
    transport: Transport,
    options: &IdentificationOptions,
) -> Vec<IdentificationRequest> {
    let mut candidates = BTreeMap::<IpAddr, BTreeSet<u16>>::new();
    let mut closed = BTreeMap::<IpAddr, BTreeSet<u16>>::new();
    for target in targets {
        for endpoint in target.endpoints.values() {
            if endpoint.transport != transport {
                continue;
            }
            if options.scope == IdentificationScope::All
                || endpoint.state == EndpointState::Open
                || (matches!(transport, Transport::Udp | Transport::Quic)
                    && endpoint.state == EndpointState::OpenFiltered)
            {
                candidates
                    .entry(target.target.address)
                    .or_default()
                    .insert(endpoint.port);
            }
            if endpoint.state == EndpointState::Closed {
                closed
                    .entry(target.target.address)
                    .or_default()
                    .insert(endpoint.port);
            }
        }
    }
    if options.os && options.scope == IdentificationScope::Candidates {
        for (ip, ports) in &mut candidates {
            if let Some(port) = closed.get(ip).and_then(|ports| ports.first()) {
                ports.insert(*port);
            }
        }
    }
    candidates
        .into_iter()
        .map(|(ip, ports)| IdentificationRequest {
            ip,
            protocol: protocol(transport).into(),
            ports: ports.into_iter().collect(),
        })
        .collect()
}

/// Optional identification settings for CLI scans and task files.
#[derive(Clone, Debug, clap::Args, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct IdentificationOptions {
    /// Identify candidate endpoints, or rescan all requested ports.
    #[arg(long = "nmap-scope", value_enum, default_value_t = IdentificationScope::Candidates)]
    pub scope: IdentificationScope,
    /// Maximum concurrent Nmap processes.
    #[arg(id = "nmap_concurrency", long = "nmap-concurrency", default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=16))]
    pub concurrency: u8,
    /// Identify services and versions with an installed Nmap executable.
    #[arg(long = "nmap")]
    pub services: bool,
    /// Identify the OS with Nmap (TCP/SYN scans; requires privileges).
    #[arg(long = "os-detect")]
    pub os: bool,
    /// Nmap executable name or path.
    #[arg(long = "nmap-path", default_value = "nmap")]
    pub executable: PathBuf,
    /// Timeout for the entire external identification phase, in milliseconds.
    #[arg(long = "nmap-timeout-ms", default_value_t = 120_000, value_parser = clap::value_parser!(u64).range(1..=3_600_000))]
    pub timeout_ms: u64,
    /// Nmap service probe intensity (0–9).
    #[arg(long = "nmap-intensity", default_value_t = 7, value_parser = clap::value_parser!(u8).range(0..=9))]
    pub intensity: u8,
}

impl Default for IdentificationOptions {
    fn default() -> Self {
        Self {
            scope: IdentificationScope::Candidates,
            concurrency: 2,
            services: false,
            os: false,
            executable: "nmap".into(),
            timeout_ms: 120_000,
            intensity: 7,
        }
    }
}

impl IdentificationOptions {
    pub fn enabled(&self) -> bool {
        self.services || self.os
    }

    pub fn validate(&self, transport: Transport) -> Result<()> {
        ensure!(
            (1..=16).contains(&self.concurrency),
            "Nmap concurrency must be between 1 and 16"
        );
        ensure!(
            (1..=3_600_000).contains(&self.timeout_ms),
            "Nmap timeout must be between 1 and 3600000 milliseconds"
        );
        ensure!(
            self.intensity <= 9,
            "Nmap intensity must be between 0 and 9"
        );
        ensure!(
            !self.executable.as_os_str().is_empty(),
            "Nmap executable must not be empty"
        );
        ensure!(
            !self.os || matches!(transport, Transport::Tcp | Transport::Syn),
            "Nmap OS identification requires a TCP or SYN scan"
        );
        Ok(())
    }
}

fn protocol(transport: Transport) -> &'static str {
    match transport {
        Transport::Tcp | Transport::Syn => "tcp",
        Transport::Udp | Transport::Quic => "udp",
    }
}

fn terminal_text(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

const MAX_XML: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Identification {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<IdentificationRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<IdentificationFailure>,
    pub source: String,
    pub version: String,
    pub complete: bool,
    pub error: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub hosts: Vec<HostDetails>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct HostDetails {
    pub ip: IpAddr,
    pub ports: Vec<PortDetails>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_summaries: Vec<PortSummary>,
    pub os_matches: Vec<OsMatch>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PortDetails {
    #[serde(alias = "@portid")]
    pub port: u16,
    #[serde(alias = "@protocol")]
    pub protocol: String,
    pub state: State,
    pub service: Option<Service>,
}

/// States that Nmap reports collectively rather than per port.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PortSummary {
    #[serde(alias = "@state")]
    pub state: String,
    #[serde(alias = "@count")]
    pub count: u32,
    #[serde(alias = "extrareasons", default)]
    pub reasons: Vec<PortReason>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PortReason {
    #[serde(alias = "@reason")]
    pub reason: String,
    #[serde(alias = "@count")]
    pub count: u32,
    #[serde(alias = "@proto")]
    pub protocol: Option<String>,
    #[serde(alias = "@ports")]
    pub ports: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct State {
    #[serde(alias = "@state")]
    pub state: String,
    #[serde(alias = "@reason")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Service {
    #[serde(alias = "@tunnel")]
    pub tunnel: Option<String>,
    #[serde(alias = "@hostname")]
    pub hostname: Option<String>,
    #[serde(alias = "@ostype")]
    pub os_type: Option<String>,
    #[serde(alias = "@devicetype")]
    pub device_type: Option<String>,
    #[serde(alias = "@name")]
    pub name: Option<String>,
    #[serde(alias = "@product")]
    pub product: Option<String>,
    #[serde(alias = "@version")]
    pub version: Option<String>,
    #[serde(alias = "@extrainfo")]
    pub extra_info: Option<String>,
    #[serde(alias = "@method")]
    pub method: Option<String>,
    #[serde(alias = "@conf")]
    pub confidence: Option<u8>,
    #[serde(alias = "cpe", default)]
    pub cpes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct OsMatch {
    #[serde(alias = "@name")]
    pub name: String,
    #[serde(alias = "@accuracy")]
    pub accuracy: u8,
    #[serde(alias = "osclass", default)]
    pub classes: Vec<OsClass>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct OsClass {
    #[serde(alias = "@accuracy")]
    pub accuracy: Option<u8>,
    #[serde(alias = "@vendor")]
    pub vendor: Option<String>,
    #[serde(alias = "@osfamily")]
    pub family: Option<String>,
    #[serde(alias = "@osgen")]
    pub generation: Option<String>,
    #[serde(alias = "@type")]
    pub device_type: Option<String>,
    #[serde(alias = "cpe", default)]
    pub cpes: Vec<String>,
}

#[derive(Deserialize)]
struct Run {
    #[serde(rename = "@scanner")]
    scanner: String,
    #[serde(rename = "@version")]
    version: String,
    #[serde(rename = "host", default)]
    hosts: Vec<Host>,
    runstats: RunStats,
}
#[derive(Deserialize)]
struct RunStats {
    finished: Finished,
}
#[derive(Deserialize)]
struct Finished {
    #[serde(rename = "@exit")]
    exit: String,
    #[serde(rename = "@errormsg")]
    error: Option<String>,
}
#[derive(Deserialize)]
struct Host {
    #[serde(rename = "@timedout", default)]
    timed_out: bool,
    #[serde(rename = "address", default)]
    addresses: Vec<Address>,
    #[serde(default)]
    ports: Ports,
    #[serde(default)]
    os: Os,
}
#[derive(Deserialize)]
struct Address {
    #[serde(rename = "@addr")]
    addr: String,
}
#[derive(Default, Deserialize)]
struct Ports {
    #[serde(rename = "extraports", default)]
    summaries: Vec<PortSummary>,
    #[serde(rename = "port", default)]
    ports: Vec<PortDetails>,
}
#[derive(Default, Deserialize)]
struct Os {
    #[serde(rename = "osmatch", default)]
    matches: Vec<OsMatch>,
}

pub struct Nmap {
    executable: PathBuf,
    version: String,
}

impl Nmap {
    /// Check availability only when external identification was requested.
    pub async fn preflight(path: &Path) -> Result<Self> {
        let (stdout, _) = execute(path, &["--version".into()], Duration::from_secs(5))
            .await
            .with_context(|| {
                format!(
                    "Nmap unavailable at {}; install Nmap or set --nmap-path",
                    path.display()
                )
            })?;
        let text = std::str::from_utf8(&stdout)?;
        let version = text
            .lines()
            .find_map(|line| line.strip_prefix("Nmap version "))
            .and_then(|line| line.split_whitespace().next())
            .context("unexpected Nmap version output")?;
        Ok(Self {
            executable: path.to_path_buf(),
            version: version.to_string(),
        })
    }

    /// Retain successful host results if a later invocation fails or times out.
    pub async fn identify(
        &self,
        targets: &[TargetReport],
        transport: Transport,
        options: &IdentificationOptions,
    ) -> Identification {
        let mut result = Identification {
            requests: Vec::new(),
            failures: Vec::new(),
            source: "nmap".into(),
            version: self.version.clone(),
            complete: false,
            error: None,
            warnings: Vec::new(),
            hosts: Vec::new(),
        };
        let deadline = tokio::time::Instant::now() + Duration::from_millis(options.timeout_ms);
        if let Err(error) = options.validate(transport) {
            result.error = Some(error.to_string());
            return result;
        }
        result.requests = plan_identification(targets, transport, options);
        let mut pending = stream::iter(result.requests.iter().cloned())
            .map(|request| async move {
                let outcome = async {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    ensure!(
                        !remaining.is_zero(),
                        "Nmap identification deadline exceeded"
                    );
                    let arguments = arguments(request.ip, &request.ports, transport, options);
                    let (xml, stderr) = execute(&self.executable, &arguments, remaining).await?;
                    let (version, host) =
                        parse(&xml, request.ip, &request.ports, &request.protocol)?;
                    ensure!(
                        version == self.version,
                        "Nmap version changed during identification"
                    );
                    Ok::<_, anyhow::Error>((host, stderr))
                }
                .await;
                (request.ip, outcome)
            })
            .buffer_unordered(usize::from(options.concurrency));
        while let Some((ip, outcome)) = pending.next().await {
            match outcome {
                Ok((host, stderr)) => {
                    result.hosts.push(host);
                    if !stderr.is_empty() {
                        result.warnings.push(format!(
                            "{ip}: {}",
                            terminal_text(&String::from_utf8_lossy(&stderr))
                        ));
                    }
                }
                Err(error) => result.failures.push(IdentificationFailure {
                    ip,
                    error: terminal_text(&format!("{error:#}")),
                }),
            }
        }
        drop(pending);
        result.hosts.sort_by_key(|host| host.ip);
        result.failures.sort_by_key(|failure| failure.ip);
        result.warnings.sort();
        result.complete = result.failures.is_empty();
        result.error = result
            .failures
            .first()
            .map(|failure| format!("{}: {}", failure.ip, failure.error));
        result
    }
}

fn arguments(
    ip: IpAddr,
    ports: &[u16],
    transport: Transport,
    options: &IdentificationOptions,
) -> Vec<String> {
    let method = if protocol(transport) == "udp" {
        "-sU"
    } else {
        "-sT"
    };
    let mut args: Vec<String> = ["-n", "-Pn", method, "-oX", "-", "-p"]
        .map(str::to_string)
        .into();
    args.push(port_spec(ports));
    if ip.is_ipv6() {
        args.push("-6".into());
    }
    if options.services {
        args.push("-sV".into());
        args.push("--version-intensity".into());
        args.push(options.intensity.to_string());
    }
    if options.os {
        args.push("-O".into());
    }
    args.push(ip.to_string());
    args
}

fn port_spec(ports: &[u16]) -> String {
    let mut ports = ports.to_vec();
    ports.sort_unstable();
    ports.dedup();
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < ports.len() {
        let start = ports[index];
        let mut end = start;
        index += 1;
        while index < ports.len() && end.checked_add(1) == Some(ports[index]) {
            end = ports[index];
            index += 1;
        }
        ranges.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
    }
    ranges.join(",")
}

async fn read_bounded(reader: impl AsyncRead + Unpin, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader.take(limit + 1).read_to_end(&mut data).await?;
    ensure!(data.len() as u64 <= limit, "Nmap output exceeds size limit");
    Ok(data)
}

// A wrapper executable may spawn children that inherit its output pipes.
// Isolate the process group on Unix so cancellation closes those pipes too.
struct ProcessGroup {
    #[cfg(unix)]
    id: Option<i32>,
}

impl ProcessGroup {
    fn new(child: &tokio::process::Child) -> Self {
        #[cfg(not(unix))]
        let _ = child;
        Self {
            #[cfg(unix)]
            id: child.id().and_then(|id| i32::try_from(id).ok()),
        }
    }

    fn disarm(&mut self) {
        #[cfg(unix)]
        {
            self.id = None;
        }
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(id) = self.id.filter(|id| *id > 0) {
            // SAFETY: the child was placed in a new process group with this ID.
            // A negative ID targets that group, never the caller's group.
            unsafe {
                libc::kill(-id, libc::SIGKILL);
            }
        }
    }
}

async fn execute(path: &Path, args: &[String], budget: Duration) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(!budget.is_zero(), "Nmap identification deadline exceeded");
    let mut command = Command::new(path);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn()?;
    let mut group = ProcessGroup::new(&child);
    let stdout = child.stdout.take().context("missing Nmap stdout")?;
    let stderr = child.stderr.take().context("missing Nmap stderr")?;
    let outcome = tokio::time::timeout(budget, async {
        let (stdout, stderr, status) = tokio::try_join!(
            read_bounded(stdout, MAX_XML),
            read_bounded(stderr, 1024 * 1024),
            async { Ok::<_, anyhow::Error>(child.wait().await?) }
        )?;
        ensure!(
            status.success(),
            "Nmap exited with {status}: {}",
            terminal_text(&String::from_utf8_lossy(&stderr))
        );
        Ok((stdout, stderr))
    })
    .await
    .context("Nmap identification timed out")
    .and_then(|result| result);
    if outcome.is_err() {
        drop(group);
        let _ = child.start_kill();
        child.wait().await.context("failed to reap Nmap process")?;
    } else {
        group.disarm();
    }
    outcome
}

fn parse(
    xml: &[u8],
    ip: IpAddr,
    requested_ports: &[u16],
    protocol: &str,
) -> Result<(String, HostDetails)> {
    // Nmap emits a DOCTYPE declaration; no external DTD or entity is loaded.
    let run: Run = quick_xml::de::from_reader(xml).context("invalid Nmap XML output")?;
    ensure!(
        run.scanner == "nmap" && run.runstats.finished.exit == "success",
        "incomplete Nmap scan: {}",
        run.runstats
            .finished
            .error
            .as_deref()
            .unwrap_or("unsuccessful exit")
    );
    let mut hosts = run.hosts.into_iter().filter(|host| {
        host.addresses
            .iter()
            .any(|addr| addr.addr.parse::<IpAddr>().ok() == Some(ip))
    });
    let host = hosts
        .next()
        .context("Nmap output does not contain the requested address")?;
    ensure!(hosts.next().is_none(), "duplicate host in Nmap output");
    ensure!(!host.timed_out, "Nmap host scan timed out");
    let requested_ports: std::collections::BTreeSet<_> = requested_ports.iter().copied().collect();
    let ports: Vec<_> = host
        .ports
        .ports
        .into_iter()
        .filter(|port| port.protocol == protocol && requested_ports.contains(&port.port))
        .collect();
    let mut seen_ports = BTreeSet::new();
    for port in &ports {
        ensure!(
            seen_ports.insert(port.port),
            "duplicate port in Nmap output"
        );
        if let Some(service) = &port.service {
            ensure!(
                service.confidence.is_none_or(|confidence| confidence <= 10),
                "invalid Nmap service confidence"
            );
        }
    }
    for matched in &host.os.matches {
        ensure!(
            matched.accuracy <= 100
                && matched
                    .classes
                    .iter()
                    .all(|class| class.accuracy.is_none_or(|accuracy| accuracy <= 100)),
            "invalid Nmap OS accuracy"
        );
    }
    ensure!(
        host.ports
            .summaries
            .iter()
            .map(|summary| u64::from(summary.count))
            .sum::<u64>()
            + ports.len() as u64
            == requested_ports.len() as u64,
        "Nmap output does not account for all requested ports"
    );
    Ok((
        run.version,
        HostDetails {
            ip,
            ports,
            port_summaries: host.ports.summaries,
            os_matches: host.os.matches,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    const XML: &str = r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.99"><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.9" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.9</cpe></service></port></ports><os><osmatch name="Linux" accuracy="95"><osclass vendor="Linux" osfamily="Linux"><cpe>cpe:/o:linux:linux_kernel</cpe></osclass></osmatch></os></host><runstats><finished exit="success"/></runstats></nmaprun>"#;
    #[test]
    fn xml_preserves_external_evidence_and_checks_identity() {
        let (version, host) =
            parse(XML.as_bytes(), "127.0.0.1".parse().unwrap(), &[22], "tcp").unwrap();
        assert_eq!(version, "7.99");
        assert_eq!(
            host.ports[0].service.as_ref().unwrap().product.as_deref(),
            Some("OpenSSH")
        );
        assert_eq!(host.os_matches[0].accuracy, 95);
        assert!(parse(XML.as_bytes(), "192.0.2.1".parse().unwrap(), &[22], "tcp").is_err());
        assert!(
            parse(
                XML.replace("exit=\"success\"", "exit=\"error\"").as_bytes(),
                host.ip,
                &[22],
                "tcp"
            )
            .is_err()
        );
        assert!(parse(b"<nmaprun", host.ip, &[22], "tcp").is_err());
        assert!(parse(XML.as_bytes(), host.ip, &[80], "tcp").is_err());
    }
    #[test]
    fn host_timeouts_and_json_roundtrip() {
        let ip = "127.0.0.1".parse().unwrap();
        assert!(
            parse(
                XML.replace("<host>", "<host timedout=\"true\">").as_bytes(),
                ip,
                &[22],
                "tcp"
            )
            .is_err()
        );
        let (_, host) = parse(XML.as_bytes(), ip, &[22], "tcp").unwrap();
        let json = serde_json::to_string(&host).unwrap();
        let decoded: HostDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.ports[0].port, 22);
        assert_eq!(decoded.os_matches[0].name, "Linux");
        assert_eq!(port_spec(&(1..=65535).collect::<Vec<_>>()), "1-65535");
    }

    #[test]
    fn arguments_are_scoped_and_ipv6_aware() {
        let args = arguments(
            "::1".parse().unwrap(),
            &[22, 443],
            Transport::Tcp,
            &IdentificationOptions {
                services: true,
                ..Default::default()
            },
        );
        assert!(args.contains(&"-6".into()));
        assert!(args.contains(&"22,443".into()));
        assert!(!args.contains(&"-O".into()));
        assert_eq!(args.last().unwrap(), "::1");
    }
    #[test]
    fn udp_identification_preserves_transport_and_validates_options() {
        let mut options = IdentificationOptions {
            services: true,
            intensity: 2,
            ..Default::default()
        };
        for transport in [Transport::Udp, Transport::Quic] {
            let args = arguments("127.0.0.1".parse().unwrap(), &[53], transport, &options);
            assert!(args.contains(&"-sU".to_string()));
            assert!(!args.contains(&"-sT".to_string()));
            assert!(
                args.windows(2)
                    .any(|pair| pair == ["--version-intensity", "2"])
            );
        }
        let xml = XML.replace("protocol=\"tcp\"", "protocol=\"udp\"");
        let (_, host) = parse(xml.as_bytes(), "127.0.0.1".parse().unwrap(), &[22], "udp").unwrap();
        assert_eq!(host.ports[0].protocol, "udp");
        options.os = true;
        assert!(options.validate(Transport::Udp).is_err());
        assert!(options.validate(Transport::Tcp).is_ok());
        options.timeout_ms = 0;
        assert!(options.validate(Transport::Tcp).is_err());
    }

    #[tokio::test]
    async fn bounded_output_rejects_oversize() {
        assert!(read_bounded(&b"12345"[..], 4).await.is_err());
    }
    #[test]
    fn aggregated_udp_states_and_os_classes_roundtrip() {
        let xml = XML.replace("<ports>", "<ports><extraports state=\"open|filtered\" count=\"2\"><extrareasons reason=\"no-response\" count=\"2\" proto=\"udp\" ports=\"53,161\"/></extraports>")
            .replace("protocol=\"tcp\"", "protocol=\"udp\"")
            .replace("osfamily=\"Linux\"", "osfamily=\"Linux\" accuracy=\"93\"");
        let (_, host) = parse(
            xml.as_bytes(),
            "127.0.0.1".parse().unwrap(),
            &[22, 53, 161],
            "udp",
        )
        .unwrap();
        assert_eq!(host.port_summaries[0].state, "open|filtered");
        assert_eq!(
            host.port_summaries[0].reasons[0].ports.as_deref(),
            Some("53,161")
        );
        assert_eq!(host.os_matches[0].classes[0].accuracy, Some(93));
        assert_eq!(
            serde_json::from_str::<HostDetails>(&serde_json::to_string(&host).unwrap()).unwrap(),
            host
        );
        assert!(parse(xml.as_bytes(), host.ip, &[22], "udp").is_err());
    }

    #[test]
    fn invalid_confidence_and_duplicate_ports_are_rejected() {
        let ip = "127.0.0.1".parse().unwrap();
        for xml in [
            XML.replace("conf=\"10\"", "conf=\"11\""),
            XML.replace("accuracy=\"95\"", "accuracy=\"101\""),
            XML.replace(
                "</ports>",
                "<port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/></port></ports>",
            ),
        ] {
            assert!(parse(xml.as_bytes(), ip, &[22], "tcp").is_err());
        }
    }

    #[test]
    fn os_only_identification_does_not_enable_version_probes() {
        let options = IdentificationOptions {
            os: true,
            ..Default::default()
        };
        for transport in [Transport::Tcp, Transport::Syn] {
            options.validate(transport).unwrap();
            let args = arguments("127.0.0.1".parse().unwrap(), &[22, 23], transport, &options);
            assert!(args.contains(&"-O".into()));
            assert!(!args.contains(&"-sV".into()));
        }
        assert!(options.validate(Transport::Quic).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_and_reaps_the_child() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let args = vec![
            "-c".into(),
            r#"echo $$ > "$1"; exec sleep 30"#.into(),
            "fixture".into(),
            pidfile.to_str().unwrap().into(),
        ];
        let error = execute(Path::new("/bin/sh"), &args, Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
        let pid: i32 = std::fs::read_to_string(pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // SAFETY: signal 0 only checks whether this child still exists.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_stops_wrapper_descendants_holding_output_pipes() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("escaped");
        let args = vec![
            "-c".into(),
            r#"(sleep 0.5; echo escaped > "$1") & exit 0"#.into(),
            "fixture".into(),
            marker.to_str().unwrap().into(),
        ];
        assert!(
            execute(Path::new("/bin/sh"), &args, Duration::from_millis(100))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_overflow_terminates_a_running_process() {
        let args = vec![
            "-c".into(),
            "while :; do printf '%1024s' x >&2; done".into(),
        ];
        let error = execute(Path::new("/bin/sh"), &args, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("size limit"), "{error:#}");
    }
    #[cfg(unix)]
    fn target_report(hostname: &str, port: u16) -> TargetReport {
        use crate::model::{EndpointResult, EndpointState, Target};
        TargetReport {
            target: Target {
                original: hostname.into(),
                hostname: Some(hostname.into()),
                address: "127.0.0.1".parse().unwrap(),
            },
            fingerprint: None,
            fingerprint_matches: Vec::new(),
            os_guesses: Vec::new(),
            endpoints: BTreeMap::from([(
                port,
                EndpointResult {
                    port,
                    transport: Transport::Tcp,
                    state: EndpointState::Open,
                    latency: Duration::ZERO,
                    observations: Vec::new(),
                    fingerprint: None,
                    fingerprint_matches: Vec::new(),
                    errors: Vec::new(),
                },
            )]),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn aliases_share_one_identification_with_the_union_of_ports() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("nmap");
        let xml = XML.replace(
            "</ports>",
            "<extraports state=\"closed\" count=\"1\"/></ports>",
        );
        std::fs::write(&script, format!("#!/bin/sh\ncase \"$*\" in *'22-23'*) ;; *) exit 3;; esac\ncat <<'XML'\n{xml}\nXML\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let nmap = Nmap {
            executable: script,
            version: "7.99".into(),
        };
        let targets = [
            target_report("first.example", 22),
            target_report("second.example", 23),
            target_report("third.example", 22),
        ];
        let result = nmap
            .identify(
                &targets,
                Transport::Tcp,
                &IdentificationOptions {
                    services: true,
                    ..Default::default()
                },
            )
            .await;
        assert!(result.complete, "{:?}", result.error);
        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ports[0].port, 22);
        assert_eq!(result.hosts[0].port_summaries[0].count, 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_execution_stops_the_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("escaped");
        let ready = dir.path().join("ready");
        let args = vec![
            "-c".into(),
            r#"echo ready > "$2"; (sleep 0.5; echo escaped > "$1") & wait"#.into(),
            "fixture".into(),
            marker.to_str().unwrap().into(),
            ready.to_str().unwrap().into(),
        ];
        let task = tokio::spawn(async move {
            execute(Path::new("/bin/sh"), &args, Duration::from_secs(10)).await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(!marker.exists());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn identification_budget_is_shared_across_hosts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("nmap");
        let xml = XML.replace("127.0.0.1", "${target}");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nfor target do :; done\nif [ \"$target\" = 127.0.0.1 ]; then sleep 1; else sleep 2.5; fi\ncat <<XML\n{xml}\nXML\n"),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let nmap = Nmap {
            executable: script,
            version: "7.99".into(),
        };
        let first = target_report("first.example", 22);
        let mut second = target_report("second.example", 22);
        second.target.address = "127.0.0.2".parse().unwrap();
        let result = nmap
            .identify(
                &[first, second],
                Transport::Tcp,
                &IdentificationOptions {
                    services: true,
                    timeout_ms: 3000,
                    concurrency: 1,
                    ..Default::default()
                },
            )
            .await;
        assert!(!result.complete);
        assert_eq!(result.hosts.len(), 1, "{:?}", result.error);
        assert!(result.error.as_deref().unwrap().contains("timed out"));
    }
    #[cfg(unix)]
    #[test]
    fn candidate_planning_uses_native_states_and_scoped_os_reference_ports() {
        let mut open = target_report("first.example", 22);
        let mut closed = target_report("second.example", 23);
        closed.endpoints.get_mut(&23).unwrap().state = EndpointState::Closed;
        let mut filtered = target_report("third.example", 24);
        filtered.endpoints.get_mut(&24).unwrap().state = EndpointState::Filtered;
        let mut options = IdentificationOptions {
            services: true,
            ..Default::default()
        };
        let targets = [open.clone(), closed.clone(), filtered.clone()];
        assert_eq!(
            plan_identification(&targets, Transport::Tcp, &options)[0].ports,
            vec![22]
        );
        options.os = true;
        assert_eq!(
            plan_identification(&targets, Transport::Tcp, &options)[0].ports,
            vec![22, 23]
        );
        assert!(plan_identification(&[closed.clone()], Transport::Tcp, &options).is_empty());
        options.scope = IdentificationScope::All;
        assert_eq!(
            plan_identification(&targets, Transport::Tcp, &options)[0].ports,
            vec![22, 23, 24]
        );
        options.os = false;
        options.scope = IdentificationScope::Candidates;
        let endpoint = open.endpoints.get_mut(&22).unwrap();
        endpoint.transport = Transport::Udp;
        endpoint.state = EndpointState::OpenFiltered;
        assert_eq!(
            plan_identification(&[open.clone()], Transport::Udp, &options)[0].ports,
            vec![22]
        );
        assert!(plan_identification(&[open], Transport::Tcp, &options).is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn one_host_failure_does_not_discard_later_successes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("nmap");
        let xml = XML.replace("127.0.0.1", "${target}");
        std::fs::write(&script, format!("#!/bin/sh\nfor target do :; done\nif [ \"$target\" = 127.0.0.2 ]; then exit 2; fi\ncat <<XML\n{xml}\nXML\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let nmap = Nmap {
            executable: script,
            version: "7.99".into(),
        };
        let targets = (1..=3)
            .map(|last| {
                let mut target = target_report("test.example", 22);
                target.target.address = format!("127.0.0.{last}").parse().unwrap();
                target
            })
            .collect::<Vec<_>>();
        for concurrency in [1, 2] {
            let result = nmap
                .identify(
                    &targets,
                    Transport::Tcp,
                    &IdentificationOptions {
                        services: true,
                        concurrency,
                        ..Default::default()
                    },
                )
                .await;
            assert!(!result.complete);
            assert_eq!(result.requests.len(), 3);
            assert_eq!(result.failures.len(), 1);
            assert_eq!(result.failures[0].ip.to_string(), "127.0.0.2");
            assert_eq!(
                result
                    .hosts
                    .iter()
                    .map(|host| host.ip.to_string())
                    .collect::<Vec<_>>(),
                vec!["127.0.0.1", "127.0.0.3"]
            );
        }
    }
}
