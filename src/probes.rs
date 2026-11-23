pub(crate) mod web;

use std::{collections::BTreeSet, sync::OnceLock, time::Duration};

use async_trait::async_trait;
use bytes::Buf;
use futures::future::poll_fn;
use h3::client;
use http::{Method, Request};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    time::{Instant, timeout, timeout_at},
};

use crate::{
    error::{NrevError, Result},
    model::{Banner, Confidence, Evidence, ProbeObservation, ServiceHint, Transport},
    tls::handshake_tls_with_alpn,
    transport::ProbeConnection,
};

#[derive(Clone, Debug)]
pub struct ProbeContext<'a> {
    pub host: &'a str,
    pub port: u16,
    pub timeout: Duration,
    pub http_body_preview_bytes: usize,
}

#[async_trait]
pub trait Probe: Send + Sync {
    fn id(&self) -> &'static str;
    fn summary(&self) -> &'static str;
    fn transport(&self) -> Transport;
    fn default_ports(&self) -> &'static [u16];
    fn matches(&self, port: u16) -> bool {
        self.default_ports().contains(&port)
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation>;
}

#[derive(Clone, Debug, Serialize)]
pub struct BuiltinProbeCatalog {
    probes: Vec<BuiltinProbeMetadata>,
}

impl BuiltinProbeCatalog {
    pub fn probes(&self) -> &[BuiltinProbeMetadata] {
        &self.probes
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BuiltinProbeMetadata {
    pub id: &'static str,
    pub summary: &'static str,
    pub transport: &'static str,
    pub ports: &'static [u16],
}

impl Default for BuiltinProbeCatalog {
    fn default() -> Self {
        Self {
            probes: builtin_probes()
                .iter()
                .map(|probe| BuiltinProbeMetadata {
                    id: probe.id(),
                    summary: probe.summary(),
                    transport: probe.transport().as_str(),
                    ports: probe.default_ports(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalProbeDefinition {
    pub id: String,
    pub transport: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    pub payload: String,
    #[serde(default)]
    pub expect: Vec<String>,
}

impl ExternalProbeDefinition {
    pub fn matches(&self, port: u16, transport: Transport) -> bool {
        let transport_match = matches!(
            (self.transport.as_str(), transport),
            ("tcp", Transport::Tcp) | ("udp", Transport::Udp) | ("quic", Transport::Quic)
        );
        transport_match && self.ports.contains(&port)
    }

    pub async fn execute(
        &self,
        connection: ProbeConnection,
        timeout_window: Duration,
    ) -> Result<ProbeObservation> {
        let body = exchange_string(connection, self.payload.as_bytes(), timeout_window).await?;
        let matched = self
            .expect
            .iter()
            .filter(|item| body.contains(item.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        Ok(ProbeObservation {
            probe_id: self.id.clone(),
            service_hint: Some(ServiceHint {
                name: self.id.clone(),
                confidence: if matched.is_empty() {
                    Confidence::Low
                } else {
                    Confidence::Medium
                },
            }),
            banner: (!body.is_empty()).then(|| normalize_banner(body)),
            tls: None,
            tags: vec!["external".to_string()],
            evidence: matched
                .into_iter()
                .map(|value| Evidence {
                    key: "match".to_string(),
                    value,
                })
                .collect(),
            confidence: Confidence::Medium,
        })
    }
}

pub fn select_builtin_probes(
    port: u16,
    transport: Transport,
    enabled: &[String],
) -> Vec<Box<dyn Probe>> {
    let enabled_set: BTreeSet<&str> = enabled.iter().map(|value| value.as_str()).collect();
    builtin_probes()
        .into_iter()
        .filter(|probe| {
            probe.transport() == transport
                && if enabled_set.is_empty() {
                    probe.matches(port)
                } else {
                    enabled_set.contains(probe.id())
                }
        })
        .collect()
}

fn builtin_probes() -> Vec<Box<dyn Probe>> {
    vec![
        Box::new(TlsProbe),
        Box::new(HttpProbe),
        Box::new(SshProbe),
        Box::new(LineProbe::greeting()),
        Box::new(LineProbe::ftp()),
        Box::new(LineProbe::smtp()),
        Box::new(LineProbe::pop3()),
        Box::new(LineProbe::imap()),
        Box::new(LineProbe::telnet()),
        Box::new(DnsTcpProbe),
        Box::new(DnsUdpProbe),
        Box::new(NtpProbe),
        Box::new(RedisProbe),
        Box::new(MemcachedProbe),
        Box::new(PostgresProbe),
        Box::new(MySqlProbe),
        Box::new(MqttProbe),
        Box::new(SmbProbe),
        Box::new(RdpProbe),
        Box::new(SqlServerProbe),
        Box::new(OracleProbe),
        Box::new(QuicProbe),
    ]
}

pub fn normalize_banner(raw: String) -> Banner {
    let normalized = raw
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .chars()
        .take(160)
        .collect();
    Banner { raw, normalized }
}

struct TlsProbe;

#[async_trait]
impl Probe for TlsProbe {
    fn id(&self) -> &'static str {
        "tls"
    }
    fn summary(&self) -> &'static str {
        "Observe TLS handshake metadata and probe HTTPS when available"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[443, 465, 636, 853, 989, 990, 993, 995, 8443]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let ProbeConnection::Tcp(stream) = connection else {
            return Err(NrevError::Tls(
                "TLS probe requires a TCP connection".to_string(),
            ));
        };
        let started = Instant::now();
        let protocols: &[&[u8]] = match context.port {
            465 | 636 | 853 | 989 | 990 | 993 | 995 => &[],
            _ => &[b"h2", b"http/1.1"],
        };
        let (tls, tls_stream) =
            handshake_tls_with_alpn(stream, Some(context.host), context.timeout, protocols).await?;

        let mut evidence = vec![Evidence {
            key: "default_port".to_string(),
            value: context.port.to_string(),
        }];
        let version = match tls_stream.get_ref().1.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_2) => Some("1.2"),
            Some(rustls::ProtocolVersion::TLSv1_3) => Some("1.3"),
            _ => None,
        };
        if let Some(value) = version {
            evidence.push(Evidence {
                key: "tls_version".into(),
                value: value.into(),
            });
        }
        let mut banner = None;
        let mut service_name = "tls".to_string();
        let mut tags = vec!["encryption".to_string()];

        let budget = context.timeout.saturating_sub(started.elapsed()) / 2;
        let response = if tls.negotiated_protocol.as_deref() == Some("h2") {
            read_http2_response(tls_stream, &context, budget).await
        } else {
            read_http_response_stream(
                tls_stream,
                http_preview_request(&context).as_bytes(),
                budget,
                context.http_body_preview_bytes,
            )
            .await
        };
        if let Ok(response) = response {
            banner = Some(normalize_banner(response.header_text.clone()));
            evidence.extend(extract_http_evidence(&response));
            service_name = "https".to_string();
            tags.push("web".to_string());
        }

        Ok(ProbeObservation {
            probe_id: self.id().to_string(),
            service_hint: Some(ServiceHint {
                name: service_name,
                confidence: Confidence::High,
            }),
            banner,
            tls: Some(tls),
            tags,
            evidence,
            confidence: Confidence::High,
        })
    }
}

struct HttpProbe;

#[async_trait]
impl Probe for HttpProbe {
    fn id(&self) -> &'static str {
        "http"
    }
    fn summary(&self) -> &'static str {
        "Collect HTTP headers and lightweight HTML metadata"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8090, 8888]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let request = http_preview_request(&context);
        let response = read_http_response(
            connection,
            request.as_bytes(),
            context.timeout,
            context.http_body_preview_bytes,
        )
        .await?;
        let banner = normalize_banner(response.header_text.clone());
        let evidence = extract_http_evidence(&response);
        Ok(ProbeObservation {
            probe_id: self.id().to_string(),
            service_hint: Some(ServiceHint {
                name: "http".to_string(),
                confidence: Confidence::High,
            }),
            banner: Some(banner),
            tls: None,
            tags: vec!["web".to_string()],
            evidence,
            confidence: Confidence::High,
        })
    }
}

struct SshProbe;

#[async_trait]
impl Probe for SshProbe {
    fn id(&self) -> &'static str {
        "ssh"
    }
    fn summary(&self) -> &'static str {
        "Read SSH identification banners"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[22]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let raw = read_ssh_identification(connection, context.timeout).await?;
        Ok(ProbeObservation {
            probe_id: self.id().to_string(),
            service_hint: Some(ServiceHint {
                name: "ssh".to_string(),
                confidence: Confidence::High,
            }),
            banner: (!raw.is_empty()).then(|| normalize_banner(raw.clone())),
            tls: None,
            tags: vec!["remote-access".to_string()],
            evidence: vec![Evidence {
                key: "ident".to_string(),
                value: raw.lines().last().unwrap_or_default().to_string(),
            }],
            confidence: Confidence::High,
        })
    }
}

/// Read complete identification lines under one deadline, including any preamble.
async fn read_ssh_identification(connection: ProbeConnection, budget: Duration) -> Result<String> {
    let ProbeConnection::Tcp(stream) = connection else {
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "SSH requires TCP").into(),
        );
    };
    let mut reader = BufReader::new(stream.take(4096));
    let mut captured = Vec::new();
    timeout(budget, async {
        loop {
            let start = captured.len();
            if reader.read_until(b'\n', &mut captured).await? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incomplete SSH identification",
                ));
            }
            let line = &captured[start..];
            if line.starts_with(b"SSH-") && line.ends_with(b"\n") && line.len() <= 255 {
                return Ok(String::from_utf8_lossy(&captured).into_owned());
            }
            if line.starts_with(b"SSH-") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid SSH identification line",
                ));
            }
        }
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "SSH identification timed out"))?
    .map_err(Into::into)
}

struct LineProbe {
    id: &'static str,
    ports: &'static [u16],
    command: Option<&'static str>,
}

pub(crate) async fn passive_greeting(
    connection: ProbeConnection,
    context: ProbeContext<'_>,
) -> Result<ProbeObservation> {
    LineProbe::greeting().execute(connection, context).await
}

impl LineProbe {
    fn greeting() -> Self {
        Self {
            id: "greeting",
            ports: &[],
            command: None,
        }
    }

    fn ftp() -> Self {
        Self {
            id: "ftp",
            ports: &[21],
            command: None,
        }
    }
    fn smtp() -> Self {
        Self {
            id: "smtp",
            ports: &[25, 587],
            command: Some("EHLO nrev.example\r\n"),
        }
    }
    fn pop3() -> Self {
        Self {
            id: "pop3",
            ports: &[110],
            command: Some("CAPA\r\n"),
        }
    }
    fn imap() -> Self {
        Self {
            id: "imap",
            ports: &[143],
            command: Some("a1 CAPABILITY\r\n"),
        }
    }
    fn telnet() -> Self {
        Self {
            id: "telnet",
            ports: &[23],
            command: None,
        }
    }
}

#[async_trait]
impl Probe for LineProbe {
    fn id(&self) -> &'static str {
        self.id
    }
    fn summary(&self) -> &'static str {
        match self.id {
            "greeting" => "Read a server-first greeting without sending application data",
            "ftp" => "Read FTP greeting banners",
            "smtp" => "Trigger SMTP greeting and capability banners",
            "pop3" => "Trigger POP3 greeting and capability banners",
            "imap" => "Trigger IMAP capability banners",
            "telnet" => "Read Telnet negotiation banners",
            _ => "Read line-oriented service banners",
        }
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        self.ports
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let payload = self.command.unwrap_or_default().as_bytes();
        let (raw, starttls) = if self.id == "smtp" {
            let ProbeConnection::Tcp(stream) = connection else {
                return Err(std::io::Error::other("SMTP requires TCP").into());
            };
            smtp_exchange(stream, payload, context.timeout).await?
        } else if self.id == "greeting" {
            let ProbeConnection::Tcp(stream) = connection else {
                return Err(std::io::Error::other("greeting requires TCP").into());
            };
            let mut reader = BufReader::new(stream.take(1024));
            let mut first = Vec::new();
            timeout(context.timeout, reader.read_until(b'\n', &mut first))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "greeting timed out")
                })??;
            if !first.ends_with(b"\n") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incomplete greeting",
                )
                .into());
            }
            (String::from_utf8_lossy(&first).into_owned(), None)
        } else {
            (
                exchange_string(connection, payload, context.timeout).await?,
                None,
            )
        };
        let mut evidence = vec![Evidence {
            key: "greeting".into(),
            value: raw.lines().next().unwrap_or_default().to_string(),
        }];
        if starttls.is_some() {
            evidence.push(Evidence {
                key: "ehlo_reply".into(),
                value: "250".into(),
            });
        }
        if starttls == Some(true) {
            evidence.push(Evidence {
                key: "ehlo_starttls".into(),
                value: "advertised".into(),
            });
        }
        Ok(ProbeObservation {
            probe_id: self.id().to_string(),
            service_hint: (self.id != "greeting").then(|| ServiceHint {
                name: self.id().to_string(),
                confidence: Confidence::Medium,
            }),
            banner: (!raw.is_empty()).then(|| normalize_banner(raw.clone())),
            tls: None,
            tags: vec!["line-protocol".to_string()],
            evidence,
            confidence: Confidence::Medium,
        })
    }
}

/// Read one complete SMTP reply, including continuation lines, within the shared byte budget.
async fn smtp_reply<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    remaining: usize,
) -> std::io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    loop {
        let start = raw.len();
        let limit = remaining.saturating_sub(start).min(512) as u64;
        let count = (&mut *reader)
            .take(limit)
            .read_until(b'\n', &mut raw)
            .await?;
        let line = &raw[start..];
        if count == 0
            || !line.ends_with(b"\r\n")
            || line.len() < 5
            || !line[..3].iter().all(u8::is_ascii_digit)
            || raw[..3] != line[..3]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "incomplete or malformed SMTP reply",
            ));
        }
        match line[3] {
            b' ' | b'\r' if line[3] == b' ' || line.len() == 5 => return Ok(raw),
            b'-' => {}
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid SMTP reply separator",
                ));
            }
        }
    }
}

async fn smtp_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    ehlo: &[u8],
    budget: Duration,
) -> Result<(String, Option<bool>)> {
    let deadline = Instant::now() + budget;
    let mut reader = BufReader::new(stream);
    let mut raw = timeout_at(deadline, smtp_reply(&mut reader, 4096))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "SMTP greeting timed out")
        })??;
    let mut starttls = None;
    if raw.starts_with(b"220") && raw.len() < 4096 && reader.buffer().is_empty() {
        // Keep the greeting if the optional capability exchange stalls or fails.
        let allowance = deadline.saturating_duration_since(Instant::now()) / 2;
        let reply = timeout(allowance, async {
            reader.get_mut().write_all(ehlo).await?;
            smtp_reply(&mut reader, 4096 - raw.len()).await
        })
        .await;
        if let Ok(Ok(reply)) = reply {
            if reply.starts_with(b"250")
                && let Ok(text) = std::str::from_utf8(&reply)
            {
                starttls = Some(text.lines().skip(1).any(|line| {
                    line.get(4..)
                        .is_some_and(|s| s.eq_ignore_ascii_case("STARTTLS"))
                }));
            }
            raw.extend(reply);
        }
    }
    Ok((String::from_utf8_lossy(&raw).into_owned(), starttls))
}

struct DnsTcpProbe;

#[async_trait]
impl Probe for DnsTcpProbe {
    fn id(&self) -> &'static str {
        "dns-tcp"
    }
    fn summary(&self) -> &'static str {
        "Send a lightweight DNS version.bind query over TCP"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[53]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let query = dns_version_query_tcp();
        let frame =
            read_negotiation_frame(connection, &query, context.timeout, FrameFormat::Dns).await?;
        Ok(dns_observation(self.id(), &query[2..], frame, 2))
    }
}

struct DnsUdpProbe;

#[async_trait]
impl Probe for DnsUdpProbe {
    fn id(&self) -> &'static str {
        "dns-udp"
    }
    fn summary(&self) -> &'static str {
        "Send a lightweight DNS version.bind query over UDP"
    }
    fn transport(&self) -> Transport {
        Transport::Udp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[53]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let query = dns_version_query_udp();
        let raw = exchange_bytes(connection, &query, context.timeout).await?;
        Ok(dns_observation(self.id(), &query, raw, 0))
    }
}

fn dns_observation(probe: &str, query: &[u8], frame: Vec<u8>, offset: usize) -> ProbeObservation {
    let raw = &frame[offset..];
    let valid = raw.len() >= 12 && raw[..2] == query[..2] && raw[2] & 0xf8 == 0x80;
    let mut details = Vec::new();
    if valid {
        details.push(Evidence {
            key: "dns_rcode".into(),
            value: (raw[3] & 0x0f).to_string(),
        });
        details.push(Evidence {
            key: "dns_answers".into(),
            value: u16::from_be_bytes([raw[6], raw[7]]).to_string(),
        });
        if let Some(text) = dns_version_txt(raw, query) {
            details.push(Evidence {
                key: "dns_version_txt".into(),
                value: text.to_owned(),
            });
        }
    }
    validated_binary_observation(probe, "dns", frame, valid, details)
}

// Accept a single TXT character-string in a successful version.bind CH reply.
// The owner must repeat the question name or use a pointer to its start.
fn dns_version_txt<'a>(raw: &'a [u8], query: &[u8]) -> Option<&'a str> {
    if raw[2] & 2 != 0
        || raw[3] & 15 != 0
        || raw.get(4..8)? != [0, 1, 0, 1]
        || !raw.get(12..query.len())?.eq_ignore_ascii_case(&query[12..])
    {
        return None;
    }
    let mut rr = raw.get(query.len()..)?;
    let name = &query[12..query.len() - 4];
    if let Some(rest) = rr.strip_prefix(&[0xc0, 12]) {
        rr = rest;
    } else if rr.get(..name.len())?.eq_ignore_ascii_case(name) {
        rr = &rr[name.len()..];
    } else {
        return None;
    }
    if rr.get(..4)? != [0, 16, 0, 3] {
        return None;
    }
    let length = usize::from(u16::from_be_bytes(rr.get(8..10)?.try_into().ok()?));
    let (size, text) = rr.get(10..10 + length)?.split_first()?;
    if *size as usize != text.len()
        || text.is_empty()
        || !text.iter().all(|b| (32..=126).contains(b))
    {
        return None;
    }
    std::str::from_utf8(text).ok()
}

struct NtpProbe;

#[async_trait]
impl Probe for NtpProbe {
    fn id(&self) -> &'static str {
        "ntp"
    }
    fn summary(&self) -> &'static str {
        "Send a safe NTP client request for response observation"
    }
    fn transport(&self) -> Transport {
        Transport::Udp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[123]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let mut request = [0_u8; 48];
        request[0] = 0x23; // NTP version 4, client mode.
        let timestamp = rand::random::<u64>().to_be_bytes();
        request[40..48].copy_from_slice(&timestamp);
        let raw = exchange_bytes(connection, &request, context.timeout).await?;
        let valid = raw.len() >= 48
            && raw[0] & 7 == 4
            && matches!((raw[0] >> 3) & 7, 3 | 4)
            && raw[24..32] == timestamp;
        let mut details = Vec::new();
        if valid {
            details.push(Evidence {
                key: "ntp_version".into(),
                value: ((raw[0] >> 3) & 7).to_string(),
            });
            details.push(Evidence {
                key: "ntp_stratum".into(),
                value: raw[1].to_string(),
            });
        }
        Ok(validated_binary_observation(
            self.id(),
            "ntp",
            raw,
            valid,
            details,
        ))
    }
}

struct RedisProbe;

#[async_trait]
impl Probe for RedisProbe {
    fn id(&self) -> &'static str {
        "redis"
    }
    fn summary(&self) -> &'static str {
        "Send PING and capture Redis banners"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[6379]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let raw = exchange_string(connection, b"*1\r\n$4\r\nPING\r\n", context.timeout).await?;
        Ok(simple_observation(
            "redis",
            raw,
            vec!["database".to_string()],
        ))
    }
}

struct MemcachedProbe;

#[async_trait]
impl Probe for MemcachedProbe {
    fn id(&self) -> &'static str {
        "memcached"
    }
    fn summary(&self) -> &'static str {
        "Request version from Memcached"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[11211]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let raw = exchange_string(connection, b"version\r\n", context.timeout).await?;
        Ok(simple_observation(
            "memcached",
            raw,
            vec!["cache".to_string()],
        ))
    }
}

struct PostgresProbe;

#[async_trait]
impl Probe for PostgresProbe {
    fn id(&self) -> &'static str {
        "postgresql"
    }
    fn summary(&self) -> &'static str {
        "Send PostgreSQL SSLRequest for protocol observation"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[5432]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let ssl_request = [0_u8, 0, 0, 8, 4, 210, 22, 47];
        let raw = exchange_bytes(connection, &ssl_request, context.timeout).await?;
        Ok(binary_observation(
            self.id(),
            "postgresql",
            raw,
            vec!["database".to_string()],
        ))
    }
}

struct MySqlProbe;

#[async_trait]
impl Probe for MySqlProbe {
    fn id(&self) -> &'static str {
        "mysql"
    }
    fn summary(&self) -> &'static str {
        "Capture MySQL or MariaDB handshake banners"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[3306]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let ProbeConnection::Tcp(stream) = connection else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "MySQL requires TCP",
            )
            .into());
        };
        let raw = read_mysql_greeting(stream, context.timeout).await?;
        let mut observation = simple_observation(
            "mysql",
            String::from_utf8_lossy(&raw).into_owned(),
            vec!["database".into()],
        );
        if let Some(version) = mysql_handshake_version(&raw) {
            observation.evidence.push(Evidence {
                key: "handshake_version".into(),
                value: version.into(),
            });
        }
        Ok(observation)
    }
}

async fn read_mysql_greeting(
    mut stream: impl AsyncRead + Unpin,
    budget: Duration,
) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + budget;
    let mut buf = [0u8; 4096];
    let mut count = 0;
    let mut end = buf.len();
    while count < end {
        let n = match timeout_at(deadline, stream.read(&mut buf[count..end])).await {
            Ok(read) => read?,
            Err(_) if count > 0 => break,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "MySQL greeting timed out",
                ));
            }
        };
        if n == 0 {
            break;
        }
        count += n;
        if count >= 4 {
            let length = u32::from_le_bytes([buf[0], buf[1], buf[2], 0]) as usize;
            if buf[3] != 0 || !(17..=buf.len() - 4).contains(&length) {
                break;
            }
            end = length + 4;
        }
    }
    if count == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty MySQL greeting",
        ));
    }
    Ok(buf[..count].to_vec())
}

// Accept the server_version only from a complete protocol-10 greeting packet.
fn mysql_handshake_version(raw: &[u8]) -> Option<&str> {
    let header: [u8; 4] = raw.get(..4)?.try_into().ok()?;
    let length = u32::from_le_bytes([header[0], header[1], header[2], 0]) as usize;
    let packet = raw.get(4..4 + length)?;
    if header[3] != 0 || packet.first()? != &10 {
        return None;
    }
    let nul = packet[1..].iter().position(|b| *b == 0)? + 1;
    let version = packet.get(1..nul)?;
    // connection ID, eight authentication bytes, filler and capability flags
    let tail = packet.get(nul + 1..)?;
    if tail.len() < 15
        || tail[12] != 0
        || version.is_empty()
        || version.len() > 128
        || !version.iter().all(|b| b.is_ascii_graphic())
    {
        return None;
    }
    std::str::from_utf8(version).ok()
}

struct MqttProbe;

#[async_trait]
impl Probe for MqttProbe {
    fn id(&self) -> &'static str {
        "mqtt"
    }
    fn summary(&self) -> &'static str {
        "Send an MQTT CONNECT packet for broker observation"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[1883]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let packet = [
            0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
        ];
        let raw = exchange_bytes(connection, &packet, context.timeout).await?;
        Ok(binary_observation(
            self.id(),
            "mqtt",
            raw,
            vec!["message-broker".to_string()],
        ))
    }
}

struct SmbProbe;

#[async_trait]
impl Probe for SmbProbe {
    fn id(&self) -> &'static str {
        "smb"
    }
    fn summary(&self) -> &'static str {
        "Send SMB2 negotiate and summarize dialect and signing"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[445]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let raw = read_negotiation_frame(
            connection,
            &smb_negotiate_request(),
            context.timeout,
            FrameFormat::DirectTcp,
        )
        .await?;
        Ok(smb_observation(raw))
    }
}

struct RdpProbe;

#[async_trait]
impl Probe for RdpProbe {
    fn id(&self) -> &'static str {
        "rdp"
    }
    fn summary(&self) -> &'static str {
        "Send RDP X.224 negotiation and summarize selected protocol"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[3389]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let request = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
            0x00, 0x03, 0x00, 0x00, 0x00,
        ];
        let raw = read_negotiation_frame(connection, &request, context.timeout, FrameFormat::Tpkt)
            .await?;
        Ok(rdp_observation(raw))
    }
}

struct SqlServerProbe;

#[async_trait]
impl Probe for SqlServerProbe {
    fn id(&self) -> &'static str {
        "mssql-prelogin"
    }
    fn summary(&self) -> &'static str {
        "Send TDS prelogin and extract version and encryption hints"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[1433]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let raw = exchange_bytes(connection, &tds_prelogin_request(), context.timeout).await?;
        Ok(mssql_observation(raw))
    }
}

struct OracleProbe;

#[async_trait]
impl Probe for OracleProbe {
    fn id(&self) -> &'static str {
        "oracle-tns"
    }
    fn summary(&self) -> &'static str {
        "Send Oracle TNS connect and summarize listener behavior"
    }
    fn transport(&self) -> Transport {
        Transport::Tcp
    }
    fn default_ports(&self) -> &'static [u16] {
        &[1521, 2483, 2484]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let connect = [
            0x00, 0x3a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x36, 0x01, 0x2c, 0x00, 0x00,
            0x08, 0x00, 0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x3a, 0x00,
            0x00, 0x00, 0x00, 0x28, 0x44, 0x45, 0x53, 0x43, 0x52, 0x49, 0x50, 0x54, 0x49, 0x4f,
            0x4e, 0x3d, 0x28, 0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x5f, 0x44, 0x41, 0x54,
            0x41, 0x3d, 0x28, 0x53, 0x45, 0x52, 0x56, 0x49, 0x43, 0x45, 0x5f, 0x4e, 0x41, 0x4d,
            0x45, 0x3d, 0x58, 0x45, 0x29, 0x29,
        ];
        let raw = exchange_bytes(connection, &connect, context.timeout).await?;
        Ok(oracle_observation(raw))
    }
}

struct QuicProbe;

#[async_trait]
impl Probe for QuicProbe {
    fn id(&self) -> &'static str {
        "quic"
    }
    fn summary(&self) -> &'static str {
        "Observe QUIC/TLS metadata and probe HTTP/3 when ALPN matches"
    }
    fn transport(&self) -> Transport {
        Transport::Quic
    }
    fn default_ports(&self) -> &'static [u16] {
        &[443, 4433, 784, 8443, 8853, 9443]
    }
    async fn execute(
        &self,
        connection: ProbeConnection,
        context: ProbeContext<'_>,
    ) -> Result<ProbeObservation> {
        let ProbeConnection::Quic(quic) = connection else {
            return Err(NrevError::Tls(
                "QUIC probe requires a QUIC connection".to_string(),
            ));
        };

        let (endpoint, connection, tls, open_signal) = quic.into_parts();
        let mut evidence = Vec::new();
        let mut banner = None;
        let mut service_hint = ServiceHint {
            name: "quic".to_string(),
            confidence: Confidence::High,
        };
        let mut tags = vec!["quic".to_string(), "udp".to_string()];

        if let Some(signal) = open_signal {
            evidence.push(Evidence {
                key: "open_signal".to_string(),
                value: signal.clone(),
            });
            banner = Some(normalize_banner(format!("QUIC {signal}")));
            service_hint.confidence = Confidence::Medium;
        }

        if let Some(alpn) = tls.negotiated_protocol.clone() {
            evidence.push(Evidence {
                key: "alpn".to_string(),
                value: alpn.clone(),
            });
            if banner.is_none() {
                banner = Some(normalize_banner(format!("QUIC alpn={alpn}")));
            }
        }

        if let Some(connection) = connection
            && tls
                .negotiated_protocol
                .as_deref()
                .is_some_and(|protocol| protocol.starts_with("h3"))
        {
            let response = read_http3_response(
                connection,
                &http_authority(context.host, context.port),
                context.timeout,
                context.http_body_preview_bytes,
            )
            .await?;
            banner = Some(normalize_banner(response.header_text.clone()));
            evidence.extend(extract_http_evidence(&response));
            service_hint = ServiceHint {
                name: "http3".to_string(),
                confidence: Confidence::High,
            };
            tags.push("web".to_string());
        }

        endpoint.close(0u32.into(), b"probe complete");

        Ok(ProbeObservation {
            probe_id: self.id().to_string(),
            confidence: service_hint.confidence.clone(),
            service_hint: Some(service_hint),
            banner,
            tls: Some(tls),
            tags,
            evidence,
        })
    }
}

fn simple_observation(service: &str, raw: String, tags: Vec<String>) -> ProbeObservation {
    ProbeObservation {
        probe_id: service.to_string(),
        service_hint: Some(ServiceHint {
            name: service.to_string(),
            confidence: Confidence::Medium,
        }),
        banner: (!raw.is_empty()).then(|| normalize_banner(raw.clone())),
        tls: None,
        tags,
        evidence: vec![Evidence {
            key: "response".to_string(),
            value: raw.lines().next().unwrap_or_default().to_string(),
        }],
        confidence: Confidence::Medium,
    }
}

fn validated_binary_observation(
    probe: &str,
    service: &str,
    raw: Vec<u8>,
    valid: bool,
    details: Vec<Evidence>,
) -> ProbeObservation {
    let mut observation = binary_observation(probe, service, raw, vec!["infrastructure".into()]);
    observation.evidence.push(Evidence {
        key: "response_validated".into(),
        value: valid.to_string(),
    });
    observation.evidence.extend(details);
    if !valid {
        // Reachability alone does not identify the responding service.
        observation.service_hint = None;
        observation.confidence = Confidence::Low;
    }
    observation
}

fn binary_observation(
    probe_id: &str,
    service: &str,
    raw: Vec<u8>,
    tags: Vec<String>,
) -> ProbeObservation {
    ProbeObservation {
        probe_id: probe_id.to_string(),
        service_hint: Some(ServiceHint {
            name: service.to_string(),
            confidence: Confidence::Medium,
        }),
        banner: Some(normalize_banner(format!("{raw:?}"))),
        tls: None,
        tags,
        evidence: vec![Evidence {
            key: "response_bytes".to_string(),
            value: format!("{raw:?}"),
        }],
        confidence: Confidence::Medium,
    }
}

enum FrameFormat {
    Dns,
    DirectTcp,
    Tpkt,
}

async fn read_negotiation_frame(
    connection: ProbeConnection,
    request: &[u8],
    budget: Duration,
    format: FrameFormat,
) -> Result<Vec<u8>> {
    let ProbeConnection::Tcp(mut stream) = connection else {
        return Err(std::io::Error::other("negotiation requires TCP").into());
    };
    timeout(budget, async {
        stream.write_all(request).await?;
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        let length = match format {
            FrameFormat::Dns => {
                let payload = usize::from(u16::from_be_bytes([header[0], header[1]]));
                if (12..=4096).contains(&payload) {
                    payload + 2
                } else {
                    0
                }
            }
            FrameFormat::DirectTcp if header[0] == 0 => u32::from_be_bytes(header) as usize + 4,
            FrameFormat::Tpkt if header[..2] == [3, 0] => {
                usize::from(u16::from_be_bytes([header[2], header[3]]))
            }
            _ => 0,
        };
        if !(4..=65536).contains(&length) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid negotiation frame length",
            ));
        }
        let mut frame = vec![0; length];
        frame[..4].copy_from_slice(&header);
        stream.read_exact(&mut frame[4..]).await?;
        Ok(frame)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "negotiation timed out"))?
    .map_err(Into::into)
}

// SMB offsets are relative to the SMB2 header, following the four-byte transport prefix.
fn smb_negotiate_request() -> Vec<u8> {
    let dialects = [0x0202u16, 0x0210, 0x0300, 0x0302, 0x0311];
    let context_offset = (64 + 36 + 2 * dialects.len()).next_multiple_of(8);
    let mut frame = vec![0; 4 + context_offset + 8 + 6 + 32];
    let length = (frame.len() - 4) as u32;
    frame[..4].copy_from_slice(&length.to_be_bytes());
    let smb = &mut frame[4..];
    smb[..4].copy_from_slice(b"\xfeSMB");
    smb[4..6].copy_from_slice(&64u16.to_le_bytes());
    smb[14] = 1; // Credit request.
    smb[64] = 36;
    smb[66] = dialects.len() as u8;
    smb[68] = 1; // Signing enabled.
    smb[76..92].copy_from_slice(&rand::random::<[u8; 16]>());
    smb[92..96].copy_from_slice(&(context_offset as u32).to_le_bytes());
    smb[96] = 1;
    for (chunk, dialect) in smb[100..].chunks_exact_mut(2).zip(dialects) {
        chunk.copy_from_slice(&dialect.to_le_bytes());
    }
    let ctx = &mut smb[context_offset..];
    ctx[0] = 1; // Preauthentication integrity capabilities.
    ctx[2] = 38;
    ctx[8] = 1;
    ctx[10] = 32;
    ctx[12] = 1; // SHA-512.
    ctx[14..].copy_from_slice(&rand::random::<[u8; 32]>());
    frame
}

fn smb_observation(raw: Vec<u8>) -> ProbeObservation {
    let negotiated = smb_negotiation(&raw);
    let mut evidence = vec![Evidence {
        key: "response_bytes".into(),
        value: format!("{} bytes", raw.len()),
    }];
    let text = if let Some((dialect, signing)) = negotiated {
        evidence.extend([
            Evidence {
                key: "smb_dialect".into(),
                value: dialect.into(),
            },
            Evidence {
                key: "smb_signing".into(),
                value: signing.into(),
            },
        ]);
        format!("SMB2 negotiate dialect={dialect} signing={signing}")
    } else {
        format!("SMB response {} bytes", raw.len())
    };
    ProbeObservation {
        probe_id: "smb".into(),
        service_hint: negotiated.map(|_| ServiceHint {
            name: "smb".into(),
            confidence: Confidence::High,
        }),
        banner: Some(normalize_banner(text)),
        tls: None,
        tags: vec!["file-sharing".into(), "enterprise".into()],
        evidence,
        confidence: if negotiated.is_some() {
            Confidence::High
        } else {
            Confidence::Low
        },
    }
}

fn oracle_observation(raw: Vec<u8>) -> ProbeObservation {
    let banner_text = parse_oracle_banner(&raw)
        .unwrap_or_else(|| format!("Oracle TNS response {} bytes", raw.len()));
    ProbeObservation {
        probe_id: "oracle-tns".to_string(),
        service_hint: Some(ServiceHint {
            name: "oracle".to_string(),
            confidence: Confidence::High,
        }),
        banner: Some(normalize_banner(banner_text)),
        tls: None,
        tags: vec!["database".to_string(), "enterprise".to_string()],
        evidence: vec![Evidence {
            key: "response_bytes".to_string(),
            value: format!("{} bytes", raw.len()),
        }],
        confidence: Confidence::Medium,
    }
}

fn rdp_observation(raw: Vec<u8>) -> ProbeObservation {
    let banner_text =
        parse_rdp_banner(&raw).unwrap_or_else(|| format!("RDP response {} bytes", raw.len()));
    let mut evidence = vec![Evidence {
        key: "response_bytes".into(),
        value: format!("{} bytes", raw.len()),
    }];
    if raw.len() == 19
        && raw[..6] == [3, 0, 0, 19, 14, 0xd0]
        && raw[10] == 0
        && raw[11] == 2
        && raw[13..15] == [8, 0]
    {
        let protocol = rdp_protocol_name(u32::from_le_bytes([raw[15], raw[16], raw[17], raw[18]]));
        if matches!(protocol, "rdp" | "ssl" | "hybrid") {
            evidence.push(Evidence {
                key: "rdp_selected_protocol".into(),
                value: protocol.into(),
            });
        }
    }
    ProbeObservation {
        probe_id: "rdp".to_string(),
        service_hint: Some(ServiceHint {
            name: "rdp".to_string(),
            confidence: Confidence::High,
        }),
        banner: Some(normalize_banner(banner_text)),
        tls: None,
        tags: vec!["remote-access".to_string(), "enterprise".to_string()],
        evidence,
        confidence: Confidence::High,
    }
}

fn mssql_observation(raw: Vec<u8>) -> ProbeObservation {
    let parsed = parse_tds_prelogin_response(&raw);
    let banner_text = parsed
        .as_ref()
        .map(|parsed| parsed.banner())
        .unwrap_or_else(|| format!("TDS prelogin response {} bytes", raw.len()));
    let mut evidence = vec![Evidence {
        key: "response_bytes".to_string(),
        value: format!("{} bytes", raw.len()),
    }];

    if let Some(parsed) = &parsed {
        evidence.push(Evidence {
            key: "response_validated".into(),
            value: parsed.framed.to_string(),
        });
        if let Some(version) = &parsed.version {
            evidence.push(Evidence {
                key: "version".to_string(),
                value: version.clone(),
            });
        }
        if let Some(encryption) = &parsed.encryption {
            evidence.push(Evidence {
                key: "encryption".to_string(),
                value: encryption.clone(),
            });
        }
        if let Some(instance) = &parsed.instance {
            evidence.push(Evidence {
                key: "instance".to_string(),
                value: instance.clone(),
            });
        }
    }

    ProbeObservation {
        probe_id: "mssql-prelogin".to_string(),
        service_hint: Some(ServiceHint {
            name: "mssql".to_string(),
            confidence: Confidence::High,
        }),
        banner: Some(normalize_banner(banner_text)),
        tls: None,
        tags: vec!["database".to_string(), "enterprise".to_string()],
        evidence,
        confidence: Confidence::Medium,
    }
}

pub(crate) fn http_status_parts(line: &str) -> Option<(&str, &str)> {
    let mut fields = line.split(' ');
    let protocol = fields.next()?;
    let code = fields.next()?;
    (code.len() == 3
        && matches!(code.as_bytes()[0], b'1'..=b'5')
        && code.bytes().all(|b| b.is_ascii_digit()))
    .then_some((protocol, code))
}

fn extract_status_line(raw: &str) -> Vec<Evidence> {
    raw.lines()
        .next()
        .map(|line| {
            vec![Evidence {
                key: "status_line".to_string(),
                value: line.to_string(),
            }]
        })
        .unwrap_or_default()
}

fn tds_prelogin_request() -> [u8; 47] {
    [
        0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00,
        0x20, 0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04, 0x04, 0x00,
        0x26, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]
}

#[derive(Debug)]
struct TdsPreloginResponse {
    framed: bool,
    version: Option<String>,
    encryption: Option<String>,
    instance: Option<String>,
    mars: Option<String>,
}

impl TdsPreloginResponse {
    fn banner(&self) -> String {
        let mut parts = vec!["TDS prelogin".to_string()];
        if let Some(version) = &self.version {
            parts.push(format!("version={version}"));
        }
        if let Some(encryption) = &self.encryption {
            parts.push(format!("encryption={encryption}"));
        }
        if let Some(instance) = &self.instance {
            parts.push(format!("instance={instance}"));
        }
        if let Some(mars) = &self.mars {
            parts.push(format!("mars={mars}"));
        }
        parts.join(" ")
    }
}

fn parse_tds_prelogin_response(raw: &[u8]) -> Option<TdsPreloginResponse> {
    if raw.len() < 8 {
        return None;
    }
    let payload = &raw[8..];
    let mut framed = raw[0] == 4
        && raw[1] & 1 == 1
        && usize::from(u16::from_be_bytes([raw[2], raw[3]])) == raw.len()
        && payload.first() == Some(&0);
    let mut seen = [false; 256];
    let mut ranges = Vec::new();
    let mut index = 0usize;
    let mut version = None;
    let mut encryption = None;
    let mut instance = None;
    let mut mars = None;

    while index < payload.len() {
        let token = *payload.get(index)?;
        if token == 0xff {
            break;
        }
        let offset =
            u16::from_be_bytes([*payload.get(index + 1)?, *payload.get(index + 2)?]) as usize;
        let length =
            u16::from_be_bytes([*payload.get(index + 3)?, *payload.get(index + 4)?]) as usize;
        let start = offset;
        let end = start.checked_add(length)?;
        let value = payload.get(start..end)?;

        framed &= !std::mem::replace(&mut seen[usize::from(token)], true);
        framed &= match token {
            0 => length == 6,
            1 | 4 => length == 1,
            _ => true,
        };
        if length > 0 {
            ranges.push(start..end);
        }

        match token {
            0x00 if value.len() >= 6 => {
                let major = value[0];
                let minor = value[1];
                let build = u16::from_be_bytes([value[2], value[3]]);
                let subbuild = u16::from_be_bytes([value[4], value[5]]);
                if subbuild == 0 {
                    version = Some(format!("{major}.{minor}.{build}"));
                } else {
                    version = Some(format!("{major}.{minor}.{build}.{subbuild}"));
                }
            }
            0x01 if !value.is_empty() => {
                encryption = Some(match value[0] {
                    0x00 => "encrypt-off".to_string(),
                    0x01 => "encrypt-on".to_string(),
                    0x02 => "encrypt-not-supported".to_string(),
                    0x03 => "encrypt-required".to_string(),
                    other => format!("unknown(0x{other:02x})"),
                });
            }
            0x02 => {
                let trimmed = value.split(|byte| *byte == 0x00).next().unwrap_or_default();
                if !trimmed.is_empty() {
                    instance = Some(String::from_utf8_lossy(trimmed).to_string());
                }
            }
            0x04 if !value.is_empty() => {
                mars = Some(if value[0] == 0x00 {
                    "off".to_string()
                } else {
                    "on".to_string()
                });
            }
            _ => {}
        }

        index += 5;
    }

    framed &= payload.get(index) == Some(&0xff);
    ranges.sort_unstable_by_key(|r| r.start);
    framed &= ranges.first().is_some_and(|r| r.start > index)
        && ranges.windows(2).all(|w| w[0].end <= w[1].start);
    Some(TdsPreloginResponse {
        framed,
        version,
        encryption,
        instance,
        mars,
    })
}

async fn exchange_string(
    connection: ProbeConnection,
    payload: &[u8],
    timeout_window: Duration,
) -> Result<String> {
    Ok(
        String::from_utf8_lossy(&exchange_bytes(connection, payload, timeout_window).await?)
            .to_string(),
    )
}

// Dropping a JoinHandle detaches its task; probing must cancel the driver instead.
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn http_preview_request(context: &ProbeContext<'_>) -> String {
    let authority = http_authority(context.host, context.port);
    let end = context.http_body_preview_bytes.saturating_sub(1);
    format!(
        "GET / HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: nrev\r\nAccept: */*\r\nRange: bytes=0-{end}\r\nConnection: close\r\n\r\n"
    )
}

fn http_authority(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

struct HttpResponsePreview {
    header_text: String,
    body_preview: Option<String>,
}

async fn read_http_response(
    connection: ProbeConnection,
    payload: &[u8],
    timeout_window: Duration,
    body_limit: usize,
) -> Result<HttpResponsePreview> {
    let ProbeConnection::Tcp(mut stream) = connection else {
        return Err(NrevError::Tls(
            "HTTP probe requires a TCP connection".to_string(),
        ));
    };

    read_http_response_stream(&mut stream, payload, timeout_window, body_limit).await
}

async fn read_http2_response(
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    context: &ProbeContext<'_>,
    budget: Duration,
) -> Result<HttpResponsePreview> {
    let deadline = Instant::now() + budget;
    let authority = http_authority(context.host, context.port);
    let request = Request::get(format!("https://{authority}/"))
        .version(http::Version::HTTP_2)
        .header("user-agent", "nrev")
        .header("accept", "*/*")
        .header(
            "range",
            format!(
                "bytes=0-{}",
                context.http_body_preview_bytes.saturating_sub(1)
            ),
        )
        .body(())
        .map_err(|e| NrevError::Tls(e.to_string()))?;
    let (response, _driver) = timeout_at(deadline, async {
        let (mut sender, connection) = h2::client::Builder::new()
            .enable_push(false)
            .max_header_list_size(16 * 1024)
            .handshake::<_, bytes::Bytes>(stream)
            .await?;
        let driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let (response, _) = sender.send_request(request, true)?;
        Ok::<_, h2::Error>((response.await?, driver))
    })
    .await
    .map_err(|_| NrevError::Tls("HTTP/2 response timed out".into()))?
    .map_err(|e| NrevError::Tls(e.to_string()))?;
    let header_text = format_http_headers("HTTP/2", response.status().as_u16(), response.headers());
    let mut body = Vec::new();
    let mut stream = response.into_body();
    let body_deadline = Instant::now() + deadline.saturating_duration_since(Instant::now()) / 2;
    while body.len() < context.http_body_preview_bytes {
        let Ok(Some(Ok(chunk))) = timeout_at(body_deadline, stream.data()).await else {
            break;
        };
        let count = chunk
            .len()
            .min(context.http_body_preview_bytes - body.len());
        body.extend_from_slice(&chunk[..count]);
        if stream.flow_control().release_capacity(chunk.len()).is_err() {
            break;
        }
    }
    Ok(HttpResponsePreview {
        header_text,
        body_preview: (!body.is_empty()).then(|| String::from_utf8_lossy(&body).into_owned()),
    })
}

async fn read_http3_response(
    connection: quinn::Connection,
    host: &str,
    timeout_window: Duration,
    body_limit: usize,
) -> Result<HttpResponsePreview> {
    let deadline = Instant::now() + timeout_window;
    let h3_connection = h3_quinn::Connection::new(connection);
    let (mut driver, mut send_request) = client::new(h3_connection)
        .await
        .map_err(|error| NrevError::Tls(error.to_string()))?;
    let _driver_task = AbortOnDrop(tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    }));

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{host}/"))
        .header("Host", host)
        .header("User-Agent", "nrev")
        .header("Range", format!("bytes=0-{}", body_limit.saturating_sub(1)))
        .body(())
        .map_err(|error| NrevError::Tls(error.to_string()))?;

    let mut stream = timeout_at(deadline, send_request.send_request(request))
        .await
        .map_err(|_| NrevError::Tls("HTTP/3 request timed out".to_string()))?
        .map_err(|error| NrevError::Tls(error.to_string()))?;
    timeout_at(deadline, stream.finish())
        .await
        .map_err(|_| NrevError::Tls("HTTP/3 stream finish timed out".to_string()))?
        .map_err(|error| NrevError::Tls(error.to_string()))?;

    let response = timeout_at(deadline, stream.recv_response())
        .await
        .map_err(|_| NrevError::Tls("HTTP/3 response timed out".to_string()))?
        .map_err(|error| NrevError::Tls(error.to_string()))?;

    let header_text = format_http_headers("HTTP/3", response.status().as_u16(), response.headers());
    let mut body = Vec::new();
    let body_deadline = Instant::now() + deadline.saturating_duration_since(Instant::now()) / 2;
    while body.len() < body_limit {
        let Ok(Ok(Some(mut chunk))) = timeout_at(body_deadline, stream.recv_data()).await else {
            break;
        };
        let count = chunk.remaining().min(body_limit - body.len());
        body.extend_from_slice(&chunk.copy_to_bytes(count));
    }

    Ok(HttpResponsePreview {
        header_text,
        body_preview: (!body.is_empty()).then(|| String::from_utf8_lossy(&body).into_owned()),
    })
}

async fn read_http_response_stream<S>(
    mut stream: S,
    payload: &[u8],
    timeout_window: Duration,
    body_limit: usize,
) -> Result<HttpResponsePreview>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const HEADER_LIMIT: usize = 64 * 1024;
    let deadline = Instant::now() + timeout_window;
    timeout_at(deadline, stream.write_all(payload))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))??;

    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let mut header_end: Option<usize> = None;
    let mut expected_body = body_limit;
    let mut read_deadline = deadline;
    loop {
        let limit = header_end.map_or(HEADER_LIMIT, |end| end.saturating_add(expected_body));
        let remaining = limit.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let read_len = remaining.min(chunk.len());
        let size = match timeout_at(read_deadline, stream.read(&mut chunk[..read_len])).await {
            Ok(Err(_)) | Err(_) if header_end.is_some() => break,
            Ok(result) => result?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP header read timed out",
                )
                .into());
            }
        };
        if size == 0 {
            break;
        }
        let search_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..size]);
        if header_end.is_none() {
            let prefix_len = buf.len().min(b"HTTP/1.".len());
            if buf[..prefix_len] != b"HTTP/1."[..prefix_len] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected HTTP response prefix",
                )
                .into());
            }
            header_end = find_http_header_end(&buf[search_from..]).map(|end| search_from + end);
            if let Some(end) = header_end {
                let headers = String::from_utf8_lossy(&buf[..end]);
                if !valid_http1_head(&headers) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid HTTP response headers",
                    )
                    .into());
                }
                let now = Instant::now();
                read_deadline = now + deadline.saturating_duration_since(now) / 2;
                // Transfer-Encoding takes precedence over Content-Length.
                let chunked = headers.lines().any(|line| {
                    line.split_once(':')
                        .is_some_and(|(key, _)| key.eq_ignore_ascii_case("transfer-encoding"))
                });
                if !chunked
                    && let Some(length) = headers.lines().find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                {
                    expected_body = expected_body.min(length);
                }
            }
        }
    }
    let end = header_end.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "incomplete HTTP headers or header limit exceeded",
        )
    })?;
    let header_text = String::from_utf8_lossy(&buf[..end]).to_string();
    let body = &buf[end..buf.len().min(end.saturating_add(expected_body))];
    Ok(HttpResponsePreview {
        header_text,
        body_preview: (!body.is_empty()).then(|| String::from_utf8_lossy(body).into_owned()),
    })
}

fn valid_http1_head(headers: &str) -> bool {
    let mut lines = headers.split("\r\n");
    let Some(status) = lines.next() else {
        return false;
    };
    if !matches!(
        http_status_parts(status),
        Some(("HTTP/1.0" | "HTTP/1.1", _))
    ) || status.bytes().any(|b| b.is_ascii_control() && b != b'\t')
    {
        return false;
    }
    let mut previous_field = false;
    for line in lines.take_while(|line| !line.is_empty()) {
        if line.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
            return false;
        }
        if line.starts_with([' ', '\t']) {
            if !previous_field {
                return false;
            }
            continue;
        }
        let Some((name, _)) = line.split_once(':') else {
            return false;
        };
        if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
            return false;
        }
        previous_field = true;
    }
    true
}

fn format_http_headers(protocol: &str, headers_status: u16, headers: &http::HeaderMap) -> String {
    let mut lines = vec![format!("{protocol} {headers_status}")];
    for (name, value) in headers {
        lines.push(format!(
            "{}: {}",
            name.as_str(),
            value.to_str().unwrap_or("<binary>")
        ));
    }
    format!("{}\r\n\r\n", lines.join("\r\n"))
}

fn extract_http_evidence(response: &HttpResponsePreview) -> Vec<Evidence> {
    let mut evidence = extract_status_line(&response.header_text);
    push_header_evidence(&mut evidence, &response.header_text, "server", "server");
    push_header_evidence(&mut evidence, &response.header_text, "location", "location");
    push_header_evidence(
        &mut evidence,
        &response.header_text,
        "x-powered-by",
        "x-powered-by",
    );
    push_header_evidence(&mut evidence, &response.header_text, "via", "via");
    push_header_evidence(&mut evidence, &response.header_text, "x-cache", "x-cache");
    push_header_evidence(
        &mut evidence,
        &response.header_text,
        "cf-cache-status",
        "cf-cache-status",
    );
    push_header_evidence(&mut evidence, &response.header_text, "alt-svc", "alt-svc");
    push_header_evidence(
        &mut evidence,
        &response.header_text,
        "set-cookie",
        "set-cookie",
    );
    push_header_evidence(
        &mut evidence,
        &response.header_text,
        "access-control-allow-origin",
        "access-control-allow-origin",
    );
    push_header_evidence(
        &mut evidence,
        &response.header_text,
        "access-control-allow-credentials",
        "access-control-allow-credentials",
    );

    if let Some(body_preview) = response
        .body_preview
        .as_deref()
        .filter(|body| !body.is_empty())
    {
        if let Some(title) = extract_html_title(body_preview) {
            evidence.push(Evidence {
                key: "title".to_string(),
                value: title,
            });
        }
        if let Some(description) = extract_meta_content(body_preview, "description") {
            evidence.push(Evidence {
                key: "description".to_string(),
                value: description,
            });
        }
        let types = extract_header_values(&response.header_text, "content-type");
        if let [content_type] = types.as_slice()
            && content_type.split(';').next().is_some_and(|v| {
                ["text/html", "application/xhtml+xml"]
                    .iter()
                    .any(|mime| v.trim().eq_ignore_ascii_case(mime))
            })
            && let Some(generator) = crate::technology::html::generator(body_preview)
        {
            evidence.push(Evidence {
                key: "generator_validated".into(),
                value: "true".into(),
            });
            evidence.push(Evidence {
                key: "generator".to_string(),
                value: generator,
            });
        }
        evidence.push(Evidence {
            key: "body_preview".to_string(),
            value: body_preview.chars().take(160).collect(),
        });
    }

    evidence
}

fn push_header_evidence(
    evidence: &mut Vec<Evidence>,
    headers: &str,
    header_name: &str,
    evidence_key: &str,
) {
    let values = extract_header_values(headers, header_name);
    if !values.is_empty() {
        evidence.push(Evidence {
            key: evidence_key.to_string(),
            value: values.join("; "),
        });
    }
}

async fn exchange_bytes(
    connection: ProbeConnection,
    payload: &[u8],
    timeout_window: Duration,
) -> Result<Vec<u8>> {
    match connection {
        ProbeConnection::Tcp(mut stream) => {
            if !payload.is_empty() {
                timeout(timeout_window, stream.write_all(payload))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout")
                    })??;
            }
            let mut buf = vec![0_u8; 4096];
            let size = timeout(timeout_window, stream.read(&mut buf))
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))??;
            if size == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed without a response",
                )
                .into());
            }
            Ok(buf[..size].to_vec())
        }
        ProbeConnection::Udp(socket) => {
            if !payload.is_empty() {
                timeout(timeout_window, socket.send(payload))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "send timeout")
                    })??;
            }
            let mut buf = vec![0_u8; 4096];
            let size = timeout(timeout_window, socket.recv(&mut buf))
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "recv timeout"))??;
            Ok(buf[..size].to_vec())
        }
        ProbeConnection::Syn(_) => Err(NrevError::Tls(
            "SYN transport does not support direct probe I/O".to_string(),
        )),
        ProbeConnection::Quic(_) => Err(NrevError::Tls(
            "QUIC transport does not support generic probe I/O".to_string(),
        )),
    }
}

fn find_http_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

pub(crate) fn extract_header_values(headers: &str, name: &str) -> Vec<String> {
    let mut lines = headers
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .peekable();
    let mut values = Vec::new();
    while let Some(line) = lines.next() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.eq_ignore_ascii_case(name)
            && !lines
                .peek()
                .is_some_and(|next| next.starts_with([' ', '\t']))
        {
            values.push(value.trim().to_owned());
        }
    }
    values
}

fn extract_html_title(body: &str) -> Option<String> {
    static TITLE_RE: OnceLock<Regex> = OnceLock::new();
    let regex = TITLE_RE.get_or_init(|| {
        Regex::new(r"(?is)<title[^>]*>\s*(.*?)\s*</title>").expect("valid title regex")
    });
    let captures = regex.captures(body)?;
    normalize_html_capture(captures.get(1)?.as_str())
}

fn extract_meta_content(body: &str, name: &str) -> Option<String> {
    let pattern = format!(
        r#"(?is)<meta[^>]+name\s*=\s*["']{}["'][^>]+content\s*=\s*["'](.*?)["'][^>]*>"#,
        regex::escape(name)
    );
    let regex = Regex::new(&pattern).ok()?;
    let captures = regex.captures(body)?;
    normalize_html_capture(captures.get(1)?.as_str())
}

fn normalize_html_capture(value: &str) -> Option<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    (!normalized.is_empty()).then_some(normalized)
}

fn smb_negotiation(raw: &[u8]) -> Option<(&'static str, &'static str)> {
    let length = u32::from_be_bytes(raw.get(..4)?.try_into().ok()?) as usize;
    let smb = &raw[4..];
    if length != smb.len()
        || smb.len() < 128
        || smb[..4] != *b"\xfeSMB"
        || smb[4..6] != [64, 0]
        || smb[8..14] != [0; 6]
        || smb[16] & 1 == 0
        || smb[20..32] != [0; 12]
        || smb[64..66] != [65, 0]
    {
        return None;
    }
    let mode = u16::from_le_bytes([smb[66], smb[67]]);
    let dialect = smb_dialect_name(u16::from_le_bytes([smb[68], smb[69]]));
    let security_offset = usize::from(u16::from_le_bytes([smb[120], smb[121]]));
    let security_length = usize::from(u16::from_le_bytes([smb[122], smb[123]]));
    if mode > 3
        || dialect == "unknown"
        || (security_length != 0
            && (security_offset < 128 || security_offset + security_length > smb.len()))
        || (dialect == "3.1.1"
            && !smb_preauth_selected(smb, 128.max(security_offset + security_length)))
    {
        return None;
    }
    Some((dialect, smb_security_mode_label(mode)))
}

// The 3.1.1 request offers only SHA-512. The reply must select it exactly once.
fn smb_preauth_selected(smb: &[u8], minimum_offset: usize) -> bool {
    let count = u16::from_le_bytes([smb[70], smb[71]]);
    let mut offset = u32::from_le_bytes(smb[124..128].try_into().unwrap()) as usize;
    if offset < minimum_offset || !offset.is_multiple_of(8) {
        return false;
    }
    let mut selected = false;
    for _ in 0..count {
        let Some(context) = smb.get(offset..).filter(|bytes| bytes.len() >= 8) else {
            return false;
        };
        let kind = u16::from_le_bytes([context[0], context[1]]);
        let length = usize::from(u16::from_le_bytes([context[2], context[3]]));
        let Some(data) = context.get(8..8 + length) else {
            return false;
        };
        if kind == 1 {
            if selected || data.len() < 6 || data[..2] != [1, 0] || data[4..6] != [1, 0] {
                return false;
            }
            let salt_length = usize::from(u16::from_le_bytes([data[2], data[3]]));
            if 6 + salt_length != data.len() {
                return false;
            }
            selected = true;
        }
        offset += (8 + length).next_multiple_of(8);
    }
    selected
}

fn smb_dialect_name(dialect: u16) -> &'static str {
    match dialect {
        0x0202 => "2.0.2",
        0x0210 => "2.1",
        0x0300 => "3.0",
        0x0302 => "3.0.2",
        0x0311 => "3.1.1",
        _ => "unknown",
    }
}

fn smb_security_mode_label(security_mode: u16) -> &'static str {
    match security_mode & 0x0003 {
        0x0000 => "disabled",
        0x0001 => "enabled",
        0x0002 => "required",
        0x0003 => "enabled+required",
        _ => "unknown",
    }
}

fn parse_oracle_banner(raw: &[u8]) -> Option<String> {
    if raw.len() < 8 {
        return None;
    }
    let packet_length = u16::from_be_bytes([raw[0], raw[1]]);
    let packet_type = raw[4];
    let packet_type_label = match packet_type {
        2 => "accept",
        4 => "refuse",
        5 => "redirect",
        6 => "data",
        11 => "resend",
        _ => "unknown",
    };

    Some(format!(
        "Oracle TNS packet_type={packet_type_label} packet_length={packet_length}"
    ))
}

fn parse_rdp_banner(raw: &[u8]) -> Option<String> {
    if raw.len() < 11 || raw[0] != 0x03 || raw[1] != 0x00 {
        return None;
    }

    let tpkt_len = u16::from_be_bytes([raw[2], raw[3]]);
    let x224_type = raw.get(5).copied()?;
    let x224_label = match x224_type {
        0xd0 => "confirm",
        0xe0 => "request",
        _ => "response",
    };

    if raw.len() >= 19 && raw[11] == 0x02 {
        let selected_protocol = u32::from_le_bytes([raw[15], raw[16], raw[17], raw[18]]);
        return Some(format!(
            "RDP X.224 {x224_label} tpkt_len={tpkt_len} selected_protocol={}",
            rdp_protocol_name(selected_protocol)
        ));
    }

    if raw.len() >= 19 && raw[11] == 0x03 {
        let failure_code = u32::from_le_bytes([raw[15], raw[16], raw[17], raw[18]]);
        return Some(format!(
            "RDP X.224 {x224_label} tpkt_len={tpkt_len} negotiation_failure={failure_code}"
        ));
    }

    Some(format!("RDP X.224 {x224_label} tpkt_len={tpkt_len}"))
}

fn rdp_protocol_name(protocol: u32) -> &'static str {
    match protocol {
        0x0000_0000 => "rdp",
        0x0000_0001 => "ssl",
        0x0000_0002 => "hybrid",
        0x0000_0004 => "rdstls",
        0x0000_0008 => "hybrid-ex",
        _ => "unknown",
    }
}

fn dns_version_query_udp() -> [u8; 30] {
    let mut query = [
        0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'v', b'e', b'r', b's', b'i', b'o', b'n', 4,
        b'b', b'i', b'n', b'd', 0, 0, 0x10, 0, 3,
    ];
    query[..2].copy_from_slice(&rand::random::<u16>().to_be_bytes());
    query
}

fn dns_version_query_tcp() -> [u8; 32] {
    let mut query = [0_u8; 32];
    query[..2].copy_from_slice(&30_u16.to_be_bytes());
    query[2..].copy_from_slice(&dns_version_query_udp());
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn smtp_collects_complete_ehlo_and_preserves_the_greeting() {
        for (reply, expected) in [
            (
                "250-mail.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n",
                Some(true),
            ),
            ("250 STARTTLS\r\n", Some(false)),
            ("250-mail.test\r\n250-STARTTLS\r\n", None),
            ("250-mail.test\r\n550 STARTTLS\r\n", None),
            ("250-mail.test\r\n250 STARTTLS-OTHER\r\n", Some(false)),
        ] {
            let (client, mut peer) = tokio::io::duplex(128);
            let server = tokio::spawn(async move {
                peer.write_all(b"220 mail.test ESMTP Postfix 3.2.2\r\n")
                    .await
                    .unwrap();
                let mut command = [0; 11];
                peer.read_exact(&mut command).await.unwrap();
                assert_eq!(&command, b"EHLO test\r\n");
                for chunk in reply.as_bytes().chunks(3) {
                    peer.write_all(chunk).await.unwrap();
                }
            });
            let (banner, advertised) =
                smtp_exchange(client, b"EHLO test\r\n", Duration::from_secs(1))
                    .await
                    .unwrap();
            assert!(banner.starts_with("220 mail.test ESMTP Postfix 3.2.2\r\n"));
            assert_eq!(advertised, expected);
            server.await.unwrap();
        }
    }

    #[test]
    fn selects_matching_builtin_probe() {
        let probes = select_builtin_probes(443, Transport::Tcp, &[]);
        let ids: Vec<&str> = probes.iter().map(|probe| probe.id()).collect();
        assert!(ids.contains(&"tls"));
    }

    #[test]
    fn selects_udp_probe() {
        let probes = select_builtin_probes(53, Transport::Udp, &[]);
        let ids: Vec<&str> = probes.iter().map(|probe| probe.id()).collect();
        assert!(ids.contains(&"dns-udp"));
    }

    #[test]
    fn selects_quic_probe() {
        let probes = select_builtin_probes(443, Transport::Quic, &[]);
        let ids: Vec<&str> = probes.iter().map(|probe| probe.id()).collect();
        assert!(ids.contains(&"quic"));
    }

    #[test]
    fn normalizes_banner() {
        let banner = normalize_banner("hello\r\nworld".to_string());
        assert_eq!(banner.normalized, "hello\\r\\nworld");
    }

    #[test]
    fn parses_tds_prelogin_response() {
        let raw = [
            0x04, 0x01, 0x00, 0x30, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06, 0x01,
            0x00, 0x1b, 0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x06, 0x04, 0x00, 0x22, 0x00, 0x01,
            0xff, 0x0f, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x03, b'M', b'S', b'S', b'Q', b'L', 0x00,
            0x00, 0x01,
        ];
        let parsed = parse_tds_prelogin_response(&raw).expect("parsed");
        assert_eq!(parsed.version.as_deref(), Some("15.160.0"));
        assert_eq!(parsed.encryption.as_deref(), Some("encrypt-required"));
        assert_eq!(parsed.instance.as_deref(), Some("MSSQL"));
        assert!(!parsed.framed);
        let mut complete = raw;
        complete[3] = complete.len() as u8;
        assert!(parse_tds_prelogin_response(&complete).unwrap().framed);
        complete[0] = 0x12;
        assert!(!parse_tds_prelogin_response(&complete).unwrap().framed);
    }

    #[test]
    fn parses_tds_prelogin_version_layout_from_wireshark_example() {
        let raw = [
            0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x06, 0x01,
            0x00, 0x20, 0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04,
            0x04, 0x00, 0x26, 0x00, 0x01, 0xff, 0x10, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = parse_tds_prelogin_response(&raw).expect("parsed");
        assert_eq!(parsed.version.as_deref(), Some("16.0.1000"));
        assert_eq!(parsed.encryption.as_deref(), Some("encrypt-on"));
        assert_eq!(parsed.mars.as_deref(), Some("off"));
    }

    #[test]
    fn smb_negotiation_uses_header_relative_offsets_and_checks_framing() {
        let request = smb_negotiate_request();
        assert_eq!(
            u32::from_be_bytes(request[..4].try_into().unwrap()) as usize,
            request.len() - 4
        );
        let smb = &request[4..];
        assert_eq!(&smb[100..110], &[2, 2, 16, 2, 0, 3, 2, 3, 17, 3]);
        let context = u32::from_le_bytes(smb[92..96].try_into().unwrap()) as usize;
        assert_eq!(context % 8, 0);
        assert_eq!(&smb[context..context + 4], &[1, 0, 38, 0]);
        let mut frame = vec![0; 132];
        frame[3] = 128;
        let smb = &mut frame[4..];
        smb[..4].copy_from_slice(b"\xfeSMB");
        smb[4] = 64;
        smb[16] = 1;
        smb[64] = 65;
        smb[66] = 3;
        smb[68..70].copy_from_slice(&0x0302u16.to_le_bytes());
        // These GUID bytes were previously mistaken for the signing mode and dialect.
        smb[72..74].copy_from_slice(&0x0202u16.to_le_bytes());
        assert_eq!(smb_negotiation(&frame), Some(("3.0.2", "enabled+required")));
        for (offset, value) in [
            (3, 127),
            (4 + 8, 1),
            (4 + 12, 1),
            (4 + 16, 0),
            (4 + 24, 1),
            (4 + 64, 64),
            (4 + 122, 8),
        ] {
            let mut invalid = frame.clone();
            invalid[offset] = value;
            assert!(smb_negotiation(&invalid).is_none());
        }
        assert!(smb_negotiation(&frame[..80]).is_none());
        frame[4 + 68..4 + 70].copy_from_slice(&0x0311u16.to_le_bytes());
        assert!(smb_negotiation(&frame).is_none());
        frame[4 + 70] = 1;
        frame[4 + 124] = 128;
        frame.extend_from_slice(&[1, 0, 6, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0]);
        frame[3] = 142;
        assert_eq!(smb_negotiation(&frame), Some(("3.1.1", "enabled+required")));
        for (offset, value) in [(70, 2), (124, 127), (130, 7), (138, 1), (140, 2)] {
            let mut invalid = frame.clone();
            invalid[4 + offset] = value;
            assert!(smb_negotiation(&invalid).is_none());
        }
    }

    #[test]
    fn parses_rdp_negotiation_banner() {
        let raw = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08,
            0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        let banner = parse_rdp_banner(&raw).expect("banner");
        assert!(banner.contains("selected_protocol=hybrid"));
    }
    #[test]
    fn parses_rdp_failure_code_in_wire_byte_order() {
        let raw = [3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 0, 0, 3, 0, 8, 0, 5, 0, 0, 0];
        assert!(
            parse_rdp_banner(&raw)
                .unwrap()
                .contains("negotiation_failure=5")
        );
    }

    #[tokio::test]
    async fn tls_observation_survives_a_silent_application() {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![key.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _tls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
                .accept(stream)
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let _guard = AbortOnDrop(task);
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let budget = Duration::from_secs(2);
        let observation = timeout(
            budget,
            TlsProbe.execute(
                ProbeConnection::Tcp(stream),
                ProbeContext {
                    host: "localhost",
                    port: address.port(),
                    timeout: budget,
                    http_body_preview_bytes: 4096,
                },
            ),
        )
        .await
        .expect("probe must retain evidence within its budget")
        .unwrap();
        assert!(observation.tls.is_some());
        assert_eq!(observation.service_hint.unwrap().name, "tls");
    }

    #[test]
    fn explicitly_selected_probe_supports_nonstandard_ports() {
        let probes = select_builtin_probes(2222, Transport::Tcp, &["ssh".into()]);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].id(), "ssh");
        assert_eq!(http_authority("::1", 8080), "[::1]:8080");
    }

    #[test]
    fn malformed_reply_headers_cannot_establish_http_identity() {
        for reply in [
            "HTTP/1.1 200 OK\r\nmissing-colon\r\n\r\n",
            "HTTP/1.1 200 OK\r\n invalid continuation\r\n\r\n",
            "HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n",
            "HTTP/1.1 200 OK\r\nServer: name\0value\r\n\r\n",
            "HTTP/1.1 200 OK\nServer: name\r\n\r\n",
        ] {
            assert!(!valid_http1_head(reply), "{reply:?}");
        }
        assert!(valid_http1_head(
            "HTTP/1.1 404 Not Found\r\nServer: example\r\n\r\n"
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn http_drip_feed_cannot_extend_deadline() {
        let (client, mut server) = tokio::io::duplex(65536);
        let sender = tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\nX-Drip: ")
                .await
                .unwrap();
            loop {
                if server.write_all(b"H").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let started = Instant::now();
        assert!(
            read_http_response_stream(client, b"", Duration::from_millis(100), 256)
                .await
                .is_err()
        );
        assert_eq!(started.elapsed(), Duration::from_millis(100));
        sender.abort();
    }

    #[tokio::test]
    async fn http_body_preview_can_exceed_eight_kilobytes() {
        let (client, mut server) = tokio::io::duplex(65536);
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n")
            .await
            .unwrap();
        server.write_all(&vec![b'x'; 20000]).await.unwrap();
        let response = read_http_response_stream(client, b"", Duration::from_secs(1), 16000)
            .await
            .unwrap();
        assert_eq!(response.body_preview.unwrap().len(), 16000);
    }

    #[tokio::test(start_paused = true)]
    async fn http_content_length_avoids_waiting_for_keep_alive_eof() {
        let (client, mut server) = tokio::io::duplex(1024);
        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        let started = Instant::now();
        let response = read_http_response_stream(client, b"", Duration::from_secs(1), 4096)
            .await
            .unwrap();
        assert_eq!(response.body_preview.as_deref(), Some("ok"));
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test]
    async fn http_body_limit_counts_bytes() {
        let (client, mut server) = tokio::io::duplex(1024);
        server
            .write_all("HTTP/1.1 200 OK\r\n\r\néééé".as_bytes())
            .await
            .unwrap();
        let response = read_http_response_stream(client, b"", Duration::from_secs(1), 4)
            .await
            .unwrap();
        assert_eq!(response.body_preview.as_deref(), Some("éé"));
    }

    #[tokio::test]
    async fn dropping_driver_guard_cancels_task() {
        let handle = tokio::spawn(std::future::pending());
        let abort = handle.abort_handle();
        drop(AbortOnDrop(handle));
        tokio::task::yield_now().await;
        assert!(abort.is_finished());
    }
}

#[cfg(test)]
mod greeting_tests {
    use super::*;

    #[test]
    fn generator_evidence_requires_a_typed_html_response() {
        for (media, expected) in [("text/plain", false), ("text/html; charset=utf-8", true)] {
            let response = HttpResponsePreview {
                header_text: format!("HTTP/1.1 200 OK\r\nContent-Type: {media}\r\n\r\n"),
                body_preview: Some(
                    "<head><meta content='WordPress 6.1.1' name=generator></head>".into(),
                ),
            };
            let fields = extract_http_evidence(&response);
            assert_eq!(
                fields
                    .iter()
                    .any(|e| e.key == "generator" && e.value == "WordPress 6.1.1"),
                expected
            );
            assert_eq!(
                fields.iter().any(|e| e.key == "generator_validated"),
                expected
            );
        }
    }

    #[tokio::test]
    async fn fragmented_mysql_frame_requires_complete_payload_and_filler() {
        let mut payload = vec![10];
        payload.extend_from_slice(b"11.4.1-MariaDB\0");
        payload.extend_from_slice(&[0; 15]);
        let mut packet = vec![payload.len() as u8, 0, 0, 0];
        packet.extend(payload);
        for length in 0..packet.len() {
            assert!(mysql_handshake_version(&packet[..length]).is_none());
        }
        let (client, mut server) = tokio::io::duplex(2);
        let write = tokio::spawn({
            let packet = packet.clone();
            async move {
                server.write_all(&packet).await.unwrap();
            }
        });
        let greeting = read_mysql_greeting(client, Duration::from_secs(1))
            .await
            .unwrap();
        write.await.unwrap();
        assert_eq!(mysql_handshake_version(&greeting), Some("11.4.1-MariaDB"));
        let filler = packet.len() - 3;
        packet[filler] = 1;
        assert!(mysql_handshake_version(&packet).is_none());
    }
}
