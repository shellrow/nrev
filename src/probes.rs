use std::{collections::BTreeSet, sync::OnceLock, time::Duration};

use async_trait::async_trait;
use bytes::Buf;
use futures::future::poll_fn;
use h3::client;
use http::{Method, Request};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use crate::{
    error::{NrevError, Result},
    model::{Banner, Confidence, Evidence, ProbeObservation, ServiceHint, Transport},
    tls::handshake_tls,
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
                && probe.matches(port)
                && (enabled_set.is_empty() || enabled_set.contains(probe.id()))
        })
        .collect()
}

fn builtin_probes() -> Vec<Box<dyn Probe>> {
    vec![
        Box::new(TlsProbe),
        Box::new(HttpProbe),
        Box::new(SshProbe),
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
        let (tls, tls_stream) = handshake_tls(stream, Some(context.host), context.timeout).await?;
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: nrev\r\nAccept: */*\r\nRange: bytes=0-4095\r\nConnection: close\r\n\r\n",
            context.host
        );

        let mut evidence = vec![Evidence {
            key: "default_port".to_string(),
            value: context.port.to_string(),
        }];
        let mut banner = None;
        let mut service_name = "tls".to_string();
        let mut tags = vec!["encryption".to_string()];

        if let Ok(response) = read_http_response_stream(
            tls_stream,
            request.as_bytes(),
            context.timeout,
            context.http_body_preview_bytes,
        )
        .await
        {
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
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: nrev\r\nAccept: */*\r\nRange: bytes=0-255\r\nConnection: close\r\n\r\n",
            context.host
        );
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
        let raw = exchange_string(connection, &[], context.timeout).await?;
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
                value: raw.lines().next().unwrap_or_default().to_string(),
            }],
            confidence: Confidence::High,
        })
    }
}

struct LineProbe {
    id: &'static str,
    ports: &'static [u16],
    command: Option<&'static str>,
}

impl LineProbe {
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
        let raw = exchange_string(connection, payload, context.timeout).await?;
        Ok(ProbeObservation {
            probe_id: self.id().to_string(),
            service_hint: Some(ServiceHint {
                name: self.id().to_string(),
                confidence: Confidence::Medium,
            }),
            banner: (!raw.is_empty()).then(|| normalize_banner(raw.clone())),
            tls: None,
            tags: vec!["line-protocol".to_string()],
            evidence: vec![Evidence {
                key: "greeting".to_string(),
                value: raw.lines().next().unwrap_or_default().to_string(),
            }],
            confidence: Confidence::Medium,
        })
    }
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
        let raw = exchange_bytes(connection, &dns_version_query_tcp(), context.timeout).await?;
        Ok(binary_observation(
            self.id(),
            "dns",
            raw,
            vec!["infrastructure".to_string()],
        ))
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
        let raw = exchange_bytes(connection, &dns_version_query_udp(), context.timeout).await?;
        Ok(binary_observation(
            self.id(),
            "dns",
            raw,
            vec!["infrastructure".to_string()],
        ))
    }
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
        let request = [
            0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let raw = exchange_bytes(connection, &request, context.timeout).await?;
        Ok(binary_observation(
            self.id(),
            "ntp",
            raw,
            vec!["infrastructure".to_string()],
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
        let raw = exchange_string(connection, &[], context.timeout).await?;
        Ok(simple_observation(
            "mysql",
            raw,
            vec!["database".to_string()],
        ))
    }
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
        let negotiate = [
            0x00, 0x00, 0x00, 0x54, 0xfe, b'S', b'M', b'B', 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00,
            0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x00, 0x9f, 0xe3, 0x51, 0xb3,
            0x44, 0xc7, 0x41, 0x4a, 0x9f, 0x4f, 0x9d, 0x84, 0xca, 0x72, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x02, 0x10, 0x02, 0x22, 0x02, 0x24, 0x02, 0x00, 0x03, 0x02, 0x03, 0x10, 0x03,
            0x11, 0x03,
        ];
        let raw = exchange_bytes(connection, &negotiate, context.timeout).await?;
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
        let raw = exchange_bytes(connection, &request, context.timeout).await?;
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
            && let Ok(response) = read_http3_response(
                connection,
                context.host,
                context.timeout,
                context.http_body_preview_bytes,
            )
            .await
        {
            banner = Some(normalize_banner(response.header_text.clone()));
            evidence.extend(extract_http_evidence(&response));
            service_hint = ServiceHint {
                name: "http3".to_string(),
                confidence: Confidence::High,
            };
            tags.push("web".to_string());
        }

        endpoint.wait_idle().await;

        Ok(ProbeObservation {
            probe_id: self.id().to_string(),
            service_hint: Some(service_hint),
            banner,
            tls: Some(tls),
            tags,
            evidence,
            confidence: Confidence::High,
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

fn smb_observation(raw: Vec<u8>) -> ProbeObservation {
    let banner_text =
        parse_smb_banner(&raw).unwrap_or_else(|| format!("SMB response {} bytes", raw.len()));
    ProbeObservation {
        probe_id: "smb".to_string(),
        service_hint: Some(ServiceHint {
            name: "smb".to_string(),
            confidence: Confidence::High,
        }),
        banner: Some(normalize_banner(banner_text)),
        tls: None,
        tags: vec!["file-sharing".to_string(), "enterprise".to_string()],
        evidence: vec![Evidence {
            key: "response_bytes".to_string(),
            value: format!("{} bytes", raw.len()),
        }],
        confidence: Confidence::Medium,
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
    ProbeObservation {
        probe_id: "rdp".to_string(),
        service_hint: Some(ServiceHint {
            name: "rdp".to_string(),
            confidence: Confidence::High,
        }),
        banner: Some(normalize_banner(banner_text)),
        tls: None,
        tags: vec!["remote-access".to_string(), "enterprise".to_string()],
        evidence: vec![Evidence {
            key: "response_bytes".to_string(),
            value: format!("{} bytes", raw.len()),
        }],
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

    Some(TdsPreloginResponse {
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

async fn read_http3_response(
    connection: quinn::Connection,
    host: &str,
    timeout_window: Duration,
    body_limit: usize,
) -> Result<HttpResponsePreview> {
    let h3_connection = h3_quinn::Connection::new(connection);
    let (mut driver, mut send_request) = client::new(h3_connection)
        .await
        .map_err(|error| NrevError::Tls(error.to_string()))?;
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{host}/"))
        .header("Host", host)
        .header("User-Agent", "nrev")
        .body(())
        .map_err(|error| NrevError::Tls(error.to_string()))?;

    let mut stream = timeout(timeout_window, send_request.send_request(request))
        .await
        .map_err(|_| NrevError::Tls("HTTP/3 request timed out".to_string()))?
        .map_err(|error| NrevError::Tls(error.to_string()))?;
    timeout(timeout_window, stream.finish())
        .await
        .map_err(|_| NrevError::Tls("HTTP/3 stream finish timed out".to_string()))?
        .map_err(|error| NrevError::Tls(error.to_string()))?;

    let response = timeout(timeout_window, stream.recv_response())
        .await
        .map_err(|_| NrevError::Tls("HTTP/3 response timed out".to_string()))?
        .map_err(|error| NrevError::Tls(error.to_string()))?;

    let header_text = format_http_headers(response.status().as_u16(), response.headers());
    let mut body = String::new();
    while body.len() < body_limit {
        let Some(chunk) = timeout(timeout_window, stream.recv_data())
            .await
            .map_err(|_| NrevError::Tls("HTTP/3 body read timed out".to_string()))?
            .map_err(|error| NrevError::Tls(error.to_string()))?
        else {
            break;
        };
        let remaining = body_limit.saturating_sub(body.len());
        let slice = chunk.chunk();
        body.push_str(&String::from_utf8_lossy(
            &slice[..slice.len().min(remaining)],
        ));
    }

    driver_task.abort();

    Ok(HttpResponsePreview {
        header_text,
        body_preview: (!body.is_empty()).then_some(body),
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
    timeout(timeout_window, stream.write_all(payload))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))??;

    let mut buf = Vec::new();
    let mut chunk = vec![0_u8; 1024];
    let mut header_end = None;
    loop {
        let size = timeout(timeout_window, stream.read(&mut chunk))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))??;
        if size == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..size]);

        if header_end.is_none() {
            header_end = find_http_header_end(&buf);
        }

        if let Some(end) = header_end
            && buf.len().saturating_sub(end) >= body_limit
        {
            break;
        }

        if buf.len() >= 8192 {
            break;
        }
    }

    let header_end = header_end.unwrap_or(buf.len());
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let body_preview = if header_end < buf.len() {
        Some(
            String::from_utf8_lossy(&buf[header_end..])
                .chars()
                .take(body_limit)
                .collect::<String>(),
        )
    } else {
        None
    };

    Ok(HttpResponsePreview {
        header_text,
        body_preview,
    })
}

fn format_http_headers(headers_status: u16, headers: &http::HeaderMap) -> String {
    let mut lines = vec![format!("HTTP/3 {headers_status}")];
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
        if let Some(generator) = extract_meta_content(body_preview, "generator") {
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

fn extract_header_values(headers: &str, name: &str) -> Vec<String> {
    headers
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.trim().eq_ignore_ascii_case(name) {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .collect()
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

fn parse_smb_banner(raw: &[u8]) -> Option<String> {
    if raw.len() < 74 {
        return None;
    }
    let offset = if raw.starts_with(&[0x00, 0x00]) || raw[0] == 0x00 {
        4
    } else {
        0
    };
    if raw.get(offset..offset + 4)? != b"\xfeSMB" {
        return None;
    }
    let security_mode = u16::from_le_bytes([*raw.get(offset + 70)?, *raw.get(offset + 71)?]);
    let dialect = u16::from_le_bytes([*raw.get(offset + 72)?, *raw.get(offset + 73)?]);
    Some(format!(
        "SMB2 negotiate dialect={} signing={}",
        smb_dialect_name(dialect),
        smb_security_mode_label(security_mode)
    ))
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
        let selected_protocol = u32::from_be_bytes([raw[15], raw[16], raw[17], raw[18]]);
        return Some(format!(
            "RDP X.224 {x224_label} tpkt_len={tpkt_len} selected_protocol={}",
            rdp_protocol_name(selected_protocol)
        ));
    }

    if raw.len() >= 19 && raw[11] == 0x03 {
        let failure_code = u32::from_be_bytes([raw[15], raw[16], raw[17], raw[18]]);
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

fn dns_version_query_udp() -> [u8; 31] {
    [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'v', b'e',
        b'r', b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd', 0x00, 0x00, 0x10, 0x00, 0x03,
        0x00,
    ]
}

fn dns_version_query_tcp() -> [u8; 33] {
    [
        0x00, 0x1f, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        b'v', b'e', b'r', b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n', b'd', 0x00, 0x00, 0x10,
        0x00, 0x03, 0x00,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn parses_rdp_negotiation_banner() {
        let raw = [
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let banner = parse_rdp_banner(&raw).expect("banner");
        assert!(banner.contains("selected_protocol=hybrid"));
    }
}
