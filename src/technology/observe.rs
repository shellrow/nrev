//! Project selected protocol fields from a single recorded exchange.
use crate::model::{ProbeObservation, Transport};

use super::{Field, MAX_FIELD};

pub(super) struct Signals<'a> {
    pub server_comment: bool,
    pub platform: Option<(Field, &'static str, &'a str)>,
    pub declarations: Vec<(Field, &'static str, &'a str)>,
    pub facts: Vec<(&'static str, &'static str, &'a str)>,
}

fn unique_text<'a>(obs: &'a ProbeObservation, key: &str) -> Option<&'a str> {
    let mut values = obs.evidence.iter().filter(|e| e.key == key);
    let value = &values.next()?.value;
    (values.next().is_none() && value.len() <= MAX_FIELD && !value.chars().any(char::is_control))
        .then_some(value)
}

fn unique<'a>(obs: &'a ProbeObservation, key: &str) -> Option<&'a str> {
    unique_text(obs, key).filter(|value| value.is_ascii())
}

fn http_status<'a>(line: &'a str, probe: &str, alpn: Option<&str>) -> Option<&'a str> {
    let (proto, code) = crate::probes::http_status_parts(line)?;
    let valid_protocol = match probe {
        "quic" => proto == "HTTP/3",
        "tls" if alpn == Some("h2") => proto == "HTTP/2",
        _ => matches!(proto, "HTTP/1.0" | "HTTP/1.1"),
    };
    valid_protocol.then_some(code)
}

/// Parse the complete RFC 9110 product list before accepting any member.
fn server_products(mut value: &str) -> Option<(Vec<&str>, bool)> {
    fn token(s: &str) -> bool {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    }
    let mut products = Vec::new();
    let mut has_comment = false;
    while !value.is_empty() {
        if value.starts_with('(') {
            if products.is_empty() {
                return None;
            }
            let mut depth = 0;
            let mut escape = false;
            let end = value.bytes().position(|b| {
                if escape {
                    escape = false;
                } else if b == b'\\' {
                    escape = true;
                } else if b == b'(' {
                    depth += 1;
                } else if b == b')' {
                    depth -= 1;
                }
                depth == 0
            })?;
            value = &value[end + 1..];
            has_comment = true;
        } else {
            let end = value.find(' ').unwrap_or(value.len());
            let item = &value[..end];
            let (name, version) = item
                .split_once('/')
                .map_or((item, None), |(n, v)| (n, Some(v)));
            if !token(name) || !version.is_none_or(token) || products.len() == 16 {
                return None;
            }
            products.push(item);
            value = &value[end..];
        }
        if !value.is_empty() && !value.starts_with(' ') {
            return None;
        }
        value = value.trim_start_matches(' ');
    }
    Some((products, has_comment))
}

/// Interpret application declarations already present in a complete HTTP head.
/// Keep the original banner as the evidence reference, including during replay.
fn product_headers<'a>(obs: &'a ProbeObservation, status: &str, signals: &mut Signals<'a>) {
    let Some(head) = obs
        .banner
        .as_ref()
        .map(|b| b.raw.as_str())
        .filter(|raw| raw.len() <= 65536)
        .and_then(|raw| raw.strip_suffix("\r\n\r\n"))
    else {
        return;
    };
    let mut lines = head.split("\r\n");
    if lines.next() != Some(status) {
        return;
    }
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return;
        };
        if http::HeaderName::from_bytes(name.as_bytes()).is_err()
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return;
        }
        if name.starts_with(['X', 'x', 'D', 'd']) {
            headers.push((name, value.trim_matches([' ', '\t'])));
        }
    }
    let single = |name: &str| {
        let mut found = headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name));
        let (_, value) = found.next()?;
        (found.next().is_none()
            && !value.is_empty()
            && value.len() <= MAX_FIELD
            && value.is_ascii())
        .then_some(*value)
    };
    for (name, field) in [
        ("x-jenkins", Field::JenkinsVersion),
        ("x-influxdb-version", Field::InfluxdbVersion),
        ("x-elastic-product", Field::ElasticProduct),
        (
            "x-github-enterprise-version",
            Field::GithubEnterpriseVersion,
        ),
        ("x-generator", Field::GeneratorHeader),
    ] {
        if let Some(value) = single(name) {
            signals.declarations.push((field, "banner.raw", value));
        }
    }
    for (index, leader, field) in [
        (
            "x-consul-index",
            "x-consul-knownleader",
            Field::ConsulLeader,
        ),
        ("x-nomad-index", "x-nomad-knownleader", Field::NomadLeader),
    ] {
        if single(index)
            .is_some_and(|v| v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<u64>().is_ok())
            && let Some(value @ ("true" | "false")) = single(leader)
        {
            signals.declarations.push((field, "banner.raw", value));
        }
    }
    let uid = |name| {
        single(name).filter(|v| {
            v.len() == 36
                && *v != "00000000-0000-0000-0000-000000000000"
                && v.bytes().enumerate().all(|(i, b)| match i {
                    8 | 13 | 18 | 23 => b == b'-',
                    _ => b.is_ascii_hexdigit(),
                })
        })
    };
    if let (Some(flow), Some(priority)) = (
        uid("x-kubernetes-pf-flowschema-uid"),
        uid("x-kubernetes-pf-prioritylevel-uid"),
    ) && !flow.eq_ignore_ascii_case(priority)
    {
        signals
            .declarations
            .push((Field::KubernetesFlowControl, "banner.raw", "paired_uids"));
    }
    if let Some(version @ "registry/2.0") = single("docker-distribution-api-version") {
        signals.facts.push(("registry.api", "banner.raw", version));
    }
}

pub(super) fn signals(obs: &ProbeObservation, transport: Transport) -> Signals<'_> {
    let mut s = Signals {
        server_comment: false,
        platform: None,
        declarations: Vec::new(),
        facts: Vec::new(),
    };
    let tcp = matches!(transport, Transport::Tcp | Transport::Syn);
    let greeting = matches!(
        obs.probe_id.as_str(),
        "smtp" | "ftp" | "imap" | "pop3" | "greeting"
    )
    .then(|| unique(obs, "greeting"))
    .flatten()
    .filter(|value| {
        obs.banner
            .as_ref()
            .and_then(|b| b.raw.split_once('\n'))
            .is_some_and(|(line, _)| line.strip_suffix('\r').unwrap_or(line) == *value)
    });
    let probe = match (obs.probe_id.as_str(), greeting) {
        ("greeting", Some(line)) if line.starts_with("SSH-") => "ssh",
        ("greeting", Some(line)) if line.starts_with("+OK ") => "pop3",
        ("greeting", Some(line)) if line.starts_with("* OK ") => "imap",
        (id, _) => id,
    };
    if obs.tags.iter().any(|t| t == "external") {
        return s;
    }
    let tls = obs.tls.as_ref().filter(|_| {
        (probe == "tls" && tcp)
            || (matches!(probe, "quic" | "quic-handshake") && transport == Transport::Quic)
    });
    if let Some(tls) = tls {
        if probe == "tls"
            && let Some(version @ ("1.2" | "1.3")) = unique(obs, "tls_version")
        {
            s.facts.push(("tls.version", "tls_version", version));
        }
        if let Some(alpn) = tls
            .negotiated_protocol
            .as_deref()
            .filter(|v| matches!(*v, "h3" | "h2" | "http/1.1"))
        {
            s.facts.push(("tls.alpn", "tls.negotiated_protocol", alpn));
        }
        if let Some(cipher) = tls.cipher_suite.as_deref().filter(|s| {
            s.starts_with("TLS")
                && s.len() <= 80
                && s.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        }) {
            s.facts
                .push(("tls.cipher_suite", "tls.cipher_suite", cipher));
        }
    }
    match probe {
        "http" | "tls" | "quic" if (probe == "http" && tcp) || tls.is_some() => {
            if let Some(status) = unique(obs, "status_line")
                && let Some(code) = http_status(
                    status,
                    probe,
                    tls.and_then(|t| t.negotiated_protocol.as_deref()),
                )
            {
                product_headers(obs, status, &mut s);
                s.facts.push(("http.status", "status_line", code));
                if let Some(title) =
                    unique_text(obs, "title").filter(|v| !v.is_empty() && v.len() <= 512)
                {
                    s.facts.push(("http.title", "title", title));
                }
                if unique(obs, "via").is_some_and(|v| !v.is_empty()) {
                    s.facts.push(("http.via_header", "via", "present"));
                }
                if tls.is_some() {
                    s.facts.push((
                        "http.carrier",
                        "status_line",
                        if probe == "quic" { "quic" } else { "tls" },
                    ));
                }
                let server = unique(obs, "server");
                if let Some(value) = server {
                    s.declarations.push((Field::ServerHeader, "server", value));
                }
                if let Some((products, has_comment)) = server.and_then(server_products) {
                    s.server_comment = has_comment;
                    if has_comment {
                        s.platform = server.map(|v| (Field::Server, "server", v));
                    }
                    for (i, token) in products.into_iter().enumerate() {
                        if token.len() <= 160 {
                            s.facts.push(("http.server_product", "server", token));
                        }
                        let field = if i == 0 {
                            Field::Server
                        } else {
                            Field::ServerComponent
                        };
                        s.declarations.push((field, "server", token));
                    }
                }
                for (key, field) in [
                    ("x-powered-by", Field::PoweredBy),
                    ("generator", Field::Generator),
                ] {
                    if field == Field::Generator
                        && unique(obs, "generator_validated") != Some("true")
                    {
                        continue;
                    }
                    if let Some(value) = unique(obs, key) {
                        s.declarations.push((field, key, value));
                    }
                }
            }
        }
        "ssh" if tcp => {
            // Older reports can contain a preamble in ident or a partial final line.
            if let Some(banner) = &obs.banner
                && let Some(line) = banner
                    .raw
                    .get(..banner.raw.len().min(4096))
                    .and_then(|s| s.split_inclusive('\n').find(|l| l.starts_with("SSH-")))
                && line.ends_with('\n')
                && line.len() <= 255
            {
                let value = line.trim_end_matches(['\r', '\n']);
                if value.bytes().all(|b| (32..=126).contains(&b))
                    && let Some((protocol, software)) =
                        value.strip_prefix("SSH-").and_then(|v| v.split_once('-'))
                    && matches!(protocol, "1.99" | "2.0" | "1.5")
                    && software
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_graphic)
                {
                    s.facts.push(("ssh.protocol", "banner.raw", protocol));
                    let token = software.split(' ').next().unwrap_or_default();
                    if token.len() <= 160 {
                        s.facts.push(("ssh.software", "banner.raw", token));
                    }
                    s.platform = Some((Field::SshIdent, "banner.raw", value));
                    s.declarations.push((Field::SshIdent, "banner.raw", value));
                }
            }
        }
        "smtp" | "ftp" | "greeting" if tcp => {
            if let Some(value) = greeting {
                if probe == "smtp"
                    && value.starts_with("220")
                    && unique(obs, "ehlo_reply") == Some("250")
                {
                    s.facts.push(("smtp.ehlo", "ehlo_reply", "accepted"));
                }
                if probe == "smtp"
                    && value.starts_with("220")
                    && unique(obs, "ehlo_starttls") == Some("advertised")
                {
                    s.facts
                        .push(("smtp.starttls", "ehlo_starttls", "advertised"));
                }
                // Both FTP and SMTP use 220. Only the protocol-specific selectors may resolve it.
                if probe != "ftp" {
                    s.declarations
                        .push((Field::SmtpGreeting, "greeting", value));
                }
                if probe != "smtp" {
                    s.declarations.push((Field::FtpGreeting, "greeting", value));
                }
            }
        }
        "imap" | "pop3" if tcp => {
            if let Some(value) = greeting {
                if probe == "imap" && value.starts_with("* OK ") {
                    s.facts.push(("imap.greeting", "greeting", "ok"));
                    s.declarations
                        .push((Field::ImapGreeting, "greeting", value));
                } else if probe == "pop3" && value.starts_with("+OK ") {
                    s.facts.push(("pop3.greeting", "greeting", "ok"));
                    s.declarations
                        .push((Field::Pop3Greeting, "greeting", value));
                }
            }
        }
        "smb" if tcp => {
            if let (
                Some(dialect @ ("2.0.2" | "2.1" | "3.0" | "3.0.2" | "3.1.1")),
                Some(signing @ ("disabled" | "enabled" | "required" | "enabled+required")),
            ) = (unique(obs, "smb_dialect"), unique(obs, "smb_signing"))
            {
                s.facts.push(("smb.dialect", "smb_dialect", dialect));
                s.facts.push(("smb.signing", "smb_signing", signing));
            }
        }
        "rdp" if tcp => {
            if let Some(protocol @ ("rdp" | "ssl" | "hybrid")) =
                unique(obs, "rdp_selected_protocol")
            {
                s.facts
                    .push(("rdp.security_protocol", "rdp_selected_protocol", protocol));
            }
        }
        "postgresql" if tcp => {
            let response = match unique(obs, "response_bytes") {
                Some("[83]") => Some("accepted"),
                Some("[78]") => Some("declined"),
                _ => None,
            };
            if let Some(value) = response {
                s.facts
                    .push(("postgresql.ssl_request", "response_bytes", value));
            }
        }
        "memcached" if tcp => {
            if let Some(version) = obs
                .banner
                .as_ref()
                .and_then(|b| b.raw.strip_suffix("\r\n"))
                .and_then(|s| s.strip_prefix("VERSION "))
                .filter(|v| super::valid_version(v))
            {
                s.facts.push(("memcached.version", "banner.raw", version));
            }
        }
        "redis" if tcp => {
            if obs.banner.as_ref().is_some_and(|b| b.raw == "+PONG\r\n") {
                s.facts.push(("resp.ping", "banner.raw", "pong"));
            }
        }
        "mysql" if tcp => {
            if let Some(v) = unique(obs, "handshake_version") {
                if super::valid_version(v) {
                    s.facts
                        .push(("mysql.server_version", "handshake_version", v));
                }
                s.declarations
                    .push((Field::MysqlVersion, "handshake_version", v));
            }
        }
        "dns-udp" | "dns-tcp" | "ntp"
            if ((probe == "dns-tcp" && tcp)
                || (probe != "dns-tcp" && transport == Transport::Udp))
                && unique(obs, "response_validated") == Some("true") =>
        {
            if probe != "ntp"
                && unique(obs, "dns_rcode") == Some("0")
                && unique(obs, "dns_answers") == Some("1")
                && let Some(text) = unique(obs, "dns_version_txt")
            {
                s.declarations
                    .push((Field::DnsVersion, "dns_version_txt", text));
            }
            let fields: &[(&str, &str, u16)] = if probe == "ntp" {
                &[
                    ("ntp_version", "ntp.version", 7),
                    ("ntp_stratum", "ntp.stratum", 255),
                ]
            } else {
                &[
                    ("dns_rcode", "dns.rcode", 15),
                    ("dns_answers", "dns.answers", 65535),
                ]
            };
            for &(key, name, max) in fields {
                if let Some(v) = unique(obs, key).filter(|v| {
                    !v.is_empty()
                        && v.bytes().all(|b| b.is_ascii_digit())
                        && v.parse::<u16>().is_ok_and(|n| n <= max)
                }) {
                    s.facts.push((name, key, v));
                }
            }
        }
        "mssql-prelogin" if tcp && unique(obs, "response_validated") == Some("true") => {
            if let Some(v) = unique(obs, "version").filter(|v| {
                let parts: Vec<_> = v.split('.').collect();
                matches!(parts.len(), 3 | 4)
                    && parts
                        .iter()
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                    && parts[..2].iter().all(|p| p.parse::<u8>().is_ok())
                    && parts[2..].iter().all(|p| p.parse::<u16>().is_ok())
            }) {
                s.facts.push(("tds.peer_version", "version", v));
            }
            if let Some(v) = unique(obs, "encryption").filter(|v| {
                matches!(
                    *v,
                    "encrypt-on" | "encrypt-off" | "encrypt-required" | "encrypt-not-supported"
                )
            }) {
                s.facts.push(("tds.encryption", "encryption", v));
            }
        }
        _ => {}
    }
    s
}
