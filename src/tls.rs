use std::{sync::Arc, time::Duration};

use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use x509_parser::parse_x509_certificate;

use crate::{
    error::{NrevError, Result},
    model::TlsObservation,
};

pub async fn observe_tls(
    stream: TcpStream,
    server_name: Option<&str>,
    timeout_window: Duration,
) -> Result<TlsObservation> {
    let (tls, _) = handshake_tls(stream, server_name, timeout_window).await?;
    Ok(tls)
}

pub async fn handshake_tls(
    stream: TcpStream,
    server_name: Option<&str>,
    timeout_window: Duration,
) -> Result<(TlsObservation, TlsStream<TcpStream>)> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in
        rustls_native_certs::load_native_certs().map_err(|err| NrevError::Tls(err.to_string()))?
    {
        let _ = roots.add(cert);
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let name = server_name
        .filter(|value| !value.is_empty())
        .unwrap_or("localhost");
    let server_name = rustls_pki_types::ServerName::try_from(name.to_string())
        .map_err(|err| NrevError::Tls(err.to_string()))?;

    let stream = timeout(timeout_window, connector.connect(server_name, stream))
        .await
        .map_err(|_| NrevError::Tls("TLS handshake timed out".to_string()))?
        .map_err(|err| NrevError::Tls(err.to_string()))?;

    let (_, session) = stream.get_ref();
    let certificates = session
        .peer_certificates()
        .map(|certs| certs.to_vec())
        .unwrap_or_default();

    let mut subjects = Vec::new();
    let mut issuers = Vec::new();
    for certificate in certificates {
        if let Ok((_, parsed)) = parse_x509_certificate(certificate.as_ref()) {
            subjects.push(parsed.subject().to_string());
            issuers.push(parsed.issuer().to_string());
        }
    }

    let observation = TlsObservation {
        negotiated_protocol: session
            .alpn_protocol()
            .map(|alpn| String::from_utf8_lossy(alpn).to_string()),
        cipher_suite: session
            .negotiated_cipher_suite()
            .map(|suite| format!("{:?}", suite.suite())),
        server_name: Some(name.to_string()),
        certificate_subjects: subjects,
        certificate_issuers: issuers,
    };

    Ok((observation, stream))
}
