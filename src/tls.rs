use std::{sync::Arc, time::Duration};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use x509_parser::parse_x509_certificate;

use crate::{
    error::{NrevError, Result},
    model::{TlsCertificateValidation, TlsObservation},
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
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(ObservationCertificateVerifier::new());
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
        certificate_validation: TlsCertificateValidation::NotPerformed,
    };

    Ok((observation, stream))
}

#[derive(Debug)]
struct ObservationCertificateVerifier(Arc<rustls::crypto::CryptoProvider>);

impl ObservationCertificateVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for ObservationCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
