use std::{sync::Arc, time::Duration};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
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
    handshake_tls_with_alpn(stream, server_name, timeout_window, &[]).await
}

pub(crate) async fn handshake_tls_with_alpn(
    stream: TcpStream,
    server_name: Option<&str>,
    timeout_window: Duration,
    protocols: &[&[u8]],
) -> Result<(TlsObservation, TlsStream<TcpStream>)> {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();
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
pub(crate) struct ObservationCertificateVerifier(Arc<rustls::crypto::CryptoProvider>);

impl ObservationCertificateVerifier {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

// webpki accepts v3 certificates. An observation can still authenticate the
// handshake signature with the public key from a complete v1 or v2 certificate.
fn legacy_public_key<'a>(
    cert: &'a CertificateDer<'_>,
    error: rustls::Error,
) -> std::result::Result<SubjectPublicKeyInfoDer<'a>, rustls::Error> {
    if let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(cause)) = &error
        && matches!(
            cause.0.downcast_ref::<webpki::Error>(),
            Some(webpki::Error::UnsupportedCertVersion)
        )
        && let Ok(([], parsed)) = parse_x509_certificate(cert.as_ref())
        && matches!(parsed.version().0, 0 | 1)
    {
        return Ok(SubjectPublicKeyInfoDer::from(
            parsed.tbs_certificate.subject_pki.raw,
        ));
    }
    Err(error)
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
        .or_else(|error| {
            let spki = legacy_public_key(cert, error)?;
            let key = webpki::RawPublicKeyEntity::try_from(&spki)
                .map_err(|_| rustls::CertificateError::BadEncoding)?;
            let (_, algorithms) = self
                .0
                .signature_verification_algorithms
                .mapping
                .iter()
                .find(|(scheme, _)| *scheme == signature.scheme)
                .ok_or(rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme)?;
            for algorithm in *algorithms {
                match key.verify_signature(*algorithm, message, signature.signature()) {
                    Ok(()) => return Ok(HandshakeSignatureValid::assertion()),
                    Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_)) => {
                        continue;
                    }
                    Err(webpki::Error::InvalidSignatureForPublicKey) => {
                        return Err(rustls::CertificateError::BadSignature.into());
                    }
                    Err(cause) => {
                        return Err(rustls::CertificateError::Other(rustls::OtherError(Arc::new(
                            cause,
                        )))
                        .into());
                    }
                }
            }
            Err(rustls::Error::General(format!(
                "certificate public key is incompatible with {:?}",
                signature.scheme
            )))
        })
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
        .or_else(|error| {
            let spki = legacy_public_key(cert, error)?;
            rustls::crypto::verify_tls13_signature_with_raw_key(
                message,
                &spki,
                signature,
                &self.0.signature_verification_algorithms,
            )
        })
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::SigningKey;
    use rustls::internal::msgs::codec::Codec;

    #[test]
    fn legacy_certificates_still_require_a_valid_handshake_signature() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::default()
            .self_signed(&key)
            .unwrap();
        // Only the handshake signature is under test. Change the explicitly
        // encoded certificate version while keeping the generated public key.
        let mut der = cert.der().to_vec();
        let version = der
            .windows(5)
            .position(|w| w == [0xa0, 3, 2, 1, 2])
            .unwrap();
        der[version + 4] = 1;
        let cert = CertificateDer::from(der);
        let message = b"handshake transcript";
        let signature = key.sign(message).unwrap();
        let mut encoded = Vec::new();
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256.encode(&mut encoded);
        (signature.len() as u16).encode(&mut encoded);
        encoded.extend(signature);
        let dss = rustls::DigitallySignedStruct::read_bytes(&encoded).unwrap();
        let verifier = ObservationCertificateVerifier::new();
        for tls13 in [false, true] {
            let verify = |msg: &[u8]| {
                if tls13 {
                    verifier.verify_tls13_signature(msg, &cert, &dss)
                } else {
                    verifier.verify_tls12_signature(msg, &cert, &dss)
                }
            };
            verify(message).unwrap();
            assert!(matches!(
                verify(b"changed transcript"),
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadSignature
                ))
            ));
        }
    }
}
