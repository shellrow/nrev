use std::{sync::Arc, time::Duration};

use clap::Parser;
use nrev::{
    cli::{Cli, Command},
    config::ScanConfig,
    data::DataRegistry,
    model::{EndpointState, TlsCertificateValidation},
    scanner::Scanner,
    target::TargetResolver,
    transport::SocketConnector,
};

fn server(alpn: &[u8]) -> quinn::Endpoint {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap()
}

async fn scan(address: std::net::SocketAddr, probes: bool) -> nrev::model::ScanReport {
    let mut args = vec![
        "nrev".into(),
        "port".into(),
        address.to_string(),
        "--transport".into(),
        "quic".into(),
        "--connect-timeout-ms".into(),
        "2000".into(),
        "--probe-timeout-ms".into(),
        "500".into(),
    ];
    if probes {
        args.extend(["--probes".into(), "quic".into()]);
    } else {
        args.push("--no-builtin-probes".into());
    }
    let Command::Port(args) = Cli::parse_from(args).command else {
        panic!("port command")
    };
    let registry = DataRegistry::default();
    let config = ScanConfig::from_scan_args(&args, &registry).unwrap();
    let targets = TargetResolver::new(config.default_ports.clone())
        .resolve(&args.targets)
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        Scanner::new(config, registry, SocketConnector).scan(targets),
    )
    .await
    .unwrap()
    .unwrap()
    .report
}

#[tokio::test]
async fn native_http3_collects_metadata_without_external_identification() {
    let endpoint = server(b"h3");
    let address = endpoint.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let resolver = h3.accept().await.unwrap().unwrap();
        let (request, mut stream) = resolver.resolve_request().await.unwrap();
        assert_eq!(
            request.uri().authority().unwrap().as_str(),
            address.to_string()
        );
        stream
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header("server", "nrev-fixture")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream
            .send_data(bytes::Bytes::from_static(b"<title>Local HTTP3</title>"))
            .await
            .unwrap();
        stream.finish().await.unwrap();
        // Keep driving the server until the client closes its connection.
        let _ = h3.accept().await;
    });
    let report = scan(address, true).await;
    let result = &report.targets[0].endpoints[&address.port()];
    assert_eq!(result.state, EndpointState::Open);
    assert!(report.identification.is_none());
    assert!(result.errors.is_empty(), "{:?}", result.errors);
    assert!(result.observations.iter().any(|observation| {
        observation
            .evidence
            .iter()
            .any(|item| item.key == "title" && item.value == "Local HTTP3")
    }));
    let tls = result
        .observations
        .iter()
        .find_map(|observation| observation.tls.as_ref())
        .unwrap();
    assert_eq!(tls.negotiated_protocol.as_deref(), Some("h3"));
    assert_eq!(
        tls.certificate_validation,
        TlsCertificateValidation::NotPerformed
    );
    assert!(!tls.certificate_subjects.is_empty());
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stalled_http3_does_not_erase_the_observed_quic_handshake() {
    let endpoint = server(b"h3");
    let address = endpoint.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut h3 =
            h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let resolver = h3.accept().await.unwrap().unwrap();
        let _request = resolver.resolve_request().await.unwrap();
        std::future::pending::<()>().await;
    });
    let report = scan(address, true).await;
    let result = &report.targets[0].endpoints[&address.port()];
    assert_eq!(result.state, EndpointState::Open);
    assert!(result.fingerprint.as_ref().unwrap().handshake_observed);
    assert!(
        result.observations.iter().any(
            |observation| observation.probe_id == "quic-handshake" && observation.tls.is_some()
        )
    );
    assert!(
        result
            .errors
            .iter()
            .any(|error| error.contains("timed out"))
    );
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn rejected_alpn_is_a_response_not_a_completed_handshake() {
    let endpoint = server(b"fixture-protocol");
    let address = endpoint.local_addr().unwrap();
    let task = tokio::spawn(async move {
        assert!(endpoint.accept().await.unwrap().await.is_err());
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    let report = scan(address, false).await;
    let result = &report.targets[0].endpoints[&address.port()];
    assert_eq!(result.state, EndpointState::Open);
    assert!(!result.fingerprint.as_ref().unwrap().handshake_observed);
    assert!(
        result.observations[0]
            .evidence
            .iter()
            .any(|item| item.key == "open_signal")
    );
    assert!(
        result.observations[0]
            .tls
            .as_ref()
            .unwrap()
            .cipher_suite
            .is_none()
    );
    task.await.unwrap();
}
