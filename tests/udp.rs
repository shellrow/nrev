use std::time::Duration;

use clap::Parser;
use nrev::{
    cli::{Cli, Command},
    config::ScanConfig,
    data::DataRegistry,
    model::EndpointState,
    scanner::Scanner,
    target::TargetResolver,
    transport::SocketConnector,
};
use tokio::net::UdpSocket;

async fn scan(port: u16) -> nrev::model::EndpointResult {
    scan_probe(port, "dns-udp").await
}

async fn scan_probe(port: u16, probe: &str) -> nrev::model::EndpointResult {
    let Command::Port(args) = Cli::parse_from([
        "nrev",
        "port",
        &format!("127.0.0.1:{port}"),
        "--transport",
        "udp",
        "--probes",
        probe,
        "--probe-timeout-ms",
        "200",
    ])
    .command
    else {
        panic!("port command")
    };
    let registry = DataRegistry::default();
    let config = ScanConfig::from_scan_args(&args, &registry).unwrap();
    let targets = TargetResolver::new(config.default_ports.clone())
        .resolve(&args.targets)
        .unwrap();
    let report = tokio::time::timeout(
        Duration::from_secs(3),
        Scanner::new(config, registry, SocketConnector).scan(targets),
    )
    .await
    .unwrap()
    .unwrap()
    .report;
    assert!(report.identification.is_none());
    report.targets[0].endpoints[&port].clone()
}

#[tokio::test]
async fn native_udp_response_confirms_an_open_endpoint() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut bytes = [0; 512];
        let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
        bytes[2] |= 0x80;
        socket.send_to(&bytes[..len], peer).await.unwrap();
    });
    let result = scan(port).await;
    assert_eq!(result.state, EndpointState::Open);
    assert!(result.fingerprint.unwrap().response_observed);
    assert!(result.errors.is_empty());
    server.await.unwrap();
}

#[tokio::test]
async fn native_udp_silence_remains_ambiguous() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let result = scan(socket.local_addr().unwrap().port()).await;
    assert_eq!(result.state, EndpointState::OpenFiltered);
    assert!(!result.fingerprint.unwrap().response_observed);
    assert!(!result.errors.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn native_udp_port_unreachable_is_closed() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let result = scan(port).await;
    assert_eq!(result.state, EndpointState::Closed, "{:?}", result.errors);
    assert!(!result.fingerprint.unwrap().response_observed);
}

#[tokio::test]
async fn udp_echo_is_open_but_is_not_misidentified_as_dns() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut bytes = [0; 512];
        let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(len, 30);
        socket.send_to(&bytes[..len], peer).await.unwrap();
    });
    let result = scan(port).await;
    assert_eq!(result.state, EndpointState::Open);
    assert!(result.observations[0].service_hint.is_none());
    assert!(
        result.observations[0]
            .evidence
            .iter()
            .any(|item| item.key == "response_validated" && item.value == "false")
    );
    server.await.unwrap();
}

#[tokio::test]
async fn native_ntp_response_is_correlated_and_records_stratum() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut request = [0; 48];
        let (len, peer) = socket.recv_from(&mut request).await.unwrap();
        assert_eq!(len, 48);
        let mut response = [0; 48];
        response[0] = 0x24;
        response[1] = 2;
        response[24..32].copy_from_slice(&request[40..48]);
        socket.send_to(&response, peer).await.unwrap();
    });
    let result = scan_probe(port, "ntp").await;
    assert_eq!(result.state, EndpointState::Open);
    assert_eq!(
        result.observations[0].service_hint.as_ref().unwrap().name,
        "ntp"
    );
    assert!(
        result.observations[0]
            .evidence
            .iter()
            .any(|item| item.key == "ntp_stratum" && item.value == "2")
    );
    server.await.unwrap();
}
