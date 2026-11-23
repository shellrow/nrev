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

fn version_txt(query: &[u8], name: &str) -> Vec<u8> {
    let mut packet = query.to_vec();
    packet[2] = 0x84;
    packet[7] = 1;
    packet.extend_from_slice(&[0xc0, 12, 0, 16, 0, 3, 0, 0, 0, 0]);
    packet.extend_from_slice(&u16::try_from(name.len() + 1).unwrap().to_be_bytes());
    packet.push(u8::try_from(name.len()).unwrap());
    packet.extend_from_slice(name.as_bytes());
    packet
}

#[tokio::test]
async fn dns_txt_product_requires_the_matching_question_and_record() {
    let db = nrev::technology::KnowledgeBase::builtin().unwrap();
    for changed in [
        None,
        Some(0),
        Some(2),
        Some(3),
        Some(13),
        Some(31),
        Some(33),
        Some(35),
        Some(41),
        Some(42),
    ] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let mut bytes = [0; 512];
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let mut reply = version_txt(&bytes[..len], "dnsmasq-2.90");
            if let Some(offset) = changed {
                reply[offset] ^= if offset == 2 { 2 } else { 1 };
            }
            socket.send_to(&reply, peer).await.unwrap();
        });
        let endpoint = scan(port).await;
        let inventory = db.identify(&endpoint).unwrap();
        if changed.is_none() {
            assert_eq!(inventory.technologies[0].id, "dnsmasq:dnsmasq");
            assert_eq!(inventory.technologies[0].version.as_deref(), Some("2.90"));
        } else {
            assert!(
                inventory.technologies.is_empty(),
                "changed offset {changed:?}"
            );
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn dns_over_tcp_reassembles_the_response_before_identifying_it() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut query = [0; 32];
        stream.read_exact(&mut query).await.unwrap();
        let reply = version_txt(&query[2..], "CoreDNS-1.12.0");
        stream
            .write_all(&(reply.len() as u16).to_be_bytes())
            .await
            .unwrap();
        for part in reply.chunks(7) {
            stream.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_nrev"))
        .args([
            "port",
            &address.to_string(),
            "--connect-timeout-ms",
            "500",
            "--probes",
            "dns-tcp",
            "-S",
            "--format",
            "json",
            "--quiet",
        ])
        .output()
        .await
        .unwrap();
    assert!(output.status.success());
    let inventory: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let product = &inventory["hosts"][0]["endpoints"][0]["technologies"][0];
    assert_eq!(product["id"], "coredns:coredns");
    assert_eq!(product["version"], "1.12.0");
    server.await.unwrap();
}
