use crate::interface::source_ip_for;
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use futures::{StreamExt, stream};
use netdev::Interface;
use nex::net::interface::Interface as NexInterface;
use nex::{
    datalink::async_io::{AsyncChannel, async_channel},
    packet::{
        builder::{
            ethernet::EthernetPacketBuilder, icmp::IcmpPacketBuilder, icmpv6::Icmpv6PacketBuilder,
            ipv4::Ipv4PacketBuilder, ipv6::Ipv6PacketBuilder, tcp::TcpPacketBuilder,
        },
        ethernet::EtherType,
        frame::Frame,
        icmp::IcmpType,
        icmpv6::Icmpv6Type,
        ip::IpNextProtocol,
        ipv4::Ipv4Flags,
        packet::Packet,
        tcp::{TcpFlags, TcpOptionPacket},
    },
};
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::{
    ClientConfig as RustlsClientConfig, RootCertStore,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::convert::TryFrom;
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::oneshot,
    time::timeout,
};
use x509_parser::parse_x509_certificate;

use crate::{
    capture::pcap::{CapturedFrame, PacketCaptureOptions, start_capture, start_capture_timed},
    fingerprint::classify_initial_ttl,
    interface::get_interface_by_name,
    model::{HostDiscoveryMethod, HostObservation, TlsObservation, Transport},
};

const SYN_SOURCE_PORT: u16 = 44322;

fn datalink_config(timeout_window: Duration) -> nex::datalink::Config {
    nex::datalink::Config::default()
        .with_read_timeout(Some(timeout_window))
        .with_promiscuous(false)
}

#[derive(Debug)]
pub struct SynAckObservation {
    pub ttl_hint: Option<u8>,
    pub ttl_class: Option<u8>,
    pub window_size: Option<u32>,
    pub syn_ack_seen: bool,
    pub rst_seen: bool,
    pub tcp_option_order: Option<String>,
    pub tcp_option_set: Option<String>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: Option<bool>,
    pub timestamps: Option<bool>,
}

#[derive(Debug)]
pub enum SynPortStatus {
    Open(SynAckObservation),
    Closed(Option<SynAckObservation>),
    Filtered,
}

#[derive(Debug)]
pub enum ProbeConnection {
    Tcp(TcpStream),
    Udp(UdpSocket),
    Syn(SynAckObservation),
    Quic(QuicConnection),
}

#[derive(Debug)]
pub struct QuicConnection {
    endpoint: Endpoint,
    connection: Option<Connection>,
    tls: TlsObservation,
    open_signal: Option<String>,
}

impl QuicConnection {
    pub fn handshake_observed(&self) -> bool {
        self.connection.is_some()
    }

    pub fn tls(&self) -> &TlsObservation {
        &self.tls
    }

    pub fn open_signal(&self) -> Option<&str> {
        self.open_signal.as_deref()
    }

    pub fn into_parts(self) -> (Endpoint, Option<Connection>, TlsObservation, Option<String>) {
        (self.endpoint, self.connection, self.tls, self.open_signal)
    }
}

#[derive(Debug)]
pub struct ConnectOutcome {
    pub connection: ProbeConnection,
    pub latency: Duration,
}

pub async fn tcp_host_probe(
    address: IpAddr,
    ports: &[u16],
    timeout_window: Duration,
) -> std::io::Result<HostObservation> {
    tcp_host_probe_on_interface(address, ports, timeout_window, None).await
}

pub(crate) async fn tcp_host_probe_on_interface(
    address: IpAddr,
    ports: &[u16],
    timeout_window: Duration,
    interface_name: Option<&str>,
) -> std::io::Result<HostObservation> {
    let samples = stream::iter(ports.iter().copied())
        .map(|port| async move {
            let started = Instant::now();
            match SocketConnector
                .connect(
                    address,
                    port,
                    Transport::Tcp,
                    timeout_window,
                    interface_name,
                    None,
                )
                .await
            {
                Ok(_stream) => Ok(HostObservation {
                    method: HostDiscoveryMethod::Tcp,
                    port: Some(port),
                    outcome: "connect-open".to_string(),
                    latency: Some(started.elapsed()),
                    ttl_hint: None,
                    mac_address: None,
                }),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    Ok(HostObservation {
                        method: HostDiscoveryMethod::Tcp,
                        port: Some(port),
                        outcome: "connection-refused".to_string(),
                        latency: Some(started.elapsed()),
                        ttl_hint: None,
                        mac_address: None,
                    })
                }
                Err(error) => Err(error),
            }
        })
        .buffer_unordered(ports.len().clamp(1, 16))
        .collect::<Vec<_>>()
        .await;

    samples
        .into_iter()
        .find_map(Result::ok)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "host did not respond"))
}

pub async fn udp_host_probe(
    address: IpAddr,
    ports: &[u16],
    timeout_window: Duration,
    interface_name: Option<&str>,
) -> std::io::Result<HostObservation> {
    let samples = stream::iter(ports.iter().copied())
        .map(|port| async move {
            let local = local_bind_addr(address, interface_name)?;
            let socket = remote_socket_addr(address, port, interface_name)?;
            let udp = UdpSocket::bind(local).await?;
            udp.connect(socket).await?;
            let started = Instant::now();
            match udp.send(&[0]).await {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    return Ok(HostObservation {
                        method: HostDiscoveryMethod::Udp,
                        port: Some(port),
                        outcome: "port-unreachable".to_string(),
                        latency: Some(started.elapsed()),
                        ttl_hint: None,
                        mac_address: None,
                    });
                }
                Err(error) => return Err(error),
            }

            let mut buf = [0_u8; 64];
            match timeout(timeout_window, udp.recv(&mut buf)).await {
                Ok(Ok(_)) => Ok(HostObservation {
                    method: HostDiscoveryMethod::Udp,
                    port: Some(port),
                    outcome: "udp-response".to_string(),
                    latency: Some(started.elapsed()),
                    ttl_hint: None,
                    mac_address: None,
                }),
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    Ok(HostObservation {
                        method: HostDiscoveryMethod::Udp,
                        port: Some(port),
                        outcome: "port-unreachable".to_string(),
                        latency: Some(started.elapsed()),
                        ttl_hint: None,
                        mac_address: None,
                    })
                }
                Ok(Err(error)) => Err(error),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "udp host probe timed out",
                )),
            }
        })
        .buffer_unordered(ports.len().clamp(1, 16))
        .collect::<Vec<_>>()
        .await;

    samples
        .into_iter()
        .find_map(Result::ok)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "host did not respond"))
}

pub async fn icmp_host_probe(
    address: IpAddr,
    timeout_window: Duration,
    interface_name: Option<&str>,
) -> std::io::Result<HostObservation> {
    let token = rand::random::<u32>();
    let interface = resolve_interface(interface_name)?;
    let config = datalink_config(timeout_window);
    let nex_interface = NexInterface::from(interface.clone());

    let AsyncChannel::Ethernet(mut tx, mut rx) =
        async_channel(&nex_interface, config).map_err(std::io::Error::other)?
    else {
        return Err(std::io::Error::other("unsupported datalink channel"));
    };

    let dst_mac = crate::neighbor::destination_mac(&interface, address, timeout_window).await?;
    let packet = build_icmp_echo_packet(&interface, address, dst_mac, token)?;
    let parse_option = capture_parse_option(&interface);
    let started = Instant::now();
    crate::capture::send_packet(&mut *tx, &interface, &packet)
        .await
        .map_err(std::io::Error::other)?;

    loop {
        if started.elapsed() >= timeout_window {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "icmp host probe timed out",
            ));
        }

        let remaining = timeout_window.saturating_sub(started.elapsed());
        match timeout(remaining, rx.next()).await {
            Ok(Some(Ok(packet))) => {
                let Some(frame) = Frame::from_buf(&packet, parse_option.clone()) else {
                    continue;
                };
                if let Some(observation) =
                    parse_icmp_host_frame(address, &frame, started.elapsed(), token)
                {
                    return Ok(observation);
                }
            }
            Ok(Some(Err(error))) => return Err(std::io::Error::other(error)),
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "capture ended",
                ));
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "icmp host probe timed out",
                ));
            }
        }
    }
}

pub async fn icmp_scan_targets(
    addresses: &[IpAddr],
    timeout_window: Duration,
    interface_name: Option<&str>,
) -> std::io::Result<BTreeMap<IpAddr, HostObservation>> {
    if addresses.is_empty() {
        return Ok(BTreeMap::new());
    }

    let token = rand::random::<u32>();
    let interface = resolve_interface(interface_name)?;
    let destination_macs =
        crate::neighbor::destination_macs(&interface, addresses, timeout_window).await?;
    let config = datalink_config(timeout_window);
    let nex_interface = NexInterface::from(interface.clone());

    let AsyncChannel::Ethernet(mut tx, mut rx) =
        async_channel(&nex_interface, config).map_err(std::io::Error::other)?
    else {
        return Err(std::io::Error::other("unsupported datalink channel"));
    };

    let mut options = PacketCaptureOptions::from_interface_index(interface.index)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "interface not found"))?;
    // The response window starts after the final send, not before the batch.
    // Dropping stop_tx on send failure or cancellation also stops capture.
    options.capture_timeout = Duration::MAX;
    options.read_timeout = timeout_window;
    options.src_ips.extend(addresses.iter().copied());
    options
        .dst_ips
        .extend(crate::interface::get_interface_local_ips(&interface));
    options.ip_protocols.insert(IpNextProtocol::Icmp);
    options.ip_protocols.insert(IpNextProtocol::Icmpv6);

    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let capture_task =
        tokio::spawn(
            async move { start_capture_timed(&mut rx, options, ready_tx, &mut stop_rx).await },
        );

    let _ = ready_rx.await;
    let mut send_times = BTreeMap::new();
    for address in addresses {
        let Some(&dst_mac) = destination_macs.get(address) else {
            continue;
        };
        let packet = build_icmp_echo_packet(&interface, *address, dst_mac, token)?;
        let sent = Instant::now();
        crate::capture::send_packet(&mut *tx, &interface, &packet)
            .await
            .map_err(std::io::Error::other)?;
        send_times.insert(*address, sent);
    }
    tokio::time::sleep(timeout_window).await;
    let _ = stop_tx.send(());

    let captured = capture_task
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))??;
    Ok(parse_icmp_scan_frames(
        &interface,
        addresses,
        &send_times,
        captured,
        token,
    ))
}

#[async_trait]
pub trait Connector: Clone + Send + Sync + 'static {
    async fn connect(
        &self,
        address: IpAddr,
        port: u16,
        transport: Transport,
        timeout_window: Duration,
        interface_name: Option<&str>,
        server_name: Option<&str>,
    ) -> std::io::Result<ConnectOutcome>;
}

#[derive(Clone, Debug, Default)]
pub struct SocketConnector;

#[async_trait]
impl Connector for SocketConnector {
    async fn connect(
        &self,
        address: IpAddr,
        port: u16,
        transport: Transport,
        timeout_window: Duration,
        interface_name: Option<&str>,
        server_name: Option<&str>,
    ) -> std::io::Result<ConnectOutcome> {
        match transport {
            Transport::Tcp => {
                let socket = remote_socket_addr(address, port, interface_name)?;
                let start = Instant::now();
                let tcp = if address.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };
                if interface_name.is_some() {
                    tcp.bind(local_bind_addr(address, interface_name)?)?;
                }
                let stream = timeout(timeout_window, tcp.connect(socket))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout")
                    })??;
                Ok(ConnectOutcome {
                    connection: ProbeConnection::Tcp(stream),
                    latency: start.elapsed(),
                })
            }
            Transport::Udp => {
                let local = local_bind_addr(address, interface_name)?;
                let socket = remote_socket_addr(address, port, interface_name)?;
                let start = Instant::now();
                let udp = UdpSocket::bind(local).await?;
                timeout(timeout_window, udp.connect(socket))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "udp connect timeout")
                    })??;
                Ok(ConnectOutcome {
                    connection: ProbeConnection::Udp(udp),
                    latency: start.elapsed(),
                })
            }
            Transport::Syn => {
                let start = Instant::now();
                let observation = syn_probe(address, port, timeout_window, interface_name).await?;
                Ok(ConnectOutcome {
                    connection: ProbeConnection::Syn(observation),
                    latency: start.elapsed(),
                })
            }
            Transport::Quic => {
                let start = Instant::now();
                let connection =
                    quic_connect(address, port, timeout_window, server_name, interface_name)
                        .await?;
                Ok(ConnectOutcome {
                    connection: ProbeConnection::Quic(connection),
                    latency: start.elapsed(),
                })
            }
        }
    }
}

pub async fn estimate_tcp_rtt(
    address: IpAddr,
    candidate_ports: &[u16],
    timeout_window: Duration,
) -> Option<Duration> {
    if candidate_ports.is_empty() {
        return None;
    }

    let samples = stream::iter(candidate_ports.iter().copied())
        .map(|port| async move {
            let socket = SocketAddr::new(address, port);
            let started = Instant::now();
            match timeout(timeout_window, TcpStream::connect(socket)).await {
                Ok(Ok(_stream)) => Some(started.elapsed()),
                Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    Some(started.elapsed())
                }
                _ => None,
            }
        })
        .buffer_unordered(candidate_ports.len().clamp(1, 8))
        .collect::<Vec<_>>()
        .await;

    samples.into_iter().flatten().min()
}

async fn quic_connect(
    address: IpAddr,
    port: u16,
    timeout_window: Duration,
    server_name: Option<&str>,
    interface_name: Option<&str>,
) -> std::io::Result<QuicConnection> {
    let bind_addr = local_bind_addr(address, interface_name)?;
    let mut endpoint = Endpoint::client(bind_addr).map_err(std::io::Error::other)?;
    endpoint.set_default_client_config(quic_client_config()?);

    let server_name = server_name
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| address.to_string());
    let remote = remote_socket_addr(address, port, interface_name)?;
    let connecting = endpoint
        .connect(remote, &server_name)
        .map_err(std::io::Error::other)?;

    match timeout(timeout_window, connecting).await {
        Ok(Ok(connection)) => Ok(QuicConnection {
            endpoint,
            tls: observe_quic_tls(&connection, &server_name),
            connection: Some(connection),
            open_signal: None,
        }),
        Ok(Err(error)) if quic_error_implies_open(&error) => Ok(QuicConnection {
            endpoint,
            connection: None,
            tls: TlsObservation {
                negotiated_protocol: None,
                cipher_suite: None,
                server_name: Some(server_name),
                certificate_subjects: Vec::new(),
                certificate_issuers: Vec::new(),
                certificate_validation: crate::model::TlsCertificateValidation::NotPerformed,
            },
            open_signal: Some(format!(
                "quic-handshake-error={}",
                format_quic_error(&error)
            )),
        }),
        Ok(Err(error)) => Err(std::io::Error::other(format_quic_error(&error))),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "quic connect timeout",
        )),
    }
}

fn quic_client_config() -> std::io::Result<ClientConfig> {
    let mut tls = RustlsClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    tls.alpn_protocols = quic_alpn_protocols();
    tls.dangerous()
        .set_certificate_verifier(SkipServerVerification::new());
    let quic_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(std::io::Error::other)?;
    Ok(ClientConfig::new(Arc::new(quic_config)))
}

fn quic_alpn_protocols() -> Vec<Vec<u8>> {
    [
        b"h3".as_slice(),
        b"h3-34".as_slice(),
        b"h3-33".as_slice(),
        b"h3-32".as_slice(),
        b"h3-31".as_slice(),
        b"h3-30".as_slice(),
        b"h3-29".as_slice(),
        b"hq-29".as_slice(),
    ]
    .into_iter()
    .map(|item| item.to_vec())
    .collect()
}

fn observe_quic_tls(connection: &Connection, server_name: &str) -> TlsObservation {
    let mut subjects = Vec::new();
    let mut issuers = Vec::new();

    if let Some(certificates) = connection.peer_identity().and_then(|identity| {
        identity
            .downcast_ref::<Vec<CertificateDer<'static>>>()
            .cloned()
    }) {
        for certificate in certificates {
            if let Ok((_, parsed)) = parse_x509_certificate(certificate.as_ref()) {
                subjects.push(parsed.subject().to_string());
                issuers.push(parsed.issuer().to_string());
            }
        }
    }

    let negotiated_protocol = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| {
            data.protocol
                .map(|value| String::from_utf8_lossy(&value).to_string())
        });

    TlsObservation {
        negotiated_protocol,
        cipher_suite: None,
        server_name: Some(server_name.to_string()),
        certificate_subjects: subjects,
        certificate_issuers: issuers,
        certificate_validation: crate::model::TlsCertificateValidation::NotPerformed,
    }
}

fn quic_error_implies_open(error: &quinn::ConnectionError) -> bool {
    matches!(
        error,
        quinn::ConnectionError::VersionMismatch
            | quinn::ConnectionError::TransportError(_)
            | quinn::ConnectionError::ConnectionClosed(_)
            | quinn::ConnectionError::ApplicationClosed(_)
            | quinn::ConnectionError::Reset
    )
}

fn format_quic_error(error: &quinn::ConnectionError) -> String {
    match error {
        quinn::ConnectionError::VersionMismatch => "version-mismatch".to_string(),
        quinn::ConnectionError::TransportError(inner) => {
            format!("transport-error({inner})")
        }
        quinn::ConnectionError::ConnectionClosed(inner) => {
            format!("connection-closed({:?})", inner.reason)
        }
        quinn::ConnectionError::ApplicationClosed(inner) => {
            format!("application-closed({:?})", inner.reason)
        }
        quinn::ConnectionError::Reset => "reset".to_string(),
        other => other.to_string(),
    }
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn syn_probe(
    address: IpAddr,
    port: u16,
    timeout_window: Duration,
    interface_name: Option<&str>,
) -> std::io::Result<SynAckObservation> {
    let sequence = rand::random::<u32>();
    let interface = resolve_interface(interface_name)?;
    let config = datalink_config(timeout_window);
    let nex_interface = NexInterface::from(interface.clone());

    let AsyncChannel::Ethernet(mut tx, mut rx) =
        async_channel(&nex_interface, config).map_err(std::io::Error::other)?
    else {
        return Err(std::io::Error::other("unsupported datalink channel"));
    };

    let mut options = PacketCaptureOptions::from_interface_index(interface.index)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "interface not found"))?;
    // The response window starts after the final send, not before the batch.
    // Dropping stop_tx on send failure or cancellation also stops capture.
    options.capture_timeout = Duration::MAX;
    options.read_timeout = timeout_window;
    options.src_ips.insert(address);
    options.src_ports.insert(port);
    options
        .dst_ips
        .extend(crate::interface::get_interface_local_ips(&interface));
    options.dst_ports.insert(SYN_SOURCE_PORT);
    options.ip_protocols.insert(IpNextProtocol::Tcp);

    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let capture_task =
        tokio::spawn(async move { start_capture(&mut rx, options, ready_tx, &mut stop_rx).await });

    let _ = ready_rx.await;
    let dst_mac = crate::neighbor::destination_mac(&interface, address, timeout_window).await?;
    let packet = build_tcp_syn_packet(&interface, address, port, dst_mac, sequence)?;
    crate::capture::send_packet(&mut *tx, &interface, &packet)
        .await
        .map_err(std::io::Error::other)?;
    tokio::time::sleep(timeout_window).await;
    let _ = stop_tx.send(());

    let frames = capture_task
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))??;
    parse_syn_frames(address, port, SYN_SOURCE_PORT, sequence, frames)
}

pub async fn syn_scan_target(
    address: IpAddr,
    ports: &[u16],
    timeout_window: Duration,
    interface_name: Option<&str>,
) -> std::io::Result<BTreeMap<u16, SynPortStatus>> {
    let sequence = rand::random::<u32>();
    let interface = resolve_interface(interface_name)?;
    let config = datalink_config(timeout_window);
    let nex_interface = NexInterface::from(interface.clone());

    let AsyncChannel::Ethernet(mut tx, mut rx) =
        async_channel(&nex_interface, config).map_err(std::io::Error::other)?
    else {
        return Err(std::io::Error::other("unsupported datalink channel"));
    };

    let mut options = PacketCaptureOptions::from_interface_index(interface.index)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "interface not found"))?;
    // The response window starts after the final send, not before the batch.
    // Dropping stop_tx on send failure or cancellation also stops capture.
    options.capture_timeout = Duration::MAX;
    options.read_timeout = timeout_window;
    options.src_ips.insert(address);
    options.src_ports.extend(ports.iter().copied());
    options
        .dst_ips
        .extend(crate::interface::get_interface_local_ips(&interface));
    options.dst_ports.insert(SYN_SOURCE_PORT);
    options.ip_protocols.insert(IpNextProtocol::Tcp);

    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let capture_task =
        tokio::spawn(async move { start_capture(&mut rx, options, ready_tx, &mut stop_rx).await });

    let _ = ready_rx.await;
    let dst_mac = crate::neighbor::destination_mac(&interface, address, timeout_window).await?;
    for port in ports {
        let packet = build_tcp_syn_packet(&interface, address, *port, dst_mac, sequence)?;
        crate::capture::send_packet(&mut *tx, &interface, &packet)
            .await
            .map_err(std::io::Error::other)?;
    }
    tokio::time::sleep(timeout_window).await;
    let _ = stop_tx.send(());

    let frames = capture_task
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))??;
    Ok(parse_syn_scan_frames(
        address,
        ports,
        SYN_SOURCE_PORT,
        sequence,
        frames,
    ))
}

pub async fn syn_scan_targets(
    targets: &[(IpAddr, Vec<u16>)],
    timeout_window: Duration,
    interface_name: Option<&str>,
) -> std::io::Result<BTreeMap<IpAddr, BTreeMap<u16, SynPortStatus>>> {
    if targets.is_empty() {
        return Ok(BTreeMap::new());
    }

    let sequence = rand::random::<u32>();
    let interface = resolve_interface(interface_name)?;
    let destination_macs = crate::neighbor::destination_macs(
        &interface,
        &targets
            .iter()
            .map(|(address, _)| *address)
            .collect::<Vec<_>>(),
        timeout_window,
    )
    .await?;
    let config = datalink_config(timeout_window);
    let nex_interface = NexInterface::from(interface.clone());

    let AsyncChannel::Ethernet(mut tx, mut rx) =
        async_channel(&nex_interface, config).map_err(std::io::Error::other)?
    else {
        return Err(std::io::Error::other("unsupported datalink channel"));
    };

    let mut options = PacketCaptureOptions::from_interface_index(interface.index)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "interface not found"))?;
    // The response window starts after the final send, not before the batch.
    // Dropping stop_tx on send failure or cancellation also stops capture.
    options.capture_timeout = Duration::MAX;
    options.read_timeout = timeout_window;
    options
        .src_ips
        .extend(targets.iter().map(|(address, _)| *address));
    options
        .src_ports
        .extend(targets.iter().flat_map(|(_, ports)| ports.iter().copied()));
    options
        .dst_ips
        .extend(crate::interface::get_interface_local_ips(&interface));
    options.dst_ports.insert(SYN_SOURCE_PORT);
    options.ip_protocols.insert(IpNextProtocol::Tcp);

    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let capture_task =
        tokio::spawn(async move { start_capture(&mut rx, options, ready_tx, &mut stop_rx).await });

    let _ = ready_rx.await;
    for (address, ports) in targets {
        let Some(&dst_mac) = destination_macs.get(address) else {
            continue;
        };
        for port in ports {
            let packet = build_tcp_syn_packet(&interface, *address, *port, dst_mac, sequence)?;
            crate::capture::send_packet(&mut *tx, &interface, &packet)
                .await
                .map_err(std::io::Error::other)?;
        }
    }
    tokio::time::sleep(timeout_window).await;
    let _ = stop_tx.send(());

    let frames = capture_task
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))??;
    Ok(parse_syn_scan_frames_multi(
        targets,
        SYN_SOURCE_PORT,
        sequence,
        frames,
    ))
}

fn parse_syn_frames(
    address: IpAddr,
    port: u16,
    source_port: u16,
    sequence: u32,
    frames: Vec<Frame>,
) -> std::io::Result<SynAckObservation> {
    for frame in frames {
        let Some(ip) = frame.ip else {
            continue;
        };
        let Some(transport) = frame.transport else {
            continue;
        };
        let (src_ip, ttl_hint) = if let Some(ipv4) = ip.ipv4 {
            (IpAddr::V4(ipv4.source), Some(ipv4.ttl))
        } else if let Some(ipv6) = ip.ipv6 {
            (IpAddr::V6(ipv6.source), Some(ipv6.hop_limit))
        } else {
            continue;
        };
        if src_ip != address {
            continue;
        }
        let Some(tcp) = transport.tcp else {
            continue;
        };
        if tcp.flags & TcpFlags::ACK == 0
            || tcp.acknowledgement != sequence.wrapping_add(1)
            || tcp.flags & (TcpFlags::SYN | TcpFlags::RST) == (TcpFlags::SYN | TcpFlags::RST)
        {
            continue;
        }
        if tcp.source != port || tcp.destination != source_port {
            continue;
        }

        if (tcp.flags & (TcpFlags::SYN | TcpFlags::ACK)) == (TcpFlags::SYN | TcpFlags::ACK) {
            let features = extract_tcp_option_signature(&tcp.options);
            return Ok(SynAckObservation {
                ttl_hint,
                ttl_class: ttl_hint.map(classify_initial_ttl),
                window_size: Some(tcp.window.into()),
                syn_ack_seen: true,
                rst_seen: false,
                tcp_option_order: features.order_key,
                tcp_option_set: features.set_key,
                mss: features.mss,
                window_scale: features.window_scale,
                sack_permitted: features.sack_permitted,
                timestamps: features.timestamps,
            });
        }
        if (tcp.flags & TcpFlags::RST) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "SYN probe received RST",
            ));
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "SYN probe timed out",
    ))
}

fn parse_syn_scan_frames(
    address: IpAddr,
    ports: &[u16],
    source_port: u16,
    sequence: u32,
    frames: Vec<Frame>,
) -> BTreeMap<u16, SynPortStatus> {
    let mut results = BTreeMap::new();
    let port_set: HashSet<u16> = ports.iter().copied().collect();

    for frame in frames {
        let Some(ip) = frame.ip else {
            continue;
        };
        let Some(transport) = frame.transport else {
            continue;
        };
        let src_ip = if let Some(ref ipv4) = ip.ipv4 {
            IpAddr::V4(ipv4.source)
        } else if let Some(ref ipv6) = ip.ipv6 {
            IpAddr::V6(ipv6.source)
        } else {
            continue;
        };
        if src_ip != address {
            continue;
        }
        let ttl_hint = if let Some(ref ipv4) = ip.ipv4 {
            Some(ipv4.ttl)
        } else {
            ip.ipv6.as_ref().map(|ipv6| ipv6.hop_limit)
        };
        let Some(tcp) = transport.tcp else {
            continue;
        };
        if tcp.flags & TcpFlags::ACK == 0
            || tcp.acknowledgement != sequence.wrapping_add(1)
            || tcp.flags & (TcpFlags::SYN | TcpFlags::RST) == (TcpFlags::SYN | TcpFlags::RST)
        {
            continue;
        }
        if tcp.destination != source_port || !port_set.contains(&tcp.source) {
            continue;
        }
        let features = extract_tcp_option_signature(&tcp.options);
        let observation = SynAckObservation {
            ttl_hint,
            ttl_class: ttl_hint.map(classify_initial_ttl),
            window_size: Some(tcp.window.into()),
            syn_ack_seen: (tcp.flags & (TcpFlags::SYN | TcpFlags::ACK))
                == (TcpFlags::SYN | TcpFlags::ACK),
            rst_seen: (tcp.flags & TcpFlags::RST) != 0,
            tcp_option_order: features.order_key,
            tcp_option_set: features.set_key,
            mss: features.mss,
            window_scale: features.window_scale,
            sack_permitted: features.sack_permitted,
            timestamps: features.timestamps,
        };
        if observation.syn_ack_seen {
            results.insert(tcp.source, SynPortStatus::Open(observation));
        } else if observation.rst_seen {
            results.insert(tcp.source, SynPortStatus::Closed(Some(observation)));
        }
    }

    for port in ports {
        results.entry(*port).or_insert(SynPortStatus::Filtered);
    }
    results
}

fn parse_syn_scan_frames_multi(
    targets: &[(IpAddr, Vec<u16>)],
    source_port: u16,
    sequence: u32,
    frames: Vec<Frame>,
) -> BTreeMap<IpAddr, BTreeMap<u16, SynPortStatus>> {
    let target_ports = targets
        .iter()
        .map(|(address, ports)| (*address, ports.iter().copied().collect::<HashSet<_>>()))
        .collect::<BTreeMap<_, _>>();
    let mut results = BTreeMap::<IpAddr, BTreeMap<u16, SynPortStatus>>::new();

    for frame in frames {
        let Some(ip) = frame.ip else {
            continue;
        };
        let Some(transport) = frame.transport else {
            continue;
        };
        let src_ip = if let Some(ref ipv4) = ip.ipv4 {
            IpAddr::V4(ipv4.source)
        } else if let Some(ref ipv6) = ip.ipv6 {
            IpAddr::V6(ipv6.source)
        } else {
            continue;
        };
        let Some(port_set) = target_ports.get(&src_ip) else {
            continue;
        };
        let ttl_hint = if let Some(ref ipv4) = ip.ipv4 {
            Some(ipv4.ttl)
        } else {
            ip.ipv6.as_ref().map(|ipv6| ipv6.hop_limit)
        };
        let Some(tcp) = transport.tcp else {
            continue;
        };
        if tcp.flags & TcpFlags::ACK == 0
            || tcp.acknowledgement != sequence.wrapping_add(1)
            || tcp.flags & (TcpFlags::SYN | TcpFlags::RST) == (TcpFlags::SYN | TcpFlags::RST)
        {
            continue;
        }
        if tcp.destination != source_port || !port_set.contains(&tcp.source) {
            continue;
        }
        let features = extract_tcp_option_signature(&tcp.options);
        let observation = SynAckObservation {
            ttl_hint,
            ttl_class: ttl_hint.map(classify_initial_ttl),
            window_size: Some(tcp.window.into()),
            syn_ack_seen: (tcp.flags & (TcpFlags::SYN | TcpFlags::ACK))
                == (TcpFlags::SYN | TcpFlags::ACK),
            rst_seen: (tcp.flags & TcpFlags::RST) != 0,
            tcp_option_order: features.order_key,
            tcp_option_set: features.set_key,
            mss: features.mss,
            window_scale: features.window_scale,
            sack_permitted: features.sack_permitted,
            timestamps: features.timestamps,
        };
        if observation.syn_ack_seen {
            results
                .entry(src_ip)
                .or_default()
                .insert(tcp.source, SynPortStatus::Open(observation));
        } else if observation.rst_seen {
            results
                .entry(src_ip)
                .or_default()
                .insert(tcp.source, SynPortStatus::Closed(Some(observation)));
        }
    }

    for (address, ports) in targets {
        let target_results = results.entry(*address).or_default();
        for port in ports {
            target_results
                .entry(*port)
                .or_insert(SynPortStatus::Filtered);
        }
    }

    results
}

fn build_tcp_syn_packet(
    interface: &Interface,
    dst_ip: IpAddr,
    dst_port: u16,
    dst_mac: netdev::MacAddr,
    sequence: u32,
) -> std::io::Result<Vec<u8>> {
    let src_mac = interface.mac_addr.unwrap_or(netdev::MacAddr::zero());

    let src_ip = source_ip_for(interface, dst_ip);

    let tcp_packet = TcpPacketBuilder::new(src_ip, dst_ip)
        .source(SYN_SOURCE_PORT)
        .destination(dst_port)
        .sequence(sequence)
        .flags(TcpFlags::SYN)
        .window(65535)
        .options(vec![
            TcpOptionPacket::mss(1460),
            TcpOptionPacket::nop(),
            TcpOptionPacket::wscale(6),
            TcpOptionPacket::nop(),
            TcpOptionPacket::nop(),
            TcpOptionPacket::timestamp(u32::MAX, u32::MIN),
            TcpOptionPacket::sack_perm(),
        ])
        .build()
        .map_err(std::io::Error::other)?;

    let ip_packet = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ipv4PacketBuilder::new()
            .source(src)
            .destination(dst)
            .protocol(IpNextProtocol::Tcp)
            .flags(Ipv4Flags::DontFragment)
            .payload(tcp_packet.to_bytes())
            .build()
            .map_err(std::io::Error::other)?
            .to_bytes(),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ipv6PacketBuilder::new()
            .source(src)
            .destination(dst)
            .next_header(IpNextProtocol::Tcp)
            .payload(tcp_packet.to_bytes())
            .build()
            .map_err(std::io::Error::other)?
            .to_bytes(),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mismatched IP address families",
            ));
        }
    };

    let ethernet_packet = EthernetPacketBuilder::new()
        .source(src_mac)
        .destination(dst_mac)
        .ethertype(match dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    Ok(ethernet_packet.to_bytes().to_vec())
}

struct TcpOptionSignature {
    order_key: Option<String>,
    set_key: Option<String>,
    mss: Option<u16>,
    window_scale: Option<u8>,
    sack_permitted: Option<bool>,
    timestamps: Option<bool>,
}

fn extract_tcp_option_signature(options: &[TcpOptionPacket]) -> TcpOptionSignature {
    use nex::packet::tcp::TcpOptionKind;

    let mut ordered = Vec::new();
    let mut compressed = Vec::new();
    let mut prev_nop = false;
    let mut mss = None;
    let mut window_scale = None;
    let mut sack_permitted = None;
    let mut timestamps = None;

    for option in options {
        let token = match option.kind() {
            TcpOptionKind::MSS => {
                mss = Some(option.maximum_segment_size());
                Some("MSS")
            }
            TcpOptionKind::SACK_PERMITTED => {
                sack_permitted = Some(true);
                Some("SACK")
            }
            TcpOptionKind::TIMESTAMPS => {
                timestamps = Some(true);
                Some("TS")
            }
            TcpOptionKind::WSCALE => {
                window_scale = Some(option.window_scale());
                Some("WS")
            }
            TcpOptionKind::NOP => Some("NOP"),
            _ => None,
        };

        let Some(token) = token else {
            continue;
        };

        ordered.push(token);
        if token == "NOP" {
            if !prev_nop {
                compressed.push(token);
            }
            prev_nop = true;
        } else {
            prev_nop = false;
            compressed.push(token);
        }
    }

    let set_key = if compressed.is_empty() {
        None
    } else {
        use std::collections::BTreeSet;

        const PRIORITY: [&str; 5] = ["MSS", "SACK", "TS", "WS", "NOP"];
        let set = compressed.iter().copied().collect::<BTreeSet<_>>();
        let mut head = PRIORITY
            .iter()
            .copied()
            .filter(|token| set.contains(token))
            .collect::<Vec<_>>();
        let mut tail = set
            .iter()
            .copied()
            .filter(|token| !PRIORITY.contains(token))
            .collect::<Vec<_>>();
        tail.sort_unstable();
        head.extend(tail);
        Some(format!("{{{}}}", head.join(",")))
    };

    TcpOptionSignature {
        order_key: (!ordered.is_empty()).then(|| ordered.join(",")),
        set_key,
        mss,
        window_scale,
        sack_permitted,
        timestamps,
    }
}

fn build_icmp_echo_packet(
    interface: &Interface,
    dst_ip: IpAddr,
    dst_mac: netdev::MacAddr,
    token: u32,
) -> std::io::Result<Vec<u8>> {
    let src_mac = interface.mac_addr.unwrap_or(netdev::MacAddr::zero());

    let src_ip = source_ip_for(interface, dst_ip);

    let ip_packet = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let icmp_packet = IcmpPacketBuilder::new(src, dst)
                .echo_fields((token >> 16) as u16, token as u16)
                .build()
                .map_err(std::io::Error::other)?;
            Ipv4PacketBuilder::new()
                .source(src)
                .destination(dst)
                .protocol(IpNextProtocol::Icmp)
                .flags(Ipv4Flags::DontFragment)
                .payload(icmp_packet.to_bytes())
                .build()
                .map_err(std::io::Error::other)?
                .to_bytes()
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let icmp_packet = Icmpv6PacketBuilder::new(src, dst)
                .echo_fields((token >> 16) as u16, token as u16)
                .build()
                .map_err(std::io::Error::other)?;
            Ipv6PacketBuilder::new()
                .source(src)
                .destination(dst)
                .next_header(IpNextProtocol::Icmpv6)
                .payload(icmp_packet.to_bytes())
                .build()
                .map_err(std::io::Error::other)?
                .to_bytes()
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mismatched IP address families",
            ));
        }
    };

    let ethernet_packet = EthernetPacketBuilder::new()
        .source(src_mac)
        .destination(dst_mac)
        .ethertype(match dst_ip {
            IpAddr::V4(_) => EtherType::Ipv4,
            IpAddr::V6(_) => EtherType::Ipv6,
        })
        .payload(ip_packet)
        .build();

    Ok(ethernet_packet.to_bytes().to_vec())
}

fn parse_icmp_host_frame(
    address: IpAddr,
    frame: &Frame,
    latency: Duration,
    token: u32,
) -> Option<HostObservation> {
    if frame.payload.get(..4) != Some(token.to_be_bytes().as_slice()) {
        return None;
    }
    let ip = frame.ip.as_ref()?;
    if let Some(ipv4) = &ip.ipv4 {
        if IpAddr::V4(ipv4.source) != address {
            return None;
        }
        let icmp = ip.icmp.as_ref()?;
        if icmp.icmp_type != IcmpType::EchoReply {
            return None;
        }
        return Some(HostObservation {
            method: HostDiscoveryMethod::Icmp,
            port: None,
            outcome: "echo-reply".to_string(),
            latency: Some(latency),
            ttl_hint: Some(ipv4.ttl),
            mac_address: None,
        });
    }

    if let Some(ipv6) = &ip.ipv6 {
        if IpAddr::V6(ipv6.source) != address {
            return None;
        }
        let icmpv6 = ip.icmpv6.as_ref()?;
        if icmpv6.icmpv6_type != Icmpv6Type::EchoReply {
            return None;
        }
        return Some(HostObservation {
            method: HostDiscoveryMethod::Icmp,
            port: None,
            outcome: "echo-reply".to_string(),
            latency: Some(latency),
            ttl_hint: Some(ipv6.hop_limit),
            mac_address: None,
        });
    }

    None
}

fn parse_icmp_scan_frame(
    interface: &Interface,
    address_set: &HashSet<IpAddr>,
    send_times: &BTreeMap<IpAddr, Instant>,
    frame: &Frame,
    captured_at: Instant,
    token: u32,
) -> Option<(IpAddr, HostObservation)> {
    if frame.payload.get(..4) != Some(token.to_be_bytes().as_slice()) {
        return None;
    }
    let ip = frame.ip.as_ref()?;
    let source_mac = frame
        .datalink
        .as_ref()
        .and_then(|datalink| datalink.ethernet.as_ref().map(|ethernet| ethernet.source));

    if let Some(ipv4) = &ip.ipv4 {
        let address = IpAddr::V4(ipv4.source);
        if !address_set.contains(&address) {
            return None;
        }
        let icmp = ip.icmp.as_ref()?;
        if icmp.icmp_type != IcmpType::EchoReply {
            return None;
        }
        let latency = Some(captured_at.checked_duration_since(*send_times.get(&address)?)?);
        return Some((
            address,
            HostObservation {
                method: HostDiscoveryMethod::Icmp,
                port: None,
                outcome: "echo-reply".to_string(),
                latency,
                ttl_hint: Some(ipv4.ttl),
                mac_address: if is_direct_neighbor(interface, address) {
                    source_mac.map(|mac| mac.to_string())
                } else {
                    None
                },
            },
        ));
    }

    if let Some(ipv6) = &ip.ipv6 {
        let address = IpAddr::V6(ipv6.source);
        if !address_set.contains(&address) {
            return None;
        }
        let icmpv6 = ip.icmpv6.as_ref()?;
        if icmpv6.icmpv6_type != Icmpv6Type::EchoReply {
            return None;
        }
        let latency = Some(captured_at.checked_duration_since(*send_times.get(&address)?)?);
        return Some((
            address,
            HostObservation {
                method: HostDiscoveryMethod::Icmp,
                port: None,
                outcome: "echo-reply".to_string(),
                latency,
                ttl_hint: Some(ipv6.hop_limit),
                mac_address: if is_direct_neighbor(interface, address) {
                    source_mac.map(|mac| mac.to_string())
                } else {
                    None
                },
            },
        ));
    }

    None
}

fn parse_icmp_scan_frames(
    interface: &Interface,
    addresses: &[IpAddr],
    send_times: &BTreeMap<IpAddr, Instant>,
    frames: Vec<CapturedFrame>,
    token: u32,
) -> BTreeMap<IpAddr, HostObservation> {
    let address_set: HashSet<IpAddr> = addresses.iter().copied().collect();
    let mut results = BTreeMap::new();

    for captured in frames {
        if let Some((address, observation)) = parse_icmp_scan_frame(
            interface,
            &address_set,
            send_times,
            &captured.frame,
            captured.captured_at,
            token,
        ) {
            results.entry(address).or_insert(observation);
        }
    }

    results
}

fn is_direct_neighbor(interface: &Interface, address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => interface
            .ipv4
            .iter()
            .any(|network| network.contains(&address)),
        IpAddr::V6(address) => interface
            .ipv6
            .iter()
            .any(|network| network.contains(&address)),
    }
}

fn capture_parse_option(interface: &Interface) -> nex::packet::frame::ParseOption {
    let mut parse_option = nex::packet::frame::ParseOption::default();
    if interface.is_tun()
        || (cfg!(any(target_os = "macos", target_os = "ios")) && interface.is_loopback())
    {
        parse_option.from_ip_packet = true;
        parse_option.offset = if interface.is_loopback() { 14 } else { 0 };
    }
    parse_option
}

fn resolve_interface(interface_name: Option<&str>) -> std::io::Result<Interface> {
    if let Some(name) = interface_name {
        return get_interface_by_name(name.to_string()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("interface not found: {name}"),
            )
        });
    }
    netdev::get_default_interface().map_err(std::io::Error::other)
}

pub(crate) fn local_bind_addr(
    address: IpAddr,
    interface_name: Option<&str>,
) -> std::io::Result<SocketAddr> {
    if let Some(name) = interface_name {
        return interface_bind_addr(address, &resolve_interface(Some(name))?);
    }
    Ok(match address {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
    })
}

fn interface_bind_addr(address: IpAddr, interface: &Interface) -> std::io::Result<SocketAddr> {
    let source = source_ip_for(interface, address);
    if source.is_unspecified() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "interface has no source address matching the destination family and scope",
        ));
    }
    Ok(scoped_socket_addr(source, 0, interface.index))
}

fn scoped_socket_addr(address: IpAddr, port: u16, interface_index: u32) -> SocketAddr {
    let mut socket = SocketAddr::new(address, port);
    if let SocketAddr::V6(socket) = &mut socket
        && socket.ip().is_unicast_link_local()
    {
        socket.set_scope_id(interface_index);
    }
    socket
}

pub(crate) fn remote_socket_addr(
    address: IpAddr,
    port: u16,
    interface_name: Option<&str>,
) -> std::io::Result<SocketAddr> {
    let index = if matches!(address, IpAddr::V6(ip) if ip.is_unicast_link_local()) {
        interface_name
            .map(|name| resolve_interface(Some(name)).map(|interface| interface.index))
            .transpose()?
            .unwrap_or(0)
    } else {
        0
    };
    Ok(scoped_socket_addr(address, port, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_interface() -> Interface {
        let mut interface = Interface::dummy();
        interface.ipv4.push("192.0.2.1/24".parse().unwrap());
        interface.ipv6.push("2001:db8::1/64".parse().unwrap());
        interface
    }

    #[test]
    fn socket_binding_selects_address_scope_and_preserves_zone() {
        let mut interface = fixture_interface();
        interface.index = 7;
        interface.ipv6.insert(0, "fe80::1/64".parse().unwrap());
        let global = interface_bind_addr("2001:db8::2".parse().unwrap(), &interface).unwrap();
        assert_eq!(global.ip(), "2001:db8::1".parse::<IpAddr>().unwrap());
        let local = interface_bind_addr("fe80::2".parse().unwrap(), &interface).unwrap();
        assert_eq!(local.to_string(), "[fe80::1%7]:0");
        assert_eq!(
            scoped_socket_addr("fe80::2".parse().unwrap(), 80, 7).to_string(),
            "[fe80::2%7]:80"
        );
        interface.ipv6.clear();
        assert!(interface_bind_addr("fe80::2".parse().unwrap(), &interface).is_err());
    }

    #[test]
    fn syn_replies_must_acknowledge_the_current_probe() {
        let interface = fixture_interface();
        for address in ["192.0.2.2", "2001:db8::2"] {
            let address: IpAddr = address.parse().unwrap();
            let sequence = u32::MAX;
            let packet =
                build_tcp_syn_packet(&interface, address, 80, netdev::MacAddr::zero(), sequence)
                    .unwrap();
            let sent = Frame::from_buf(&packet, Default::default()).unwrap();
            assert_eq!(
                sent.transport
                    .as_ref()
                    .unwrap()
                    .tcp
                    .as_ref()
                    .unwrap()
                    .sequence,
                sequence
            );
            let mut reply = sent;
            let ip = reply.ip.as_mut().unwrap();
            match address {
                IpAddr::V4(address) => ip.ipv4.as_mut().unwrap().source = address,
                IpAddr::V6(address) => ip.ipv6.as_mut().unwrap().source = address,
            }
            let tcp = reply.transport.as_mut().unwrap().tcp.as_mut().unwrap();
            tcp.source = 80;
            tcp.destination = SYN_SOURCE_PORT;
            tcp.flags = TcpFlags::SYN | TcpFlags::ACK;
            tcp.acknowledgement = sequence.wrapping_add(1);
            assert!(
                parse_syn_frames(address, 80, SYN_SOURCE_PORT, sequence, vec![reply.clone()])
                    .is_ok()
            );
            assert!(
                parse_syn_frames(address, 80, SYN_SOURCE_PORT, 123, vec![reply.clone()]).is_err()
            );
            assert!(matches!(
                parse_syn_scan_frames(address, &[80], SYN_SOURCE_PORT, 123, vec![reply.clone()])
                    [&80],
                SynPortStatus::Filtered
            ));
            assert!(matches!(
                parse_syn_scan_frames_multi(
                    &[(address, vec![80])],
                    SYN_SOURCE_PORT,
                    123,
                    vec![reply.clone()]
                )[&address][&80],
                SynPortStatus::Filtered
            ));
            reply
                .transport
                .as_mut()
                .unwrap()
                .tcp
                .as_mut()
                .unwrap()
                .flags = TcpFlags::RST | TcpFlags::ACK;
            assert!(matches!(
                parse_syn_scan_frames(
                    address,
                    &[80],
                    SYN_SOURCE_PORT,
                    sequence,
                    vec![reply.clone()]
                )[&80],
                SynPortStatus::Closed(_)
            ));
            reply
                .transport
                .as_mut()
                .unwrap()
                .tcp
                .as_mut()
                .unwrap()
                .flags = TcpFlags::RST;
            assert!(matches!(
                parse_syn_scan_frames(address, &[80], SYN_SOURCE_PORT, sequence, vec![reply])[&80],
                SynPortStatus::Filtered
            ));
        }
    }

    #[test]
    fn icmp_discovery_rejects_other_operations_and_pre_send_frames() {
        let interface = fixture_interface();
        let token = 0x12345678;
        for address in ["192.0.2.2", "2001:db8::2"] {
            let address: IpAddr = address.parse().unwrap();
            let packet =
                build_icmp_echo_packet(&interface, address, netdev::MacAddr::zero(), token)
                    .unwrap();
            let mut reply = Frame::from_buf(&packet, Default::default()).unwrap();
            let ip = reply.ip.as_mut().unwrap();
            match address {
                IpAddr::V4(address) => {
                    ip.ipv4.as_mut().unwrap().source = address;
                    ip.icmp.as_mut().unwrap().icmp_type = IcmpType::EchoReply;
                }
                IpAddr::V6(address) => {
                    ip.ipv6.as_mut().unwrap().source = address;
                    ip.icmpv6.as_mut().unwrap().icmpv6_type = Icmpv6Type::EchoReply;
                }
            }
            assert!(parse_icmp_host_frame(address, &reply, Duration::ZERO, token).is_some());
            assert!(parse_icmp_host_frame(address, &reply, Duration::ZERO, token + 1).is_none());
            let captured = Instant::now();
            let addresses = HashSet::from([address]);
            let sent = BTreeMap::from([(address, captured)]);
            assert!(
                parse_icmp_scan_frame(&interface, &addresses, &sent, &reply, captured, token)
                    .is_some()
            );
            assert!(
                parse_icmp_scan_frame(&interface, &addresses, &sent, &reply, captured, token + 1)
                    .is_none()
            );
            let sent = BTreeMap::from([(address, captured + Duration::from_millis(1))]);
            assert!(
                parse_icmp_scan_frame(&interface, &addresses, &sent, &reply, captured, token)
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn socket_transports_reject_missing_interfaces_before_connecting() {
        for transport in [Transport::Tcp, Transport::Udp, Transport::Quic] {
            let error = SocketConnector
                .connect(
                    "127.0.0.1".parse().unwrap(),
                    9,
                    transport,
                    Duration::from_millis(50),
                    Some("nrev-test-nonexistent-interface"),
                    Some("127.0.0.1"),
                )
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        }
    }
}
