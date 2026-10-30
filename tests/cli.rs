use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[test]
fn http_scan_on_nonstandard_port_preserves_json_and_file_output() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(peer) => break peer,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "scanner did not connect");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut buf).unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&buf[..count]);
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .contains(&format!("Host: {address}\r\n"))
        );
        let body = "<title>Local fixture</title>";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nServer: fixture\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_nrev"))
        .args([
            "port",
            &address.to_string(),
            "--probes",
            "http",
            "--connect-timeout-ms",
            "500",
            "--probe-timeout-ms",
            "2000",
            "--quiet",
            "--format",
            "json",
            "--output",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(report, saved);
    let endpoint = &report["targets"][0]["endpoints"][address.port().to_string()];
    assert_eq!(endpoint["state"], "open");
    assert_eq!(endpoint["observations"][0]["probe_id"], "http");
    assert_eq!(endpoint["errors"], serde_json::json!([]));
    assert!(
        endpoint["observations"][0]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["key"] == "title" && item["value"] == "Local fixture")
    );
    server.join().unwrap();
}

#[test]
fn unknown_probe_is_a_cli_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_nrev"))
        .args(["port", "127.0.0.1", "--probes", "not-a-probe", "--quiet"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown probe"));
}
