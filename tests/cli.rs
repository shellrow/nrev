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
        stream.set_nonblocking(false).unwrap();
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

fn scan_command(target: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nrev"));
    command.args([
        "port",
        target,
        "--no-builtin-probes",
        "--connect-timeout-ms",
        "50",
        "--format",
        "json",
    ]);
    command
}

#[test]
fn standalone_scan_does_not_require_nmap_and_preflight_precedes_connections() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing-nmap");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let output = scan_command(&target)
        .arg("--nmap-path")
        .arg(&missing)
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.get("identification").is_none());
    assert!(report["targets"][0]["os_guesses"].is_null());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let output = scan_command(&listener.local_addr().unwrap().to_string())
        .args(["--nmap", "--nmap-path"])
        .arg(&missing)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Nmap unavailable"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(unix)]
mod identification {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    fn fake_nmap(dir: &Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("fake nmap");
        fs::write(&path, format!("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n echo 'Nmap version 7.993 (test)'\n exit 0\nfi\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn xml(port: u16) -> String {
        format!(
            r#"<nmaprun scanner="nmap" version="7.993"><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="{port}"><state state="closed" reason="reset"/><service name="http" tunnel="ssl" product="Fixture Server" version="1.2" method="probed" conf="10"><cpe>cpe:/a:fixture:server:1.2</cpe></service></port></ports><os><osmatch name="Fixture OS" accuracy="95"/></os></host><runstats><finished exit="success"/></runstats></nmaprun>"#
        )
    }

    #[test]
    fn external_results_are_separate_and_task_settings_are_honored() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let fake = fake_nmap(
            dir.path(),
            &format!(
                "case \"$*\" in *'--version-intensity 2'*) ;; *) exit 3;; esac\necho 'fixture warning' >&2\ncat <<'XML'\n{}\nXML",
                xml(address.port())
            ),
        );
        let task = dir.path().join("scan.json");
        fs::write(&task, serde_json::to_vec(&serde_json::json!({
            "target": address.to_string(), "builtin_probes": false,
            "connect_timeout_ms": 50, "format": "json", "output": "result.json",
            "identification": {"services": true, "os": true, "executable": "./fake nmap", "intensity": 2}
        })).unwrap()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_nrev"))
            .arg("task")
            .arg(task)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.path().join("result.json")).unwrap()).unwrap();
        assert_eq!(report, saved);
        assert_eq!(
            report["targets"][0]["endpoints"][address.port().to_string()]["state"],
            "open"
        );
        let details = &report["identification"];
        assert_eq!(details["complete"], true);
        assert_eq!(details["version"], "7.993");
        assert_eq!(details["hosts"][0]["ports"][0]["state"]["state"], "closed");
        assert_eq!(details["hosts"][0]["ports"][0]["service"]["tunnel"], "ssl");
        assert_eq!(details["hosts"][0]["os_matches"][0]["name"], "Fixture OS");
        assert!(!details["warnings"].as_array().unwrap().is_empty());
        let output = Command::new(env!("CARGO_BIN_EXE_nrev"))
            .args([
                "port",
                &address.to_string(),
                "--no-builtin-probes",
                "--connect-timeout-ms",
                "50",
                "--nmap",
                "--nmap-intensity",
                "2",
                "--nmap-path",
            ])
            .arg(fake)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("Fixture Server"));
    }

    #[test]
    fn failures_preserve_basic_results_and_return_failure() {
        for body in [
            "echo fixture-error >&2; exit 2",
            "echo '<broken'",
            "exec sleep 10",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let fake = fake_nmap(dir.path(), body);
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let path = dir.path().join("report.json");
            let started = Instant::now();
            let output = scan_command(&address.to_string())
                .args(["--nmap", "--nmap-timeout-ms", "50", "--nmap-path"])
                .arg(fake)
                .arg("--output")
                .arg(&path)
                .output()
                .unwrap();
            assert!(started.elapsed() < Duration::from_secs(5));
            assert!(!output.status.success());
            let report: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(
                report,
                serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
            );
            assert_eq!(
                report["targets"][0]["endpoints"][address.port().to_string()]["state"],
                "open"
            );
            assert_eq!(report["identification"]["complete"], false);
            assert!(report["identification"]["error"].is_string());
        }
    }

    #[test]
    fn later_host_failure_keeps_completed_identification() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let fake = fake_nmap(
            dir.path(),
            &format!(
                "for target do :; done\nif [ \"$target\" != '127.0.0.1' ]; then exit 2; fi\ncat <<'XML'\n{}\nXML",
                xml(address.port())
            ),
        );
        let output = scan_command(&address.to_string())
            .arg(format!("127.0.0.2:{}", address.port()))
            .args(["--nmap", "--nmap-scope", "all", "--nmap-path"])
            .arg(fake)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["targets"].as_array().unwrap().len(), 2);
        assert_eq!(report["identification"]["complete"], false);
        assert_eq!(
            report["identification"]["hosts"].as_array().unwrap().len(),
            1
        );
        assert_eq!(report["identification"]["hosts"][0]["ip"], "127.0.0.1");
    }
    #[test]
    fn udp_identification_retains_summaries_without_changing_native_states() {
        let dir = tempfile::tempdir().unwrap();
        let xml = r#"<nmaprun scanner="nmap" version="7.993"><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><extraports state="open|filtered" count="2"><extrareasons reason="no-response" count="2" proto="udp" ports="53,161"/></extraports><port protocol="udp" portid="5353"><state state="open" reason="udp-response"/><service name="domain" product="Fixture DNS" method="probed" conf="10"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>"#;
        let fake = fake_nmap(
            dir.path(),
            &format!("case \"$*\" in *'-sU'*) ;; *) exit 3;; esac\ncat <<'XML'\n{xml}\nXML"),
        );
        let output = scan_command("127.0.0.1")
            .args([
                "--ports",
                "53,161,5353",
                "--transport",
                "udp",
                "--nmap",
                "--nmap-path",
            ])
            .arg(fake)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let host = &report["identification"]["hosts"][0];
        assert_eq!(host["ports"][0]["protocol"], "udp");
        assert_eq!(host["port_summaries"][0]["count"], 2);
        assert_eq!(host["os_matches"], serde_json::json!([]));
        assert_eq!(
            report["targets"][0]["endpoints"]["5353"]["state"],
            "open_filtered"
        );
        let decoded = serde_json::from_value(report).unwrap();
        let human = nrev::output::render_human_scan_report(&decoded, false);
        assert!(human.contains("2 port(s): open|filtered"));
        assert!(human.contains("Fixture DNS"));
    }

    #[test]
    fn os_only_toml_task_uses_os_detection_without_service_probes() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        fake_nmap(
            dir.path(),
            &format!(
                "case \"$*\" in *'-O'*) ;; *) exit 3;; esac\ncase \"$*\" in *'-sV'*) exit 4;; esac\ncat <<'XML'\n{}\nXML",
                xml(address.port())
            ),
        );
        let task = dir.path().join("scan.toml");
        fs::write(
            &task,
            format!(
                r#"
target = "{address}"
builtin_probes = false
connect_timeout_ms = 50
format = "json"
[identification]
os = true
executable = "./fake nmap"
"#
            ),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_nrev"))
            .arg("task")
            .arg(task)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["identification"]["hosts"][0]["os_matches"][0]["accuracy"],
            95
        );
        assert!(report["targets"][0].get("os_guesses").is_none());
    }

    #[test]
    fn incompatible_os_mode_is_rejected_before_starting_nmap() {
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_nmap(dir.path(), "exit 99");
        let output = scan_command("127.0.0.1:53")
            .args(["--transport", "udp", "--os-detect", "--nmap-path"])
            .arg(fake)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("requires a TCP or SYN scan"));
    }
}

#[test]
fn progress_color_is_optional_and_never_changes_json_output() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    for (flags, no_color, colored) in [
        (vec![], false, false),
        (vec!["--color", "always"], false, true),
        (vec!["--color", "never"], false, false),
        (vec!["--no-color"], false, false),
        (vec![], true, false),
        (vec!["--color", "always"], true, true),
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_nrev"));
        command.env_remove("NO_COLOR").env_remove("TERM");
        if no_color {
            command.env("NO_COLOR", "1");
        }
        let output = command
            .args(["port", &address, "--no-builtin-probes", "--format", "json"])
            .args(flags)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(output.stderr.contains(&0x1b), colored);
        assert!(!output.stdout.contains(&0x1b));
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap();
    }
}

#[test]
fn diagnostic_color_option_works_before_the_subcommand() {
    for (mode, colored) in [("always", true), ("never", false)] {
        let output = Command::new(env!("CARGO_BIN_EXE_nrev"))
            .args([
                "--color",
                mode,
                "port",
                "127.0.0.1",
                "--probes",
                "unknown-probe",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(output.stderr.contains(&0x1b), colored);
    }
}
