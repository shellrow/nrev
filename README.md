# nrev

A cross-platform tool for port scanning, host discovery, and service probing.

Features:

- Port scanning with TCP, UDP, TCP-SYN, and QUIC transports
- Host discovery with ICMP, UDP, and TCP probes
- Ping with ICMP, UDP, TCP, and QUIC probes
- Traceroute with UDP and ICMP probes
- Neighbor discovery with ARP and NDP
- Service probes, TLS metadata, and HTTP/3 support
- Evidence-based product inventory, offline report replay, and optional local advisory correlation
- Optional detailed service and OS identification through Nmap
- Structured JSON output for automation
- External data packs for probes, fingerprint rules, profiles, and recipes
- Task files for repeatable scans

## Supported platforms

- Linux
- macOS
- Windows

## Installation

### Shell installer

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/nrev/releases/latest/download/nrev-installer.sh | sh
```

### PowerShell installer

```sh
irm https://github.com/shellrow/nrev/releases/latest/download/nrev-installer.ps1 | iex
```

### Release archives

Download prebuilt binaries from [GitHub Releases](https://github.com/shellrow/nrev/releases).

### Cargo

Build and install with Cargo:

```sh
cargo install nrev
```

Or install a prebuilt binary with [cargo-binstall](https://github.com/cargo-bins/cargo-binstall):

```sh
cargo binstall nrev
```

## Commands

```text
Usage: nrev <COMMAND>

Commands:
  inventory  Replay a saved port report as a technology inventory
  port    Scan ports and collect structured observations
  task    Run a port-scan task from a JSON or TOML file
  host    Discover reachable hosts with ICMP, UDP, or TCP probes
  ping    Send repeated probes to a target with ICMP, UDP, TCP, or QUIC
  trace   Trace the path to a target with UDP or ICMP probes
  nei     Discover a neighbor with ARP or NDP
  probe   Show the built-in and externally loaded probe catalog
  recipe  Show externally loaded scan recipes
```

## Quick start

Replace the example addresses with your own targets.

```sh
nrev port 192.0.2.10 --ports 22,80,443
nrev port 192.0.2.10 --transport quic --ports 443
nrev host 192.0.2.0/24 --method tcp --ports 80,443
nrev port 192.0.2.10 --format json --output result.json
```

The default port report shows native probe observations, identified products
and versions. Use `-S` or `--service` for the evidence supporting each identification.
A directly addressed web service such as `nrev port localhost:44321` can be
identified as HTTP or HTTPS without choosing a probe. Add `-O` or
`--os` to collect TCP stack evidence with SYN transport. Existing
users can request a separately installed Nmap with `--nmap` or `--nmap-os`.

```sh
nrev port 127.0.0.1 --ports 22,80,443 -O
```

Only scan systems you own or have permission to test.

## Technology inventory

The embedded database identifies web servers and frameworks, proxies, managed
services, platform APIs, data stores, DNS servers and remote access services.
The [coverage guide](docs/TECHNOLOGY.md#bundled-product-coverage) describes
which observations identify each product and when a version can be reported.

Replay the included synthetic scan with a local advisory. The inventory includes
the observed version, evidence references, upstream range and configuration
review needed for each candidate.

```sh
nrev inventory samples/inventory/scan.json --advisories samples/inventory/advisories.json --format human
```

For live collection, add `--service` to a port scan. Save the underlying
observations with `--output` to reproduce the inference later. See the
[technology inventory guide](docs/TECHNOLOGY.md).

## Documentation and examples

See the [usage guide](docs/USAGE.md) for scan options, output formats, and
configuration. Run `nrev <command> --help` for the full option list.

- [Recipes](samples/recipes): reusable scan settings
- [Data packs](samples/data-pack): custom probes, fingerprint rules, and recipes
- [Tasks](samples/tasks): targets and scan settings in one file

## Privileges

Raw-packet modes require elevated network privileges. TCP connect mode does not
normally require administrator access.

### Linux

Grant raw-packet permissions with `setcap`:

```sh
sudo setcap 'cap_net_raw,cap_net_admin+ep' "$(command -v nrev)"
```

These capabilities allow the binary to send and capture raw packets without
`sudo`. Grant them only to trusted binaries on systems where all users are
trusted. Alternatively, run individual commands with `sudo`:

```sh
sudo nrev host 192.0.2.0/24
```

### macOS

Raw-packet modes require access to Berkeley Packet Filter (BPF) devices. Run
commands with `sudo`, or use [chmod-bpf](https://github.com/shellrow/chmod-bpf)
to manage BPF permissions.

Install `chmod-bpf`:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/chmod-bpf/releases/latest/download/chmod-bpf-installer.sh | sh
```

Check permissions and install the daemon:

```sh
chmod-bpf check
sudo chmod-bpf install
```

### Windows

Raw-packet modes require [Npcap](https://npcap.com/#download). Select
"Install Npcap in WinPcap API-compatible Mode" during installation.
Npcap is loaded at runtime; building `nrev` does not require the Npcap SDK.

Raw probes to Windows loopback addresses (`127.0.0.1` and `::1`) are currently
unsupported by the datalink backend. Use TCP, UDP, or QUIC socket probes for
loopback targets.

## License

nrev is available under the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
Attribution for the embedded knowledge database is in [knowledge/NOTICE](knowledge/NOTICE).
