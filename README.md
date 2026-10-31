# nrev

A cross-platform tool for port scanning, host discovery, and service probing.

Features:

- Port scanning with TCP, UDP, TCP-SYN, and QUIC transports
- Host discovery with ICMP, UDP, and TCP probes
- Ping with ICMP, UDP, TCP, and QUIC probes
- Traceroute with UDP and ICMP probes
- Neighbor discovery with ARP and NDP
- Service probes, TLS metadata, and HTTP/3 support
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

```sh
nrev port 192.168.10.10 --ports 22,80,443
nrev port 192.168.10.10 --transport quic --ports 443
nrev host 192.168.10.0/24 --method tcp --ports 80,443
nrev port 192.168.10.10 --format json --output result.json
```

Add `--nmap` for service/version identification or `--os-detect` for OS
identification. These options require Nmap to be installed separately.

```sh
nrev port 192.168.10.10 --ports top-100 --nmap
```

Only scan systems you own or have permission to test.

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
sudo nrev host 192.168.1.0/24
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
