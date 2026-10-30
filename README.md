# nrev

A cross-platform tool for port scanning, host discovery, and service probing.

Features:

- Port scanning with TCP, UDP, TCP-SYN, and QUIC transports
- Host discovery with ICMP, UDP, and TCP probes
- Active ping with ICMP, UDP, TCP, and QUIC methods
- Traceroute with UDP and ICMP probes
- Neighbor discovery with ARP and NDP
- Built-in service observation for common protocols
- Structured JSON output for automation
- External data packs for probes, fingerprint rules, profiles, and recipes
- Task files for repeatable target lists and scan executions

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

## Output

Reports include:

- Human-readable output
- JSON output with a versioned schema
- Phase timings for resolution, discovery, scanning, and follow-up probes

JSON reports include `metadata.schema_version` and use `snake_case` enum values.
File output is written atomically to avoid leaving a partial report.
TLS and QUIC certificates are observed rather than trusted; reports mark
`certificate_validation` as `not_performed` and must not be used as a trust
decision.

## Operational safety

Only scan systems you own or are authorized to assess. Target expansion is
limited to 65,536 unique addresses and 1,000,000 endpoint assignments per
invocation. Split larger inventories across separate invocations.

## External Data

`--data` accepts:

- A single `.json` file
- A single `.toml` file
- A directory containing multiple `.json` and `.toml` files

Each file may contain any combination of:

- `probes`
- `fingerprint_rules`
- `recipes`

## Samples

The repository includes sample data under [samples/](samples):

- [samples/recipes/](samples/recipes) for recipe-only examples
- [samples/data-pack/](samples/data-pack) for mixed external data pack examples
- [samples/tasks/](samples/tasks) for runnable task-file examples

## Documentation

- [Usage Guide](docs/USAGE.md)

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
