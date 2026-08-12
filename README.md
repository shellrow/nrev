# nrev

An observation-first, cross-platform network mapper for discovery and probing.

`nrev` focuses on:

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
### Install prebuilt binaries via shell script

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/nrev/releases/latest/download/nrev-installer.sh | sh
```

### Install prebuilt binaries via powershell script

```sh
irm https://github.com/shellrow/nrev/releases/latest/download/nrev-installer.ps1 | iex
```

### From Releases
You can download archives of precompiled binaries from the [releases](https://github.com/shellrow/nrev/releases) .

### Cargo
If you have Rust and the Cargo package manager installed on your system, you can install (download and build) `nrev` with the following command:
```
cargo install nrev
```

Or you can use [binstall](https://github.com/cargo-bins/cargo-binstall) for install nrev from github release.
```
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

`nrev` provides:

- Compact human-readable reports for interactive use
- Stable JSON reports for downstream tooling
- Phase timings for resolution, discovery, scanning, and follow-up probes

JSON reports carry an explicit `schema_version`. Enum values use stable
`snake_case` names so reports can be consumed without depending on Rust type
names. File output is written atomically to avoid leaving a partial report.
TLS and QUIC certificates are observed rather than trusted; reports mark
`certificate_validation` as `not_performed` and must not be used as a trust
decision.

## Operational safety

Only scan systems you own or are authorized to assess. Target expansion is
limited to 65,536 unique addresses and 1,000,000 endpoint assignments per
invocation so an accidental IPv6 network or target/port Cartesian product
cannot exhaust memory. Split larger authorized inventories into task files and
separate invocations.

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

### Note for Linux Users
`nrev` requires elevated privileges to send/receive raw-packet. On Linux, you can configure these privileges using two main methods:

#### 1. Using `setcap`

Granting capabilities to the `nrev` binary allows it to operate with the necessary privileges without requiring `sudo` for each execution.  
This method is recommended for single-user machines or in environments where all users are trusted.

Assign necessary capabilities to the nrev binary
```sh
sudo setcap 'cap_net_raw,cap_net_admin+ep' "$(command -v nrev)"
```

Run nrev as an unprivileged user:
```sh
nrev
```

The `cap_net_raw` and `cap_net_admin` capabilities enable raw packet sending
and capture. Grant them only on trusted systems and to trusted binaries.

#### 2. Using `sudo` (for multi-user environments)
For environments with multiple users, requiring privilege escalation each time nrev is run can enhance security.
```
sudo nrev
```

### Note for macOS Users
On macOS, managing access to the Berkeley Packet Filter (BPF) devices is necessary for `nrev` to send/receive raw-packet
Alternatively, of course, you can also use `sudo` to temporarily grant the necessary permissions.
#### Install `chmod-bpf` to automatically manage permissions for BPF devices:

Install prebuilt binaries via shell script
```
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/shellrow/chmod-bpf/releases/latest/download/chmod-bpf-installer.sh | sh
```

#### Check BPF device permissions
```
chmod-bpf check
```

#### Install the chmod-bpf daemon to automatically manage BPF device permissions
```
sudo chmod-bpf install
```

### Note for Windows Users
- Ensure that you have [Npcap](https://npcap.com/#download) installed, which is necessary for `nrev` to send/receive raw-packet on Windows
- Download and install Npcap from [Npcap](https://npcap.com/#download). Choose the "Install Npcap in WinPcap API-compatible Mode" during installation.
- Npcap is loaded at runtime; building `nrev` does not require the Npcap SDK.
