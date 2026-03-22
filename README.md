# nrev

An observation-first, cross-platform network mapper for discovery and probing.

It focuses on:

- port scanning with TCP, UDP, TCP-SYN, and QUIC transports
- host discovery with ICMP, UDP, and TCP probes
- built-in service observation for common protocols
- structured JSON output for automation
- external data packs for probes, fingerprint rules, profiles, and recipes

## Commands

```text
Usage: nrev <COMMAND>

Commands:
  port    Scan ports and collect structured observations
  host    Discover reachable hosts with ICMP, UDP, or TCP probes
  probe   Show the built-in and externally loaded probe catalog
  recipe  Show externally loaded scan recipes
```

## Output

`nrev` provides:

- compact human-readable reports for interactive use
- stable JSON reports for downstream tooling
- phase timings for resolution, discovery, scanning, and follow-up probes

## External Data

`--data` accepts:

- a single `.json` file
- a single `.toml` file
- a directory containing multiple `.json` and `.toml` files

Each file may contain any combination of:

- `probes`
- `fingerprint_rules`
- `recipes`

## Samples

The repository includes sample data under [samples/](samples):

- [samples/recipes/](samples/recipes) for recipe-only examples
- [samples/data-pack/](samples/data-pack) for mixed external data pack examples

## Documentation

- [Usage Guide](docs/USAGE.md)

## Privileges
`nrev` uses a raw socket which require elevated privileges. Execute with administrator privileges.

### Note for Linux Users
`nrev` requires elevated privileges to send/receive raw-packet. On Linux, you can configure these privileges using two main methods:

#### 1. Using `setcap`

Granting capabilities to the `nrev` binary allows it to operate with the necessary privileges without requiring `sudo` for each execution.  
This method is recommended for single-user machines or in environments where all users are trusted.

Assign necessary capabilities to the nrev binary
```sh
sudo setcap 'cap_sys_ptrace,cap_dac_read_search,cap_net_raw,cap_net_admin+ep' $(command -v nrev)
```

Run nrev as an unprivileged user:
```sh
nrev
```

#### Capabilities Explained:
- `cap_sys_ptrace,cap_dac_read_search`: Allows `nrev` to access `/proc/<pid>/fd/` to identify which open port belongs to which process.
- `cap_net_raw,cap_net_admin`: Enables packet capturing capabilities.

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
- Build Dependencies:
    - Place the Packet.lib file from the [Npcap SDK](https://npcap.com/#download) or WinPcap Developers pack in a directory named lib at the root of this repository.
    - You can use any of the locations listed in the %LIB% or $Env:LIB environment variables.
    - For the 64-bit toolchain, the Packet.lib is located in <SDK>/Lib/x64/Packet.lib.
    - For the 32-bit toolchain, the Packet.lib is located in <SDK>/Lib/Packet.lib.
