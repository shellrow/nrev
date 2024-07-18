[crates-badge]: https://img.shields.io/crates/v/nrev.svg
[crates-url]: https://crates.io/crates/nrev

# nrev [![Crates.io][crates-badge]][crates-url]
Simple and Fast Network Mapper. Written in Rust.  
Designed to be used in network mapping, probe, and security tests.

## Features
- Port Scan
- Host Scan
- Ping
- Traceroute
- Neighbor Discovery
- Subdomain scan
- Show Network Interfaces

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

### Install prebuilt binaries via Homebrew

```sh
brew install shellrow/tap-nrev/nrev
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

## Basic Usage
### Default Port Scan 
To scan the default 1000 ports on a target, simply specify the target
```
nrev --target scanme.nmap.org
```

Sub-commands and Options
```
Usage: nrev [OPTIONS] [COMMAND]

Commands:
  port        Scan port. nrev port --help for more information
  host        Scan host in specified network or host-list. nrev host --help for more information
  ping        Ping to specified host. nrev ping --help for more information
  trace       Traceroute to specified host. nrev trace --help for more information
  subdomain   Find subdomains. nrev subdomain --help for more information
  nei         Resolve IP address to MAC address
  interfaces  Show network interfaces
  interface   Show default network interface
  check       Check dependencies (Windows only)
  help        Print this message or the help of the given subcommand(s)

Options:
  -t, --target <target>             Specify the target host. IP address or Hostname
  -i, --interface <interface_name>  Specify the network interface
      --noping                      Disable initial ping
  -F, --full                        Scan all ports (1-65535)
  -j, --json                        Displays results in JSON format.
  -o, --save <file_path>            Save scan result in JSON format - Example: -o result.json
  -h, --help                        Print help
  -V, --version                     Print version
```

## Examples
### Port scan
Scan default 1000 ports
```
nrev port scanme.nmap.org
```

Specify the ports
```
nrev port scanme.nmap.org --ports 22,80,443,5000,8080
```

Specify the range
```
nrev port scanme.nmap.org --range 20-100
```

Scan well-known ports
```
nrev port scanme.nmap.org --wellknown
```

#### Settings
By default, nrev determines the waiting time until packet reception (before concluding the scan task) based on the results of the initial PING.  
The initial PING is executed in the order of ICMP Ping, UDP Ping, TCP Ping (on port 80), and if successful, proceeds to the next scan task.  
If all PING attempts fail, nrev exits before executing the scan. This step can be skipped by setting the `--noping` flag.  
For other settings, please refer to `nrev port -h` for details.

### Host scan
ICMP Host scan
```
nrev host 192.168.1.0/24
```
```
nrev host <path-to-host-list>
```

TCP Host scan
```
nrev host 192.168.1.0/24 -P TCP --port 80
```

### Ping 
Default ICMP Ping
```
nrev ping 1.1.1.1
```

UDP Ping
```
nrev ping 1.1.1.1 -P UDP
```

TCP Ping
```
nrev ping 1.1.1.1:443 -P TCP
```

### Traceroute
TCP Ping
```
nrev trace 8.8.8.8
```

You can specify the interval in milliseconds for faster trace.
```
nrev trace 8.8.8.8 --rate 500
```

### Subdomain scan
```
nrev subdomain google.com
```

### Neighbor (ARP/NDP)
```
nrev nei 192.168.1.1
```

### Specify the network interface
```
nrev -i tun0 port 10.10.11.14
```

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

Install prebuilt binaries via Homebrew
```sh
brew install shellrow/tap-chmod-bpf/chmod-bpf
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
