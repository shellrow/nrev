[crates-badge]: https://img.shields.io/crates/v/nerum.svg
[crates-url]: https://crates.io/crates/nerum

# nerum [![Crates.io][crates-badge]][crates-url]
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

### Precompiled binaries
Archives of precompiled binaries for `nerum` are available for Linux, macOS and Windows.  
You can download from the [releases](https://github.com/shellrow/nerum/releases) .

### Cargo
If you have Rust and the Cargo package manager installed on your system, you can install (download and build) `nerum` with the following command:
```
cargo install nerum
```

Or you can use [binstall](https://github.com/cargo-bins/cargo-binstall) for install nerum from github release.
```
cargo binstall nerum
```

## Usage
```
nerum --help
```
Or
```
nerum <sub-command> --help
```

## Examples
### Default 
Initial ping and scan default 1000 ports
```
nerum --host scanme.nmap.org
```

### Port scan
Scan default 1000 ports
```
nerum pscan scanme.nmap.org
```

Specify the ports
```
nerum pscan scanme.nmap.org --ports 22,80,443,5000,8080
```

Specify the range
```
nerum pscan scanme.nmap.org --range 20-100
```

Scan well-known ports
```
nerum pscan scanme.nmap.org --wellknown
```

#### Settings
By default, nerum determines the waiting time until packet reception (before concluding the scan task) based on the results of the initial PING.  
The initial PING is executed in the order of ICMP Ping, UDP Ping, TCP Ping (on port 80), and if successful, proceeds to the next scan task.  
If all PING attempts fail, nerum exits before executing the scan. This step can be skipped by setting the `--noping` flag.  
For other settings, please refer to `nerum pscan -h` for details.

### Host scan
```
nerum hscan 192.168.1.1/24
```

```
nerum hscan <path-to-host-list>
```

### Ping 
Default ICMP Ping
```
nerum ping 1.1.1.1
```

UDP Ping
```
nerum ping 1.1.1.1 -P UDP
```

TCP Ping
```
nerum ping 1.1.1.1:443 -P TCP
```

### Traceroute
TCP Ping
```
nerum trace 8.8.8.8
```

You can specify the interval in milliseconds for faster trace.
```
nerum trace 8.8.8.8 --rate 500
```

### Subdomain scan
```
nerum subdomain google.com
```

### Neighbor (ARP/NDP)
```
nerum nei 192.168.1.1
```

### Specify the network interface
```
nerum -i tun0 pscan 10.10.11.14
```

## Privileges
`nerum` uses a raw socket which require elevated privileges. Execute with administrator privileges.

## Note for Windows Users
If you are using Windows, please consider the following points before building and running the application:

- Npcap or WinPcap Installation:
    - Ensure that you have [Npcap](https://npcap.com/#download) or WinPcap installed on your system.
    - You can check installation by `nerum check` command. Or Please install Npcap from https://npcap.com/#download
    - If using Npcap, make sure to install it with the "Install Npcap in WinPcap API-compatible Mode" option.
- Build Dependencies:
    - Place the Packet.lib file from the [Npcap SDK](https://npcap.com/#download) or WinPcap Developers pack in a directory named lib at the root of this repository.
    - You can use any of the locations listed in the %LIB% or $Env:LIB environment variables.
    - For the 64-bit toolchain, the Packet.lib is located in <SDK>/Lib/x64/Packet.lib.
    - For the 32-bit toolchain, the Packet.lib is located in <SDK>/Lib/Packet.lib.
