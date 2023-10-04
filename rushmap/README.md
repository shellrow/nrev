[crates-badge]: https://img.shields.io/crates/v/rushmap.svg
[crates-url]: https://crates.io/crates/rushmap

# rushmap(rmap) [![Crates.io][crates-badge]][crates-url]
High-performance Network Mapper for discovery and management

>Please check the latest version on [GitHub](https://github.com/shellrow/rushmap) .  
>Publishing to crates.io may be discontinued in the future (if deemed unnecessary due to distribution methods).

## Features
- Port Scan
    - Service detection
    - OS detection
- Host Scan
- Ping
- Traceroute
- Subdomain scan

## Supported platforms
- Linux
- macOS
- Windows

## Installation
The binary name for rushmap is `rmap` .

### Precompiled binaries
Archives of precompiled binaries for `rushmap` are available for Linux, macOS and Windows.  
You can download from the [releases](https://github.com/shellrow/rushmap/releases) .

### Cargo
If you have Rust and the Cargo package manager installed on your system, you can install `rushmap` with the following command:
```
cargo install rushmap
```

### Using Installer (Coming Soon...)
Currently working on a dedicated installer for `rushmap` that will simplify the installation process even further.

## Usage
```
rmap --help
```

## Privileges
`rmap` uses a raw socket which require elevated privileges.  Execute with administrator privileges.

## Note for Windows users
- You must have npcap or WinPcap installed.
- For Traceroute, you may need to set up firewall rules that allow `ICMP Time-to-live Exceeded` and `ICMP Destination (Port) Unreachable` packets to be received.

`netsh` example 
```
netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any
netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
```

## Related my projects
- [default-net](https://github.com/shellrow/default-net)
- [cross-socket](https://github.com/shellrow/cross-socket)
- [netscan](https://github.com/shellrow/netscan)
- [tracert](https://github.com/shellrow/tracert)
