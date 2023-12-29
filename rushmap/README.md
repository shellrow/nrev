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

## Note for Windows Users
If you are using Windows, please consider the following points before building and running the application:

- Npcap or WinPcap Installation:
    - Ensure that you have [Npcap](https://npcap.com/#download) or WinPcap installed on your system.
    - If using Npcap, make sure to install it with the "Install Npcap in WinPcap API-compatible Mode" option.
- Build Dependencies:
    - Place the Packet.lib file from the [Npcap SDK](https://npcap.com/#download) or WinPcap Developers pack in a directory named lib at the root of this repository.
    - You can use any of the locations listed in the %LIB% or $Env:LIB environment variables.
    - For the 64-bit toolchain, the Packet.lib is located in <SDK>/Lib/x64/Packet.lib.
    - For the 32-bit toolchain, the Packet.lib is located in <SDK>/Lib/Packet.lib.

## Related my projects
- [default-net](https://github.com/shellrow/default-net) Cross-platform library for network interface and gateway 
- [xenet](https://github.com/shellrow/xenet) Cross-platform networking library
- [netscan](https://github.com/shellrow/netscan) Cross-platform network scan library 
