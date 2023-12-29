# RushMap Desktop
High-Performance Network Mapper for discovery and management. with GUI.

## Features
- Port Scan
    - Service detection
    - OS detection
- Host Scan
- Ping
- Traceroute

## Supported platforms
- Linux
- macOS
- Windows

## Installation
To get started with RushMap Desktop, download the latest installer from the [releases](https://github.com/shellrow/rushmap/releases) page.

## Privileges
Please note that `rushmap-desktop` utilizes a raw socket, which requires elevated privileges. By default, the application attempts to start with administrator privileges to ensure the seamless execution of network scanning features. If the application encounters any issues with permissions during startup, make sure to run it with appropriate administrative rights.

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
