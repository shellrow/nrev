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
