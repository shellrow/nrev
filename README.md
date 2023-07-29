# NetProbe
The Simple and High-Performance Network Mapper for discovery and management.

## Installation
To get started with NetProbe, download the latest installer from the [releases](https://github.com/shellrow/netprobe/releases) page.

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

## Privileges
Please note that `netprobe` utilizes a raw socket, which requires elevated privileges. By default, the application attempts to start with administrator privileges to ensure the seamless execution of network scanning features. If the application encounters any issues with permissions during startup, make sure to run it with appropriate administrative rights.

## Note for Windows users
For Traceroute functionality on Windows, you may need to set up firewall rules that allow `ICMP Time-to-live Exceeded` and `ICMP Destination (Port) Unreachable` packets to be received. Here's an example of using netsh to add the necessary rules:
```
netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any
netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
```

## Related my projects
- [default-net](https://github.com/shellrow/default-net)
- [netscan](https://github.com/shellrow/netscan)
- [tracert](https://github.com/shellrow/tracert)