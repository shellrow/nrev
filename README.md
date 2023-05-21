# nesmap-desktop
Network mapper for diagnosis and discovery
`nesmap-desktop` is a cross-platform graphical `nesmap` frontend.

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
`nesmap` and `nesmap-desktop` uses a raw socket which require elevated privileges.  Execute with administrator privileges.

## Note for Windows users
For Traceroute, you may need to set up firewall rules that allow `ICMP Time-to-live Exceeded` and `ICMP Destination (Port) Unreachable` packets to be received.

`netsh` example 
```
netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any
netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
```

## Additional Notes
Support for VM environments is in progress. Results may not be correct.
