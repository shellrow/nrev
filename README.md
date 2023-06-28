# enmap
The Simple and High-Performance GUI Network Mapper. Optimized for efficient network discovery and management.

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
`enmap` uses a raw socket which require elevated privileges.  Execute with administrator privileges.

## Note for Windows users
For Traceroute, you may need to set up firewall rules that allow `ICMP Time-to-live Exceeded` and `ICMP Destination (Port) Unreachable` packets to be received.

`netsh` example 
```
netsh advfirewall firewall add rule name="All ICMP v4" dir=in action=allow protocol=icmpv4:any,any
netsh advfirewall firewall add rule name="All ICMP v6" dir=in action=allow protocol=icmpv6:any,any
```

## Additional Notes
Support for VM environments is in progress. Results may not be correct.

## Related my projects
- [default-net](https://github.com/shellrow/default-net)
- [netscan](https://github.com/shellrow/netscan)
- [tracert](https://github.com/shellrow/tracert)
