# nrev Usage

This guide shows common command patterns for `nrev`.

Replace example targets with systems you own or are authorized to test.

## Command Overview

```text
Usage: nrev <COMMAND>

Commands:
  port    Scan ports and collect structured observations
  task    Run a port-scan task from a JSON or TOML file
  host    Discover reachable hosts with ICMP, UDP, or TCP probes
  ping    Send repeated probes to a target with ICMP, UDP, TCP, or QUIC
  trace   Trace the path to a target with UDP or ICMP probes
  nei     Discover a neighbor with ARP or NDP
  probe   Show the built-in and externally loaded probe catalog
  recipe  Show externally loaded scan recipes
```

## Port Scanning

Basic TCP scan:

```sh
nrev port 192.168.10.10
nrev port 192.168.10.10 --ports 22,80,443,3389
nrev port 192.168.10.0/24 --ports top-100
```

Supported named port sets:

```sh
nrev port 192.168.10.10 --ports top-100
nrev port 192.168.10.10 --ports top-1000
nrev port 192.168.10.10 --ports well-known
```

UDP scan:

```sh
nrev port 192.168.10.10 --transport udp --ports 53,123
```

SYN scan:

```sh
nrev port 192.168.10.10 --transport syn --ports 22,80,443
nrev port 192.168.10.0/24 --transport syn --ports top-100
```

QUIC scan:

```sh
nrev port edge.example --transport quic --ports 443,8443
```

Host-and-port input:

```sh
nrev port 192.168.10.10:443
```

Show closed and filtered states in the human-readable report:

```sh
nrev port 192.168.10.10 --ports 22,80,443 --all-states
```

Write JSON output:

```sh
nrev port 192.168.10.10 --format json --output result.json
```

## Host Discovery

Basic reachability scan:

```sh
nrev host 192.168.10.0/24
```

TCP-based discovery on selected ports:

```sh
nrev host yourcorpone.com --method tcp --ports 80,443
```

UDP-based discovery:

```sh
nrev host 192.168.10.0/24 --method udp --ports 33434,40125
```

Read targets from a file:

```sh
nrev host @./targets.txt --method tcp --ports 80,443
```

Show unreachable hosts in the human-readable report:

```sh
nrev host 192.168.10.0/24 --all-hosts
```

Write JSON output:

```sh
nrev host 192.168.10.0/24 --format json --output hosts.json
```

## Ping

Basic ICMP ping:

```sh
nrev ping 192.168.10.10
```

UDP, TCP, and QUIC ping:

```sh
nrev ping example.com --method udp --port 33435
nrev ping example.com --method tcp --port 443
nrev ping example.com --method quic --port 443
```

Tune probe count and timing:

```sh
nrev ping example.com --count 5 --interval-ms 250 --timeout-ms 1500
```

Write JSON output:

```sh
nrev ping example.com --format json --output ping.json
```

## Traceroute

Basic UDP trace:

```sh
nrev trace example.com
```

ICMP trace:

```sh
nrev trace example.com --method icmp
```

Tune hop limit and timeout:

```sh
nrev trace example.com --max-hops 20 --interval-ms 250 --timeout-ms 1200
```

Write JSON output:

```sh
nrev trace example.com --format json --output trace.json
```

## Neighbor Discovery

Auto-select ARP for IPv4 and NDP for IPv6:

```sh
nrev nei 192.168.10.1
nrev nei fe80::1 --interface en0
```

Force a method explicitly:

```sh
nrev nei 192.168.10.1 --method arp
nrev nei fe80::1 --method ndp --interface en0
```

Write JSON output:

```sh
nrev nei 192.168.10.1 --format json --output neighbor.json
```

## Progress and Verbosity

Quiet mode:

```sh
nrev port 192.168.10.10 --quiet
```

Explicit progress mode:

```sh
nrev port 192.168.10.10 --progress verbose
```

Tune timeout and retry behavior:

```sh
nrev port 192.168.10.10 --connect-timeout-ms 1200 --probe-timeout-ms 3000 --retries 1
```

## Profiles

Load a profile file:

```sh
nrev port 192.168.10.10 --profile ./tmp/manual-tests/profile-web.toml
```

CLI flags override profile values:

```sh
nrev port 192.168.10.10 --profile ./tmp/manual-tests/profile-web.toml --ports 80,443
```

## Recipes

List sample recipes:

```sh
nrev recipe --data ./samples/recipes
```

Run a built-in sample recipe:

```sh
nrev port 192.168.10.10 --data ./samples/recipes --recipe web-balanced
nrev port 192.168.10.0/24 --data ./samples/recipes --recipe fast-syn-triage
```

Command-line targets and recipe selection remain supported:

```sh
nrev port 192.168.10.10 --data ./samples/recipes --recipe web-balanced
```

## Tasks

Run a task file that includes its own targets and scan settings:

```sh
nrev task ./samples/tasks/web-balanced.toml
```

Example task file:

```toml
name = "web-balanced"
targets = ["192.168.10.10", "@./targets.txt"]
data = "../recipes"
recipe = "web-balanced"
format = "json"
output = "./web-balanced-report.json"
```

Task files support the same port-scan settings as `nrev port`, including:

- `targets` or `target`
- `ports`
- `transport`
- `interface`
- `concurrency`
- `connect_timeout_ms`
- `probe_timeout_ms`
- `http_body_preview_bytes`
- `retries`
- `probes`
- `builtin_probes`
- `profile`
- `data`
- `recipe`
- `all_states`
- `quiet`
- `progress`
- `format`
- `output`

Relative paths in `profile`, `data`, and `output` are resolved from the task file location.

## External Data Packs

Show probes from a mixed data-pack directory:

```sh
nrev probe --data ./samples/data-pack
```

Show recipes from the bundled JSON pack:

```sh
nrev recipe --data ./samples/data-pack/pack.json --json
```

Run a scan with an external recipe:

```sh
nrev port 192.168.10.10 --data ./samples/data-pack --recipe corp-web-alt
nrev port 192.168.10.130 --data ./samples/data-pack/pack.json --recipe corp-quic
```

Run only external probes:

```sh
nrev port 192.168.10.10 --ports 8080,8088 --data ./samples/data-pack --probes corp-http-alt --no-builtin-probes
```

## Short Options

Common short forms:

```sh
nrev port 192.168.10.10 -p 80,443 -t tcp -c 128 -q -f json -o result.json
nrev host 192.168.10.0/24 -m tcp -p 80,443 -c 128 -t 1200 -f json -o hosts.json
nrev ping example.com -m tcp -p 443 -c 5 -t 1500 -f json -o ping.json
nrev trace example.com -m icmp -t 1200 -f json -o trace.json
nrev nei 192.168.10.1 -m arp -t 1000 -f json -o neighbor.json
nrev probe -d ./samples/data-pack -j
nrev recipe -d ./samples/recipes -j
```
