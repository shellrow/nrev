# nrev Usage

This guide shows common command patterns for `nrev`.

Replace example targets with systems you own or are authorized to test.

## Command Overview

```text
Usage: nrev <COMMAND>

Commands:
  port    Scan ports and collect structured observations
  host    Discover reachable hosts with ICMP, UDP, or TCP probes
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
nrev probe -d ./samples/data-pack -j
nrev recipe -d ./samples/recipes -j
```
