# Usage

Run `nrev <command> --help` for all options. Examples assume you have permission
to scan the target. See [Privileges](../README.md#privileges) for raw-packet setup.

## Port scanning

TCP connect is the default transport. Ports accept lists, ranges, or the named
sets `top-100` (default), `top-1000`, and `well-known`.

```sh
nrev port 192.168.10.10
nrev port 192.168.10.10 --ports 22,80,443,8000-8010
nrev port 192.168.10.0/24 --ports top-1000
nrev port 192.168.10.10 --transport udp --ports 53,123
sudo nrev port 192.168.10.10 --transport syn --ports top-100
nrev port edge.example --transport quic --ports 443,8443
```

Use `--all-states` to include closed, filtered, and failed endpoints.
UDP silence is reported as `open_filtered`, a response as `open`, and a
connection refusal as `closed`.

### Probe selection

Built-in probes run on their default ports. Use `--probes` to select probes
explicitly, including on nonstandard ports:

```sh
nrev probe
nrev port 192.168.10.10 --ports 2222 --probes ssh
nrev port 192.168.10.10 --ports 8080 --probes http
nrev port 192.168.10.10 --ports 8443 --probes tls
```

Selected built-in probes run on every requested port of the matching transport.
External probes keep their configured port restrictions. Unknown probe IDs are
rejected. `--no-builtin-probes` disables built-in probes but allows external ones.

TLS certificates are collected without trust validation; reports set
`certificate_validation` to `not_performed`. QUIC retains handshake observations
if HTTP/3 probing fails or is disabled. A QUIC rejection does not count as a
completed TLS handshake.

### Timeouts and concurrency

```sh
nrev port 192.168.10.10 --concurrency 128 \
  --connect-timeout-ms 1200 --probe-timeout-ms 3000 --retries 1
```

`--probe-timeout-ms` limits each service probe. Reduce `--concurrency` if you
encounter file-descriptor limits; connections retained for probing can require
up to another `--concurrency` descriptors.

For TCP and QUIC scans, `--interface` selects a source address. Routing remains
under operating-system control.

## Nmap identification

Use `--nmap` for service/version identification and `--os-detect` for OS
identification. nrev looks for `nmap` on `PATH`; `--nmap-path` selects another
executable.

```sh
nrev port 192.168.10.10 --ports top-100 --nmap
sudo nrev port 192.168.10.10 --ports top-100 --nmap --os-detect
sudo nrev port 192.168.10.10 --transport udp --ports 53,123 --nmap
```

OS identification requires TCP/SYN mode and elevated privileges. Nmap UDP
identification also requires privileges. Nmap uses its own routing and does not
inherit `--interface` or hostname-based probes.

| Option | Default | Purpose |
| --- | --- | --- |
| `--nmap-scope` | `candidates` | Identify candidate ports, or use `all` to rescan every requested port |
| `--nmap-intensity` | `7` | Service probe intensity, from 0 to 9 |
| `--nmap-timeout-ms` | `120000` | Total time allowed for the identification phase |
| `--nmap-concurrency` | `2` | Concurrent Nmap processes, from 1 to 16 |

Candidates are open TCP/SYN ports and open or open-filtered UDP/QUIC ports.
QUIC endpoints are passed to Nmap as UDP. For OS identification, nrev also passes
one observed closed TCP port when available; Nmap sends additional OS probes.

The human-readable report combines native and Nmap results under each host and
port. Matching states and services appear once. Only the highest-ranked OS match
is shown; ties favor generic Linux and general-purpose OS descriptions.

JSON keeps all Nmap results under `identification`, including `requests`,
`failures`, and `hosts`. Aggregate port states are in `hosts[].port_summaries`.
If identification fails, completed results are retained, `complete` is `false`,
and nrev exits with status `1`.

## Host discovery

```sh
nrev host 192.168.10.0/24 --method tcp --ports 80,443
sudo nrev host 192.168.10.0/24
sudo nrev host 192.168.10.0/24 --method udp --ports 33434,40125
nrev host @./targets.txt --method tcp --ports 80,443 --all-hosts
```

The default method is ICMP. `--all-hosts` includes unreachable hosts.

## Ping and traceroute

```sh
sudo nrev ping 192.168.10.10 --count 5
nrev ping example.com --method tcp --port 443 --count 5
nrev ping example.com --method quic --port 443 --count 5
sudo nrev ping example.com --method udp --port 33435
sudo nrev trace example.com
sudo nrev trace example.com --method icmp --max-hops 20
```

Use `--interval-ms` and `--timeout-ms` to adjust timing. Traceroute defaults to UDP.

## Neighbor discovery

The default method is ARP for IPv4 and NDP for IPv6.

```sh
sudo nrev nei 192.168.10.1
sudo nrev nei fe80::1 --interface en0
```

Use `--method arp` or `--method ndp` to choose explicitly.

## Output

Reports default to a human-readable tree. `--format json` writes JSON to stdout;
`--output` saves a JSON report regardless of the stdout format.

```sh
nrev port 192.168.10.10 --output result.json
nrev port 192.168.10.10 --quiet --format json
nrev host 192.168.10.0/24 --method tcp --ports 443 --output hosts.json
```

Use `--quiet` to disable progress or `--progress verbose` for more detail.
Probe failures appear in endpoint `errors` and in the tree output.

JSON files are replaced atomically. Check `metadata.schema_version` when parsing
reports. Enum values use `snake_case`. Terminal output escapes control characters;
JSON preserves observations using JSON escaping.

## Target files and IPv6

```sh
nrev port @./targets.txt --ports 80,443
nrev port '[::1]:443' --probes tls
```

Target files may include other files using `@relative/path.txt`. Includes resolve
relative to the containing file; repeated or cyclic includes are read once.
Use brackets around IPv6 addresses that include a port.

Each command accepts up to 65,536 unique addresses and 1,000,000 endpoint
assignments. Target files are limited to 1,024 files, 16 MiB total, and 65,536
tokens. Split larger inventories across commands.

## Profiles and recipes

A profile supplies scan defaults. For example, `profile-web.toml`:

```toml
name = "web"
ports = "80,443,8080,8443"
connect_timeout_ms = 1200
probe_timeout_ms = 3000
```

CLI flags override profile values:

```sh
nrev port 192.168.10.10 --profile ./profile-web.toml --ports 80,443
```

Recipes provide named settings in a data pack:

```sh
nrev recipe --data ./samples/recipes
nrev port 192.168.10.10 --data ./samples/recipes --recipe web-balanced
```

A recipe that omits `probes` inherits the profile's selection. An empty list
restores automatic probe selection.

## Tasks

Task files combine targets and scan settings in JSON or TOML:

```toml
name = "web-scan"
targets = ["192.168.10.10", "@./targets.txt"]
ports = "80,443,8080,8443"
transport = "tcp"
concurrency = 128
probe_timeout_ms = 3000
output = "./report.json"

[identification]
services = true
os = false
intensity = 7
scope = "candidates"
concurrency = 2
timeout_ms = 120000
executable = "nmap"
```

```sh
nrev task ./scan.toml
```

Task keys use underscores, such as `connect_timeout_ms`, `all_states`, and
`http_body_preview_bytes`. Use `builtin_probes = false` to disable built-in probes.
Tasks also accept `profile`, `data`, `recipe`, `probes`, `interface`, `retries`,
`quiet`, `progress`, and `format`.

Paths in `profile`, `data`, and `output` resolve relative to the task file.
Executable names use `PATH`; relative executable paths also resolve from the task
file. See [sample tasks](../samples/tasks) for more examples.

## External data

`--data` accepts a JSON or TOML file, or a directory of those files. Each file
can contain `probes`, `fingerprint_rules`, and `recipes`.

```sh
nrev probe --data ./samples/data-pack
nrev recipe --data ./samples/data-pack --json
nrev port 192.168.10.10 --data ./samples/data-pack --recipe corp-web-alt
nrev port 192.168.10.10 --ports 8080,8088 --data ./samples/data-pack \
  --probes corp-http-alt --no-builtin-probes
```

See [sample data packs](../samples/data-pack) for definitions.

## Response limits

HTTP/1 headers are limited to 64 KiB. `--http-body-preview-bytes` limits body
inspection; chunked framing and compression are not decoded. Invalid text bytes
are replaced with UTF-8 replacement characters.

Raw capture stops with an error after 65,536 matching frames or 64 MiB of matching
packet data. Each batch waits for responses until its timeout after the final send.
