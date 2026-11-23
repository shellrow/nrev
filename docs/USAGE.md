# Usage

Run `nrev <command> --help` for all options. Replace the documentation addresses
in the examples and sample tasks with targets you have permission to scan.
See [Privileges](../README.md#privileges) for raw-packet setup.

## Port scanning

TCP connect is the default transport. Ports accept lists, ranges, or the named
sets `top-100` (default), `top-1000`, and `well-known`.

```sh
nrev port 192.0.2.10
nrev port 192.0.2.10 --ports 22,80,443,8000-8010
nrev port 192.0.2.0/24 --ports top-1000
nrev port 192.0.2.10 --transport udp --ports 53,123
sudo nrev port 192.0.2.10 --transport syn --ports top-100
nrev port edge.example --transport quic --ports 443,8443
```

Use `--all-states` to include closed, filtered, and failed endpoints.
UDP silence is reported as `open_filtered`, a response as `open`, and a
connection refusal as `closed`.

### Probe selection

For a host and a numeric port, nrev can identify HTTP or HTTPS without
a probe selection. Either form below works with a listening web service.

```sh
nrev port localhost:44321
nrev port localhost --ports 44321,44322 --service
```

On an unassigned port, nrev briefly listens for a greeting before trying
HTTP. If the response is inconclusive it tries TLS on a fresh connection.
A TLS handshake identifies TLS. HTTPS requires an HTTP response inside TLS.
Both attempts share the probe timeout. The native HTTPS probe supports HTTP/1.x
and HTTP/2 with ALPN. Certificate trust and service identity are reported separately.

Automatic web negotiation applies to directly addressed hosts with inline
ports or numeric port lists, on unassigned and built-in web ports. Dedicated
service probes, matching external probes and explicit probe selections take
precedence. Port ranges and presets use the normal port mappings, as do CIDRs.
Raw print ports 9100–9107 are excluded from automatic web requests.

To select probes explicitly:

```sh
nrev probe
nrev port 192.0.2.10 --ports 2222 --probes ssh
nrev port 192.0.2.10 --ports 8080 --probes http
nrev port 192.0.2.10 --ports 8443 --probes tls
```

Selected built-in probes run on every requested port of the matching transport.
External probes keep their configured port restrictions. Unknown probe IDs are
rejected. `--no-builtin-probes` disables built-in probes but allows external ones.

TLS certificates are collected without trust validation; reports set
`certificate_validation` to `not_performed`. The TCP probe supports TLS 1.2 and
1.3. For X.509 v1 or v2 certificates, it uses the certificate's public key to
verify the handshake signature. If a listener returns a cleartext HTTP error
and TLS negotiation fails, the endpoint retains both the HTTP response and
the TLS error. QUIC retains handshake observations
if HTTP/3 probing fails or is disabled. A QUIC rejection does not count as a
completed TLS handshake.

### Timeouts and concurrency

```sh
nrev port 192.0.2.10 --concurrency 128 \
  --connect-timeout-ms 1200 --probe-timeout-ms 3000 --retries 1
```

`--probe-timeout-ms` limits each service probe. Reduce `--concurrency` if you
encounter file-descriptor limits; connections retained for probing can require
up to another `--concurrency` descriptors.

For TCP, UDP, and QUIC socket probes, `--interface` selects a source address.
Routing remains under operating-system control. Specify an interface for IPv6
link-local targets.

## Technology inventory

Native service probes run by default. Use `-S` or `--service` (alias
`--inventory`) for the product and version inventory. Use `-O` or `--os`
(aliases `--native-os` and `--os-detect`) to include native TCP stack evidence.
`-O` already includes the service inventory. Use `port --bundled-advisories`
to display advisory candidates from the scan in the same command.

```sh
nrev port 127.0.0.1:8080 --probes http --service --format json --output observations.json
nrev port 127.0.0.1 --ports 22,80,443 --os
nrev inventory observations.json --format human
nrev inventory observations.json --advisories advisories.json
```

The first command displays inferred products and saves the port scan. The
second requests native SYN collection and inventory. This requires packet
capture/injection access on the chosen interface. The last two commands replay
the saved file locally. Scan tasks support `inventory = true`, `native_os = true`,
and `bundled_advisories = true`.
See the [inventory guide](TECHNOLOGY.md) for evidence, supported protocols,
advisory ranges and API usage.

## Nmap identification

Use `--nmap` for external service/version identification and `--nmap-os`
for external OS identification. The `--os-detect` option now selects the native
SYN-based OS inventory, like `--os`. Scripts that previously used
`--os-detect` for Nmap OS results should use `--nmap-os`. nrev looks for `nmap` on `PATH`; `--nmap-path` selects another
executable. On Windows, use the Nmap executable directly: cancellation stops
the immediate process but does not terminate descendants started by wrappers.

```sh
nrev port 192.0.2.10 --ports top-100 --nmap
sudo nrev port 192.0.2.10 --ports top-100 --nmap --nmap-os
sudo nrev port 192.0.2.10 --transport udp --ports 53,123 --nmap
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
nrev host 192.0.2.0/24 --method tcp --ports 80,443
sudo nrev host 192.0.2.0/24
sudo nrev host 192.0.2.0/24 --method udp --ports 33434,40125
nrev host @./targets.txt --method tcp --ports 80,443 --all-hosts
```

The default method is ICMP. `--all-hosts` includes unreachable hosts.

## Ping and traceroute

```sh
sudo nrev ping 192.0.2.10 --count 5
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
sudo nrev nei 192.0.2.1
sudo nrev nei fe80::1 --interface en0
```

Use `--method arp` or `--method ndp` to choose explicitly.

## Output

The default port report groups products, versions, service settings and observed
responses under each endpoint. A redirect includes its Location when available.
Counts summarize closed, filtered and unreachable native ports. Use
`--all-states` to list them individually and `-S` to see which observation
supports a product claim. Use `-O` for this
view with native OS evidence. A saved scan can be reviewed with
`nrev inventory FILE --format human`.

| Port options | Standard output | File written by `--output FILE` |
| --- | --- | --- |
| Default | Observations and identified products | Raw scan JSON |
| `-S` or `-O` | Observations, identified products and supporting evidence | Raw scan JSON |
| `--format json` | Raw scan JSON | Same raw scan JSON |
| `-S` or `-O` with `--format json` | Technology inventory JSON | Raw scan JSON |
| `--bundled-advisories` | Detailed inventory and advisory candidates (inventory JSON with `--format json`) | Raw scan JSON |

Human-readable web results show the HTTP status line and selected headers.
Set-Cookie is reported by presence. Raw JSON retains the captured header values.

```sh
nrev port 192.0.2.10 --output result.json
nrev port 192.0.2.10 --quiet --format json
nrev host 192.0.2.0/24 --method tcp --ports 443 --output hosts.json
```

Use `--quiet` to disable progress or `--progress verbose` for more detail.
Progress and diagnostics use color when stderr is a terminal. Use `--no-color`
(or `--color never`) to disable it, or `--color always` to force it. Automatic
color respects `NO_COLOR` and `TERM=dumb`. Reports and JSON remain uncolored.
Probe failures appear in endpoint `errors` and in the tree output. Transport
errors appear in human output and make port scans exit with status 1. Use
`--all-states` to include failed endpoints in JSON. Raw host-capture failures also return status 1.

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

Port scans accept up to 65,536 target identities (address and hostname) and
1,000,000 endpoint assignments. Host discovery accepts up to 65,536 addresses.
Target files are limited to 1,024 files, 16 MiB total, and 65,536 tokens. Split larger inventories across commands.

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
nrev port 192.0.2.10 --profile ./profile-web.toml --ports 80,443
```

Recipes provide named settings in a data pack:

```sh
nrev recipe --data ./samples/recipes
nrev port 192.0.2.10 --data ./samples/recipes --recipe web-balanced
```

A recipe that omits `probes` inherits the profile's selection. An empty list
restores automatic probe selection.

## Tasks

Task files combine targets and scan settings in JSON or TOML:

```toml
name = "web-scan"
targets = ["192.0.2.10", "@./targets.txt"]
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
can contain `probes`, `fingerprint_rules`, and `recipes`. Data files, profiles,
and task files are limited to 16 MiB each.

```sh
nrev probe --data ./samples/data-pack
nrev recipe --data ./samples/data-pack --json
nrev port 192.0.2.10 --data ./samples/data-pack --recipe corp-web-alt
nrev port 192.0.2.10 --ports 8080,8088 --data ./samples/data-pack \
  --probes corp-http-alt --no-builtin-probes
```

External payload probes support TCP and UDP. Use the built-in `quic` probe for
QUIC and HTTP/3. Probe IDs and recipe names must be unique within a data pack.

See the [sample directory](../samples/data-pack) and the alternative
[JSON file](../samples/data-pack.json) for definitions. Load either one; do not
combine them, as they define the same probes and recipes.

## Response limits

HTTP/1 headers are limited to 64 KiB. `--http-body-preview-bytes` limits body
inspection; chunked framing and compression are not decoded. Invalid text bytes
are replaced with UTF-8 replacement characters.

Raw capture stops with an error after 65,536 matching frames or 64 MiB of matching
packet data. Each batch waits for responses until its timeout after the final send.
