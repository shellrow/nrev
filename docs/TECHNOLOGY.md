# Technology inventory

nrev derives an endpoint inventory from a port report. Each product has a stable
`vendor:product` identifier, a role, version evidence and references back to the
input. The embedded nrev Knowledge Database (NKDB) works offline.

## Bundled product coverage

Revision `2026.11.23.3` ships with 74 product identities and 80 signatures.
Each signature has a labeled example checked during the build. The
[catalog](../knowledge/products.json) lists the exact fields, patterns, roles,
version schemes, CPE aliases and sources. The following are examples of the
evidence available to an ordinary installation.

| Area | Examples | What the inventory can establish |
| --- | --- | --- |
| Web servers and runtimes | nginx, IIS, Apache HTTP Server, Jetty, Kestrel, Gunicorn, Uvicorn, Werkzeug, aiohttp, WEBrick | Server declarations distinguish an HTTP implementation from a runtime or crypto library in the same response. |
| Proxies, managed services and embedded HTTP | Envoy, Kong, Squid, Varnish, Apache Traffic Server, Cloudflare, CloudFront, AWS ALB, Amazon S3, MinIO, GoAhead, MiniUPnPd | An edge or storage declaration describes the responding layer. The fixed ALB token supplies no software release. |
| Web frameworks and generators | Express, Next.js, ASP.NET, Drupal, WordPress, Jekyll, Hugo, MediaWiki, Ghost | Framework declarations and validated generator metadata have separate roles. A generator describes how content was produced. |
| Platform APIs and tools | Kubernetes API server, Consul, Nomad, Jenkins, GitHub Enterprise Server | Kubernetes requires both flow-control UID fields. Consul and Nomad each require their own index and leader fields. Jenkins and GitHub Enterprise Server can declare a version directly. |
| Data services | MariaDB, TiDB, Elasticsearch, InfluxDB, CouchDB | Named handshake or HTTP declarations identify the product. TiDB's MySQL compatibility prefix is excluded from its release. A Redis-compatible PONG and a PostgreSQL SSLRequest reply identify protocol behavior only. |
| DNS | CoreDNS, dnsmasq, Unbound, PowerDNS Authoritative Server and Recursor | A matching CHAOS TXT answer can declare a resolver product and release over UDP or TCP. A numeric answer alone leaves the product unknown. |
| SSH, mail and FTP | OpenSSH, Dropbear, AsyncSSH, Paramiko, Exim, Postfix, Dovecot, Cyrus IMAP, vsftpd, pyftpdlib | Protocol-specific greeting grammar separates an implementation's declaration from a host name, comment or compatibility claim. |

Platform HTTP header rules also work on older saved scans with complete
response heads. Duplicate identity fields, incomplete heads and mismatched
status lines are excluded. A registry API version is a protocol fact and
does not identify the registry implementation. The inventory does not request
extra API paths to obtain these fields. Implementations that suppress their
declarations can therefore remain unknown.

## Collect and replay

```sh
nrev port 192.0.2.10 --ports 22,80,443,9443,9999 --bundled-advisories
nrev port 127.0.0.1:43210 --service --format json --output scan.json
nrev port 127.0.0.1 --ports 22,80,443 --os --output stack.json
nrev inventory stack.json --format human
nrev inventory scan.json --bundled-advisories
nrev inventory scan.json --nvd local-nvd-page.json
nrev inventory scan.json --advisories samples/inventory/advisories.json
nrev inventory scan.json --knowledge knowledge/products.json
```

With `port --bundled-advisories`, nrev reviews the observations in memory and
prints the inventory and advisory candidates. Saving a report is optional.
Port and task commands use the requested probes and collection limits.
`--service` enables native inventory display. Directly specifying a host
and a numeric port enables automatic HTTP/HTTPS negotiation, including with
the standard port report. The [probe selection guide](USAGE.md#probe-selection)
describes which endpoints are eligible. With automatic web negotiation
inactive, inventory can still listen for a greeting on an otherwise unused
open TCP connection for up to 150 ms.
Use `--probes greeting` to request a passive read explicitly with the configured
probe timeout. `--output` saves the underlying
schema-v1 scan. The inventory and saved report use the same endpoint filter, including `--all-states`.
Replay defaults to JSON, accepts a local file and preserves the original report
timestamp. Knowledge loading, replay and advisory matching require zero
additional probes or external API requests. Advisory URLs are source labels.

## Native OS and service identification

`--os` selects SYN transport and inventory. It needs capture and packet
injection access on the selected interface. The matcher also runs during offline
replay of a scan with recorded stack features. For ordinary TCP connects, a
service can disclose its environment even when the kernel family is unknown.

| Result | Evidence and scope |
| --- | --- |
| `operating_system.stack_matches` | Each candidate identifies its port, NKDB profile and source. Matching uses SYN/ACK flags, ordered TCP options, TTL, window, MSS, window scaling and SACK evidence. |
| `operating_system.status` | `stack_inference` indicates a responding stack family. `corroborated_family` also has a consistent service declaration. `service_hint_only` has no stack match. Incompatible families produce `conflicting`. Insufficient evidence produces `unknown`. |
| `endpoints[].service_platforms` | A structured HTTP or SSH declaration describes a service environment. An explicit release belongs to that declaration. Proxies, containers and port forwarding can put a different stack in front of the service. |
| `endpoints[].services` | The basis identifies a validated protocol reply, a product-specific greeting, or a probe's service hint. A hint alone can come from the probe selection. |

The built-in profiles cover selected Linux, Darwin and Windows TCP option layouts.
TCP profiles do not determine kernel version, edition, build or patch level.
Filtered replies, disabled TCP options, middleboxes and other implementations
sharing a layout affect the result. Repeated matches retain their source ports.

## Reading the result

| Output | Interpretation |
| --- | --- |
| `observed` | Protocol facts from one recorded exchange, such as an HTTP status code, negotiated ALPN, or a validated NTP stratum. Bounded `http.server_product` and `ssh.software` tokens preserve a peer declaration even when NKDB has no canonical product match. |
| `technologies[].declarations` | Peer claims or product CPEs from an already recorded Nmap service match. A rule name such as `nginx:nginx#0` identifies a zero-based signature within that NKDB product. |
| `identity_status` | An endpoint with no qualifying claim is `unknown`. Different products claiming the same role give `conflicting`. Distinct roles can coexist. |
| `confidence` | A product claim is a `weak_inference`. An endpoint can advertise an arbitrary identity. Repeated responses and multiple fields from one response never increase confidence. |
| `version_status` | `declared` fits the product's comparison grammar. `partial` lacks expected components. `unparsed` retains an opaque version. `missing` and `conflicting` withhold the aggregate version. |
| `qualified` | A source included additional context such as a distribution comment or CPE edition. The report retains the qualification flag. Consult the referenced observation for details. |
| `review` | A configuration requiring administrative review, such as a TDS peer reporting that encryption is unsupported. This can appear on an unknown product. |
| `advisory_candidates` | Potential matches from the supplied local advisory file, with the source, applicable bounds and any operator-supplied condition. |

An observation reference identifies the zero-based entry within the endpoint
and its named field. A Nmap reference identifies positions in
`identification.hosts[h].ports[p].service.cpes[c]`. Only probed application CPEs
from open ports on the same IP, port and wire transport participate. An Nmap
match can derive from the same banner as a native observation. Disagreement on
identity suppresses advisory matching for that role. Disagreement on a version
keeps the declarations and produces an indeterminate candidate.

A TLS or QUIC exchange that also contains a parsed HTTP response supplies the
`http.carrier` relationship. A Via header supplies a presence indicator.
Deployment identity behind an intermediary, shared ownership across ports and
OS patch level require separate evidence. The underlying scan retains the captured stack fields for replay.

## Protocol coverage

| Source | Eligible evidence |
| --- | --- |
| HTTP/1.x, HTTP/2 over TLS, HTTP/3 | Valid status line, complete Server product list, X-Powered-By and generator metadata. The Server parser handles subproducts and nested comments. |
| TLS, QUIC | Negotiated TLS version, supported HTTP ALPN or recorded cipher suite. Certificate subjects and hostnames do not establish product identity. |
| SSH | A complete identification line, including after preamble lines. The portable patch suffix is significant when present. |
| SMTP, FTP, IMAP, POP3 | Complete protocol-specific greeting declarations and SMTP STARTTLS advertisement from a completed EHLO reply. A host name, port number or generic success code supplies insufficient product evidence. |
| MySQL protocol 10 | Bounded, complete server greeting with a structured version field. MariaDB and TiDB can declare their own release after a compatibility prefix. |
| DNS over UDP or TCP, NTP over UDP | Recorded protocol fields gated on response validation. DNS product matching also checks the echoed question, record owner, type, class and TXT framing, and excludes truncated replies. Older reports without decoded TXT evidence retain their recorded facts. |
| TDS prelogin | Recorded peer version, encryption mode and configuration review. |
| PostgreSQL, Redis-compatible services, Memcached | SSLRequest acceptance or refusal, RESP PONG, or a structured Memcached version response. |
| SMB, RDP | Negotiated SMB dialect and signing mode, or selected RDP negotiation protocol. These describe the service on this connection. |
| Optional recorded Nmap service analysis | Reviewed CPE aliases joined to matching native endpoints. OS and hardware CPEs do not identify application products. |

The HTTP field grammar, SSH identification framing and TDS prelogin structure
follow their protocol definitions. [HTTP Server field](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.4)
[SSH protocol version exchange](https://www.rfc-editor.org/rfc/rfc4253.html#section-4.2)
[TDS PRELOGIN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868)

For HTTPS the TLS probe offers HTTP/2 and HTTP/1.1 via ALPN. If the peer
selects `h2`, nrev requests a bounded preview over that connection and retains
completed headers if the body stalls. Common dedicated mail, directory and
DNS-over-TLS ports use the general TLS handshake. [HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)

Headers, page content and service declarations can be spoofed. A structurally
valid impersonation can produce a wrong product hypothesis. Raw reports can
also contain cookies, certificate names, body snippets and diagnostic strings.
Inventory output retains selected facts, short version tokens, target identity
and evidence references. It also includes HTTP page titles, endpoint latency
in milliseconds and collection diagnostics. `collection_errors` counts all
diagnostics; `errors` includes the first 32 messages, up to 512 characters each.
Titles and diagnostics can include site-specific details.

## Local advisory files

`samples/inventory/advisories.json` contains one historical example derived from
the nginx advisory for CVE-2021-23017. The fixture scan advertises version 1.20.0.
It produces one potential candidate and identifies the resolver configuration
check. [Vendor advisory](https://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html)

A schema-1 file has a `records` array. Each record requires `id`, `product` and
`source`. Use a canonical NKDB product ID or an exact, catalogued wildcard CPE
product name. Supply `introduced` (inclusive), `fixed` (exclusive), or both. A
free-text `condition` records configuration or edition prerequisites for review.
Schema 1 accepts one continuous range per product/advisory pair. The loader rejects
duplicate pairs, reversed ranges, unknown products and unsupported bounds.
Schema 2 also accepts `ranges`, a list of disjoint, ordered upstream intervals.
An interval can end with `fixed` (exclusive) or `last_affected` (inclusive).
An optional `observed_when` object such as
`{"fact":"smtp.starttls","equals":"advertised"}` links a positive condition
to an exchange that declared the same product. Missing evidence leaves the
condition unobserved. The inventory includes the input record count and each
technology's `advisory_status`, including `no_product_records` and
`outside_supplied_ranges`.

Choose one advisory source for replay. `--bundled-advisories` loads the
[offline advisory pack](../knowledge/advisories.json). As of November 23,
2026 it contains 36 product records. Six cover older nginx and Apache HTTP
Server issues. The other 30 cover 29 CVEs published in 2026 across 25 products.
PowerDNS Authoritative Server and Recursor have separate fixes for the same CVE.
The publication year can differ from the identifier year, as it does for
the OpenSSL CMS advisory CVE-2025-15467.

The selection prioritizes supported products in the
[CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and high-impact upstream advisories with identifiable release boundaries.
Each record links to its source and states what operators should check.
For example, the Drupal advisory applies to PostgreSQL deployments, and
the OpenSSH advisory concerns Linux systems using musl with PAM disabled.
WordPress backports and Jenkins LTS fixes have separate intervals so that
an older, patched branch can fall outside an affected range. A missing
record means the pack supplies no assessment for that issue.

`--advisories FILE` loads a reviewed local file. `--nvd FILE` reads one saved
NVD CVE API 2.0 JSON page (up to 8 MiB). The adapter imports representable
upstream application CPEs and records the page timestamp, start index, total
results and counts of imported, skipped and out-of-catalog records under
`nvd_coverage`. Conjunctions, negation, unrepresentable ranges and environment
constraints can change applicability and cause the CVE to be skipped. These
inputs describe their own coverage and publication date. [NVD API schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)

Numeric components compare as integers at the catalogued width. The Jenkins and
Exim rules accept two-component releases and treat the omitted patch number as
zero for comparisons. The displayed version retains the peer's spelling.
Portable SSH adds a numeric `p` component. Partial strings, unrecognized suffixes, missing
versions and conflicting declarations stay indeterminate. A distribution
qualification requires package review even if the upstream number looks fixed.
A candidate can be resolved using the installed package, vendor backport status
and actual configuration. The inventory has no path that promotes a version
match to a verified vulnerability.

## Library and migration

```rust
use nrev::{model::ScanReport, technology::KnowledgeBase};

fn replay(json: &[u8]) -> anyhow::Result<nrev::technology::Inventory> {
    let report: ScanReport = serde_json::from_slice(json)?;
    KnowledgeBase::builtin()?.inventory(&report, None)
}
```

Share a compiled `KnowledgeBase` across workers. `identify` accepts an
`EndpointResult`. `inventory` also joins the optional recorded Nmap analysis.
`Advisories::from_bytes` validates local records against a particular knowledge
base. Pair that instance with the same knowledge base for replay.

Existing schema-v1 saved scans, data packs and commands continue to work.
Callers constructing `ScanArgs` or `ScanTask` struct literals must supply
`inventory: false` and `native_os: false` for the previous behavior. Direct `ScanConfig` constructors
set `explicit_web_ports` for numeric port lists and `passive_greetings` for passive inventory collection.
Exhaustive matches on the CLI
command enum need an `Inventory` arm. The new inventory document has its own
schema and knowledge revision. Old MySQL reports may lack the new handshake
field. TDS configuration review requires a structurally validated prelogin
response. Generator inference requires a typed HTML/XHTML preview with a
delimited head and the generator validation marker. Earlier reports or long,
incomplete HTML heads can therefore yield an unknown generator. A truncated old
SSH record can also yield an unknown identity.

## Maintaining the catalog

The default catalog ships inside the CLI binary. The inventory engine compiles
the signatures once per catalog load and indexes them by evidence field. All
endpoints in a report share this index. Operators can supply a replacement
catalog with `--knowledge` or update local advisory inputs independently.

Define product IDs, roles, version schemes, CPE aliases and field-specific
signatures in `knowledge/products.json`. Give each product a provenance entry.
When a rule changes, update the catalog revision and its labeled examples in
`knowledge/review.json`. The build checks every signature against a positive
example and requires a negative example for each field. It rejects duplicate
IDs, ambiguous matches in the examples and invalid version captures.

```sh
cargo test --locked
cargo bench --locked --bench technology
```

The benchmark measures catalog loading, endpoint identification and advisory
matching against a saved scan. Each reported latency percentile summarizes
batches of 2,000 operations and excludes report decoding and network I/O.

The OS replay fixture contains four redacted SYN/ACK observations in
`samples/inventory/platforms.json`. They cover a Darwin loopback connection,
a Linux loopback connection and two Windows peers with different receive
windows. The Windows observations come from the public
`smb-on-windows-10.pcapng` and `dhcpfo.pcapng` captures.
[Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures)
