# Service Attribution And Destination Intelligence

Process attribution alone only identifies the program that opened a connection;
it cannot tell which site or service a browser, Electron container, or messaging
client reached. Service Attribution gives an analyst a conservative answer to:
"Which known
service is this flow probably reaching, and why?" It is a local metadata
correlation layer. A label is an explainable inference, not proof of application
content or user activity.

## Pipeline Position

```text
Capture
  -> metadata extraction and central redaction
  -> Service Attribution Engine
  -> Flow Engine and conversation views
  -> Live Ring / Event Aggregator / Batch Persistence
  -> Inspect, Flows, and Ops Snapshot
```

The engine is used by live capture. Its result is stored on redacted packet and
flow summaries, allowing the same attribution to be reviewed in Inspect, Flow
Details, recent ring-buffer records, and persistence without another lookup.

## Local Evidence

The engine may correlate:

- visible HTTP Host metadata;
- visible TLS SNI metadata;
- DNS query names and recent DNS answer-to-IP observations;
- optional ASN organization metadata already supplied by the capture path;
- destination IP and port as context;
- process name as context only; and
- the bundled local fingerprint registry.

The default registry is
`backend/app/data/service_fingerprints.json`. It covers common video,
messaging, developer-platform, cloud/search, social, and CDN providers. Registry
matching is deterministic and performs no outbound network request.
Recent DNS and unique-flow metric correlation caches have fixed internal caps,
so long capture sessions cannot make this layer grow without a bound.

## Confidence And Reasons

Every result contains a `0..100` confidence score, a `high`, `medium`, `low`, or
`unknown` label, evidence sources, and short reasons. Visible HTTP Host and TLS
SNI are stronger evidence than recent DNS correlation. Multiple agreeing
sources can increase confidence. Conflicting sources reduce confidence.

Browser and container process names are deliberately weak context. For example,
`chrome.exe` alone does not mean Google or YouTube. ASN evidence for a shared CDN
is labeled `CDN only` unless stronger domain evidence identifies the final
service.

## Unknown Encrypted Destinations

Encrypted traffic with no visible DNS, SNI, or Host evidence is reported as
`Unknown encrypted destination`. NetBotPro does not invent a service name.
Common reasons include Encrypted Client Hello (ECH), DNS over HTTPS, VPN or
proxy use, encrypted QUIC, shared CDN infrastructure, browser connection reuse,
NAT with multiple hosts, missing process metadata, missing DNS history, and
missing SNI.

Examples of intended output include `chrome.exe -> YouTube -> googlevideo.com`
with high confidence when visible SNI agrees with the registry, and
`chrome.exe -> Unknown encrypted destination` when only an encrypted endpoint
is visible.

## Operations Metrics

`/api/monitoring/metrics` exposes a fixed `service_attribution` object:

- enabled and health;
- registry size;
- attributed and unknown unique-flow totals;
- high, medium, and low confidence totals;
- encrypted-unknown and CDN-only totals;
- attribution error total;
- average and p95 attribution latency; and
- safe pressure-reason identifiers.

Metrics never include observed domains, headers, packet text, credentials,
cookies, sessions, authorization values, or tokens. A high unknown rate is a
diagnostic signal, not automatically a security problem.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `NETBOT_SERVICE_ATTRIBUTION_ENABLED` | `true` | Enables local attribution. |
| `NETBOT_SERVICE_ATTRIBUTION_REGISTRY` | bundled JSON path | Selects a local registry file. |
| `NETBOT_SERVICE_ATTRIBUTION_DNS_WINDOW_SEC` | `300` | Limits DNS answer correlation age. |
| `NETBOT_SERVICE_ATTRIBUTION_MAX_REASONS` | `8` | Bounds explanation length. |
| `NETBOT_SERVICE_ATTRIBUTION_UNKNOWN_RATE_WARN` | `0.75` | Sets the Ops warning threshold after a meaningful sample. |

Invalid registry rows are skipped. A missing or wholly invalid registry does
not crash capture; it is reported as critical attribution health and flows stay
Unknown.

## Privacy And Security Boundaries

All displayed and persisted attribution data passes through central redaction.
This feature does not add:

- TLS decryption or MITM;
- credential collection;
- browser history scraping;
- cookie/session inspection;
- raw payload forwarding, raw packet forwarding, or Agent PCAP forwarding;
- command/control, remote shell, or file collection; or
- IPS/auto-blocking or autonomous AI actions.

Agent/Fleet Mode remains telemetry-only and read-only. Service Attribution runs
on the authorized capture host; it does not expand Agent collection or
forwarding behavior.

## Safe And Authorized Use

Use NetBotPro only on systems and networks you own or are explicitly authorized
to monitor. Attribution should guide investigation and validation, not serve as
the sole basis for disciplinary, blocking, or incident decisions.
