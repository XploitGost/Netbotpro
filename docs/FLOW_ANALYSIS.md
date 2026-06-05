# Flow Analysis And Protocol Intelligence

NetBotPro groups packet metadata into directional flows and bidirectional
conversations so analysts can understand network behavior without reading every
packet as an isolated row.

Use these capabilities only on systems and networks you own or are explicitly
authorized to monitor.

## Flow

A flow is a directional network session identified by source/destination IP,
source/destination port, transport, and direction.

For each flow NetBotPro calculates first/last seen time, duration, packet and
byte counts, sent/received bytes, process attribution when available, protocol
metadata, related alerts, explainable risk, and redacted packet samples.

Flow snapshots are stored in `.runtime/logs/flows.db`. The schema initializes
automatically. Retention defaults to seven days and can be configured with:

```text
NETBOT_FLOW_HISTORY_RETENTION_DAYS=7
```

Raw packet payloads are not stored in the flow database.

## Conversation

A conversation joins both directions of the same endpoint pair and transport.
It provides combined flow IDs, packet/byte totals, protocols, maximum risk, and
a merged timeline. Conversation analysis is a read-only analytical view.

## Protocol Intelligence

The metadata-safe protocol layer currently identifies DNS, HTTP, visible TLS
metadata, SSH, RDP, SMB, SMTP, IMAP, POP3, ICMP, and unknown traffic.

Detection uses decoded fields already visible in the packet parser, safe
signatures, transport metadata, and service-port hints.

### DNS

NetBotPro can show query name, query type, response code, answer count, and
repeated NXDOMAIN risk hints when available.

### HTTP

NetBotPro can show method, host, redacted path, status code, redacted user
agent, and content type. Authorization, Cookie, Set-Cookie, passwords, tokens,
sessions, and API keys are never included in flow metadata.

### TLS

NetBotPro can show visible handshake metadata such as SNI, ALPN, TLS version,
and certificate metadata when exposed without decryption.

There is no TLS decryption, MITM, key extraction, or credential sniffing.

### SSH, RDP, SMB, And Mail

These protocols use port and safe signature hints. Only protocol/banner-style
metadata suitable for defensive analysis is retained. Credentials and session
content are not collected.

### Unknown Traffic

Unknown flows retain transport, port, direction, packet-size, volume, and risk
hints so unusual traffic remains reviewable without exposing raw content.

## Conversation Timeline

Flow timelines may contain `flow_started`, `protocol_detected`, `dns_query`,
`http_request`, `tls_handshake_metadata`, `alert_triggered`, and
`unusual_destination` events. Each event contains a timestamp, type, summary,
severity, redacted metadata, and optional related packet/alert IDs.

## Flow Risk Scoring

Flow risk is a bounded `0..100` score:

- `low`: `0..29`;
- `medium`: `30..59`;
- `high`: `60..79`;
- `critical`: `80..100`.

Inputs include alert density, suspicious or uncommon protocols, unusual ports,
new external destinations, repeated DNS failures, high packet/byte volume, and
outbound activity from sensitive processes. Every score includes readable
reasons. Risk is an investigation aid, not proof of malicious activity.

## API

```text
GET /api/flows
GET /api/flows/summary
GET /api/flows/top
GET /api/flows/{flow_id}
GET /api/flows/{flow_id}/timeline
GET /api/conversations
GET /api/conversations/{conversation_id}
GET /api/protocols/summary
GET /api/protocols/{protocol}/flows
GET /api/reports/flows/summary
GET /api/reports/flows/summary.csv
```

Flow filters include protocol, risk, source/destination IP, direction, port,
alert presence, limit, and sort.

## Offline PCAP Support

Offline PCAP analysis preserves existing response fields and additionally
returns flow summary, flows, top conversations, top risky flows, protocol
summary, risk distribution, and redacted conversation timelines.

## Redaction And Deliberate Exclusions

All UI-visible summaries, protocol metadata, timeline text, reports, and flow
samples are built from redacted metadata.

NetBotPro intentionally does not expose or collect raw passwords, cookies,
authorization values, tokens, API keys, sessions, credentials, decrypted TLS
content, or keys.

Full and Forensic capture remain authorized opt-in capture modes, but they do
not bypass central redaction for UI/report/flow output.

## Agent Limitations

Agent Mode remains telemetry-only and read-only. This phase does not add
command/control, remote execution, shell, file collection, Agent raw packets,
raw payload forwarding, PCAP forwarding, credential collection, or Agent
auto-update.
