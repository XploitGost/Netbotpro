# Deep Packet Inspection

NetBotPro v0.3.0 adds Wireshark-style packet inspection for authorized local
captures, authorized Remote Sensor captures, and intentionally supplied PCAP
files. It complements Wireshark; it does not attempt to expose sensitive
content or replace every protocol decoder.

## Packet Dissection And Details Tree

The Packet Dissector converts safe packet metadata into a searchable,
expandable layer tree. Supported MVP layers are Frame, Ethernet, ARP, IPv4,
IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS metadata, SSH, RDP, SMB, mail protocol
metadata, and Unknown. Fields include stable keys, display values, severity,
and byte ranges when available.

## Hex View

Metadata mode never exposes raw payload bytes. Full and Forensic modes may
produce a bounded bytes preview only when existing capture policy permits it.
ASCII is always centrally redacted and the UI displays a sensitivity warning.

## Display Filters

The safe parser supports `==`, `!=`, `contains`, `startswith`, `endswith`,
numeric comparisons, `and`, `or`, and `not`. It does not use Python `eval`.
Filters operate on redacted packet and flow metadata.

The Inspect workspace includes field suggestions, common recipes, built-in
filters, custom saved filters, and recent safe search results. Saved filters
are stored in `.runtime/logs/saved_filters.json`; sensitive-looking values are
redacted before persistence.

Common examples:

- `ip.addr == 10.0.0.5`
- `tcp.flags.reset == true`
- `dns.rcode != NOERROR`
- `http.status >= 400`
- `app_protocol == TLS`

## Protocol Intelligence Expansion

Protocol Intelligence turns collected packet metadata into operational
summaries:

- TCP analysis tracks handshake state, flags, resets, duplicate-ACK hints,
  retransmission hints, and zero-window hints.
- DNS analysis tracks query types, response codes, NXDOMAIN rate, repeated
  queries, long names, and high-entropy label hints.
- HTTP analysis tracks methods, status groups, hosts, content types, cleartext
  external traffic, and suspicious path hints after URL redaction.
- TLS analysis tracks visible SNI, ALPN, versions, and deprecated-version
  warnings without decrypting TLS.

The Protocol Statistics view combines packet count, flow count, bytes, alerts,
and bounded risk for each detected protocol.

## Packet Search

Packet Search queries safe metadata fields such as IP addresses, ports,
protocols, redacted summaries, redacted protocol metadata, risk, and Expert
Info categories. It does not search unredacted raw payloads or retain raw
sensitive queries in logs.

## Stream Reconstruction And Expert Info

Follow Stream orders packets and labels client-to-server or server-to-client
traffic. Metadata mode returns summaries only. Full and Forensic modes return
bounded redacted previews. TLS streams remain encrypted.

Expert Info highlights TCP resets, fragmentation, DNS NXDOMAIN, HTTP errors,
cleartext external HTTP, uncommon ports, protocol/port mismatch, high volume,
high alert density, incomplete handshakes, retransmission hints, and deprecated
TLS versions. Items include a category, severity, evidence, related flow or
packet, and a recommended action.

## Offline PCAP Deep Analysis

Authorized PCAP analysis adds packet details, protocol stacks, safe Hex
metadata, Expert Info, flow/conversation summaries, stream summaries, and the
same TCP/DNS/HTTP/TLS intelligence summaries used by live capture while
preserving previous response fields.

## Privacy And Security Boundaries

- No credential collection.
- No TLS decryption, MITM, private-key extraction, or session-key capture.
- No raw Authorization, Cookie, password, token, or secret in UI, logs,
  reports, exports, ASCII previews, or stream previews.
- Agent Mode remains telemetry-only and read-only. Agents do not forward raw
  packets, payloads, or PCAP files.
- Deep inspection is restricted to authorized captures and PCAPs.

## Differences From Wireshark

Wireshark has a much larger decoder ecosystem and advanced reassembly.
NetBotPro focuses on an operational protocol set, explainable warnings,
central redaction, flow correlation, and safe management views.
