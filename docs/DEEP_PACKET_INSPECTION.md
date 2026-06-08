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

## Stream Reconstruction And Expert Info

Follow Stream orders packets and labels client-to-server or server-to-client
traffic. Metadata mode returns summaries only. Full and Forensic modes return
bounded redacted previews. TLS streams remain encrypted.

Expert Info highlights TCP resets, fragmentation, DNS NXDOMAIN, HTTP errors,
cleartext external HTTP, uncommon ports, protocol/port mismatch, high volume,
and high alert density.

## Offline PCAP Deep Analysis

Authorized PCAP analysis adds packet details, protocol stacks, safe Hex
metadata, Expert Info, flow/conversation summaries, and stream summaries while
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
