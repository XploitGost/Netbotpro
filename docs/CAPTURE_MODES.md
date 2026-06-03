# Capture Modes

NetBotPro supports three defensive capture modes for authorized systems.

## Metadata

Metadata is the default and safest mode.

- Stores packet metadata, flow context, protocol hints, process attribution, alerts, and summaries.
- Does not store raw payload previews.
- Does not require full-capture authorization for local/dev use.
- Reports and exports remain redacted.

## Full

Full mode enables redacted payload previews for controlled server investigations.

- Requires `NETBOT_ALLOW_FULL_CAPTURE=1`.
- Requires Safe Use Policy acceptance through `NETBOT_SAFE_USE_ACCEPTED=1` or Settings.
- Requires trusted client access and token enforcement.
- UI, JSON-style metadata, reports, and audit logs must use redacted values.
- Raw artifacts, if present, are only downloadable through raw export policy checks.

## Forensic

Forensic mode is intended for incident response on servers you own or administer.

- Requires the same controls as Full mode.
- Requires either `forensic_duration_minutes` or explicit confirmation that capture runs until stopped.
- Writes mode-specific audit events.
- Should use shorter retention and tighter operator IP allowlists.

## Redaction

Redaction is enabled by default for non-raw outputs. NetBotPro masks Authorization, Proxy-Authorization, Cookie, Set-Cookie, Basic/Bearer tokens, password/token/api key/session/secret key-value pairs, sensitive query parameters, and JWT-like strings.

## Raw PCAP Warning

Raw PCAP can contain credentials, cookies, session material, personal data, and proprietary traffic. Only export raw artifacts in Full or Forensic mode, with token authorization, Safe Use acceptance, and a matching audit trail.
