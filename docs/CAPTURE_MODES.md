# Capture Modes

NetBotPro supports three defensive capture modes for systems you own,
administer, or have explicit permission to monitor. The default posture is
metadata-first: collect enough context for detection and reporting without
keeping raw packet contents.

Full and Forensic capture are only for authorized servers, with permission from
the server owner or administrator. Do not enable payload or raw artifact capture
on third-party networks or systems you do not administer.

## Metadata

Metadata is the default and safest mode.

- Stores packet metadata, flow context, protocol hints, process attribution,
  alerts, and summaries.
- Disables payload preview storage even when `NETBOT_PAYLOAD_CAPTURE=1`.
- Does not require Safe Use acceptance or full-capture authorization for
  local/dev use.
- Allows normal dashboard views and redacted session/report exports.
- Rejects raw PCAP export.

## Full

Full mode enables payload-aware capture for controlled server investigations.
Use it only on an authorized server where the owner or administrator has
approved packet-content monitoring.

- Requires `NETBOT_ALLOW_FULL_CAPTURE=1`.
- Requires Safe Use Policy acceptance through `NETBOT_SAFE_USE_ACCEPTED=1` or
  Settings.
- Requires trusted client access; remote clients also need a valid
  `X-NetBot-Token` and must pass `NETBOT_REMOTE_IP_ALLOWLIST` when configured.
- Enables payload previews only when `NETBOT_PAYLOAD_CAPTURE=1`.
- Shows only redacted values in UI, JSON-style metadata, reports, and audit
  logs.
- Allows raw PCAP download only through `/api/exports/raw-pcap` after token,
  Safe Use, mode, suffix, path-containment, and audit checks pass.

## Forensic

Forensic mode is intended for incident response on authorized servers.
Use it only when the server owner or administrator has approved incident
evidence capture and retention.

- Requires every Full mode control.
- Requires either `forensic_duration_minutes` or explicit confirmation that
  capture may run until the operator stops it.
- Writes mode-specific audit events for start/stop and raw artifact download.
- Should use shorter retention, restricted operator IP allowlists, and secure
  storage for raw artifacts.
- Allows raw PCAP download through the same guarded raw export path as Full
  mode.

## Redaction

Redaction is enabled by default for non-raw outputs. NetBotPro masks
Authorization, Proxy-Authorization, Cookie, Set-Cookie, Basic/Bearer tokens,
password/token/api key/session/secret key-value pairs, sensitive query
parameters, and JWT-like strings.

Redaction is applied before payload previews, report/export dataframes, and
JSON-style summaries leave the backend. Raw PCAP is intentionally not redacted,
so it is only exposed through the guarded raw artifact export.

## Raw PCAP Warning

Raw PCAP can contain credentials, cookies, session material, personal data, and
proprietary traffic. Only export raw artifacts in Full or Forensic mode, with
token authorization, Safe Use acceptance, and a matching audit trail.
