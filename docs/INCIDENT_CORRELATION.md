# Incident Correlation

NetBotPro groups related, already-derived analysis signals into a smaller set of
explainable security incidents. The engine is local, deterministic, read-only,
bounded, and designed to reduce alert fatigue without claiming that a correlated
pattern is automatically malicious.

## Signal Flow

```text
Packet / flow metadata
  -> protocol and detection analysis
  -> service attribution and expert information
  -> bounded incident correlation
  -> Live Ring Buffer and WebSocket incident batches
  -> Incident API and UI
```

The engine currently runs in memory. Incident persistence is intentionally left
for a later schema-reviewed step. Incidents age out after the configured retention
period and both incident count and timeline length have hard limits.

## Supported Incident Types

- **Possible Beaconing:** repeated encrypted traffic to an unknown destination,
  optionally strengthened by related alerts or expert evidence.
- **Possible Port Scan / Connection Sweep:** existing scan or sweep signals from
  the same source in the correlation window.
- **Suspicious DNS Activity:** existing entropy, NXDOMAIN, DGA, or DNS-tunnel
  signals.
- **Unusual External Service:** repeated unknown, rare, or low-confidence external
  service attribution.
- **Data Exfiltration Indicator:** existing exfiltration/upload signals or very
  high outbound flow volume combined with related context.

Agent/host-health incidents are not generated in this step because agent health
snapshots are not yet connected to the live correlation stream. No unsupported
detection is simulated.

## Correlation And Scoring

Signals are compared by source host, flow key, destination, application, service,
domain, alert ID, and time. A single weak signal does not create an incident.
Multiple related sources of evidence or repeated strong signals are required.

Severity describes accumulated impact evidence: `info`, `low`, `medium`, `high`,
or `critical`. Confidence is `low`, `medium`, or `high` and describes how strongly
the signals appear to belong together, not whether activity is malicious.
Every incident includes correlation reasons, bounded evidence, recommended manual
investigation steps, and false-positive notes.

## Timeline

Timeline entries contain only a timestamp, event type, redacted summary, source,
and related safe identifiers. Entries are timestamp-sorted and capped by
`NETBOT_INCIDENT_MAX_SIGNALS_PER_INCIDENT`.

## Reading An Incident

Start with severity to prioritize review, then use confidence to understand how
strongly the evidence belongs together. Compare first and last seen to establish
the activity window. Source hosts, applications, services, and domains provide
scope, while evidence and correlation reasons explain why the signals were grouped.
The timeline shows their order. Recommended investigation steps are manual guidance;
false-positive notes highlight common benign explanations that should be checked.

## Redacted Summary Export

Select an incident and choose **Generate Markdown** in the Incident summary section.
NetBotPro requests a fresh summary from the protected local API and displays it in
a read-only text area. Use **Copy Markdown** to place that text on the clipboard for
an authorized ticket, investigation note, or handoff.

The export is generated in memory and is not persisted by NetBotPro. It contains
only bounded incident fields and passes through central redaction. Raw payloads,
credentials, cookies, authorization headers, sessions, and secrets are excluded or
masked. Generating or copying a summary performs no response action and does not
change incident state.

## Configuration

| Variable | Default | Purpose |
| --- | ---: | --- |
| `NETBOT_INCIDENTS_ENABLED` | `true` | Enables read-only correlation. |
| `NETBOT_INCIDENT_CORRELATION_WINDOW_SEC` | `600` | Maximum time between related signals. |
| `NETBOT_INCIDENT_MAX_OPEN` | `1000` | Hard cap for in-memory incidents. |
| `NETBOT_INCIDENT_MAX_SIGNALS_PER_INCIDENT` | `500` | Evidence and timeline cap per incident. |
| `NETBOT_INCIDENT_RETENTION_HOURS` | `24` | In-memory retention. |
| `NETBOT_INCIDENT_MIN_SEVERITY` | `low` | Minimum displayed severity. |
| `NETBOT_INCIDENT_HIGH_SIGNAL_THRESHOLD` | `5` | Signal count that promotes severity to high. |
| `NETBOT_INCIDENT_CRITICAL_SIGNAL_THRESHOLD` | `10` | Signal count that promotes severity to critical. |

Invalid values fall back to bounded defaults.

## Security Boundaries

All signal data passes through central redaction. Raw payloads, credentials,
authorization headers, cookies, tokens, and sessions are not part of an incident.
The engine does not block hosts, execute response actions, send commands to agents,
decrypt TLS, inspect browser data, or change Remote Sensor and Agent boundaries.

False positives remain possible. Analysts should validate context and use the
recommended steps before drawing conclusions.
