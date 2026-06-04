# Agent Mode

Agent Mode is a lightweight telemetry runner for servers you own or administer.
It connects an authorized host to a central NetBotPro backend without exposing
raw packets, payload previews, or PCAP artifacts in phase one.

Remote Sensor mode still runs the full FastAPI capture backend on the remote
host. Agent Mode is smaller: it registers the host, sends heartbeat events, and
posts redacted health and capture summaries to the central dashboard.

## What Agent Mode Sends

Agent telemetry is summary-only:

- Stable agent ID, hostname, OS, platform, machine type, and agent version.
- Health data such as CPU percent, memory percent, disk percent, uptime, boot
  time, and process count.
- Network counters and interface names from the host.
- Capture state summary when supplied by the runner.
- Alert counts, severity summary, and recent alert metadata if supplied.
- Flow counts and protocol summaries if supplied.

The agent payload builder runs central redaction before data is submitted.
Authorization headers, cookies, passwords, API keys, secrets, session values,
tokens, and JWT-like strings are masked.

The central backend redacts the same payload again before it is stored or shown
in the UI. This double-redaction posture is deliberate: the agent should avoid
sending secrets, and the central service should still defend itself if a future
agent version or custom integration submits sensitive text.

## What Agent Mode Does Not Send

Phase one does not send:

- Raw packets.
- Raw payload bytes.
- Payload previews.
- Raw PCAP or PCAPNG files.
- Browser cookies, bearer tokens, passwords, or API keys.
- Remote shell commands or command output.

Raw capture artifacts remain guarded by Full and Forensic capture policies on
the sensor backend. Agent Mode does not bypass those controls.

## Architecture

Agent Mode has three small boundaries:

- `agent/agent_runner.py` owns the loop: load config, create identity, register,
  heartbeat, submit telemetry, and retry with backoff.
- `agent/agent_payloads.py` owns the summary payload shape and calls central
  redaction before sending anything to the backend.
- `backend/app/services/agent_registry.py` owns server-side registration,
  token verification, redaction, in-memory state, and append-only event storage.

The React console reads the registry through local-token-protected API routes
and renders the `Agents` page. The page shows host, status, OS, health, capture
summary, alert counts, and recent telemetry. It does not expose raw packet
tables, payload previews, or raw artifact links for agents.

## Backend Endpoints

Agents use token-authenticated endpoints:

- `POST /api/agents/register`
- `POST /api/agents/heartbeat`
- `POST /api/agents/telemetry`

The dashboard uses local-token-protected endpoints:

- `GET /api/agents`
- `GET /api/agents/{agent_id}`
- `GET /api/agents/{agent_id}/telemetry`

Agent requests must include:

```text
X-NetBot-Agent-Id: <agent uuid>
X-NetBot-Agent-Token: <shared agent token>
```

If `NETBOT_AGENT_TOKEN` is configured on the central backend, registration and
all later agent requests must match it.

Dashboard reads still use the normal local dashboard controls:

- loopback is trusted for local development;
- remote dashboard access requires `NETBOT_REMOTE_ACCESS=1`;
- sensitive dashboard reads require `X-NetBot-Token` when
  `NETBOT_LOCAL_TOKEN` is configured.

Agent authentication is intentionally separate from dashboard authentication.
An agent token can submit telemetry, but it cannot read the operator dashboard.

## Configuration

Agent environment variables:

| Variable | Required | Purpose |
| --- | --- | --- |
| `NETBOT_CENTRAL_API` | yes | Central API base, for example `http://host:8000/api`. |
| `NETBOT_AGENT_TOKEN` | yes | Shared secret used in `X-NetBot-Agent-Token`. |
| `NETBOT_AGENT_ID` | no | Pre-provisioned UUID. If omitted, a stable local UUID is created. |
| `NETBOT_AGENT_MODE` | no | Enables explicit agent-mode runtime intent when set to `1`, `true`, `yes`, or `on`. |
| `NETBOT_AGENT_DISPLAY_NAME` | no | Friendly display name, mainly useful for local demo fleets. |
| `NETBOT_AGENT_HEARTBEAT_INTERVAL` | no | Heartbeat seconds, clamped by config loader. |
| `NETBOT_AGENT_TELEMETRY_INTERVAL` | no | Telemetry seconds, clamped by config loader. |

Central backend environment:

| Variable | Required | Purpose |
| --- | --- | --- |
| `NETBOT_AGENT_TOKEN` | recommended | Rejects agent registration and telemetry unless the submitted token matches. |
| `NETBOT_LOCAL_TOKEN` | recommended | Protects dashboard reads including `/api/agents`. |
| `NETBOT_REMOTE_ACCESS` | remote only | Enables non-loopback dashboard clients when explicitly needed. |
| `NETBOT_AGENT_OFFLINE_AFTER_SECONDS` | no | Marks agents offline when `last_seen` is older than this threshold. Default: `90`. |
| `NETBOT_AGENT_HISTORY_RETENTION_DAYS` | no | Default retention window for history cleanup. Default: `30`. |

## Run On Windows

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-agent.ps1 `
  -CentralApi "http://CENTRAL_HOST:8000/api" `
  -AgentToken "use-a-long-random-token"
```

Check or stop the runner:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\status-agent.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\dev\stop-agent.ps1
```

The scripts write:

- PID: `.runtime/agent-runner.pid`
- stdout: `.runtime/logs/agent-runner.log`
- stderr: `.runtime/logs/agent-runner.err.log`

The token is never printed by the status script and is hidden by the start
script output. The agent runner also sanitizes sync exception text before it is
written to `.runtime/logs/agent-runner.err.log`.

## Run On Linux Or macOS

```bash
export NETBOT_AGENT_MODE=1
export NETBOT_CENTRAL_API="http://CENTRAL_HOST:8000/api"
export NETBOT_AGENT_TOKEN="use-a-long-random-token"
python -m agent.agent_runner
```

## Identity

If `NETBOT_AGENT_ID` is not set, the agent creates a stable UUID in:

```text
.runtime/agent-identity.json
```

That ID is reused across restarts. Set `NETBOT_AGENT_ID` only when you need a
pre-provisioned identity.

## Storage

Agent history now uses SQLite by default:

```text
.runtime/logs/agents.db
```

The database is initialized automatically on startup. The schema is intentionally
split by analytical surface so the dashboard can query fleet summaries without
replaying raw telemetry blobs.

Tables:

- `agents`
- `agent_heartbeats`
- `agent_telemetry`
- `agent_health_snapshots`
- `agent_alert_snapshots`
- `agent_flow_snapshots`
- `agent_risk_snapshots`

`agent_telemetry` keeps the redacted full summary envelope. The snapshot tables
store focused history for health trends, alert trends, flow trends, capture
status analysis, and risk scoring.

Append-only JSONL is still available as a development fallback when the registry
is explicitly constructed with a `.jsonl` path:

```text
.runtime/logs/agents.jsonl
```

Both storage paths keep redacted public records, telemetry summaries,
timestamps, and a SHA-256 token hash for local verification when no central
`NETBOT_AGENT_TOKEN` is configured. The raw agent token is not stored.

SQLite is the preferred path for multi-server dashboards because it supports
indexed history queries, retention, migrations, compaction, integrity checks,
and concurrent read patterns without replaying a growing log file.

## Agent History

The central backend stores:

- heartbeat history;
- telemetry history;
- health history;
- alert summary history;
- flow summary history;
- capture status history inside the redacted telemetry envelope;
- risk score history.

History endpoints support `range=1h`, `range=24h`, `range=7d`, and
`range=30d`. Sparse data returns an empty or partial result rather than an
error.

```text
GET /api/agents/{agent_id}/telemetry?range=24h
GET /api/agents/{agent_id}/health/history?range=24h
GET /api/agents/{agent_id}/alerts/history?range=24h
GET /api/agents/{agent_id}/risk/history?range=24h
```

Fleet endpoints:

```text
GET /api/agents/overview
GET /api/agents/alerts/summary
GET /api/agents/risk/summary
```

## Demo Data

Use the seed script when you need to show the Fleet Dashboard without real
servers:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\seed-agent-demo.ps1 -Reset -Count 4
```

The script writes realistic, redacted records to:

```text
.runtime/logs/agents.db
```

The seeded fleet includes:

- a healthy low-risk web server;
- a database server under CPU/RAM pressure;
- an API server with critical alerts;
- an offline file server.

The script does not print raw tokens, credentials, cookies, authorization
headers, raw payloads, raw packets, or PCAP paths. Demo records include a `demo`
capability so the UI can show a `Demo data` indicator.

## Local Multi-Agent Simulation

For operational QA against a running central backend, start several local agent
runners:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-agent-demo-fleet.ps1 `
  -Count 3 `
  -CentralApi "http://127.0.0.1:8765/api" `
  -Interval 15 `
  -AgentToken "use-a-long-random-token"
```

Check or stop the local fleet:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\status-agent-demo-fleet.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\dev\stop-agent-demo-fleet.ps1
```

The fleet scripts create per-agent PID files and logs under:

```text
.runtime/agent-demo-fleet/
.runtime/agent-demo-fleet/logs/
```

Status output shows running/stopped state, PID, log path, and last log write
time. It never prints the raw agent token.

## Offline Detection

Agents are marked offline when `last_seen` is older than the configured
threshold:

```text
NETBOT_AGENT_OFFLINE_AFTER_SECONDS=90
```

The value is clamped to a defensive range and defaults to 90 seconds. Offline
detection is computed when agents are listed or fetched, so stale records do not
need a background worker to appear offline.

## Risk Scoring

Risk score is a bounded `0..100` value with a severity label:

- `low`: `0..29`
- `medium`: `30..59`
- `high`: `60..79`
- `critical`: `80..100`

Inputs:

- critical, high, medium, and low alert counts;
- CPU, RAM, and disk pressure;
- capture errors;
- offline status;
- traffic spike signals when flow or packet counts are available.

The score is stored in `agent_risk_snapshots` and copied onto each public agent
record for fast fleet sorting.

## Dashboard Overview

The Agents page is a read-only multi-server dashboard:

- total, online, offline, high-risk, total alert, critical alert, average CPU,
  average RAM, and average disk counts;
- top risky servers;
- status, hostname, OS, last seen, CPU, RAM, disk, capture mode, capture state,
  alerts today, and risk score;
- filters for online/offline, high risk, critical alerts, capture running, and
  OS;
- sorting by risk, last seen, and alerts;
- detail view with health, network, capture status, recent alerts, flow summary,
  risk, health history, alert trend, risk trend, last heartbeat, and last
  telemetry.
- empty, loading, and error states for operational demos;
- a demo data indicator when seeded records are present;
- a fleet summary export button.

The UI must not render agent tokens, raw packet data, raw payloads, credentials,
cookies, authorization headers, or PCAP forwarding controls.

## Fleet Summary Report

Operators can generate a redacted fleet summary:

```text
GET /api/agents/reports/fleet-summary
GET /api/agents/reports/fleet-summary.csv
```

The JSON report includes:

- `generated_at`;
- total, online, offline, high-risk, and critical alert counts;
- top risky agents;
- an agent table summary;
- risk distribution;
- alert distribution;
- health summary;
- recommended actions.

Report generation records an audit event:

```text
event_type = agent_fleet_report_generated
```

Report output is redacted and must not include tokens, credentials, raw payloads,
raw packets, or PCAP data.

## History Retention

Cleanup is intentionally limited to history tables. It does not delete agent
identity rows from the `agents` table.

Run a dry-run cleanup:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\cleanup-agent-history.ps1 `
  -DbPath ".runtime/logs/agents.db" `
  -RetentionDays 30 `
  -DryRun
```

Run cleanup:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\cleanup-agent-history.ps1 `
  -DbPath ".runtime/logs/agents.db" `
  -RetentionDays 30
```

The internal function is:

```text
cleanup_agent_history(retention_days)
```

In code this is implemented as `AgentRegistry.cleanup_history(retention_days)`.
The script reports per-table deletion counts and does not print tokens.

## Operational QA

Use `docs/AGENT_QA_CHECKLIST.md` before customer demos or release candidates.
It covers backend startup, single-agent and multi-agent runs, register,
heartbeat, telemetry, offline detection, risk scoring, SQLite persistence,
dashboard overview, detail view, filters, fleet summary report, retention
cleanup, log sanitization, demo seed data, and frontend build.

## Logging

Agent scripts write stdout and stderr to:

```text
.runtime/logs/agent-runner.log
.runtime/logs/agent-runner.err.log
```

Expected log content:

- agent ID;
- central API URL;
- registration success;
- heartbeat or telemetry retry messages;
- sanitized exception summaries.

Forbidden log content:

- `NETBOT_AGENT_TOKEN`;
- `X-NetBot-Agent-Token` raw values;
- Authorization, Cookie, password, API key, secret, session, or JWT-like values;
- raw packets, payload bytes, payload previews, PCAP paths submitted by an
  agent.

The test suite includes script and sanitizer coverage to keep the raw token out
of agent console output and sync failure logs.

## Security Notes

Use Agent Mode only on systems and networks where you have explicit permission.
Expose the central backend through trusted private networking, VPN, SSH tunnel,
or a TLS reverse proxy. Keep `NETBOT_AGENT_TOKEN` long, random, and out of logs.

Agent Mode is currently read-only monitoring. This phase does not add
command/control, remote command execution, shell access, file collection, raw
packet forwarding, raw payload forwarding, PCAP forwarding, credential
collection, or browser/session capture.

Any future command queue belongs in a separate phase with explicit design,
authorization, audit, and operator confirmation. It is documented only as future
work, not implemented in executable code in this phase.

## Next Phase Checklist

Before Agent Mode grows beyond summary telemetry, add:

- SQLite migration versioning beyond the current auto-init schema.
- Per-agent token rotation or per-agent token hashes instead of one shared
  fleet token.
- Explicit enrollment and revocation workflow.
- Audit events for operator reads and registry state changes.
- TLS deployment guidance for central API exposure.
- Separate policy gates for any future command, file, or raw capture feature.
