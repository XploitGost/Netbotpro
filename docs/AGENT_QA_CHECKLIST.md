# Agent Operational QA Checklist

Use this checklist before demos, customer reviews, and release candidates for
Agent Mode. Agent Mode must remain read-only monitoring in this phase.

## Startup

- Start the central backend and confirm `/api/status` is healthy.
- Configure `NETBOT_AGENT_TOKEN` with a long random value.
- Configure `NETBOT_LOCAL_TOKEN` for dashboard reads.
- Confirm `.runtime/logs/agents.db` is created automatically.

## Single Agent

- Start one agent with `scripts/dev/start-agent.ps1`.
- Confirm `POST /api/agents/register` succeeds.
- Confirm `POST /api/agents/heartbeat` updates `last_seen`.
- Confirm `POST /api/agents/telemetry` stores redacted summary telemetry.
- Confirm `scripts/dev/status-agent.ps1` never prints the raw token.
- Stop the agent with `scripts/dev/stop-agent.ps1`.

## Local Multi-Agent Simulation

- Start a local demo fleet with `scripts/dev/start-agent-demo-fleet.ps1`.
- Confirm each agent has a separate PID file.
- Confirm each agent has separate stdout and stderr logs.
- Confirm status shows running/stopped, PID, log path, and last log write time.
- Confirm `scripts/dev/stop-agent-demo-fleet.ps1` removes stale PID files.

## Demo Seed Data

- Run `scripts/dev/seed-agent-demo.ps1 -Reset -Count 4`.
- Confirm the dashboard shows the demo data indicator.
- Confirm the seeded fleet includes low, elevated, critical, and offline cases.
- Confirm seeded alert text is redacted.
- Confirm no token, credential, cookie, authorization header, raw payload, raw
  packet, or PCAP path appears in the database or UI.

## Backend API

- Verify `GET /api/agents`.
- Verify `GET /api/agents/overview`.
- Verify `GET /api/agents/{agent_id}`.
- Verify telemetry, health, alerts, and risk history endpoints for `1h`, `24h`,
  `7d`, and `30d`.
- Verify `GET /api/agents/alerts/summary`.
- Verify `GET /api/agents/risk/summary`.
- Verify `GET /api/agents/reports/fleet-summary`.
- Verify `GET /api/agents/reports/fleet-summary.csv`.
- Confirm fleet report generation records `agent_fleet_report_generated`.

## Dashboard

- Verify empty state when no agents are registered.
- Verify loading state during refresh.
- Verify error state and retry if the central backend is unavailable.
- Verify total, online, offline, high-risk, critical alert, average CPU, average
  RAM, and average disk overview metrics.
- Verify risk badges for low, medium, high, and critical severities.
- Verify offline badges are visible.
- Verify detail view health, network, capture, alerts, flows, risk, and trends.
- Verify filters for online/offline, high risk, critical alerts, capture running,
  and OS.
- Verify sorting by risk, last seen, and alerts.

## Retention

- Run `scripts/dev/cleanup-agent-history.ps1 -DryRun`.
- Confirm per-table deletion counts are reported.
- Run cleanup without `-DryRun` against test data.
- Confirm old history rows are removed.
- Confirm agent identity rows remain in `agents`.

## Safety Boundaries

- Confirm no command/control endpoint exists.
- Confirm no remote command execution exists.
- Confirm no shell access exists.
- Confirm no file collection exists.
- Confirm no raw packet forwarding exists.
- Confirm no raw payload forwarding exists.
- Confirm no PCAP forwarding exists.
- Confirm no credential collection or browser/session capture exists.
- Confirm tokens are absent from UI, logs, reports, and exported fleet summaries.

## Final Checks

- Run `python -m pip check`.
- Run `python -m unittest discover -s tests -v`.
- Run `cd frontend && npm ci && npm run build`.
- Optionally run `cd frontend && npm run test:ui`.
