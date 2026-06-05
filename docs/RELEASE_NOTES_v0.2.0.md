# NetBotPro v0.2.0 Release Notes

## Summary

NetBotPro v0.2.0 is the Agent and Fleet Monitoring release. It adds a
read-only, summary-only monitoring path for authorized servers while preserving
the existing local analysis and controlled Remote Sensor workflows.

This release focuses on fleet visibility, historical analysis, release
readiness, and privacy. It does not add command/control, remote command
execution, file collection, raw packet forwarding, raw payload forwarding,
PCAP forwarding, or Agent auto-update.

## Highlights

- Read-only Agent Mode with stable identity, configuration, API client, runner,
  heartbeat, and redacted telemetry.
- Auto-initialized SQLite Agent history for heartbeat, telemetry, health,
  alerts, flows, capture status, and risk snapshots.
- Fleet Dashboard with overview metrics, filtering, sorting, offline detection,
  risk scoring, Agent details, and historical trends.
- Redacted Fleet Summary Report in JSON and CSV.
- Demo Agent seed data, local multi-Agent simulation, retention cleanup, and
  operational QA scripts.
- Polished Feature Matrix, architecture diagrams, deployment guide, and release
  QA checklist.

## Demo Instructions

Install dependencies and start the local demo:

```powershell
python -m pip install -r requirements-dev.txt
cd frontend
npm ci
cd ..
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-demo.ps1 -StartFrontend
```

Open:

```text
http://127.0.0.1:5173/?page=agents
```

The launcher seeds four realistic demo Agents and does not print the raw local
token.

## Deployment Notes

- Windows is the validated desktop release target for v0.2.0.
- The GitHub Release contains versioned Windows setup and portable artifacts
  plus `SHA256SUMS-windows.txt`.
- Linux packaging is staged and requires native production validation before
  distribution.
- Keep Remote Sensor and central Agent APIs behind a VPN, private network, or
  secured reverse proxy.
- Configure strong local, sensor, and Agent tokens outside source control.

See [Deployment Overview](DEPLOYMENT_OVERVIEW.md) and
[Agent Mode](AGENT_MODE.md) for operational details.

## Security Notes

- Central redaction masks credentials, authorization headers, cookies, tokens,
  secrets, session values, and JWT-like strings before visible output or Agent
  history persistence.
- Agent tokens are hashed for registry storage.
- Agent and sensor scripts hide raw tokens by default.
- Agent sync errors are sanitized before logging.
- Remote Sensor mode requires explicit remote access, token protection,
  optional IP/CIDR allowlists, and authorized capture policy acceptance.
- Full and Forensic capture remain guarded opt-in modes for authorized systems.

## Known Limitations

- Agent Mode is read-only monitoring only.
- There is no command/control, remote command execution, remote shell, or file
  collection in this release.
- No raw packet forwarding is available from Agents.
- No raw payload forwarding or payload preview forwarding is available from
  Agents.
- No PCAP forwarding is available from Agents.
- Agents do not forward credentials.
- Agent auto-update is not included.
- Linux desktop packaging remains staged; macOS desktop packaging is planned.

## QA Status

- Python dependency health: passed.
- Backend test suite: passed.
- Frontend UI tests: passed.
- Frontend production build: passed.
- Backend and frontend CI on Windows, Linux, and macOS: passed.
- Windows Desktop Smoke: passed.
- Windows desktop packaging and SHA256 checksum generation: passed.
- Release-readiness, token-safety, redaction, Agent history, and capture-policy
  checks: passed.

See [Release QA Checklist](RELEASE_QA_CHECKLIST.md) for the complete sign-off
list.
