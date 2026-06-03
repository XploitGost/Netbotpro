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
script output.

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

## Security Notes

Use Agent Mode only on systems and networks where you have explicit permission.
Expose the central backend through trusted private networking, VPN, SSH tunnel,
or a TLS reverse proxy. Keep `NETBOT_AGENT_TOKEN` long, random, and out of logs.

Phase one is intentionally telemetry-only. Remote commands, file collection,
and raw capture forwarding are separate future work and must keep the same
authorization, audit, and redaction boundaries.
