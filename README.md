# NetBotPro

[![CI](https://github.com/XploitGost/Netbotpro/actions/workflows/ci.yml/badge.svg)](https://github.com/XploitGost/Netbotpro/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/XploitGost/Netbotpro?label=release)](https://github.com/XploitGost/Netbotpro/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Defensive Use](https://img.shields.io/badge/use-defensive%20security-blue)](#legal-and-defensive-use-notice)

NetBotPro is a local-first network analysis and defensive detection product for Windows-first desktop workflows, browser-based investigation, and authorized server-side packet sensing.

It combines a FastAPI backend, a React investigation console, an Electron desktop shell, live packet capture through Scapy/Npcap, offline PCAP analysis, alert scoring, process attribution, exports, reports, and remote sensor mode for systems you own or administer.

## Screenshots

| Monitor | Inspect | Reports |
| --- | --- | --- |
| ![NetBotPro monitor dashboard](docs/assets/netbotpro-monitor.png) | ![NetBotPro inspect workspace](docs/assets/netbotpro-inspect.png) | ![NetBotPro reports workspace](docs/assets/netbotpro-reports.png) |

## Project Overview

NetBotPro v0.2.0 is a local-first defensive network analysis and fleet
monitoring platform. It combines packet inspection, redacted reporting,
authorized Remote Sensor capture, and summary-only Agent/Fleet monitoring in a
single operator dashboard.

Agent Mode is intentionally read-only. It sends health, network, capture,
alert, flow, and risk summaries without forwarding raw packets, raw payloads,
or PCAP artifacts.

## Key Features

- Live packet and alert monitoring with a responsive analyst console.
- Inspect workspace for packet, alert, flow, process, protocol, and related-activity investigation.
- Local token authentication for sensitive API and websocket routes.
- Websocket auth via subprotocol negotiation to avoid leaking tokens in URLs.
- Offline PCAP analysis with upload size and file-type controls.
- Traceroute, export, report, and investigation packaging flows.
- Desktop mode with a generated secure local token and an isolated Electron preload bridge.
- Remote sensor mode for legally authorized servers and networks.
- Agent Mode for summary-only server telemetry, fleet history, demo data, and
  read-only multi-server dashboards.
- SQLite Agent history, offline detection, risk scoring, redacted Fleet Summary
  Reports, and operational demo/QA scripts.

## Feature Matrix

| Area | Status | Notes |
| --- | --- | --- |
| Local web dashboard | Stable dev path | React/Vite console on `127.0.0.1:5173`. |
| Electron desktop shell | Windows-ready | Secure preload bridge, packaged backend, setup and portable artifacts. |
| Live packet capture | Environment-dependent | Requires Npcap/libpcap and elevated privileges where needed. |
| Inspect workspace | Active | Packet, alert, flow, process, protocol, and related-activity context. |
| Offline PCAP analysis | Active | Restricted file types and upload size limits. |
| Reports and exports | Active | Safe generated downloads inside the log directory. |
| Remote sensor mode | Controlled/opt-in | Requires `NETBOT_REMOTE_ACCESS=1`, a strong token, and authorized infrastructure. |
| Agent Mode | Active read-only monitoring | Summary-only agents, SQLite history, fleet dashboard, and demo/QA tooling. |
| Windows packaging | Active | Built and smoke-tested first. |
| Linux/macOS packaging | Staged | Scripts exist; production release validation is still pending. |

## Architecture

```mermaid
flowchart LR
    Operator["Analyst / Operator"]

    subgraph Client["Client Runtime"]
        Browser["React Analyst Console"]
        Desktop["Electron Desktop Shell"]
        Preload["Hardened Preload Bridge"]
        Token["Local Token Store"]
    end

    subgraph Central["Central / Local Control Plane"]
        API["FastAPI Control Plane"]
        WS["WebSocket Event Stream"]
        Policy["Remote Access / Token / Allowlist"]
        AgentAPI["Agent Registry API"]
        AgentStore["Agent Telemetry Store"]
        Audit["Audit Log"]
    end

    subgraph Sensor["Authorized Remote Sensor Host"]
        SensorAPI["Sensor FastAPI Backend"]
        CapturePolicy["Capture Policy<br/>metadata / full / forensic"]
    end

    subgraph Core["Core Network Pipeline"]
        Capture["Scapy / Npcap Capture Provider"]
        Parser["Packet Parser + Layer 7 Metadata"]
        Redaction["Central Redaction"]
        Detection["IDS Rules / ML Scoring"]
        ProcessMap["Process Attribution"]
    end

    subgraph Data["Local Data Plane"]
        History["SQLite History Repository"]
        Reports["Redacted Reports / JSON / ZIP"]
        Raw["Guarded Raw PCAP Export"]
    end

    subgraph Agents["Agent Mode Hosts"]
        AgentRunner["Agent Runner"]
        AgentIdentity["Stable Agent Identity"]
        AgentHealth["Health / Network / Capture Summary"]
    end

    Operator --> Browser
    Desktop --> Preload --> Browser
    Desktop --> Token
    Token --> Browser
    Browser -->|"X-NetBot-Token"| API
    Browser -->|"netbot.auth subprotocol"| WS
    Browser -->|"Fleet View"| AgentAPI
    Policy --> API
    API --> Audit
    API --> SensorAPI
    SensorAPI --> CapturePolicy
    SensorAPI --> Audit
    SensorAPI --> Capture --> Parser --> Redaction --> Detection
    Parser --> ProcessMap
    Redaction --> History
    Detection --> History
    History --> Reports
    CapturePolicy --> Raw
    API --> Reports
    API --> Raw
    AgentRunner --> AgentIdentity
    AgentRunner --> AgentHealth
    AgentRunner -->|"register / heartbeat / redacted telemetry"| AgentAPI
    AgentAPI --> AgentStore
    AgentAPI --> Audit
```

## Repository Layout

- `backend/` - FastAPI routes, service layer, websocket event stream, desktop backend entrypoint.
- `core/` - capture providers, packet parsing, IDS logic, scoring, traceroute, firewall helpers, offline analyzer.
- `frontend/` - React/Vite web console.
- `desktop/electron/` - Electron shell, secure preload bridge, packaged desktop runtime.
- `scripts/dev/` - local setup, doctor, start/stop, Npcap install, remote sensor start.
- `scripts/qa/` - smoke, acceptance, security, packaged backend, and release readiness checks.
- `packaging/` - Windows/Linux/macOS packaging scripts and PyInstaller configuration.
- `tests/` - backend, security, capture, persistence, desktop-path, and packaging smoke tests.

## Operational Guides

- [Agent Mode](docs/AGENT_MODE.md)
- [Agent Operational QA Checklist](docs/AGENT_QA_CHECKLIST.md)
- [Deployment Overview](docs/DEPLOYMENT_OVERVIEW.md)
- [Release QA Checklist](docs/RELEASE_QA_CHECKLIST.md)
- [Remote Sensor](docs/REMOTE_SENSOR.md)
- [Capture Modes](docs/CAPTURE_MODES.md)

## Quick Demo

Install dependencies once:

```powershell
python -m pip install -r requirements-dev.txt
cd frontend
npm ci
cd ..
```

Start the backend, seed four realistic demo Agents, and optionally start the
frontend:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-demo.ps1 -StartFrontend
```

Open:

```text
http://127.0.0.1:5173/?page=agents
```

The demo launcher prints dashboard and log paths, but never prints the raw
local token. The token remains in `.runtime/demo-local-token.txt`.

## Setup

Prerequisites:

- Python 3.13 recommended.
- Node.js 20 recommended.
- Npcap on Windows for live capture.
- Administrator privileges when starting live capture or firewall actions on Windows.

Install everything on Windows:

```powershell
cd "C:\Users\ASIA SYSTEM\Desktop\netbotpro"
powershell -ExecutionPolicy Bypass -File .\scripts\dev\setup.ps1
```

Manual install:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
npm --prefix .\frontend install
npm --prefix .\desktop\electron install
```

## Environment

Copy `.env.example` to `.env` for local experiments. The default secure path is still to let the dev or desktop launcher generate a local token automatically.

- `NETBOT_LOCAL_TOKEN` protects sensitive API routes and websocket sessions.
- `NETBOT_ALLOWED_ORIGINS` controls browser origins allowed to connect to the API/websocket.
- `NETBOT_REMOTE_ACCESS=1` is required before non-loopback clients can access a sensor backend.
- `NETBOT_HOST` and `NETBOT_PORT` control backend bind address and port.
- `NETBOT_AGENT_TOKEN` authorizes summary-only Agent Mode registration and telemetry.

## Usage

Start the local web stack:

```powershell
cd "C:\Users\ASIA SYSTEM\Desktop\netbotpro"
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-local.ps1
```

Start with elevated privileges for live capture:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-local.ps1 -Elevated
```

Open the dashboard:

```text
http://127.0.0.1:5173
```

Start the Electron desktop shell after dependencies are installed:

```powershell
cd "C:\Users\ASIA SYSTEM\Desktop\netbotpro\desktop\electron"
npm run dev
```

Start a remote sensor on a server you own or administer:

```powershell
cd "C:\Users\ASIA SYSTEM\Desktop\netbotpro"
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-sensor.ps1 -BindHost 0.0.0.0 -Port 8765 -AllowedOrigins "http://YOUR_DASHBOARD_HOST:5173"
```

Then connect the dashboard to that sensor:

```text
http://127.0.0.1:5173/?api=http://SERVER_IP:8765/api&ws=ws://SERVER_IP:8765/ws
```

Remote sensor mode is not a public internet service mode. Treat it as a private, controlled sensor endpoint for systems where you have explicit authorization. Prefer VPN, SSH tunneling, private routing, or a TLS reverse proxy, and restrict inbound access to trusted operator IPs.

## Remote Sensor Mode

Remote Sensor Mode runs authorized packet capture on a server while operators
use the dashboard from another trusted machine. Remote access is opt-in,
token-protected, allowlist-capable, and should remain behind a VPN/private
network or secure reverse proxy. Metadata mode is the default; Full and
Forensic capture require explicit authorization and audit.

See [Remote Sensor Mode](docs/REMOTE_SENSOR.md) and
[Capture Modes](docs/CAPTURE_MODES.md).

## Agent And Fleet Mode

Agent Mode is a staged, summary-only server telemetry runner. It registers an
authorized host with the central backend and sends health, network, capture,
alert, and flow summaries without forwarding raw packets, payload previews, or
PCAP artifacts. See [docs/AGENT_MODE.md](docs/AGENT_MODE.md).

The Fleet Dashboard provides online/offline status, health pressure, alerts,
risk scoring, trends, filters, sorting, demo data, history retention, and
redacted JSON/CSV fleet summary reports.

Server Mode adds extra guardrails:

- Safe Use Policy acceptance is required before remote capture starts.
- Remote dashboard clients can be restricted with `NETBOT_REMOTE_IP_ALLOWLIST` or Settings allowlist entries.
- Payload previews are disabled by default; when enabled, Authorization, Cookie, Basic Auth, Bearer token, and sensitive query values are redacted.
- Alert-only mode keeps payload previews empty while still allowing detection metadata.
- Retention settings can automatically remove old packet history and generated reports.
- Capture start/stop, exports, report downloads, and successful remote dashboard authentication are written to `audit.jsonl`.

## Demo Data

Seed or reset demo data without starting the full demo workflow:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\seed-agent-demo.ps1 -Reset -Count 4
```

Seeded records include healthy, pressured, critical-alert, and offline Agent
profiles. Demo data contains no raw payload, credential, cookie, authorization
header, or token.

## Deployment Options

- Local demo deployment with `scripts/dev/start-demo.ps1`.
- Local desktop/Electron operation.
- Remote Sensor behind VPN/private routing or a TLS reverse proxy.
- Central Agent/Fleet backend with SQLite history.
- Linux systemd sensor deployment.
- Windows script, Scheduled Task, or reviewed service-wrapper deployment.

See [Deployment Overview](docs/DEPLOYMENT_OVERVIEW.md).

## Testing

```powershell
python -m pip install -r requirements-dev.txt
python -m pip check
python -m unittest discover -s tests -v
npm --prefix .\frontend ci
npm --prefix .\frontend run test:ui
npm --prefix .\frontend run build
npm --prefix .\frontend run smoke
npm --prefix .\frontend run security
powershell -ExecutionPolicy Bypass -File .\scripts\qa\release_readiness.ps1
```

Build Windows desktop artifacts:

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\windows\build.ps1
```

## Security Model

- Loopback-only by default for local development and desktop mode.
- Remote access is opt-in and requires both `NETBOT_REMOTE_ACCESS=1` and `NETBOT_LOCAL_TOKEN`.
- Optional `NETBOT_REMOTE_IP_ALLOWLIST` limits remote dashboard clients by IP/CIDR.
- Remote sensor mode is documented as an authorized-use-only deployment path, not a general hosted SaaS mode.
- Desktop mode generates a cryptographically secure random token when no token is provided.
- Electron exposes runtime config through a narrow IPC preload bridge with `contextIsolation`, `sandbox`, and `nodeIntegration: false`.
- Sensitive HTTP routes require `X-NetBot-Token`.
- Websocket sessions prefer the `netbot.auth.*` subprotocol instead of query-string tokens.
- Downloads are constrained to generated safe file types inside the NetBotPro log directory.
- Payload previews are off by default and sensitive HTTP/token fields are redacted when previews are enabled.
- Agent tokens are hashed for registry storage and excluded from script/log
  output.
- Agent Mode has no command/control, remote shell, file collection, raw packet
  forwarding, raw payload forwarding, or PCAP forwarding.

## Limitations

- Live capture depends on OS permissions, Npcap/libpcap availability, and visible capture interfaces.
- Process attribution can be incomplete for short-lived sockets, kernel-owned traffic, NAT, or traffic observed away from the endpoint.
- Remote sensor mode analyzes traffic visible to that server/interface; it does not magically see traffic from unrelated network segments.
- Windows artifacts are currently unsigned unless a signing certificate is configured.
- Linux/macOS packaging paths exist, but production-grade desktop release validation is strongest on Windows right now.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `Start Sniffer` says no capture interface is available | Npcap/libpcap is missing, blocked, or not visible to Scapy | Install Npcap, reopen PowerShell as Administrator, then run `scripts\dev\doctor.ps1`. |
| Frontend shows `ECONNREFUSED 127.0.0.1:8765` | Backend is not running or crashed | Run `scripts\dev\start-local.ps1`, then inspect `.runtime\backend-dev.err.log`. |
| Protected API returns `401` | Missing or wrong local token | Use `.runtime\local-token.txt`, `.runtime\demo-local-token.txt`, or your configured `NETBOT_LOCAL_TOKEN`. |
| Websocket returns `403` | Token/origin mismatch | Confirm `NETBOT_ALLOWED_ORIGINS` includes the dashboard origin and the frontend sends the local token. |
| Electron launches but backend fails | Packaged runtime or Python dev runtime is missing | Run `scripts\qa\release_readiness.ps1`, then rebuild with `packaging\windows\build.ps1`. |
| Remote dashboard cannot connect to sensor | Firewall, origin, token, or bind address mismatch | Use `start-sensor.ps1`, set `AllowedOrigins`, keep `NETBOT_REMOTE_ACCESS=1`, and test over VPN/private network first. |

## Roadmap

- Versioned SQLite schema migrations and longer-lived deployment operations.
- Per-Agent enrollment, rotation, and revocation workflows.
- Signed desktop artifacts when release signing infrastructure is available.
- Additional Linux/macOS release validation.

Command/control, remote shell, file collection, raw packet forwarding, raw
payload forwarding, PCAP forwarding, and Agent auto-update are not part of
v0.2.0.

## Safe And Authorized Use Notice

NetBotPro is intended for defensive monitoring, troubleshooting, education, and authorized security analysis. Only capture, inspect, or analyze traffic on systems, accounts, servers, and networks where you have explicit legal permission. Do not use this project for unauthorized surveillance, intrusion, credential theft, evasion, or abuse.

## Release

Current release target: `v0.2.0`.

GitHub Actions builds CI on push and pull request. Desktop release artifacts are produced by the `Release Desktop` workflow. Pushing a version tag such as `v0.2.0` triggers the release workflow, generates SHA256 checksums, and publishes versioned artifacts with release notes from `CHANGELOG.md`.

## Documentation Links

- [Architecture](docs/ARCHITECTURE.md)
- [Security policy](SECURITY.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Safe use policy](docs/SAFE_USE_POLICY.md)
- [Capture modes](docs/CAPTURE_MODES.md)
- [Server deployment](docs/SERVER_DEPLOYMENT.md)
- [Remote sensor mode](docs/REMOTE_SENSOR.md)
- [Agent mode](docs/AGENT_MODE.md)
- [Agent QA checklist](docs/AGENT_QA_CHECKLIST.md)
- [Deployment overview](docs/DEPLOYMENT_OVERVIEW.md)
- [Release QA checklist](docs/RELEASE_QA_CHECKLIST.md)
- [Desktop shell](docs/DESKTOP_SHELL.md)
- [Web migration notes](docs/WEB_MIGRATION.md)
- [Contributing](CONTRIBUTING.md)
