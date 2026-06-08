# Architecture

NetBotPro is a local-first defensive network analysis product. The project is intentionally split into a small set of runtime layers so desktop packaging, browser development, backend testing, and remote sensor operation can evolve without mixing responsibilities.

## Product Shape

- `backend/`: FastAPI API, session control, event transport, packet and Agent
  history, exports, reports, and security middleware.
- `frontend/`: React/Vite analyst dashboard for Monitor, Inspect, Agents,
  Settings, Traceroute, Exports, Reports, and Offline Analysis.
- `desktop/electron/`: local desktop shell that starts the backend, injects runtime configuration, and hosts the built frontend.
- `core/`: packet capture, parsing, protocol enrichment, IDS heuristics, scoring, traceroute helpers, firewall helpers, process mapping, and offline analysis.
- `agent/`: read-only Agent runner, stable identity, redacted summary payloads,
  and central API client.
- `config/`: persisted runtime settings.
- `packaging/`: PyInstaller and Electron packaging scripts.
- `scripts/`: dev setup, local runtime, QA smoke checks, and release staging.

## Runtime Flow

```mermaid
flowchart TB
    subgraph Client["Client Runtime"]
        Analyst["Analyst / Operator"]
        Frontend["React Analyst Console"]
        ApiClient["Authenticated API Client"]
        LiveClient["WebSocket Live Client"]
        Desktop["Electron Shell"]
        Preload["Preload Runtime Config"]
        Token["Secure Local Token"]
    end

    subgraph Boundary["HTTP / WebSocket Trust Boundary"]
        Trusted["Trusted Client Gate"]
        Origin["Allowed Origin Check"]
        RateLimit["Rate Limits"]
        Allowlist["Remote IP Allowlist"]
    end

    subgraph Backend["FastAPI Backend"]
        Routes["REST API Routes"]
        Events["/ws/events Event Stream"]
        Settings["Settings Service"]
        CapturePolicy["Capture Policy Service"]
        AgentAPI["Agent Registry API"]
        AgentRisk["Offline Detection + Risk Scoring"]
        Audit["Audit Service"]
        ExportService["Export / Report Services"]
    end

    subgraph Pipeline["Core Capture And Analysis Pipeline"]
        Provider["Capture Provider<br/>Scapy / Npcap / libpcap"]
        Parser["Packet Parser"]
        Layer7["Layer 7 / TLS Metadata"]
        ProtocolIntel["Protocol Intelligence"]
        FlowEngine["Flow Engine"]
        Conversation["Conversation Timeline"]
        FlowRisk["Flow Risk Scoring"]
        Redaction["Central Redaction"]
        Detection["IDS Rules + ML Scoring"]
        Process["Process Attribution"]
    end

    subgraph Storage["Local Storage And Artifacts"]
        History["SQLite History Repository"]
        AgentHistory["Agent SQLite History<br/>agents + snapshot tables"]
        Reports["Redacted Reports / JSON / ZIP"]
        FleetReports["Redacted Fleet JSON / CSV"]
        RawPcap["Guarded Raw PCAP Export"]
        Logs["Runtime Logs + audit.jsonl"]
    end

    subgraph Remote["Remote Sensor Mode"]
        SensorHost["Authorized Server Sensor"]
        Env["NETBOT_REMOTE_ACCESS<br/>NETBOT_LOCAL_TOKEN<br/>NETBOT_REMOTE_IP_ALLOWLIST"]
        Service["systemd / PowerShell Sensor Scripts"]
    end

    subgraph Fleet["Read-only Agent / Fleet Mode"]
        AgentRunner["Agent Runner"]
        AgentIdentity["Stable Agent Identity"]
        AgentSummary["Redacted Health / Network / Capture / Alert Summary"]
    end

    Analyst --> Frontend
    Desktop --> Preload --> Frontend
    Desktop --> Token --> ApiClient
    Frontend --> ApiClient
    Frontend --> LiveClient
    ApiClient -->|"X-NetBot-Token"| Trusted
    LiveClient -->|"netbot.auth subprotocol"| Origin
    Origin --> Trusted
    Trusted --> RateLimit --> Routes
    Allowlist --> Trusted
    Routes --> Settings
    Routes --> CapturePolicy
    Routes --> ExportService
    Routes --> Audit
    Routes --> AgentAPI
    Events --> LiveClient
    CapturePolicy --> Provider
    Provider --> Parser --> Layer7 --> ProtocolIntel --> FlowEngine
    FlowEngine --> Conversation
    FlowEngine --> FlowRisk
    ProtocolIntel --> Redaction
    Conversation --> Redaction
    FlowRisk --> Redaction
    Redaction --> Detection
    Parser --> Process
    Detection --> History
    Redaction --> History
    History --> ExportService --> Reports
    CapturePolicy --> RawPcap
    Audit --> Logs
    SensorHost --> Env --> Service --> Routes
    Service --> Events
    AgentRunner --> AgentIdentity
    AgentRunner --> AgentSummary
    AgentRunner -->|"register / heartbeat / telemetry"| AgentAPI
    AgentAPI --> AgentRisk --> AgentHistory --> FleetReports
    AgentAPI --> Audit
```

1. The backend owns capture, enrichment, detection, persistence, and control actions.
2. The frontend reads state from `/api/*` and live events from `/ws/events`.
3. Electron starts a local backend process, generates or forwards a local token, and exposes runtime config through the preload bridge.
4. Remote sensor mode runs the same backend on an owned server, but only when explicitly enabled and token-protected.
5. Agent Mode sends redacted summary telemetry to the Agent Registry API; the
   backend evaluates offline state and risk, then stores focused SQLite
   snapshots for fleet dashboards and trends.

## Runtime Boundaries

| Plane | Owns | Does not own |
| --- | --- | --- |
| Operator clients | Navigation, investigation views, filters, fleet trends, and authenticated API calls. | Capture, secret storage in UI state, or direct database access. |
| Control plane | Authentication, origin/allowlist checks, API routing, websocket events, and audit. | Packet parsing or Agent-side collection. |
| Local analysis data plane | Capture, parsing, protocol enrichment, detection, redaction, packet/alert history, and guarded raw export. | Fleet command execution. |
| Remote Sensor Mode | Authorized server-side capture through the same capture policy gates. | Implicit remote access or unrestricted raw export. |
| Agent/Fleet monitoring plane | Registration, heartbeat, redacted summary telemetry, SQLite history, offline detection, risk scoring, and fleet reports. | Command/control, remote shell, file collection, raw packet/payload forwarding, or PCAP forwarding. |

## Control Plane

The control plane is intentionally narrow. All browser and desktop clients talk
to FastAPI through authenticated REST routes and the authenticated websocket
event stream. Sensitive actions require `X-NetBot-Token`; websocket sessions
prefer the `netbot.auth.*` subprotocol so tokens do not have to travel in URLs.

Remote sensor deployments add another gate before the backend routes are useful:
`NETBOT_REMOTE_ACCESS=1`, a configured local token, optional IP/CIDR allowlists,
allowed origins, and rate limits. Loopback development remains convenient, while
remote dashboard access is explicit and auditable.

## Data Plane

The data plane stays local to the machine running the backend. Packets flow from
the capture provider into parsing, layer-7 metadata extraction, redaction,
detection, process attribution, history persistence, and report/export services.
Metadata mode avoids storing payload previews. Full and Forensic modes are
guarded by the capture policy service and are only intended for authorized
servers with owner or administrator approval.

Raw PCAP artifacts are not treated like normal reports. They are exposed only
through the guarded raw export path, require Full or Forensic mode, require Safe
Use acceptance, require token authorization, and create audit records.

## Flow And Protocol Intelligence

The Flow Engine consumes the same enriched packet metadata used by live
detection and offline PCAP analysis. It builds directional flow IDs from
endpoint, port, transport, and direction fields, then joins reverse directions
into a conversation ID.

Protocol Intelligence classifies DNS, HTTP, visible TLS metadata, SSH, RDP,
SMB, mail protocols, ICMP, and unknown traffic using decoded metadata, safe
signatures, and port hints. It does not perform TLS decryption, MITM, key
extraction, or credential collection.

Conversation Timeline correlates protocol detection, DNS/HTTP/TLS metadata,
alerts, and unusual destinations. Flow Risk Scoring creates a bounded score and
explainable reasons. Redacted snapshots are persisted separately in
`.runtime/logs/flows.db`; raw payloads are not stored in this database.

## Agent And Fleet Monitoring Plane

Agent Mode is separate from Remote Sensor Mode. The Agent runner collects
summary-only host health, network counters, capture status, alert counts, and
flow summaries. It applies central redaction before submission and never sends
raw packets, raw payloads, files, or PCAP artifacts.

The backend Agent Registry verifies Agent credentials, redacts received
telemetry again, computes offline state and a bounded risk score, and persists
history in SQLite. Focused snapshot tables support overview, detail, health,
alert, flow, and risk trend queries without replaying telemetry logs.

The fleet monitoring plane is read-only by design in `v0.2.0`. There is no
command/control endpoint, remote shell, file collection, or Agent auto-update
path.

## Security-Critical Services

- `backend/app/security.py`: client trust, local token checks, websocket token
  extraction, origin checks, remote allowlists, rate limits, and safe path
  validation.
- `backend/app/services/capture_policy.py`: metadata/full/forensic mode gates,
  Safe Use enforcement, full-capture opt-in, and forensic duration/confirmation.
- `backend/app/services/audit_service.py`: append-only JSONL audit events with
  credential redaction.
- `backend/app/services/agent_registry.py`: Agent authentication, central
  redaction, SQLite history, offline detection, risk scoring, retention, and
  fleet summaries.
- `backend/app/services/redaction.py` and `core/redaction.py`: shared masking for
  UI-visible payload previews, reports, exports, and audit text.

## Backend Layer

The FastAPI app in `backend/app/main.py` is the product boundary for UI clients. It exposes status, settings, capture control, packet history, alert history, exports, reports, traceroute, and offline PCAP analysis.

Important service modules:

- `backend/app/services/sniffer_service.py`: capture lifecycle and runtime state.
- `backend/app/services/history_service.py`: history reads and detail/context retrieval.
- `backend/app/services/event_bus.py`: versioned live event fan-out.
- `backend/app/services/report_service.py`: report enumeration and safe download metadata.
- `backend/app/security.py`: local token, remote access, origin checks, validation, rate limiting, and safe path handling.

## Core Layer

The `core/` package keeps network-domain behavior away from HTTP concerns.

- `core/capture/`: capture provider abstraction and system capture integration.
- `core/netbotpro_sniffer_core/`: packet parsing, TLS/layer-7 helpers, interface handling, and runtime utilities.
- `core/ids_*` and `core/score_engine.py`: alert rules and risk scoring.
- `core/process_mapping.py`: process attribution for local traffic.
- `core/offline_analyzer.py`: PCAP analysis path.

## Frontend Layer

The frontend is intentionally API-driven. It does not perform packet capture itself.

- `frontend/src/hooks/useDashboardController.js`: top-level state machine for dashboard data, live events, filters, and navigation.
- `frontend/src/hooks/useApiClient.js`: authenticated API client.
- `frontend/src/hooks/useLiveEvents.js`: websocket transport.
- `frontend/src/components/`: visual workspaces and reusable panels.
- `frontend/src/lib/`: runtime config, network classification, inspection models, and operational health helpers.

## Desktop Layer

The Electron shell keeps a narrow trust boundary:

- `main.cjs` owns backend process launch, local token creation, window hardening, and IPC registration.
- `preload.cjs` exposes only frozen runtime config to the frontend.
- `contextIsolation`, `sandbox`, `nodeIntegration: false`, and navigation restrictions are enabled.

## Trust Boundaries

- Browser UI to backend API: protected by local token on sensitive routes.
- Browser UI to websocket: protected by token subprotocol and allowed origin checks.
- Desktop shell to frontend: narrow preload bridge only.
- Remote client to sensor backend: disabled unless `NETBOT_REMOTE_ACCESS=1` and `NETBOT_LOCAL_TOKEN` are set.
- Generated files to download API: constrained to safe suffixes and log/export directories.

## Persistence And Data

Runtime data is local-first. Desktop mode maps config, data, and logs into the
Electron user-data directory. Dev mode uses project-local runtime paths where
configured. Exports and reports are generated under the log directory and
exposed only through safe relative filenames.

Packet and alert history use the main SQLite history repository. Agent/Fleet
history uses a separate automatically initialized SQLite registry with:

- `agents`;
- `agent_heartbeats`;
- `agent_telemetry`;
- `agent_health_snapshots`;
- `agent_alert_snapshots`;
- `agent_flow_snapshots`;
- `agent_risk_snapshots`.

Agent JSONL storage remains available only as a development fallback. Raw Agent
tokens are not stored; visible text is redacted before history persistence.

## Release Posture

## Deep Packet Inspection

The Packet Dissector builds a structured layer tree from authorized packet
metadata. The Display Filter Engine evaluates safe expressions without
`eval`. The Stream Reassembler returns directional metadata or redacted
previews, and the Expert Info Engine produces explainable packet and flow
warnings. Packet Details APIs expose these views through the existing trusted
client and local-token guardrails. TLS decryption and Agent raw forwarding are
intentionally absent.

Windows is the validated desktop release target for `0.2.0`. Linux and macOS packaging scripts exist, but production validation remains staged until those artifacts are built and smoke-tested on native hosts.
