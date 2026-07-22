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
- `deploy/`: Linux server deployment templates for systemd and Docker notes.
- `packaging/`: PyInstaller and Electron packaging scripts.
- `scripts/`: dev setup, local runtime, QA smoke checks, and release staging.

Runtime profiles keep deployment intent explicit. `desktop` is the local
trusted/Electron path, `server` is a stricter central Linux API/UI profile, and
`sensor`/`agent` are metadata-only remote node profiles. Server mode adds
config validation and health/readiness endpoints; it does not add
command/control, remote shell, file collection, raw payload forwarding, PCAP
forwarding, TLS decryption, or autonomous response actions.

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
        IntakeQueue["Bounded Packet Intake Queue"]
        QueueWorker["Packet Queue Dispatcher"]
        FlowWorkers["Flow-aware Worker Pool<br/>Ordered Flow Lanes"]
        LiveRing["Live Ring Buffer<br/>Bounded Redacted History"]
        EventAggregator["Event Aggregator"]
        Parser["Packet Parser"]
        Layer7["Layer 7 / TLS Metadata"]
        ProtocolIntel["Protocol Intelligence"]
        TCPIntel["TCP Analysis"]
        DNSIntel["DNS Intelligence"]
        HTTPIntel["HTTP Intelligence"]
        TLSIntel["TLS Metadata Intelligence"]
        DisplayFilters["Safe Display Filters + Saved Filter Storage"]
        ExpertSummary["Expert Summary"]
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
    Provider --> IntakeQueue --> QueueWorker --> FlowWorkers --> Parser --> Layer7 --> ProtocolIntel --> FlowEngine
    Redaction --> LiveRing --> EventAggregator --> Events
    ProtocolIntel --> TCPIntel
    ProtocolIntel --> DNSIntel
    ProtocolIntel --> HTTPIntel
    ProtocolIntel --> TLSIntel
    DisplayFilters --> Routes
    TCPIntel --> ExpertSummary
    DNSIntel --> ExpertSummary
    HTTPIntel --> ExpertSummary
    TLSIntel --> ExpertSummary
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
the capture provider into the bounded packet intake queue, then through parsing,
layer-7 metadata extraction, redaction, detection, process attribution, history
persistence, and report/export services.
Metadata mode avoids storing payload previews. Full and Forensic modes are
guarded by the capture policy service and are only intended for authorized
servers with owner or administrator approval.

Raw PCAP artifacts are not treated like normal reports. They are exposed only
through the guarded raw export path, require Full or Forensic mode, require Safe
Use acceptance, require token authorization, and create audit records.

## Service Attribution / Destination Intelligence

`ServiceAttributionEngine` runs after metadata extraction and before flow
aggregation. It correlates only locally available DNS query/answer metadata,
visible TLS SNI, HTTP Host, optional ASN organization metadata, and the bundled
`backend/app/data/service_fingerprints.json` registry. It never performs a
network lookup.

Attribution is attached to packet summaries before `FlowEngine` ingestion, so
the same centrally redacted structure can travel through flow snapshots,
conversation views, the Live Ring Buffer, WebSocket Event Aggregator, batch
persistence, Inspect, and Flow Details. Flat service fields remain available
for backward compatibility.

Each result includes a confidence score and label, evidence sources, human
readable reasons, encryption/CDN/proxy hints, and an explicit Unknown state.
HTTP Host and visible SNI are stronger evidence than recent DNS correlation;
agreement can raise confidence and conflicting metadata lowers it. A browser
or container process name alone is never treated as proof of a destination
service. Shared CDN/ASN evidence is labeled conservatively.

Ops Snapshot receives only fixed counters, latency, health, and bounded
pressure-reason identifiers. It does not receive observed domains, headers,
packet text, credentials, cookies, sessions, or tokens. ECH, DoH, VPNs,
proxies, shared CDNs, and connection reuse can legitimately leave a destination
Unknown. No TLS decryption, MITM, browser history inspection, cookie/session
inspection, or credential collection is part of this layer.

## Incident Correlation Layer

After protocol analysis, alert generation, expert information, and Service
Attribution, `IncidentCorrelationEngine` consumes bounded, centrally redacted
metadata signals. It requires repeated or multi-source evidence before creating an
incident and matches later signals by source, flow, destination, application,
service/domain, and a bounded time window.

Incident summaries and sorted bounded timelines are exposed through protected
read-only APIs, the Incident workspace, the Live Ring Buffer, and batched WebSocket
updates. Ops Monitoring reports engine count, latency, drops, and pressure. Incident
persistence is not enabled in this step; the in-memory store has explicit count and
retention limits. A future read-only analyst may consume this evidence, but no AI or
response action is part of the current architecture.

## Performance Pipeline Foundation

### Batch Persistence Foundation

`BatchPersistenceWriter` is the storage-pressure boundary for packet, alert,
and flow history. It accepts centrally redacted typed envelopes, keeps pending
work bounded, flushes by size/time/priority/manual request/shutdown, and uses
the existing SQLite bulk writes. Retry is finite and exponentially backed off;
overflow and terminal failures are visible in operational metrics.

Audit logging stays outside this asynchronous path so security and control
records retain immediate ordering and reliability.

The current performance foundation is intentionally narrow. `BoundedPacketQueue`
sits between capture callbacks and the existing packet processing path. The
queue has a fixed maximum size, explicit `drop_oldest` and `drop_newest`
overflow policies, accepted/drop counters, high-water tracking, safe last-drop
reasons, and packet queue worker liveness.

`/api/monitoring/metrics` exposes queue pressure metrics so Ops Snapshot can
show current depth, utilization, dropped packets, overflow policy, worker
status, and pressure reasons. This makes backpressure visible without exposing
packet payloads, credentials, cookies, authorization headers, sessions, or
tokens.

This foundation now includes bounded packet intake, WebSocket event
aggregation, and bounded batch persistence. Packet and alert rows share
transactional SQLite batches; flow snapshots are coalesced by `flow_id` and
written with batched upserts. Queue depth, utilization, dropped/failed writes,
write latency, retry state, and worker liveness are visible in Ops metrics.
User-triggered report files remain synchronous and outside the packet-rate
queue.

The Flow-aware Worker Pool is the processing-pressure boundary after packet
intake. TCP and UDP use canonical bidirectional endpoint keys; other protocols
use normalized endpoint/protocol keys. Stable hashing selects a fixed FIFO lane,
so packets in one flow retain order while different flows can execute in
parallel. Incomplete metadata uses a safe fallback lane. Worker queues remain
bounded and expose backlog, utilization, failures, drops/rejections, processing
latency, and liveness to `/api/monitoring/metrics` and Ops Snapshot.

The Live Ring Buffer sits after processing and central redaction. It holds
separate bounded deques for recent packet, flow, alert, Expert, protocol,
Agent-status, and ops summaries. Current capture integration writes packet,
flow, alert, and Expert records. Oldest records are evicted at each category's
hard capacity, optional TTL pruning is bounded, and read APIs cap result size.
It supports Inspect/Dashboard recovery and future read-only context without
retaining raw payloads or allowing unbounded memory growth.

The Event Aggregator remains the realtime delivery-pressure boundary after the
ring buffer, while Batch Persistence remains the storage-pressure boundary.
The synthetic benchmark suite exercises each boundary independently and as a
full local pipeline. Its CI-safe smoke test checks bounded queues, visible
drops, report generation, and structural health without real capture,
Administrator privileges, or external network access. Machine-dependent
throughput is documented separately and is not treated as a capacity promise.

## WebSocket Event Aggregator

The Event Aggregator is the Step 3 performance component between packet
processing and websocket delivery. Packet and alert events are collected into
short windows, flow updates are sent as deltas, and dashboard or ops summaries
are coalesced before fan-out to clients.

Each websocket client has a bounded outgoing queue. Slow clients are protected
with the configured policy: `coalesce`, `drop_oldest`, or `drop_newest`.
WebSocket metrics expose clients, slow clients, batches sent, events received,
events sent, coalesced events, dropped events, queue depth, average/p95 send
latency, and safe last-drop reasons.

This layer preserves websocket authentication and trusted-client checks. It
does not alter Agent/Fleet telemetry boundaries and does not add command/control,
remote shell, file collection, raw packet forwarding, raw payload forwarding,
PCAP forwarding, TLS decryption, MITM, credential collection, IPS behavior, or
AI autonomous actions.

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

The Protocol Intelligence expansion uses focused analyzers in
`core/tcp_analysis.py`, `core/dns_intelligence.py`,
`core/http_intelligence.py`, and `core/tls_intelligence.py`. The same modules
serve live capture and offline PCAP analysis. Saved Display Filters use a small
redacted JSON store, while Expert Summary and inspection reports combine
protocol hints without persisting raw credentials or decrypted TLS content.

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
