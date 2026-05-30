# Architecture

## Product shape

NetBotPro is a local-first network investigation console with three active runtime layers:

- `backend/`: FastAPI API, session control, event transport, history, export, report, and security middleware
- `frontend/`: React/Vite analyst dashboard for monitor, inspect, alerts, and workflow panels
- `desktop/electron/`: local desktop shell that launches the backend and hosts the built frontend

## Core domain modules

- `core/netbotpro_sniffer_core/`: capture lifecycle, packet parsing, interface discovery, TLS/layer-7 enrichment
- `core/netbotpro_logging/`: persistence, export, privacy shaping, storage helpers
- `core/`: IDS, scoring, firewall, traceroute, offline analysis, process mapping, enrichment helpers

## Supporting layers

- `config/`: persisted settings defaults and file-backed settings storage
- `tests/`: backend, service, runtime, security, persistence, and packaging-adjacent test coverage
- `packaging/`: PyInstaller spec plus Windows/Linux/macOS packaging wrappers
- `scripts/dev/`: local setup, doctor, clean, start, stop, and dev repair helpers

## Runtime flow

1. Capture and analysis originate from the backend and core modules
2. Backend services normalize state, publish live events, and persist history when enabled
3. Frontend consumes `/api/*` and `/ws/events` for live and historical investigation
4. Electron wraps the frontend and backend into a local desktop workflow
