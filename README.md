# Netbotpro

Netbotpro is a local-first desktop network analysis and detection product.

The product is built around a packaged desktop experience: Electron hosts the UI, a local Python backend handles capture and detection, and packet history plus offline analysis stay on the operator's machine instead of being pushed into a hosted control plane.

## Why This Repo Exists

- Desktop-first: the primary delivery target is an installable desktop app, not a browser-only deployment
- Local-first: capture, detections, exports, and PCAP analysis run on the same machine as the user
- Detection-focused: live packet inspection, app-aware alerts, persistence, exports, and offline triage share one runtime
- Cross-platform core: Windows, Linux, and macOS share the same engine and UI, with platform-specific capture/runtime adapters

## Product Layout

- `desktop/electron/`: packaged shell, backend lifecycle, runtime path wiring, release config
- `backend/`: FastAPI API, websocket layer, desktop entrypoint, service orchestration
- `core/`: capture runtime, IDS pipeline, scoring, persistence, offline PCAP analysis
- `frontend/`: React desktop UI and runtime config handling
- `packaging/`: PyInstaller spec, staged runtime assets, OS-specific build wrappers
- `config/`: local settings persistence

## Desktop Runtime Model

1. Electron starts a local backend process through `backend.app.desktop_entry`
2. The backend reads desktop-owned config, data, and log paths from environment variables
3. The frontend talks only to the local loopback API and websocket endpoints
4. Release packaging stages the frozen backend into `packaging/runtime/backend` before Electron distribution

## Local Development

Backend API:

```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Frontend:

```powershell
cd frontend
npm install
npm run dev
```

Desktop shell:

```powershell
cd desktop\electron
npm install
$env:NETBOT_DESKTOP_DEV_SERVER_URL='http://127.0.0.1:5173'
npm run dev
```

## QA Paths

Desktop smoke:

```powershell
python scripts\qa\desktop_smoke.py
```

Packaged backend smoke:

```powershell
python scripts\release\stage_backend_runtime.py
python scripts\qa\packaged_backend_smoke.py
```

## Packaging

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1
```

Linux:

```bash
bash packaging/linux/build.sh
```

macOS:

```bash
bash packaging/macos/build.sh
```

## Release Positioning

- Primary rollout target: Windows desktop
- Follow-on targets: Linux desktop, then macOS desktop
- Platform differences stay isolated in capture/runtime adapters instead of leaking into product behavior

## Additional Docs

- [Desktop shell notes](docs/DESKTOP_SHELL.md)
- [QA and release flow](docs/QA_RELEASE.md)
- [Repository metadata](docs/REPO_METADATA.md)
- [Migration notes](docs/WEB_MIGRATION.md)
- [Legacy notes](docs/README.md)
