# NetBotPro

NetBotPro is now organized around a single primary execution path:

- `backend/` for the FastAPI API and realtime event layer
- `frontend/` for the React dashboard
- `core/` for packet capture, IDS, scoring, traceroute, firewall, and offline analysis
- `config/` for persisted settings

## Current product focus

NetBotPro is a local-first network investigation console with:

- a live Monitor workspace for packets and alerts
- an analyst-focused Inspect workspace for packet, alert, flow, and process investigation
- process attribution and same-process traffic correlation
- flow and conversation context with related packets, related alerts, and remote-host recurrence
- protocol identification that combines port hints, payload hints, handshake checks, and unusual-port detection
- risk explanation panels with top reasons, likely benign signals, confidence text, and analyst-readable narrative
- persisted history that keeps investigation context much closer to live mode

## Investigation highlights

- Packet and alert clicks land directly in Inspect instead of forcing a long Monitor scroll.
- Inspect now includes `Packet`, `Flow`, and `Process` tabs, plus next/prev navigation, pin, and freeze-live controls.
- Detail views show protocol guess, risk, confidence, flow stats, process attribution, related activity, behavior correlation, and payload previews.
- History queries support process and PID filtering, and stored evidence is re-interpreted on read so older rows still get richer protocol context when possible.

## Security hardening

- The API remains loopback-only by default and now applies stricter response headers plus rate limits on settings, exports, reports, traceroute, and control actions.
- Local token authentication is still required for sensitive routes, but the browser UI now keeps unmanaged tokens in `sessionStorage` instead of `localStorage`.
- Live websocket authentication no longer needs a `?token=` query string; the frontend sends the local token through websocket subprotocol negotiation to reduce token leakage in logs and URLs.
- Export and report downloads are constrained to generated safe file types inside the NetBotPro log directory, and report enumeration skips unsafe or symlinked files.
- Firewall block targets reject unsupported addresses such as loopback, multicast, and unspecified IPs.

## Main architecture

- API entrypoint: `backend/app/main.py`
- Web frontend: `frontend/src/App.jsx`
- Desktop shell: `desktop/electron/main.cjs`
- Sniffer runtime: `core/core_sniffer.py`
- Logging facade: `log_manager.py`
- Settings store: `config/settings_manager.py`

## Install

```powershell
python -m pip install -r requirements.txt
cd frontend
npm install
```

Recommended on Windows:

- Install Npcap if you want live packet capture through Scapy
- Run the backend with administrator privileges if you need packet capture or firewall operations

## Run

Backend:

```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Frontend:

```powershell
cd frontend
npm run dev
```

Desktop shell:

```powershell
cd desktop\electron
npm install
npm run build:frontend
npm run dev
```

## Verification

Useful checks during development:

```powershell
python -m compileall backend core
python -m unittest discover -s tests
cd frontend
npm run build
```

## Notes

- The supported primary UI is the web stack.
- The maintained desktop delivery path is the Electron shell in `desktop/electron/`.
- Deprecated Tkinter UI files were removed to keep the repository focused on the active product path.
- Temporary caches, build artifacts, and zip backups are intentionally excluded from the final repo layout.

## More docs

- Detailed migration notes: `docs/WEB_MIGRATION.md`
- Desktop shell notes: `docs/DESKTOP_SHELL.md`
- Repo cleanup notes: `docs/README.md`
