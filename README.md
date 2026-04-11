# NetBotPro Web

NetBotPro is now organized around a single primary execution path:

- `backend/` for the FastAPI API and realtime event layer
- `frontend/` for the React dashboard
- `core/` for packet capture, IDS, scoring, traceroute, firewall, and offline analysis
- `config/` for persisted settings
- `legacy/` for the deprecated Tkinter desktop UI

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

## Notes

- The supported primary UI is the web stack.
- A cross-platform Electron shell is now scaffolded for the desktop delivery path.
- The desktop UI was moved to `legacy/` and is not the active development path.
- Temporary caches, build artifacts, and zip backups are intentionally excluded from the final repo layout.

## More docs

- Detailed migration notes: `docs/WEB_MIGRATION.md`
- Desktop shell notes: `docs/DESKTOP_SHELL.md`
- Legacy/deprecation notes: `docs/README.md`
