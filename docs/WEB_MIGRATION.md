# NetBotPro Web Migration

This workspace now includes a starter split between:

- `backend/app/main.py`: FastAPI entrypoint
- `backend/app/services/`: service layer for web migration
- `frontend/`: Vite + React dashboard starter

## Suggested next steps

1. Move IDS orchestration from the Tkinter handlers into backend services.
2. Add routes for alerts, reports, traceroute, and PCAP history.
3. Replace the starter frontend tables with dedicated feature modules.
4. Decide whether the final Windows delivery target is browser-based or Electron.

## Local dev

Backend:

```bash
python -m uvicorn backend.app.main:app --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```
