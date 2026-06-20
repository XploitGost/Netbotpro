# Docs

## Primary path

The maintained product path is:

- `backend/`
- `frontend/`
- `core/`
- `config/`

## Cleanup policy

The repository should stay focused on the active desktop and web runtime. Old debug artifacts and abandoned UI paths should not remain in the tree.

Do not keep:

- `__pycache__/`
- `*.pyc`
- `.runtime-cache/`
- `.codex_tmp_stage2/`
- `frontend/node_modules/`
- `frontend/dist/`
- backup zips or nested zips
- `*.save`, `*.bak`, `*.old`

## Current layout

```text
project/
├── backend/
├── frontend/
├── core/
├── config/
├── tests/
├── docs/
├── requirements.txt
└── .gitignore
```

## Operational Monitoring

Operational monitoring is intentionally compact. The backend exposes
`/api/monitoring/metrics` with capture state, packet intake queue pressure,
websocket delivery counters, SQLite persistence pressure, history query
latency, flow totals, and detection counters.

The UI uses that snapshot to show short recommended actions for stale metrics,
stopped capture, packet queue drops, persistence backlog, websocket delivery
gaps, and backend runtime pressure. These metrics are operational metadata only;
they do not include raw payloads, credentials, cookies, authorization headers,
or Agent raw packet forwarding.
