# Docs

## Primary path

The maintained product path is:

- `backend/`
- `frontend/`
- `core/`
- `config/`

## Legacy desktop UI

The files in `legacy/` are kept only as a deprecated desktop reference:

- `legacy/ui_kali.py`
- `legacy/ui_main.py`
- `legacy/main_kali.py`

They are not the active development target.

## Cleanup policy

The repository should not keep:

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
├── legacy/
├── tests/
├── docs/
├── requirements.txt
└── .gitignore
```
