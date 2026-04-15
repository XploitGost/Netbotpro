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
