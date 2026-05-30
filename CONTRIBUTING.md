# Contributing

## Development workflow

1. Run `powershell -ExecutionPolicy Bypass -File scripts\dev\setup.ps1`
2. Run `powershell -ExecutionPolicy Bypass -File scripts\dev\doctor.ps1`
3. Start local services with `powershell -ExecutionPolicy Bypass -File scripts\dev\start-local.ps1`
4. Stop local services with `powershell -ExecutionPolicy Bypass -File scripts\dev\stop-local.ps1`

## Quality bar

- Keep the API loopback-only by default
- Add or update tests for backend logic changes
- Keep generated artifacts, caches, logs, and local builds out of the repository
- Prefer small, reviewable changes that preserve the current product path: `backend/`, `frontend/`, `core/`, `desktop/electron/`

## Before packaging

- Run `python -m unittest discover -s tests`
- Run `cd frontend && npm run build`
- Use `packaging/windows/build.ps1` for the Windows packaging path
