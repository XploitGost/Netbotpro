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

## Git and Pull Requests

- Work on a focused branch, for example `git switch -c fix/capture-recovery`.
- Before staging, inspect `git status --short` and `git diff`.
- Stage specific source paths. Run `python scripts/qa/repository_hygiene.py --staged`
  and `git diff --cached --check` before committing.
- Never force-push shared history. Use `git revert` for an already published fix.
- Use a pull request for review and wait for CI. Dependency update PRs are not
  automatically merged; inspect compatibility and tests first.
- Do not develop against the installed application as a second source tree.
  See [architecture boundaries](docs/ARCHITECTURE_BOUNDARIES.md) and the
  [desktop source checkpoint](frontend/desktop-reference/README.md).

The hygiene check detects selected artifact and credential patterns. It is not
a replacement for reviewing the diff, secret scanning or privacy review.

## Before packaging

- Run `python -m unittest discover -s tests`
- Run `cd frontend && npm run build`
- Use `packaging/windows/build.ps1` for the Windows packaging path
