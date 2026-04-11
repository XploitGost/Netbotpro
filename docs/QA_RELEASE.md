# Netbotpro QA And Release

This document covers phase 5 and phase 6 of the cross-platform roadmap.

## Phase 5: Cross-platform QA

The baseline smoke path is:

1. Run Python unit/integration tests
2. Build the React frontend
3. Validate Electron entrypoint syntax
4. Start the backend under desktop-specific env paths
5. Call `/api/status` and `/api/interfaces`
6. Confirm capture preflight is present
7. Confirm `/api/status` does not expose development-only path metadata

Local smoke command:

```powershell
python scripts\qa\desktop_smoke.py
```

Binary-only backend smoke:

```powershell
python scripts\release\stage_backend_runtime.py
python scripts\qa\packaged_backend_smoke.py
```

## Phase 6: Release automation

The repository now includes:

- `scripts/release/stage_backend_runtime.py`
- `packaging/windows/build.ps1`
- `packaging/linux/build.sh`
- `packaging/macos/build.sh`

The expected release sequence is:

1. Build backend executable with PyInstaller
2. Stage the full backend runtime bundle into `packaging/runtime/backend`
3. Build frontend bundle
4. Run Electron packaging

## CI workflows

GitHub Actions should validate:

- backend tests on Windows, Linux, macOS
- frontend build on Windows, Linux, macOS
- desktop smoke validation on Windows, Linux, macOS
- manual release packaging workflow for staged per-OS builds
