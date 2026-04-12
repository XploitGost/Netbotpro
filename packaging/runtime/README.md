Drop the full packaged backend bundle here before running Electron release builds.

Expected names:
- `backend/netbotpro-backend.exe` on Windows
- `backend/netbotpro-backend` on Linux/macOS

Use `python scripts/release/stage_backend_runtime.py` after PyInstaller finishes to copy the
whole one-dir bundle into `packaging/runtime/backend`.
