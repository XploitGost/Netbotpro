# NetBotPro Desktop Shell

The Electron shell in `desktop/electron/` provides the local desktop delivery path for NetBotPro. It wraps the web dashboard and starts a backend runtime so the application can run without asking the user to manually start FastAPI.

## Runtime Model

- Electron starts a backend subprocess through `backend.app.desktop_entry` in dev mode or a staged PyInstaller binary in packaged mode.
- The backend receives config/data/log paths through environment variables.
- The frontend is loaded from Vite during development or from the built `frontend/dist/app.html` in packaged mode.
- Runtime API and websocket bases are injected through a narrow preload bridge.
- A local token is generated with cryptographic randomness when `NETBOT_LOCAL_TOKEN` is not already configured.

## Security Defaults

- `contextIsolation: true`
- `sandbox: true`
- `nodeIntegration: false`
- `webSecurity: true`
- external navigation is blocked unless it points to a local allowed URL
- runtime config is exposed as a frozen object through `window.netbotproDesktop`

The desktop shell should not expose Node APIs to the renderer. New renderer capabilities should go through explicit, narrow IPC handlers.

## Desktop Directories

The shell maps runtime state into the Electron user-data directory:

- config: `NETBOT_CONFIG_DIR`
- data/db: `NETBOT_DATA_DIR`
- logs/exports: `NETBOT_LOG_DIR`

This keeps packaged application state separate from the source checkout and avoids writing into installation directories.

## Development

Recommended local web stack:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-local.ps1
```

Recommended desktop dev shell:

```powershell
cd desktop\electron
npm run dev
```

If Electron is installed but `path.txt` points to the wrong runtime, the dev script runs `scripts/dev/repair-electron-path.js` before launching.

## Packaging

- Electron config: `desktop/electron/package.json`
- Backend bundle: `packaging/pyinstaller/netbotpro_backend.spec`
- Windows wrapper: `packaging/windows/build.ps1`
- Linux wrapper: `packaging/linux/build.sh`
- macOS wrapper: `packaging/macos/build.sh`

Windows artifacts are named from the package version:

- `Netbotpro-${version}-setup-${arch}.exe`
- `Netbotpro-${version}-portable-${arch}.exe`

For `0.2.0`, the release artifacts are:

- `Netbotpro-0.2.0-setup-x64.exe`
- `Netbotpro-0.2.0-portable-x64.exe`
- `SHA256SUMS-windows.txt`

## Windows Toolchain Notes

- Node 20 works for CI builds; Node 22 is preferred locally for newer Electron tooling.
- Python 3.13 is used by CI.
- `packaging/windows/build.ps1` reuses local Electron dependencies when possible.
- Packaged backend smoke tests should pass before publishing a desktop release.

## Staged Platforms

Linux and macOS build scripts are present, but Windows is the validated release platform for `0.2.0`. Before calling Linux/macOS production-ready, build and smoke-test artifacts on native hosts, verify capture limitations, confirm signing/notarization expectations, and document platform-specific installation steps.
