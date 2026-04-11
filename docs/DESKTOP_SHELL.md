# Netbotpro Desktop Shell

Netbotpro now includes an Electron shell in `desktop/electron/` for the cross-platform local desktop path.

## Runtime model

- Electron launches a local backend subprocess through `backend.app.desktop_entry`
- The backend reads config/data/log paths from environment variables
- The frontend can run:
  - in browser dev mode through Vite proxy
  - in desktop mode from `file://` with runtime-injected absolute API and WebSocket bases

## Desktop directories

The shell maps desktop runtime state into the Electron user-data directory:

- config: `NETBOT_CONFIG_DIR`
- data/db: `NETBOT_DATA_DIR`
- logs/exports: `NETBOT_LOG_DIR`

## Packaging

- Electron packaging config: `desktop/electron/package.json`
- Backend bundling spec: `packaging/pyinstaller/netbotpro_backend.spec`
- Platform wrappers:
  - `packaging/windows/build.ps1`
  - `packaging/linux/build.sh`
  - `packaging/macos/build.sh`

## Release strategy

- Windows first
- Linux second
- macOS third

The architecture is cross-platform now, but packaged release rollout can stay staged.
