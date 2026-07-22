# NetBotPro Install And Run Guide

NetBotPro is a local-first defensive network monitoring and analysis tool.
Only run live capture, Remote Sensor mode, or Agent telemetry on systems and
networks you own or have explicit permission to administer.

## Requirements

- Python 3.13 is recommended for source and CI parity.
- Node.js 20 or newer is recommended. Node 20.17+ avoids newer Electron
  tooling engine warnings.
- Npcap on Windows for live packet capture.
- Administrator privileges on Windows, or root/capture capabilities on Linux,
  when live packet capture is required.
- Git and PowerShell 7 or Windows PowerShell for the provided scripts.

Offline PCAP analysis, report review, docs, and most UI development paths do
not require packet-capture privileges.

## Supported OS Notes

- Windows is the strongest validated desktop target.
- Linux supports source runs, backend services, and staged desktop packaging.
- macOS runs backend/frontend CI paths, but desktop release validation is not
  currently the strongest release target.

Live capture behavior depends on OS drivers, interface visibility, privileges,
and what traffic is observable from the selected host/interface.

Linux live capture may require libpcap/tcpdump plus `sudo` or narrowly scoped
`CAP_NET_RAW`/`CAP_NET_ADMIN`. Do not run the central server as root just to
capture packets; prefer a separate authorized sensor or offline PCAP analysis.

## Windows Notes

Install Npcap before using live capture. Reopen the terminal after installing
Npcap, and run the desktop app or backend terminal as Administrator when live
capture or firewall actions are needed.

Antivirus or endpoint security products can flag packet capture tools,
PyInstaller bundles, or unsigned desktop artifacts. Review alerts carefully and
allow only builds you created from trusted source.

## Backend From Source

```powershell
git clone https://github.com/XploitGost/Netbotpro.git
cd Netbotpro
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m backend.app.desktop_entry
```

For a direct API server run:

```powershell
$env:NETBOT_LOCAL_TOKEN = "use-a-long-random-token"
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8765
```

The backend status endpoint is available at:

```text
http://127.0.0.1:8765/api/status
```

For Linux central API/UI deployment, use `NETBOT_PROFILE=server` and follow
[Linux Server Deployment](LINUX_SERVER_DEPLOYMENT.md). Server profile adds
strict startup validation: explicit allowed origins, strong trusted tokens,
debug disabled, writable runtime/log directories, and no wildcard CORS for
public binds.

## Frontend From Source

```powershell
cd frontend
npm ci
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

If the backend runs on a non-default address, pass the API and websocket URLs
through the app query string:

```text
http://127.0.0.1:5173/?api=http://127.0.0.1:8765/api&ws=ws://127.0.0.1:8765/ws
```

## Desktop App

```powershell
cd desktop\electron
npm ci
npm run dev
```

The desktop shell creates or forwards a local token, starts the backend, and
loads the built frontend through the hardened Electron preload bridge. The
renderer does not receive Node.js access.

## Packaged Backend

Build the backend runtime with the existing PyInstaller flow:

```powershell
python -m PyInstaller packaging\pyinstaller\netbotpro_backend.spec --clean --noconfirm
python scripts\release\stage_backend_runtime.py
python scripts\qa\packaged_backend_smoke.py
```

The staged runtime should include required backend assets such as
`service_fingerprints.json` and should pass the packaged backend smoke test
without exposing tokens in logs or status payloads.

## Offline PCAP Mode

Offline PCAP analysis is local and does not require live capture privileges.
Use the UI upload flow or the backend `/api/analyze-pcap` endpoint with `.pcap`
or `.pcapng` files. Upload size and file type are restricted by the backend.

Offline output includes redacted packet summaries, protocol intelligence,
flow/conversation summaries, timelines, and risk distributions. It does not
decrypt TLS or collect credentials.

## Common Troubleshooting

| Symptom | Likely Cause | Fix |
| --- | --- | --- |
| No capture interfaces | Npcap/libpcap missing or not visible | Install Npcap/libpcap, reopen the terminal, and run the app with capture privileges. |
| Permission denied for capture | Terminal or desktop app lacks privileges | Start PowerShell or the desktop app as Administrator, or grant capture capabilities on Linux. |
| Frontend cannot reach backend | Backend is stopped, wrong port, or blocked by firewall | Confirm `http://127.0.0.1:8765/api/status`, then restart the backend. |
| Protected API returns `401` | Missing or wrong local token | Use the launcher-generated token file or set `NETBOT_LOCAL_TOKEN`. |
| Websocket fails with `403` | Token or allowed origin mismatch | Confirm `NETBOT_ALLOWED_ORIGINS` and websocket token subprotocol configuration. |
| Electron download fails | Network, proxy, cache, or registry issue | Re-run `npm ci` in `desktop\electron` on a network that can reach Electron releases, or configure an approved Electron cache/mirror. |
| Port already in use | Another backend or dev server is running | Stop the old process or set a different `NETBOT_PORT` / Vite port. |
| Python dependency install fails | Old pip, incompatible Python, or wheel download issue | Upgrade pip and use Python 3.13 where possible. |
| Node/npm install fails | Old Node/npm, cache issue, or corporate proxy | Use Node 20.17+ and retry `npm ci` after clearing the npm cache if needed. |
| Antivirus flags the build | Packet capture and unsigned bundles can look unusual | Verify the source, checksums, and build pipeline before allowing the artifact. |

## Safe Use Reminder

NetBotPro is for defensive monitoring, troubleshooting, education, and
authorized security analysis. It intentionally does not add command/control,
remote shell, credential collection, TLS decryption, MITM, browser history
scraping, cookie/session inspection, or Agent raw packet/payload/PCAP
forwarding.
