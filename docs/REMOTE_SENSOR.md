# Remote Sensor Mode

Remote Sensor Mode lets NetBotPro capture packets on a server you own or administer while you view the dashboard from another machine.

Use this mode only for systems, servers, and networks where you have explicit legal authorization. It is designed for defensive operations, incident response, troubleshooting, and lab work; it is not intended for public exposure, third-party traffic monitoring, or unauthorized packet capture.

## Security model

- Remote access is disabled by default.
- Remote clients are accepted only when `NETBOT_REMOTE_ACCESS=1` is enabled.
- Remote clients must send the `X-NetBot-Token` header with the configured `NETBOT_LOCAL_TOKEN`.
- Remote client IPs can be restricted with `NETBOT_REMOTE_IP_ALLOWLIST=1.2.3.4,10.0.0.0/24`.
- Websocket clients use the `netbot.auth.*` subprotocol token when possible; query token is only a fallback.
- Capture defaults to `metadata` mode. `full` and `forensic` modes require Safe Use acceptance and explicit full-capture authorization.
- Keep the backend behind a VPN, SSH tunnel, private network, or HTTPS reverse proxy for real deployments.
- Do not expose port `8765` to the public internet without TLS, firewall rules, and a strong token.
- Prefer allowlisted operator IPs and private routing. A strong token is required, but it is not a replacement for network-level access control.
- Run with elevated privileges only when live capture is actually required.

## Start the sensor on the server

```powershell
cd "C:\Users\ASIA SYSTEM\Desktop\netbotpro"
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-sensor.ps1 -BindHost 0.0.0.0 -Port 8765 -AllowedOrigins "http://YOUR_DASHBOARD_HOST:5173" -CaptureMode metadata
```

For background mode:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-sensor.ps1 -Background -BindHost 0.0.0.0 -Port 8765 -AllowedOrigins "http://YOUR_DASHBOARD_HOST:5173" -Allowlist "203.0.113.10"
```

The script stores a strong token in `.runtime\sensor-token.txt` and prints only the file path by default. Use `-ShowToken` only in a private terminal.

## Open the dashboard from your workstation

Run the frontend locally, then open:

```text
http://127.0.0.1:5173/?api=http://SERVER_IP:8765/api&ws=ws://SERVER_IP:8765/ws
```

Paste the sensor token into the Local Token field when prompted.

## Recommended production path

- Put the sensor behind WireGuard/Tailscale/ZeroTier or another private network.
- If you must use a public domain, use HTTPS/WSS through a reverse proxy.
- Restrict firewall access to your workstation IP.
- Run with administrator/root privileges only when live capture is required.
- Use `scripts\dev\status-sensor.ps1` to inspect process/log/token-file paths without printing the token.
- Use `scripts\dev\stop-sensor.ps1` to stop the background sensor and clean stale PID files.
