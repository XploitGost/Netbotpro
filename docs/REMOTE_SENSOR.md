# Remote Sensor Mode

Remote Sensor Mode lets NetBotPro capture packets on a server you own or administer while you view the dashboard from another machine.

## Security model

- Remote access is disabled by default.
- Remote clients are accepted only when `NETBOT_REMOTE_ACCESS=1` is enabled.
- Remote clients must send the `X-NetBot-Token` header with the configured `NETBOT_LOCAL_TOKEN`.
- Keep the backend behind a VPN, SSH tunnel, private network, or HTTPS reverse proxy for real deployments.
- Do not expose port `8765` to the public internet without TLS, firewall rules, and a strong token.

## Start the sensor on the server

```powershell
cd "C:\Users\ASIA SYSTEM\Desktop\netbotpro"
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-sensor.ps1 -BindHost 0.0.0.0 -Port 8765 -AllowedOrigins "http://YOUR_DASHBOARD_HOST:5173"
```

For background mode:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-sensor.ps1 -Background -BindHost 0.0.0.0 -Port 8765 -AllowedOrigins "http://YOUR_DASHBOARD_HOST:5173"
```

The script prints and stores a strong token in `.runtime\sensor-token.txt`.

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
