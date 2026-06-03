# Server Deployment

NetBotPro Server Capture Mode is for servers and networks you own, administer, or have explicit permission to monitor.

## Windows Server

1. Install Python and project dependencies.
2. Install Npcap when live capture is required.
3. Run PowerShell as Administrator for capture/firewall operations.
4. Start the sensor:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\start-sensor.ps1 -Background -BindHost 0.0.0.0 -Port 8765 -AllowedOrigins "https://dashboard.example"
```

Use `-ShowToken` only in a private terminal. The default output shows the token file path instead of the token value.

## Linux

Run with root privileges or grant capture capabilities to the Python/scapy runtime. Prefer a dedicated service user plus explicit packet-capture permissions where your platform supports it.

```bash
sudo systemctl enable --now netbotpro-sensor.service
sudo journalctl -u netbotpro-sensor.service -f
```

## Network Exposure

Prefer one of these patterns:

- VPN or private subnet access.
- SSH tunnel from the operator workstation.
- TLS reverse proxy that terminates HTTPS/WSS.
- Firewall rules restricting inbound access to trusted operator IPs.
- `NETBOT_REMOTE_IP_ALLOWLIST` with exact IPs or CIDRs.

## Environment

Set these in an env file or service manager:

```text
NETBOT_REMOTE_ACCESS=1
NETBOT_LOCAL_TOKEN=<long-random-token>
NETBOT_ALLOWED_ORIGINS=https://dashboard.example
NETBOT_REMOTE_IP_ALLOWLIST=203.0.113.10,10.10.0.0/24
NETBOT_CAPTURE_MODE=metadata
NETBOT_REDACT_SENSITIVE_DATA=1
NETBOT_RETENTION_DAYS=7
```

For Full or Forensic mode, also set:

```text
NETBOT_ALLOW_FULL_CAPTURE=1
NETBOT_SAFE_USE_ACCEPTED=1
NETBOT_PAYLOAD_CAPTURE=1
```

## Windows Service Options

Use NSSM or a Scheduled Task that runs `scripts\dev\start-sensor.ps1 -Background` after reboot. Configure restart-on-failure in the service manager and keep logs under `.runtime\logs`.

## Troubleshooting

- `403 Local access only`: set `NETBOT_REMOTE_ACCESS=1`.
- `401 Invalid local token`: confirm `X-NetBot-Token` or websocket subprotocol auth.
- `403 Remote dashboard IP is not allowlisted`: add the operator IP/CIDR.
- `451 Safe Use Policy`: accept the Safe Use Policy before Full/Forensic capture.
- `0 capture interfaces`: install Npcap/libpcap and run with elevated capture permissions.
