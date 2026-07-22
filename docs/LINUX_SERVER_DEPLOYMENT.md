# Linux Server Deployment

NetBotPro server mode runs a central Linux API/UI node for authorized defensive monitoring. Remote sensors and agents report redacted telemetry and metadata only. Server mode is not command/control and does not add remote shell, file collection, payload forwarding, PCAP forwarding, TLS decryption, MITM, credential collection, or autonomous response actions.

## Runtime profiles

Set `NETBOT_PROFILE` to one of `dev`, `desktop`, `server`, `sensor`, or `agent`.

- `dev`: local development with relaxed local defaults.
- `desktop`: current local desktop/Electron behavior, SQLite/runtime paths, trusted local access.
- `server`: central API/UI mode with strict validation, explicit origins, health/readiness, and reverse proxy support.
- `sensor`: remote redacted metadata sender; no UI, command receiving, raw payload forwarding, remote shell, or file collection.
- `agent`: remote system/health telemetry sender; no raw packets, payloads, PCAP forwarding, or command execution.

For public or non-localhost server binds, configure explicit origins and strong tokens:

```env
NETBOT_PROFILE=server
NETBOT_SERVER_MODE=true
NETBOT_HOST=127.0.0.1
NETBOT_PORT=8000
NETBOT_PUBLIC_BASE_URL=https://netbotpro.example.com
NETBOT_ALLOWED_ORIGINS=https://netbotpro.example.com
NETBOT_TRUSTED_TOKENS=replace-with-a-long-random-token
NETBOT_AGENT_TOKEN=replace-with-a-separate-agent-registration-token
NETBOT_RUNTIME_DIR=/var/lib/netbotpro
NETBOT_LOG_DIR=/var/log/netbotpro
NETBOT_ENABLE_LIVE_CAPTURE=false
NETBOT_DEBUG=false
```

Server mode rejects wildcard CORS, missing trusted tokens, debug mode, default-looking secrets, and unwritable runtime/log directories.

## Ubuntu/Debian install

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nodejs npm tcpdump libpcap-dev
sudo useradd --system --home /var/lib/netbotpro --shell /usr/sbin/nologin netbotpro
sudo mkdir -p /opt/netbotpro /etc/netbotpro /var/lib/netbotpro /var/log/netbotpro
sudo chown -R netbotpro:netbotpro /opt/netbotpro /var/lib/netbotpro /var/log/netbotpro
```

Copy the source into `/opt/netbotpro`, then install dependencies:

```bash
cd /opt/netbotpro
sudo -u netbotpro python3 -m venv .venv
sudo -u netbotpro .venv/bin/python -m pip install --upgrade pip
sudo -u netbotpro .venv/bin/python -m pip install -r requirements.txt
```

Build the frontend when serving a packaged UI separately:

```bash
cd /opt/netbotpro/frontend
npm ci
npm run build
```

Create `/etc/netbotpro/netbotpro.env` from `deploy/systemd/netbotpro.env.example`, replace all tokens, then run manually:

```bash
set -a
. /etc/netbotpro/netbotpro.env
set +a
cd /opt/netbotpro
sudo -u netbotpro .venv/bin/python -m uvicorn backend.app.main:app --host "$NETBOT_HOST" --port "$NETBOT_PORT"
```

## systemd

```bash
sudo cp /opt/netbotpro/deploy/systemd/netbotpro.service /etc/systemd/system/netbotpro.service
sudo systemctl daemon-reload
sudo systemctl enable --now netbotpro
sudo systemctl status netbotpro
journalctl -u netbotpro -f
```

The service runs as `netbotpro`, reads `/etc/netbotpro/netbotpro.env`, uses `/opt/netbotpro`, and writes only to `/var/lib/netbotpro` and `/var/log/netbotpro`.

## Health and readiness

```bash
curl http://127.0.0.1:8000/api/health
curl http://127.0.0.1:8000/api/ready
curl -H "X-NetBot-Token: $NETBOT_TRUSTED_TOKENS" http://127.0.0.1:8000/api/monitoring/metrics
```

Health reports alive status, version, profile, uptime, and safe metadata. Readiness reports service status for config, runtime directory, persistence, event aggregation, live ring buffer, incident engine, service attribution, monitoring, and optional capture readiness.

## Nginx reverse proxy

```nginx
server {
    listen 443 ssl http2;
    server_name netbotpro.example.com;

    ssl_certificate /etc/letsencrypt/live/netbotpro.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/netbotpro.example.com/privkey.pem;

    client_max_body_size 64m;
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Set `NETBOT_ALLOWED_ORIGINS=https://netbotpro.example.com`. Do not expose the backend directly to the internet without HTTPS and token-based access.

## Caddy reverse proxy

```caddyfile
netbotpro.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8000
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer
    }
}
```

Caddy handles HTTPS automatically when DNS points to the server and ports 80/443 are reachable.

## HTTPS/TLS

Use Caddy automatic HTTPS or Nginx with certbot. For LAN-only use, a private CA or self-signed certificate may be acceptable, but clients must trust it explicitly. WebSockets should traverse the proxy as WSS. This TLS guidance protects NetBotPro web/API access only; NetBotPro does not decrypt third-party TLS traffic.

Open only required firewall ports, typically 80/443 to the reverse proxy and no public access to backend port 8000.

## Linux live capture permissions

Live capture on Linux usually depends on libpcap/tcpdump and interfaces such as `eth0`, `ens*`, `wlan*`, or `lo`. Capturing often requires `sudo` or carefully scoped `CAP_NET_RAW`/`CAP_NET_ADMIN`.

Running the whole server as root is discouraged. Prefer one of these authorized-use patterns:

- Run central server mode without live capture and ingest redacted telemetry.
- Run a separate sensor on controlled interfaces with limited Linux capabilities.
- Use authorized offline PCAP analysis when raw packet inspection is needed.
- Keep Docker capture as an advanced setup only; host networking and capabilities change the trust boundary.

Do not grant broad privileges silently. Any capability changes should be reviewed and documented by the operator.

## Docker

```bash
export NETBOT_TRUSTED_TOKENS="$(openssl rand -hex 32)"
export NETBOT_AGENT_TOKEN="$(openssl rand -hex 32)"
docker compose up --build
```

The default compose deployment binds localhost only, uses runtime/log volumes, and does not enable privileged live capture.

## CI-safe validation on a server

```bash
python -m pip check
python -m unittest discover -s tests -v
cd frontend && npm ci && npm run test:ui && npm run build
cd ../desktop/electron && npm ci && npm audit --omit=dev
cd ../..
python -m unittest tests.test_performance_benchmarks -v
```

These checks do not require root, Docker daemon access, live capture, Nginx, Caddy, or external network during test execution after dependencies are installed.

## Troubleshooting

- Port already in use: change `NETBOT_PORT` or stop the conflicting service.
- Runtime/log permission denied: verify ownership of `/var/lib/netbotpro` and `/var/log/netbotpro`.
- CORS/origin rejected: set `NETBOT_ALLOWED_ORIGINS` to the exact HTTPS origin.
- Missing trusted token: set `NETBOT_TRUSTED_TOKENS` to a strong random value.
- WebSocket proxy issue: ensure `Upgrade` and `Connection` headers are forwarded.
- Service attribution registry missing: reinstall from a complete source tree and restart.
- Live capture permission denied: use a separate sensor or review Linux capabilities.
- Docker volume permission issue: recreate volumes or fix ownership inside the container.
- Nginx/Caddy proxy issue: verify backend health on `127.0.0.1:8000`.
- High CPU/RAM pressure: run the CI-safe benchmark and inspect `/api/monitoring/metrics`.
- Benchmark degraded: treat it as sizing guidance, then lower capture/load or increase CPU/RAM.

