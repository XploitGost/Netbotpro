# NetBotPro Docker Deployment

This Docker foundation runs NetBotPro as a central API/UI backend for server mode. It is intentionally not privileged and does not enable live packet capture by default.

## Quick start

```bash
export NETBOT_TRUSTED_TOKENS="$(openssl rand -hex 32)"
export NETBOT_AGENT_TOKEN="$(openssl rand -hex 32)"
docker compose up --build
```

The compose file binds `127.0.0.1:8000` on the host. Put Caddy or Nginx in front of it for HTTPS and public access.

## Safety notes

- Do not bake tokens into the image.
- Do not run the default service with `privileged: true`.
- Keep `.runtime`, databases, logs, PCAP files, and `node_modules` out of the image context.
- Docker live capture is advanced only; it may require host networking and Linux capabilities. Prefer a separate authorized sensor process that reports redacted metadata.

