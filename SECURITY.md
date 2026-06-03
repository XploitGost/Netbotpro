# Security Policy

NetBotPro is a defensive network analysis tool. Security reports, hardening suggestions, and responsible vulnerability disclosures are welcome.

## Supported Versions

| Version | Support status |
| --- | --- |
| 0.1.3 | Current release |
| 0.1.2 and older | Historical; upgrade recommended |

## Reporting A Security Issue

For private repositories or private deployments, report security issues directly to the repository owner/maintainer. Include:

- affected version or commit
- affected platform
- clear reproduction steps
- expected impact
- whether credentials, tokens, exported reports, or packet data may be exposed

Do not publish exploit details publicly until the issue has been triaged and a fix or mitigation is available.

## Security Boundaries

NetBotPro treats these as sensitive boundaries:

- local token authentication for sensitive HTTP routes
- websocket token subprotocol authentication
- allowed browser origins
- remote sensor opt-in configuration
- Electron preload and IPC bridge
- generated export/report download paths
- packet capture permissions

## Deployment Guidance

- Keep the default loopback-only mode for local analysis.
- Enable remote sensor mode only on systems and networks you own or administer.
- Use strong `NETBOT_LOCAL_TOKEN` values for any remote deployment.
- Use `NETBOT_REMOTE_IP_ALLOWLIST` or the Settings page allowlist to restrict remote dashboard clients by IP/CIDR.
- Accept the Safe Use Policy before starting capture in Server Mode.
- Leave payload preview capture disabled unless you explicitly need redacted payload snippets for a controlled investigation.
- Use Alert-only mode when you want detection metadata without packet payload previews.
- Configure retention windows for packet history and generated reports when running long-lived sensors.
- Prefer VPN, SSH tunneling, private routing, or a TLS reverse proxy.
- Restrict inbound access with firewall rules or allowlisted operator IPs.
- Run elevated/admin only when live capture or firewall operations require it.

## Audit Events

NetBotPro writes defensive audit events to `audit.jsonl` in the configured log directory for capture start/stop, export creation, report downloads, and successful remote dashboard authentication. Audit records redact token-like fields and are best-effort so audit failures do not interrupt capture.

## Out Of Scope

The project does not attempt to hide monitoring activity, bypass endpoint controls, exfiltrate credentials, or inspect traffic without authorization.
