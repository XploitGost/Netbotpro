# Safe Use Policy

NetBotPro is intended for defensive monitoring, troubleshooting, education, authorized incident response, and analysis of systems you own or administer.

## Allowed Use

- Monitoring your own workstation, lab, server, or owned infrastructure.
- Troubleshooting packet capture, routing, DNS, HTTP, TLS, or process-attribution issues.
- Reviewing PCAP files you are authorized to analyze.
- Running remote sensor mode on servers where you have explicit administrative permission.
- Running Full or Forensic capture only on authorized servers with owner/admin permission.
- Generating reports for internal defensive investigation.
- Running summary-only Agent/Fleet monitoring on authorized servers.

## Disallowed Use

- Capturing traffic from networks, devices, accounts, or users without permission.
- Using NetBotPro for credential theft, surveillance, evasion, intrusion, or unauthorized reconnaissance.
- Exposing remote sensor mode as a public service without access control.
- Sharing packet captures, reports, tokens, or sensitive telemetry publicly without authorization.
- Committing or sharing local, sensor, or Agent tokens.

## Remote Sensor Rules

- Keep remote sensor mode disabled unless it is needed.
- Use `NETBOT_REMOTE_ACCESS=1` only on controlled infrastructure.
- Configure a long random `NETBOT_LOCAL_TOKEN`.
- Restrict inbound access through VPN, SSH tunnel, private routing, allowlisted IPs, or a TLS reverse proxy.
- Do not rely on the local token alone as the only protection for internet-exposed deployments.
- Full/Forensic capture may collect sensitive packet content. Enable it only with explicit authorization, audit logging, retention limits, and redaction for non-raw outputs.

## Agent Mode Rules

- Agent Mode is read-only monitoring in v0.2.0.
- Agent Mode does not provide command/control, remote command execution, remote
  shell, file collection, or Agent auto-update.
- Agent Mode does not forward raw packets, raw payloads, or PCAP artifacts.
- Keep the central Agent API behind a VPN/private network or secure reverse
  proxy.
- Keep Agent tokens out of source control, logs, screenshots, and shared
  messages.
- Redact credentials and sensitive text before telemetry, reports, or exports
  are stored or shared.

## Evidence Handling

Reports, exports, packet metadata, and payload snippets can contain sensitive information. Store them securely, share them only with authorized people, and delete them when retention is no longer needed.
