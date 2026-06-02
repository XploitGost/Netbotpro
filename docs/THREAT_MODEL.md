# Threat Model

This document describes the main assets, trust boundaries, and expected mitigations for NetBotPro.

## Assets

- Local token values.
- Captured packet metadata and payload snippets.
- Historical packet and alert records.
- Generated reports and exports.
- Desktop runtime paths and backend process configuration.
- Remote sensor endpoints.

## Primary Trust Boundaries

| Boundary | Risk | Mitigation |
| --- | --- | --- |
| Browser to backend API | Unauthorized control or data reads | Local token required on sensitive routes. |
| Browser to websocket | Token leakage or unauthorized stream access | Token subprotocol, origin checks, trusted client checks. |
| Remote client to sensor | Public exposure of capture/control API | Remote mode disabled by default, token required, private network recommended. |
| Electron renderer to main process | Renderer compromise reaching Node APIs | Context isolation, sandbox, no nodeIntegration, narrow preload config. |
| Export download path | Path traversal or unsafe file disclosure | Safe suffix allowlist and directory containment checks. |
| Capture provider | OS privilege abuse or unavailable interfaces | Preflight diagnostics and admin/root guidance. |

## Assumptions

- Operators have legal authorization to monitor the target systems.
- Local machines running the dashboard are reasonably trusted.
- Remote sensor deployments are placed behind controlled network access.
- Tokens are not shared publicly or committed to source control.

## Notable Threats

### Unauthorized Remote API Use

If the backend is bound to a non-loopback interface, an attacker could try to call capture, export, settings, or report endpoints. Remote access requires `NETBOT_REMOTE_ACCESS=1` and a valid `NETBOT_LOCAL_TOKEN`; deployments should still use network-level restrictions.

### Token Exposure

Tokens in URLs can leak through logs and browser history. NetBotPro prefers websocket subprotocol authentication instead of query-string websocket tokens. Operators should avoid pasting tokens into screenshots or public logs.

### Unsafe Generated Downloads

Reports and exports can contain sensitive network evidence. Download paths are constrained to generated safe file types, but operators should still treat artifacts as sensitive evidence.

### Desktop Renderer Compromise

The renderer is treated as less trusted than the Electron main process. The preload bridge exposes runtime config only and should remain narrow. Do not add broad filesystem, shell, or Node access to the renderer.

### Over-Privileged Capture Runtime

Live capture may require administrator/root privileges. Run elevated only when needed, and avoid combining remote exposure with unnecessary elevated control actions.

## Residual Risk

NetBotPro can inspect sensitive traffic metadata and generated evidence. Secure storage, operator discipline, and network isolation remain important parts of any deployment.
