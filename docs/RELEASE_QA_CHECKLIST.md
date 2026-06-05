# Release QA Checklist

Use this checklist before tagging NetBotPro v0.2.0 or delivering a release
candidate.

## Dependency And Test Validation

- [ ] Run `python -m pip install -r requirements-dev.txt`.
- [ ] Run `python -m pip check`.
- [ ] Run `python -m unittest discover -s tests -v`.
- [ ] Run `cd frontend && npm ci`.
- [ ] Run `npm run test:ui`.
- [ ] Run `npm run build`.

## Runtime Validation

- [ ] Start the backend and confirm `/api/status`.
- [ ] Start the frontend and open the dashboard.
- [ ] Run `scripts/dev/start-demo.ps1`.
- [ ] Seed demo Agent data and confirm four realistic servers appear.
- [ ] Confirm the Agents dashboard loads overview, table, details, and trends.
- [ ] Confirm Fleet Summary Report JSON returns redacted output.
- [ ] Confirm Fleet Summary Report CSV downloads successfully.

## Security And Privacy

- [ ] Verify Authorization, Cookie, token, password, API key, secret, session,
  and JWT-like data are redacted.
- [ ] Verify no raw token appears in backend, sensor, Agent, demo, or fleet
  logs.
- [ ] Verify Agent Mode has no command/control or remote command execution.
- [ ] Verify Agent Mode has no raw packet, raw payload, or PCAP forwarding.
- [ ] Confirm Full and Forensic capture still require explicit authorization
  and audit.

## Operational Scripts

- [ ] Test sensor start/status/stop scripts and stale PID handling.
- [ ] Test Agent start/status/stop scripts and token-safe output.
- [ ] Test local multi-Agent demo fleet start/status/stop scripts.
- [ ] Run Agent history cleanup with `-DryRun`.
- [ ] Confirm cleanup preserves Agent identity rows.

## Desktop And Artifacts

- [ ] Run Electron smoke validation when the environment supports it.
- [ ] Build Windows desktop artifacts.
- [ ] Confirm artifact filenames include version `0.2.0`.
- [ ] Confirm SHA256 checksum files are generated.
- [ ] Confirm the GitHub Release workflow accepts `v*` tags.
- [ ] Confirm release notes include `CHANGELOG.md`.
- [ ] Confirm the release candidate contains no committed tokens or runtime
  secrets.

## Release Sign-Off

- [ ] `README.md`, `SECURITY.md`, Safe Use, deployment, Agent, and capture-mode
  documentation reviewed.
- [ ] CI is green on `main`.
- [ ] Tag `v0.2.0` points at the approved commit.
- [ ] Release artifacts and checksums downloaded and independently verified.
