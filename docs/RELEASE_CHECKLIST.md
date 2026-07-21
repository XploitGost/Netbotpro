# Release Checklist

Use this checklist before tagging or publishing a release candidate.

## Source State

- [ ] Work from the intended `main` commit or release branch.
- [ ] Confirm `git status --short --branch` is clean.
- [ ] Confirm versions, release notes, and tag naming are consistent.
- [ ] Confirm no large temporary files are staged.
- [ ] Confirm `.runtime/`, benchmark output, `node_modules/`, `dist/`,
  `build/`, caches, local env files, and generated ZIPs are ignored.
- [ ] Confirm `.gitattributes` handles Python/Markdown/JSON/JavaScript as LF
  and PowerShell/batch scripts as CRLF.
- [ ] Confirm docs do not contain machine-specific local paths.

## Backend

- [ ] `python -m pip install -r requirements-dev.txt`
- [ ] `python -m pip check`
- [ ] `python -m unittest discover -s tests -v`
- [ ] Review warnings and expected-error tests.
- [ ] Confirm no naive UTC timestamp deprecation warnings remain.
- [ ] Confirm expected-error logs do not make CI unreadable.

## Frontend

- [ ] `cd frontend`
- [ ] `npm ci`
- [ ] `npm run test:ui`
- [ ] `npm run build`
- [ ] `npm audit --omit=dev`
- [ ] `npm audit`
- [ ] If full dev audit requires a risky major upgrade, document the
  dev-only scope and follow-up.

## Desktop

- [ ] `cd desktop\electron`
- [ ] `npm ci`
- [ ] `npm audit --omit=dev`
- [ ] `npm audit`
- [ ] Validate Electron entrypoints with `node --check main.cjs` and
  `node --check preload.cjs`.
- [ ] Run `scripts\qa\electron_smoke.ps1`.
- [ ] Confirm startup logging works and does not expose secrets.
- [ ] Confirm packaged desktop dependencies install in a network environment
  where Electron downloads are reachable.

## PyInstaller And Packaged Backend

- [ ] `python -m PyInstaller packaging\pyinstaller\netbotpro_backend.spec --clean --noconfirm`
- [ ] `python scripts\release\stage_backend_runtime.py`
- [ ] Confirm `service_fingerprints.json` is included.
- [ ] Confirm required backend data/config files are included.
- [ ] `python scripts\qa\packaged_backend_smoke.py`
- [ ] Confirm health and monitoring smoke checks pass.
- [ ] Confirm bundled logs/status payloads do not expose tokens.

## Security Boundaries

- [ ] No command/control.
- [ ] No remote shell.
- [ ] No file collection.
- [ ] No raw packet forwarding from Agent.
- [ ] No raw payload forwarding from Agent.
- [ ] No PCAP forwarding from Agent.
- [ ] No TLS decryption or MITM.
- [ ] No credential collection.
- [ ] No IPS or automatic response actions.
- [ ] No AI autonomous actions.
- [ ] No browser history scraping, cookie/session inspection, browser
  extension injection, or keylogging.
- [ ] Agent/Fleet telemetry-only boundary is unchanged.
- [ ] Remote Sensor boundary is unchanged.
- [ ] Metrics, reports, exports, and incident summaries are redacted.

## Performance

- [ ] Run the CI-safe benchmark smoke:
  `python benchmarks/soak_test_pipeline.py --duration-sec 10 --events-per-sec 200 --flows 20 --ci-safe --output .runtime/benchmarks/release-hardening-smoke`
- [ ] Confirm bounded queues and buffers remain visible in Ops Snapshot.
- [ ] Confirm packet queue, event aggregator, worker pool, persistence, live
  ring buffer, service attribution, and incident sections are present.
- [ ] Treat benchmark smoke as structural validation, not a production capacity
  claim.

## Release Artifacts

- [ ] Source ZIP.
- [ ] Packaged backend runtime.
- [ ] Desktop package where applicable.
- [ ] SHA256 checksums.
- [ ] Changelog and release notes.
- [ ] Release workflow status.
- [ ] Artifact names include the intended version.

## Known Limitations To Confirm

- [ ] Live capture requires authorization, drivers, and privileges.
- [ ] Service Attribution confidence is limited by ECH, DoH, VPNs, NAT, CDN
  fronting, and weak metadata.
- [ ] Incident Engine is currently bounded/in-memory unless a later persistence
  step is added.
- [ ] Server Mode is not a full production multi-node deployment yet.
- [ ] AI Analyst is not implemented in this release.
