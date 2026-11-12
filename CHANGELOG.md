# Changelog

## Unreleased

### Added

- Isolated, bounded Windows service probe for synthetic or explicit live
  history-confirmed capture, with temporary-data cleanup and numeric-only reports.
- ALPN list/tuple storage normalization for packet and alert history, fixing a
  real-capture SQLite binding failure that prevented journal acknowledgement.
- Experimental history-confirmed journal acknowledgement waits for one bounded
  packet/alert commit receipt before publication and journal reclamation, with
  failure/replay regression tests. Default callback policy and installed settings
  are unchanged; stateful analysis is not transactional (ADR 0009).
- Versioned detector occurrence keys and targeted alert-history uniqueness protect
  identified journal detections on replay while preserving unknown/legacy alerts,
  independent occurrences and existing live IDs. Capture acknowledgement and
  stateful analysis replay remain separate work (ADR 0008).
- Opt-in, bounded history-group receipts distinguish admission, confirmed commit,
  rejection, eviction, skips and failure without changing normal Capture or
  journal acknowledgement. Legacy returns cannot certify these handles (ADR 0007).
- Explicit history commit/disabled/unavailable outcomes and typed batch processing
  versus skip counts prevent skipped or unavailable writes being reported as
  stored events; flush receipts retain skip visibility (ADR 0006).
- Stable journal occurrence IDs and optional unique packet-history keys protect
  retained packet rows on reopen/replay, preserving old records and independent
  identical packets. Alerts/flow state and end-to-end durability remain separate
  work (ADR 0005).
- Prepared persistence operations preserve successful history/flow steps within
  one retry cycle, preventing duplicate history inserts after later flow failure
  without adding a disk ledger or claiming crash-safe deduplication (ADR 0004).
- Explicit persistence flush receipts distinguish completion, timeout, eviction
  and unavailable workers. New write failures or drops prevent false success;
  existing overflow/retry policies remain unchanged (ADR 0003).
- Journal batch acknowledgement boundary, stage-specific failure diagnostics and
  completed-versus-acknowledged counters, with encrypted replay regression tests
  (ADR 0002); no change to downstream durability or automatic retry policy.
- Typed analysis-to-delivery handoff and explicit delivery ports, preserving
  existing destination order and redaction responsibilities (ADR 0001).
- Regression coverage for later clean stability windows without erasing historical
  failures or treating counter resets/missing metrics as healthy samples.

- Synthetic, reproducible Command Center, Monitor, Investigation and Fleet
  documentation screenshots, an updated architecture/roadmap, and Persian overview.
- Known-advisory audits for all requirement/lock files and packaged ML/export probes.
- Explicit per-core versus available-capacity CPU budgets for benchmark validation.
- Isolated Electron renderer/IPC/startup/drain smoke on the upgraded runtime.

- Repository source-safety guard and regression tests, contribution templates,
  dependency update policy and explicit repository maintenance documentation.
- Preserved desktop UI source checkpoint and architecture boundary roadmap.
- Capture recovery, flow-detail compaction and expanded regression coverage.

- Release hardening documentation with an install/run guide and release
  checklist covering source cleanliness, audits, desktop validation,
  PyInstaller smoke, security boundaries, and release artifacts.
- Performance Pipeline foundation: bounded packet intake, WebSocket Event
  Aggregator, Batch Persistence / Storage Backpressure, Flow-aware Worker
  Pool, Live Ring Buffer, and CI-safe benchmark/soak validation.
- Service Attribution / Destination Intelligence with metadata-only
  confidence scoring and conservative handling for encrypted/CDN traffic.
- Incident Correlation Engine with redacted incident timelines, severity,
  confidence, investigation guidance, and read-only Markdown summary export.
- Protocol Intelligence Expansion for TCP, DNS, HTTP, and visible TLS metadata.
- Saved Display Filters with built-in recipes and safe field suggestions.
- Protocol Statistics and safe Packet Search in the Inspect workspace.
- Expanded Expert Info and redacted protocol/inspection summary reports.
- Offline PCAP parity for protocol intelligence summaries.

### Changed

- Updated vulnerable Python dependencies, Electron/tooling and npm packaging graph.
- Restored dynamically imported export/ML modules to packaged backend builds.
- Replaced a compiled-bundle row-windowing symbol with the shared source hook.

- Replaced remaining naive UTC timestamp call sites with timezone-aware UTC
  timestamps.
- Refreshed frontend development lockfile dependencies with compatible
  patch/minor updates and cleaned desktop Electron audit findings.
- Reduced expected-error test log noise while preserving production logging and
  failure-path coverage.

## v0.2.0 - Agent & Fleet Monitoring Release - 2026-06-05

### Added

- Added read-only Agent Mode with identity, configuration, client, runner, and
  summary-only telemetry payloads.
- Added SQLite-backed Agent history for heartbeat, telemetry, health, alert,
  flow, capture status, and risk snapshots.
- Added Agent registration, heartbeat, telemetry, overview, detail, history,
  alerts summary, risk summary, and fleet report APIs.
- Added the Fleet Dashboard with filtering, sorting, risk badges, offline
  detection, trend views, demo states, and JSON summary export.
- Added realistic Demo Agent seed data and local multi-agent simulation
  start/status/stop scripts.
- Added Fleet Summary Report endpoints in redacted JSON and CSV formats.
- Added Agent history retention cleanup with dry-run support.
- Added Agent Operational QA and Release QA checklists.
- Added Agent log sanitization and central redaction wrappers.
- Added deployment overview and official v0.2.0 release notes.
- Polished the README Feature Matrix and architecture diagrams.

### Security

- Agent tokens are hashed before registry storage.
- Agent logs and operational scripts do not print raw tokens.
- Agent Mode does not forward raw packets, raw payloads, or PCAP artifacts.
- Fleet report and export output is redacted before it is returned.
- Demo, status, cleanup, sensor, and Agent scripts keep tokens hidden by
  default.
- Remote Sensor mode keeps explicit token, allowlist, remote-access, capture
  policy, and authorization guardrails.

### Changed

- Moved the default Agent registry storage from JSONL MVP storage to
  auto-initialized SQLite storage.
- Updated the README architecture and release/deployment guidance.
- Improved the Agent/Fleet dashboard for operational demos and multi-server
  review.
- Upgraded GitHub Actions to current supported major versions.

### Testing

- Expanded backend API, storage, redaction, history, retention, and release
  consistency tests.
- Expanded PowerShell script safety tests.
- Added frontend Agent UI tests and production build validation.
- Validated backend tests and frontend builds on Windows, Linux, and macOS CI.
- Validated the packaged Windows backend with Desktop Smoke.
- Added release-readiness checks for version, documentation, workflow, and
  safety consistency.

### Limitations

- Agent Mode is read-only monitoring only.
- This release has no command/control or remote command execution.
- This release has no raw packet, raw payload, or PCAP forwarding from Agents.

## 0.1.3 - 2026-06-02

### Added
- Added a lightweight history performance smoke benchmark so large synthetic investigation reads can be timed before release builds.
- Added packaged desktop icon assets so Windows builds no longer ship with the default Electron branding.
- Added remote sensor mode for authorized server-side packet review.
- Added a professional release README, secure environment template, MIT license, pinned Python dependencies, and dev dependency lock file.
- Added tag-driven desktop release publishing through GitHub Actions.

### Changed
- Improved capture preflight reporting with clearer discovery source/reason metadata and actionable first-run recommendations in the Monitor hero.
- Improved process attribution stability by retrying cache misses, recognizing wildcard-bound sockets, and using a conservative port fallback when the match is unique.
- Improved history read-path parity by rehydrating older process metadata from persisted executable paths and backfilling clearer attribution reasons.
- Improved packaged backend smoke discovery so QA can validate the runtime from either the staged backend bundle or the built Windows desktop output.
- Hardened CI to install pinned dev dependencies and run dependency health checks before tests and desktop smoke.

### Fixed
- Confirmed the Electron desktop runtime config path uses a registered IPC bridge and secure local token injection.

## 0.1.2 - 2026-04-27

### Added
- Added final alert investigation context so Inspect can correlate packet, alert, flow, process, related alerts, and root-cause style groupings.
- Added richer investigation UX with packet, flow, and process tabs, related flow views, same-process and same-remote activity, plus next/prev and pin/freeze controls.
- Added analyst-readable risk explanation panels with top reasons, likely benign signals, confidence text, and investigation narrative.
- Restored GitHub Actions workflows for backend tests, frontend builds, Windows desktop smoke checks, and manual desktop packaging.

### Changed
- Improved protocol identification with stronger port, payload, handshake, encrypted/binary, and unusual-port evidence.
- Brought persisted history closer to live parity by persisting more protocol and payload evidence and enriching older rows again on the read path.
- Expanded README documentation to reflect the current Inspect-first investigation workflow and development verification steps.
- Hardened local auth and realtime transport so websocket sessions prefer subprotocol-based token exchange and unmanaged browser tokens stay in session-scoped storage.
- Improved history and inspection wording so process gaps, confidence text, stream anomalies, and fallback summaries read more like analyst notes than raw placeholders.
- Added list/detail caching plus stale-request guards so monitor and inspect stay smoother under heavier history navigation.
- Tightened desktop runtime behavior by reducing packaged-backend log verbosity and avoiding raw launch path details in desktop logs.
- Prepared Linux packaging scripts and Electron build config for real `dist:linux` runs on a Linux host.
- Hardened Windows packaging so local Electron and cached dependencies are reused instead of forcing unnecessary downloads during desktop builds.

### Fixed
- Fixed history parity gaps where persisted rows could lose important protocol context compared with live traffic.
- Fixed alert-to-packet linking and flow correlation so related alerts and root-cause summaries stay consistent in Inspect.
- Fixed history queries against older SQLite schemas by degrading gracefully when newer evidence columns are not present.
- Fixed unsafe report enumeration and export download handling by filtering to generated safe file types and rejecting traversal-style paths.
- Fixed loopback, firewall, and traceroute validation edge cases that could allow weaker input handling or less predictable runtime failures.
- Fixed async alert-context caching in the history service so repeated detail reads no longer bypass the new cache path.
- Fixed Windows desktop packaging failures caused by remote Electron asset fetches when a valid local Electron runtime was already present.

## 0.1.1 - 2026-04-15

### Added
- Added the new Inspect workspace so packet and alert selection lands directly in an investigation-focused view.

### Changed
- Simplified the Monitor experience with a cleaner layout, lighter cards, sticky navigation, and an internal detail-panel scroll area.
- Unified IP classification across live capture, history, and inspect.
- Improved remote/local detection accuracy.
- Aligned backend and UI peer/remote flow interpretation.

### Fixed
- Fixed CGNAT and local edge cases in detection and filtering.
- Corrected remote-only filtering for IPv6 local flows and interfaces that use a public address locally.
