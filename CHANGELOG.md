# Changelog

## Unreleased

### Added

### Changed

### Fixed

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
