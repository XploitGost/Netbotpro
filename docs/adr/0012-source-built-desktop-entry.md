# ADR 0012: Source-built desktop entry

Date: 2026-11-12
Status: Accepted for isolated validation; not promoted to installed default

## Context

The preserved desktop design depended on an old compiled JavaScript baseline
and minified function-name replacements. A normal source build could not
reproduce it. Separate frontend logic also risked losing controller fixes.

## Decision

- Move authored components, styles and pure models into `frontend/src/desktop`.
  Keep compatibility re-exports for model tests and documentation.
- Build `app.html` and `desktop.html` with one Vite configuration. Retire the
  baseline patcher. Electron defaults to standard; `NETBOT_DESKTOP_UI=desktop`
  explicitly selects the experimental entry. Unknown values fail.
- Use one `useDashboardController` per mounted entry. Inject desktop views into
  the shared workspace without importing them into the standard dependency path.
  Navigation and selection use callbacks, not DOM mutation observers.
- Memoize the API client by base URL and token. Unrelated stream renders must
  not restart polling effects depending on the API object's identity.
- Confine fixtures to the documentation context. Production entrypoints do not
  activate fixture data through query parameters or compatibility globals.
- Keep experiments separate from the installed app and its databases.

## Validation

Unit contracts cover default-page selection, in-place packet selection, stable
API identity and authentication/cancellation. Browser fixtures exercise desktop
and mobile navigation, packet selection, investigation, Auto-follow and Fleet.
Isolated Electron smoke checks backend startup, sandbox, context isolation,
preload bridge and acknowledged shutdown for each entry.

The Electron smoke window is hidden and uses DOM event dispatch for navigation;
browser fixtures separately test pointer actionability and capture synthetic
screenshots. Smoke profiles are temporary and capture is not started. These
tests do not demonstrate driver losslessness or multi-hour stability.

## Limits And Promotion Gate

The installed overlay is unchanged. This migration does not certify parity with
every later binary-only patch. Advanced workspace panels remain accessible,
including folded extended agent telemetry. Alert calibration, complete error-state
parity and migrated component polling still need targeted validation.

Promotion requires a separately staged package, real capture, VPN handover,
filtered history/Auto-follow checks and a bounded long soak with disk-growth
limits. Rust is not introduced by this change.
