# Standard Frontend Live-Follow Continuity

Source validation checkpoint: 2026-11-12. This document describes the standard
frontend, not the historical installed desktop overlay.

## Corrected Behavior

Previously Resume only set a boolean. From an older history page it left nonzero
offsets in place, so subsequent live batches were still ignored. It also claimed
live follow without fetching fresh history or detecting refresh failure. The table
buttons directly used the state setter instead of the controller's follow action.

Resume now fetches fresh packet and alert page zero with current filters preserved,
bypasses the short history cache, and enables follow only after both complete.
The explicit toggle action is wired to both packet and alert controls. Browsing an
older alert page now freezes follow consistently with packet pagination.

One shared AbortController and a request generation own each resynchronization.
Pause, reset, auth change, new filter/focus/history-paging actions, superseding Resume
and unmount cancel the pending generation. Late responses cannot overwrite the
newer view. A failed sibling cancels the other request and releases loading state.
A bounded eight-second refresh timeout leaves the view paused with an error and
allows retry. No capture is stopped, raw payload enabled or filter silently cleared
by these actions. Pausing row updates does not pause capture or traffic counters.

## Repeatable Checks

```powershell
cd frontend
npm run test:ui
npm run build
cd desktop-reference
node test-standard-live-follow.mjs
```

The browser check uses the standard `frontend/dist` build and the existing
Playwright dependency in `desktop-reference`; it does not build/use the preserved
overlay. It requires preinstalled Chrome (or `NETBOT_CHROME_PATH`), runs headless
with an isolated browser context, serves assets on an ephemeral loopback port,
fulfills synthetic API traffic and replaces WebSocket input with fixture messages.
Non-fixture network requests are blocked. Browser and HTTP server close afterward;
no screenshots, browsing history or traffic reports are retained by the check.

Controller regression tests cover paused rows/counters, resume from older filtered
pages, fresh cache bypass, failure, stalled siblings, late responses after Pause,
capture reset and bounded timeout/retry. The browser check passed at 1440x1000 and
390x844 with no page errors, exercising actual controls and table rows for old-page
Resume, stable Pause and failed Resume staying paused. It waits for displayed row
and counter changes rather than assuming a click completed asynchronous loading.

## Remaining Acceptance

Fixtures do not measure real backend latency or prove end-to-end live coverage.
No installed UI update, physical VPN change or multi-hour soak was performed.
The preserved overlay still needs a reproducible canonical build migration before
these standard-controller fixes can be claimed for that installed UI. Other detail
requests and histories have their existing contracts; this is not global API
timeout hardening or an exactly-once live-stream guarantee.
