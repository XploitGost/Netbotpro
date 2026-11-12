# Desktop contracts and documentation harness

Canonical components and models now live in `../src/desktop/`. Matching files
here re-export that source for model contracts and documentation tools; they
are not a second implementation.

From the parent frontend directory, `npm ci` and `npm run build` build both
`app.html` (standard default) and `desktop.html` (experimental desktop UI).
`node desktop-reference/build.mjs` delegates to the same Vite build. The old
compiled-bundle patcher and historical-baseline requirement are retired.
No installed application is overwritten by these commands.

The Electron setting `NETBOT_DESKTOP_UI=desktop` explicitly chooses the new
entry. Unset or `standard` preserves `app.html`. Both share the real controller
and authenticated API. The desktop entry does not use the old DOM bridge or
documentation fixtures. See [ADR 0012](../../docs/adr/0012-source-built-desktop-entry.md).

Run model tests with `node --test *Model.test.mjs` here. After `npm ci` here,
`node test-source-desktop.mjs` checks the built desktop entry using synthetic
HTTP/WebSocket transport and headless Chrome. Four bounded synthetic screenshots
are written under `.runtime/source-desktop-check/`. The standard entry has its
own `test-standard-live-follow.mjs` regression script.

`test-electron-runtime.mjs` uses a temporary profile and isolated database paths.
CI supplies `NETBOT_SMOKE_BACKEND_DIR` for its freshly packaged backend. Local
source tests can instead set `NETBOT_SMOKE_PYTHON_BIN` to a Python executable
with repository requirements. This verifies startup, IPC isolation and normal
drain, not driver capture or long-soak stability.

`docs-preview.jsx`, `capture-docs.mjs` and `docs-shell.css` remain a synthetic,
preview-only documentation harness. See `../../docs/SCREENSHOTS.md`.
