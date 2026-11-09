# Screenshot Provenance

The README images are browser screenshots of the actual preserved components in
`frontend/desktop-reference/`, rendered by `docs-preview.jsx` with synthetic
fixtures. They are component previews, not screenshots of a production-certified
release or proof that the standard frontend build includes the overlay.
The surrounding layout in `docs-shell.css` is a preview-only host, not a capture
of the installed desktop shell.

Only documentation IP ranges, example.net, invented hosts/agents and synthetic
alerts are used. The simulation is visible in the top bar. No live backend is
queried and the capture script blocks external browser requests. It does not
inspect browser history, accounts or user traffic.

## Regenerate

Install dependencies in `frontend/` and `frontend/desktop-reference/`. Then:

```shell
cd frontend/desktop-reference
npx playwright install chromium
node capture-docs.mjs
```

An existing compatible Chromium can be selected with `NETBOT_CHROME_PATH`.
The script starts a temporary loopback-only preview server, captures four
1672x941 views into `docs/assets/`, and closes browser/server in a finally block.
Generated JavaScript/CSS stays under ignored `.runtime/docs-preview/`.

Review all images before committing. Do not substitute a live desktop screenshot
containing private addresses, domains, process paths, tokens or personal accounts.
The license text is legal content and is not rewritten as part of visual refresh.
