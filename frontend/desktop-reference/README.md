# Desktop UI source checkpoint

This directory preserves the authored Command Center, Live Monitor, Investigate,
Fleet, navigation, styles and pure model tests used by the desktop UI work.
It is not yet the canonical frontend entry point. The normal React application
and its build remain in the parent directory.

Run the model tests with `node --test *Model.test.mjs` from this directory.
Dependencies can be installed with `npm ci`.

## Transitional build limitation

`build.mjs` is a historical compatibility overlay: it patches named boundaries
inside a specific prebuilt desktop JavaScript bundle, including
`assets/index-B8rp-3mx.js`. It requires the matching baseline, not an arbitrary
new build of the parent frontend. Supply that baseline through
`NETBOT_DESKTOP_FRONTEND` on first build; the script copies it to `.baseline`.
Generated files and the baseline are intentionally not committed. Do not treat
this as a clean-checkout release build or install its output automatically.
Later installed UI patches are not all represented by this original build script.

The architecture migration must move these components into the normal source
entry point and replace compiled-bundle edits with explicit props, controller
contracts and tests. Publishing this checkpoint does not complete that migration.
