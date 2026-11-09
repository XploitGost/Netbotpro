# Repository Maintenance

## Source and Release Discipline

The `main` branch is the development integration branch, not a declaration that
every commit is production-ready. Release tags must follow the packaging and
runtime validation checklist. Do not create a release to publish an unvalidated
desktop overlay. Source migration limitations are recorded in
[ARCHITECTURE_BOUNDARIES.md](ARCHITECTURE_BOUNDARIES.md).

Use focused branches and pull requests for subsequent changes. The repository
contains a bug-report form and a pull-request checklist. Do not place private
packet data, user browsing information, tokens or installed binaries in either.

## Local Git Policy

The maintained working copy uses fast-forward-only pulls, simple pushes,
automatic pruning of removed remote branch references (not local branches or
tags), and readable three-way conflict markers. These are repository-local Git
settings, not global machine policy. A new clone does not inherit them:

```shell
git config --local pull.ff only
git config --local push.default simple
git config --local fetch.prune true
git config --local fetch.pruneTags false
git config --local merge.conflictStyle zdiff3
```

`.gitattributes` defines source line endings, including native C and Electron
modules; `.editorconfig` guides editors. Existing files are not mass-reformatted.

## GitHub Controls

As configured on 2026-11-09, `main` disallows force pushes and deletion, including
for administrators. Conversation resolution is required for pull requests.
After the security/docs checkpoint passes remote CI, changes to `main` require
a pull request and successful hygiene, dependency, backend, frontend and Windows
desktop checks against an up-to-date base. No second-person approval is required
for this single-maintainer project. Repository settings are remote state, not
installed by cloning; confirm the actual branch protection before assuming it.

Secret scanning and push protection are enabled. Dependency vulnerability alerts
and private vulnerability reporting are enabled. Security-update PRs
are enabled. Dependabot checks Actions, Python and npm
dependencies weekly with bounded open PR counts. No auto-merge is configured.
Merged feature branches are deleted automatically; existing branches and tags
are not deleted by this maintenance work.

## CI and Artifact Limits

### Dependency Remediation Checkpoint

The reviewed requirements and all three npm lockfiles were upgraded and audited
with no known advisories reported at the checkpoint. This includes Pillow,
Electron, HTTP/multipart dependencies and certificate bundles, plus a targeted
minimatch override in the packaging graph. Fresh-environment tests and packaged
ML/export probes validate more than optional-import fallback. GitHub recomputes
its own alerts after a push; wait for that result rather than dismissing alerts.
Clean audits are time-bounded evidence, not proof of absence of vulnerabilities.
These source changes do not silently replace an older installed application.

### Workflow Policy

CI uses read-only repository permissions, bounded job timeouts and cancellation
of superseded runs on the same ref. It checks tracked source hygiene, Python,
frontend/model tests, builds and Windows desktop smoke. Release packaging has
read-only permissions; only publishing jobs receive contents-write permission.
Release build artifacts expire after 14 days. Published release assets are not
deleted by artifact retention. A tag or explicit publish request is still needed
to publish a release.

Run before committing:

```shell
python scripts/qa/repository_hygiene.py --staged
git diff --cached --check
```

The hygiene guard is deliberately limited: it catches known credential formats,
private-key headers, selected runtime artifacts and oversized source files.
It is not a complete secret detector and does not replace GitHub scanning or
human review. It does not scan ignored local databases or history by default.

Use `git revert` for a published regression. If a real credential is ever exposed,
revoke or rotate it first; removing it in a later commit does not remove history.
