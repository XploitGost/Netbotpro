# Validation And Measurement

## Different Evidence Answers Different Questions

Unit/replay tests verify covered contracts. Dependency audits report known
advisories at audit time. Packaged probes verify bundled dependencies and startup.
Screenshots verify a rendered state. A continuous real-traffic soak is a separate
gate; none of these replaces the others.

Run the standard suite and frontend/Electron tests listed in the root README.
Run npm audit against all three lockfiles, and audit the pinned Python files:

```shell
python -m pip install pip-audit==2.10.1
python -m pip_audit --no-deps --disable-pip --strict -r requirements-dev.txt
npm audit --prefix frontend --package-lock-only --audit-level=low
npm audit --prefix frontend/desktop-reference --package-lock-only --audit-level=low
npm audit --prefix desktop/electron --package-lock-only --audit-level=low
```

The Python command audits explicit pins, not an unrecorded transitive dependency.
`pip check` and a fresh environment must validate resolution. Unknown future
advisories can invalidate a previously clean audit. Do not dismiss an advisory
solely to turn CI green.

## CPU Units And The Windows CI Failure

`psutil.Process.cpu_percent()` uses one logical CPU as 100%; a threaded process
can legitimately report more than 100%. The previous Windows smoke used a raw
144% average against a 100% threshold, confusing per-core usage with machine share.

Raw resource measurements remain unchanged. The long-soak runner now accepts
`--cpu-budget-basis available-cpus` to divide validation values by available CPU
affinity, falling back to the system logical CPU count (or 1 if unknown). The
default remains `one-core` for compatibility. JSON records the chosen basis,
divisor and evaluated average/peak. Pipeline failures still fail validation.
Sub-50ms trailing intervals are not treated as CPU samples; they remain blank in
the time series rather than becoming fabricated zero values or huge spikes.
Validation rejects a run with no usable CPU samples.

The CI structural smoke uses a 100% average capacity budget and 200% short-interval
peak budget. The peak tolerance is for sampling variability, not a production
capacity assertion. Run isolated longer benchmarks for performance conclusions;
shared CI runners and short intervals are unsuitable for throughput certification.
Older raw resource pressure hints remain per-core indicators.

## Packaged Runtime

Build from the reviewed source and dependency set. Verify backend smoke plus
`--ml-runtime-probe` and `--export-runtime-probe` on the packaged executable.
ML must actually train; an optional-import fallback is not a successful ML probe.
Exports must produce valid nonempty artifacts, including the empty-session case.

## Long-Run Gate

Record capture/analysis counters, driver-stat coverage, raw and journal backlog,
history progress, errors, memory and sampling continuity. Treat ring/view eviction
separately from capture loss. Any unexplained gap invalidates continuous-window
qualification. No complete production stability certification is claimed here.

The recorder keeps historical errors sticky in the run assessment while allowing
a later clean window to accumulate from error-counter deltas. A new increment,
counter reset, missing previously observed metric, backlog, session change or
sampling gap interrupts that window. Recovering a window never erases cumulative
driver drops or certifies the entire earlier run as healthy.
