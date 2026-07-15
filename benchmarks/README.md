# Performance Benchmarks

This directory validates NetBotPro's bounded performance pipeline with local,
synthetic packet summaries. The tools do not capture traffic, open network
connections, require Administrator privileges, or store raw payloads.

## Quick smoke test

```powershell
python benchmarks/soak_test_pipeline.py `
  --duration-sec 10 `
  --events-per-sec 200 `
  --flows 20 `
  --ci-safe `
  --output .runtime/benchmarks/smoke
```

The command writes:

- `benchmark_results.json`: structured configuration, resource, stage, and
  operational-health metrics.
- `benchmark_summary.md`: a compact human-readable interpretation.

Both outputs pass through central redaction before they are written.

## Stage benchmarks

Run a focused benchmark with the same common CLI options:

```powershell
python benchmarks/benchmark_packet_pipeline.py --duration-sec 10 --events-per-sec 500
python benchmarks/benchmark_worker_pool.py --duration-sec 10 --events-per-sec 500 --flows 50
python benchmarks/benchmark_websocket_aggregator.py --duration-sec 10 --events-per-sec 500
python benchmarks/benchmark_batch_persistence.py --duration-sec 10 --events-per-sec 500
python benchmarks/benchmark_live_ring_buffer.py --duration-sec 10 --events-per-sec 500
```

Available options include `--duration-sec`, `--events-per-sec`, `--flows`,
`--packet-rate`, `--alert-rate`, `--output`, `--json`, `--markdown`,
`--profile`, `--no-live-capture`, and `--ci-safe`. The `ci-safe` profile caps
duration and event rate. Live capture remains disabled regardless of profile.

## Longer local soak

The local profile defaults to five minutes when duration is omitted:

```powershell
python benchmarks/soak_test_pipeline.py --profile local --events-per-sec 1000 --flows 100
```

Results are machine-dependent. They validate bounded behavior, observable
drops, ordering, report generation, and resource trends; they are not a
production capacity guarantee. Use authorized workload traces separately when
sizing a deployment.
