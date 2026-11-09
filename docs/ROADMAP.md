# Roadmap

This is an engineering sequence, not a date commitment or a list of completed work.

| Stage | Remaining work | Acceptance gate |
| --- | --- | --- |
| Source/build ownership | Integrate preserved desktop components; retire compiled-bundle patches | Clean checkout reproduces the intended UI/backend without installed files |
| Capture contract | Version batch schema, sequencing, handover, cancellation and final counters | Replay parity and route-change tests preserve counts/order and expose errors |
| Durable acknowledgement | Specify journal reclaim versus committed history and crash recovery | Forced-crash/restart tests establish exactly which records are durable |
| Long-lived state | Archive active/catalog state without breaking IDs, selection or history queries | Bounded-memory validation across a representative long run |
| Detection quality | Label benign/hostile fixtures, calibrate rate/scan/ML/correlation rules | Measured false positives and misses; severity justified by evidence |
| Destination evidence | Improve scoped DNS/SNI/Host correlation, expiry and ambiguity presentation | No invented domain identity; encrypted/unknown cases remain explicit |
| Runtime qualification | Route changes, sustained authorized traffic, interrupted delivery and disk pressure | Continuous soak with known sampling/driver coverage and no unexplained gaps |
| Native optimization | Profile and consider a Rust batch/state module where justified | Reference parity, fewer boundary copies, measured benefit and safe fallback |
| Release | Cross-platform CI, Windows packaged probes and reviewed screenshots/docs | Versioned candidate, reproducible artifacts, checksums and documented remaining limits |

Do not replace these gates with a lower test threshold, hidden drops, dismissed
advisories, stale screenshots or an unsupported claim that all work is complete.
