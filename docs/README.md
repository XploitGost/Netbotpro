# Documentation Index

Current development documentation, reviewed 2026-11-09. Historical release notes
describe their own release, not the current branch or installed desktop overlay.

## Start Here

- [Project overview](../README.md) and [Persian overview](../README.fa.md)
- [Install and run](INSTALL.md)
- [Contributing](../CONTRIBUTING.md), [security policy](../SECURITY.md), [MIT license](../LICENSE)

## Design And Evidence

- [Current architecture](ARCHITECTURE.md)
- [Target boundaries](ARCHITECTURE_BOUNDARIES.md)
- [ADR 0001: analysis-to-delivery handoff](adr/0001-packet-analysis-delivery-boundary.md)
- [ADR 0002: journal batch acknowledgement](adr/0002-journal-batch-acknowledgement.md)
- [ADR 0003: persistence flush results](adr/0003-persistence-flush-receipts.md)
- [ADR 0004: partial persistence retry](adr/0004-partial-persistence-retry.md)
- [ADR 0005: stable journal packet identity](adr/0005-journal-packet-occurrence-identity.md)
- [ADR 0006: explicit history write outcomes](adr/0006-explicit-history-write-outcomes.md)
- [ADR 0007: tracked history-group receipts](adr/0007-tracked-history-group-receipts.md)
- [ADR 0008: versioned alert occurrence keys](adr/0008-versioned-alert-occurrence-keys.md)
- [ADR 0009: opt-in history-confirmed journal ack](adr/0009-opt-in-history-confirmed-journal-ack.md)
- [ADR 0010: retained-journal recovery lifecycle](adr/0010-retained-journal-recovery-lifecycle.md)
- [ADR 0011: validated capture-route confirmation](adr/0011-validated-capture-route-confirmation.md)
- [ADR 0012: source-built desktop entry](adr/0012-source-built-desktop-entry.md)
- [Roadmap and acceptance gates](ROADMAP.md)
- [Validation and CPU measurement](VALIDATION.md)
- [Isolated journal/history probe and local evidence](JOURNAL_HISTORY_PROBE.md)
- [Standard frontend live-follow continuity](LIVE_FOLLOW_VALIDATION.md)
- [Isolated Windows desktop candidate](DESKTOP_CANDIDATE.md)
- [Screenshot provenance](SCREENSHOTS.md)
- [Repository and GitHub maintenance](REPOSITORY_MAINTENANCE.md)

## Operations And Features

- [Deployment overview](DEPLOYMENT_OVERVIEW.md) and [Linux server](LINUX_SERVER_DEPLOYMENT.md)
- [Flow analysis](FLOW_ANALYSIS.md), [packet inspection](DEEP_PACKET_INSPECTION.md)
- [Destination evidence](SERVICE_ATTRIBUTION.md), [incident correlation](INCIDENT_CORRELATION.md)
- [Pipeline configuration](PERFORMANCE_PIPELINE.md)
- [Performance validation](PERFORMANCE_VALIDATION.md), [real-load tests](REAL_LOAD_TESTING.md)
- [Release checklist](RELEASE_CHECKLIST.md), [release QA](RELEASE_QA_CHECKLIST.md)
- [Historical v0.2.0 release notes](RELEASE_NOTES_v0.2.0.md)

The architecture and validation documents take precedence over older descriptions
of development readiness. Feature documents are not promises of universal network
visibility, automated attack confirmation or lossless capture on every driver.
