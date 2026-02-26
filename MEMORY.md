# MEMORY

## 2026-02-26

- Initialized independent Git repository at `SecretHawk/.git`.
- Bootstrapped Go project skeleton for SecretHawk CLI.
- Added initial project operation docs (`README.md`, `RUNBOOK.md`) and seed configuration files.
- Added CI bootstrap (`.github/workflows/go-ci.yml`) with go test/build gates.
- Added `Makefile` for local developer workflow shortcuts.
- Added Cobra-based CLI command tree scaffolding aligned with PRD command spec.
- Seeded baseline project assets: `.secrethawk/policy.yaml`, `rules/aws.yaml`, `schemas/finding-v1.schema.json`.
- Added initial unit tests for command tree + scan default flags.
- Phase 1 completed: implemented scan engine with rule loading, policy allowlist, baseline suppression, severity threshold, fail-on exit logic, and human/json/sarif output.
- Added unit tests for scan detection, allowlist, baseline suppression, and fail-on behavior.
- Added severity utilities, baseline helpers, and output formatter package.
