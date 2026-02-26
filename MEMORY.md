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
- Phase 2 completed: implemented policy check/test, baseline create/update, and report generation commands.
- Added command-level tests for policy flows, baseline creation from findings JSON, and incident report output.
- Strengthened rule test cases in rules/aws.yaml to ensure policy test stability.
- Phase 3 completed: implemented connector registry (AWS/GitHub), validate command, patch engine, remediate auto/dry-run flow, and history-clean safeguards.
- Added phase-3 command tests covering connector listing, validation argument guard, patch dry-run, remediate dry-run, and dirty-repo protection for history-clean.
- Scan --validate now uses connector mapping when possible.
