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
- Phase 4 completed: added SARIF/output regression tests, scan fail-on command test, GitHub secret-scan workflow, and pre-commit hook config.
- Final regression run includes go test/build/help/policy test/connector list plus scan->report smoke path.
- Repository now supports phased development flow with stage-wise push history.
- Enhanced built-in rule coverage to include AWS secret key, GitHub PAT/OAuth tokens, Slack token/webhook, Stripe API key, and private key header.
- Added Slack/Stripe connectors to registry as manual-guidance connectors and aligned connector-rule mapping.
- Hardened patch engine to skip generic entropy findings and non-code files, plus target-scoped `.env.example` generation.
- Added regression tests for built-in rule catalog and patch file-scope safety.
- Completed competitor research (GitHub Secret Protection, GitGuardian, TruffleHog, Gitleaks, detect-secrets) and documented opportunity map in `COMPETITOR_RESEARCH_2026Q1.md`.
- Defined 90-day reinforcement roadmap focused on verification intelligence, remediation automation, and governance.
- Updated repository hygiene: added `技术文档.md` and `COMPETITOR_RESEARCH_2026Q1.md` to `.gitignore` and removed both from Git tracking while keeping local copies.
- Implemented `scan --fail-on-active` to gate CI on validated ACTIVE findings only (auto-enables validation).
- Added confidence refinement in scan pipeline and displayed confidence+status in human output.
- Updated CI workflow to use `--validate --fail-on-active` and added regression tests for new scan behavior.
- Implemented real AWS connector flow: STS-based validation, IAM revoke, IAM rotate with rollback-on-failure.
- Added robust AWS connector unit tests using fake STS/IAM clients (no cloud credentials required).
- Integrated AWS SDK v2 dependencies and verified connector preflight behavior when credentials are missing.
