# SecretHawk

SecretHawk is a Go CLI focused on the full lifecycle of secret incidents: detect, validate, patch, baseline, and report.

## Implemented command map

```text
secrethawk
├── scan          # scan filesystem / staged / since / all-history + human/json/sarif
├── validate      # validate secrets via connector (direct secret / findings file)
├── remediate     # guided or auto remediation workflow
├── patch         # replace hardcoded secrets with env/placeholder/secretmanager refs
├── history-clean # guarded git history cleanup workflow
├── report        # incident markdown report generator
├── policy
│   ├── init
│   ├── check
│   └── test
├── connector
│   ├── list
│   ├── test
│   └── rotate
├── baseline
│   ├── create
│   └── update
├── growth
│   ├── init     # initialize campaign brief template
│   ├── plan     # generate cross-channel draft queue with UTM links
│   ├── approve  # human approval gate for one queue item
│   └── export   # export approved publish cards for manual posting
└── version
```

## Quick start

```bash
go test ./...
go build ./cmd/secrethawk
./secrethawk.exe scan . --format human
./secrethawk.exe scan . --validate --fail-on high --fail-on-active
./secrethawk.exe growth init
./secrethawk.exe growth plan --brief .secrethawk/growth/campaign.yaml
```

## CI / Hook

- GitHub Action: `.github/workflows/secret-scan.yml`
- Pre-commit sample: `.pre-commit-config.yaml`

## Notes

- Connectors currently include `aws` and `github` with preflight + validation helpers.
- `scan --validate` uses connector mapping when rule/connector are known.
- `history-clean` enforces clean working tree and backup branch safeguards.
- `growth` is a Human-in-the-Loop growth workflow (draft -> approve -> export) and intentionally avoids direct autonomous posting to reduce policy/compliance risk.
