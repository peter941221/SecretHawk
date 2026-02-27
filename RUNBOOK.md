# RUNBOOK

## Test

```bash
go test ./...
```

## Build

```bash
go build ./cmd/secrethawk
```

## Core workflows

```bash
# Scan
./secrethawk.exe scan . --format human --fail-on high
./secrethawk.exe scan . --validate --fail-on high --fail-on-active

# Validate a token directly
./secrethawk.exe validate --connector github --secret <token>

# Patch secrets into env references
./secrethawk.exe patch --target . --replace-with env

# Remediate automatically
./secrethawk.exe remediate --auto

# Generate incident report from findings
./secrethawk.exe report --input findings.json
```

## Growth workflow (Human-in-the-Loop)

```bash
# 1) Initialize editable campaign brief
./secrethawk.exe growth init --path .secrethawk/growth/campaign.yaml

# 2) Generate draft queue from brief
./secrethawk.exe growth plan --brief .secrethawk/growth/campaign.yaml --output .secrethawk/growth/queue.json

# 3) Approve one item for publishing
./secrethawk.exe growth approve --queue .secrethawk/growth/queue.json --id x-01 --approver peter

# 4) Export approved publish cards (manual posting material)
./secrethawk.exe growth export --queue .secrethawk/growth/queue.json --out-dir .secrethawk/growth/out
```

## Policy / Baseline

```bash
./secrethawk.exe policy init
./secrethawk.exe policy check
./secrethawk.exe policy test
./secrethawk.exe baseline create --input findings.json
```
