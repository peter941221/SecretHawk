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

## Policy / Baseline

```bash
./secrethawk.exe policy init
./secrethawk.exe policy check
./secrethawk.exe policy test
./secrethawk.exe baseline create --input findings.json
```
