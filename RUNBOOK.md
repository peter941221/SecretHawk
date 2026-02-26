# RUNBOOK

## Build

```bash
go build ./cmd/secrethawk
```

## Test

```bash
go test ./...
```

## Run

```bash
go run ./cmd/secrethawk --help
go run ./cmd/secrethawk scan --help
```

## Local policy bootstrap

```bash
go run ./cmd/secrethawk policy init
```
