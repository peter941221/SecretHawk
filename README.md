# SecretHawk

SecretHawk is a Go CLI focused on secret remediation, not just secret detection.

## Current status

- Project scaffold initialized from PRD v0.1
- Command tree stubbed and ready for feature development
- Seed policy/rule/schema files added for local iteration

## Command tree (MVP skeleton)

```text
secrethawk
├── scan
├── validate
├── remediate
├── patch
├── history-clean
├── report
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
└── version
```

## Quick start

```bash
go test ./...
go build ./cmd/secrethawk
./secrethawk.exe version
```

## Next milestone

- Implement `scan` engine and finding schema output (`json`, `human`)
- Add rule loader and policy parser
- Add baseline filtering path
