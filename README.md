# SecretHawk

[![Go CI](https://github.com/peter941221/SecretHawk/actions/workflows/go-ci.yml/badge.svg)](https://github.com/peter941221/SecretHawk/actions/workflows/go-ci.yml)
[![Secret Scan](https://github.com/peter941221/SecretHawk/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/peter941221/SecretHawk/actions/workflows/secret-scan.yml)
[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> A practical CLI for secret incidents: find it, verify it, clean it up, report it.

## Why Teams Care

Most tools stop at: "we found something."
SecretHawk continues to: "here is how we close the incident."

```text
[Detect leak] -> [Validate if active] -> [Plan remediation] -> [Generate incident report]
```

For small teams, this means fewer noisy blocks and faster real closure.

## 10-Second Tour

- Watch the terminal demo: [Demo GIF](https://raw.githubusercontent.com/peter941221/SecretHawk/main/docs/assets/demo-vhs-v6.gif)
- Run it in one minute: see `Start In 60 Seconds` below
- Explore capabilities: jump to `Command Map`

## Scanner vs SecretHawk

| Typical secret scanner | SecretHawk |
| --- | --- |
| Finds leaked patterns | Finds + validates + drives response |
| Leaves remediation as manual work | Supports dry-run and auto remediation flow |
| Limited incident trace | Generates report artifacts for incident trail |
| Easy to create alert fatigue | Supports practical CI gates (`--fail-on-active`) |

## Demo (Movie-Style Subtitles)

![SecretHawk vhs headless demo](https://raw.githubusercontent.com/peter941221/SecretHawk/main/docs/assets/demo-vhs-v6.gif)

Regenerate demo GIF:

```bash
pwsh docs/vhs/render-demo.ps1
```

Demo flow:

```text
[vhs + ttyd]
    |
    v
[render base terminal gif]
    |
    v
[ffmpeg subtitle overlay + palette optimize]
    |
    v
[movie-style gif in docs/assets]
```

## Start In 60 Seconds

```bash
go build ./cmd/secrethawk
./secrethawk.exe scan . --validate --fail-on high --fail-on-active
./secrethawk.exe remediate --auto
```

## What Happens In A Real Incident

```text
Scene 1: Secret gets committed by mistake
Scene 2: scan finds it and rates severity
Scene 3: validate clarifies risk state
Scene 4: remediate prepares rotate/revoke + patch actions
Scene 5: report creates a traceable incident record
```

## Why Teams Use SecretHawk

- Fewer false-positive disruptions in CI (`--fail-on-active`).
- End-to-end flow, not detection-only.
- Local-first CLI with JSON/SARIF output.
- Built for practical adoption, not heavyweight setup.

## Command Map

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
├── growth
│   ├── init
│   ├── plan
│   ├── approve
│   └── export
└── version
```

## Connectors

- `aws`: validate + revoke + rotate (with rollback guard).
- `github`: token validate + revoke (with app-api fallback path).
- `slack`: manual-guidance connector.
- `stripe`: manual-guidance connector.

## CI Integration

- Go CI: `.github/workflows/go-ci.yml`
- Secret scan gate: `.github/workflows/secret-scan.yml`
- Pre-commit sample: `.pre-commit-config.yaml`

## Growth Workflow (Optional)

```bash
./secrethawk.exe growth init --path .secrethawk/growth/campaign.yaml
./secrethawk.exe growth plan --brief .secrethawk/growth/campaign.yaml --output .secrethawk/growth/queue.json
./secrethawk.exe growth approve --queue .secrethawk/growth/queue.json --id x-01 --approver you
./secrethawk.exe growth export --queue .secrethawk/growth/queue.json --out-dir .secrethawk/growth/out
```

This stays human-in-the-loop by design for platform-policy safety.

## About

Project narrative and public-facing copy:

- [ABOUT.md](ABOUT.md)

## License

MIT. See [LICENSE](LICENSE).
