Output docs/assets/demo-vhs-v5.gif
Set Shell "pwsh"
Set FontSize 18
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set TypingSpeed 8ms

Type 'Write-Host "[SUBTITLE] A leaked key just slipped into the repo." -ForegroundColor Yellow'
Enter
Sleep 1000ms

Type 'Write-Host "[SUBTITLE] First, we build SecretHawk." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "go build ./cmd/secrethawk"
Enter
Sleep 1200ms

Type 'Write-Host "[SUBTITLE] Next, we recreate the mistake on purpose." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type '$k="AKIA"+"A1B2C3D4E5F6G7H8"'
Enter
Sleep 500ms

Type 'Set-Content -Encoding utf8 docs/vhs/demo-src/app.py "AWS_ACCESS_KEY_ID = `"$k`""'
Enter
Sleep 500ms

Type 'Add-Content -Encoding utf8 docs/vhs/demo-src/app.py "SERVICE_URL = `"https://example.internal`""'
Enter
Sleep 900ms

Type 'Write-Host "[SUBTITLE] Scan the code. We expect one CRITICAL hit." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format human"
Enter
Sleep 1800ms

Type 'Write-Host "[SUBTITLE] Save findings to JSON for the next step." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format json --output docs/vhs/findings.json"
Enter
Sleep 1100ms

Type 'Write-Host "[SUBTITLE] Dry-run remediation. See the plan, change nothing." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe remediate --input docs/vhs/findings.json --auto --dry-run"
Enter
Sleep 1800ms

Type 'Write-Host "[SUBTITLE] Finally, generate the incident report." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe report --input docs/vhs/findings.json --output docs/vhs/incident.md"
Enter
Sleep 1800ms

Type 'Write-Host "[SUBTITLE] Done. Detect -> Remediate -> Report, end to end." -ForegroundColor Green'
Enter
Sleep 1800ms
