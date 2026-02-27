Output docs/assets/demo-vhs-v2.gif
Set Shell "pwsh"
Set FontSize 18
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Type 'Write-Host "STEP 1/5 - Build CLI" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "go build ./cmd/secrethawk"
Enter
Sleep 1200ms

Type 'Write-Host "STEP 2/5 - Seed demo leak into file" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type '$k="AKIA"+"A1B2C3D4E5F6G7H8"'
Enter
Sleep 600ms

Type 'Set-Content -Encoding utf8 docs/vhs/demo-src/app.py "AWS_ACCESS_KEY_ID = `"$k`""'
Enter
Sleep 600ms

Type 'Add-Content -Encoding utf8 docs/vhs/demo-src/app.py "SERVICE_URL = `"https://example.internal`""'
Enter
Sleep 1200ms

Type 'Write-Host "STEP 3/5 - Scan and detect secret" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format human"
Enter
Sleep 1800ms

Type 'Write-Host "STEP 4/5 - Export findings and run remediation dry-run" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format json --output docs/vhs/findings.json"
Enter
Sleep 1200ms

Type "./secrethawk.exe remediate --input docs/vhs/findings.json --auto --dry-run"
Enter
Sleep 1800ms

Type 'Write-Host "STEP 5/5 - Generate incident report" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe report --input docs/vhs/findings.json --output docs/vhs/incident.md"
Enter
Sleep 2000ms

Type 'Write-Host "DONE - End-to-end flow complete" -ForegroundColor Green'
Enter
Sleep 1500ms
