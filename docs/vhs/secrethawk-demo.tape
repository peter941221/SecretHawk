Output docs/assets/demo-vhs-v4.gif
Set Shell "pwsh"
Set FontSize 18
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set TypingSpeed 8ms

Type 'Write-Host "Caption 0/6: We are about to run the full secret-response flow." -ForegroundColor Yellow'
Enter
Sleep 1000ms

Type 'Write-Host "Caption 1/6: First, build the CLI so every command below can run." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "go build ./cmd/secrethawk"
Enter
Sleep 1200ms

Type 'Write-Host "Caption 2/6: Now we add a fake leaked key to simulate a real mistake." -ForegroundColor Cyan'
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

Type 'Write-Host "Caption 3/6: Run scan. You should see one CRITICAL secret finding." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format human"
Enter
Sleep 1800ms

Type 'Write-Host "Caption 4/6: Export findings to JSON so remediation can use it." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format json --output docs/vhs/findings.json"
Enter
Sleep 1100ms

Type 'Write-Host "Caption 5/6: Run remediation in dry-run mode. No files are changed." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe remediate --input docs/vhs/findings.json --auto --dry-run"
Enter
Sleep 1800ms

Type 'Write-Host "Caption 6/6: Generate an incident report for tracking and follow-up." -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe report --input docs/vhs/findings.json --output docs/vhs/incident.md"
Enter
Sleep 1800ms

Type 'Write-Host "Done: Detect -> Remediate (dry-run) -> Report in one repeatable flow." -ForegroundColor Green'
Enter
Sleep 1800ms
