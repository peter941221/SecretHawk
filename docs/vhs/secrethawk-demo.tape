Output docs/assets/demo-vhs.gif
Set Shell "pwsh"
Set FontSize 18
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set TypingSpeed 0ms

Type "go build ./cmd/secrethawk"
Enter
Sleep 200ms

Type '$k="AKIA"+"A1B2C3D4E5F6G7H8"'
Enter
Sleep 200ms

Type 'Set-Content -Encoding utf8 docs/vhs/demo-src/app.py "AWS_ACCESS_KEY_ID = `"$k`""'
Enter
Sleep 200ms

Type 'Add-Content -Encoding utf8 docs/vhs/demo-src/app.py "SERVICE_URL = `"https://example.internal`""'
Enter
Sleep 200ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format human"
Enter
Sleep 500ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format json --output docs/vhs/findings.json"
Enter
Sleep 300ms

Type "./secrethawk.exe remediate --input docs/vhs/findings.json --auto --dry-run"
Enter
Sleep 300ms

Type "./secrethawk.exe report --input docs/vhs/findings.json --output docs/vhs/incident.md"
Enter
Sleep 500ms
