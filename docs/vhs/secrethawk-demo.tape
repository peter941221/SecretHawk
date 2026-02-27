Output docs/assets/demo-vhs-v3.gif
Set Shell "pwsh"
Set FontSize 18
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set TypingSpeed 8ms

Type 'Write-Host "字幕 0/6：演示从检测到报告的闭环" -ForegroundColor Yellow'
Enter
Sleep 1000ms

Type 'Write-Host "字幕 1/6：先编译 CLI，确保后续命令可执行" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "go build ./cmd/secrethawk"
Enter
Sleep 1200ms

Type 'Write-Host "字幕 2/6：写入演示密钥，模拟泄漏场景" -ForegroundColor Cyan'
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

Type 'Write-Host "字幕 3/6：执行扫描，预期看到 CRITICAL 命中" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format human"
Enter
Sleep 1800ms

Type 'Write-Host "字幕 4/6：导出 findings.json 给修复流程" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe scan docs/vhs/demo-src --format json --output docs/vhs/findings.json"
Enter
Sleep 1100ms

Type 'Write-Host "字幕 5/6：自动修复 dry-run（不改代码）" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe remediate --input docs/vhs/findings.json --auto --dry-run"
Enter
Sleep 1800ms

Type 'Write-Host "字幕 6/6：生成 incident report 便于复盘" -ForegroundColor Cyan'
Enter
Sleep 800ms

Type "./secrethawk.exe report --input docs/vhs/findings.json --output docs/vhs/incident.md"
Enter
Sleep 1800ms

Type 'Write-Host "完成：你看到的是 Detect -> Remediate(dry-run) -> Report 闭环" -ForegroundColor Green'
Enter
Sleep 1800ms
