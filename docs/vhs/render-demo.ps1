$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Push-Location $repoRoot

try {
    $seedApp = @'
# Seed content only; vhs tape will overwrite this file with demo secret text at runtime.
SERVICE_URL = "https://example.internal"
'@
    $subtitleStyle = "Alignment=2,FontName=Arial,FontSize=26,Outline=2,Shadow=0,MarginV=28,PrimaryColour=&H00FFFFFF,OutlineColour=&H00000000,BorderStyle=3,BackColour=&H78000000"

    Write-Host "1/4 Render base GIF with vhs..."
    vhs docs/vhs/secrethawk-demo.tape

    Write-Host "2/4 Overlay movie-style subtitles (bottom center) + optimize GIF..."
    ffmpeg -y -i docs/assets/demo-vhs-base.gif -vf "subtitles=docs/vhs/demo-vhs-v6.srt:force_style='$subtitleStyle',fps=25,scale=1200:-1:flags=lanczos,palettegen=stats_mode=single" -frames:v 1 -update 1 docs/assets/demo-vhs-v6-palette.png
    ffmpeg -y -i docs/assets/demo-vhs-base.gif -i docs/assets/demo-vhs-v6-palette.png -lavfi "[0:v]subtitles=docs/vhs/demo-vhs-v6.srt:force_style='$subtitleStyle',fps=25,scale=1200:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=sierra2_4a" docs/assets/demo-vhs-v6.gif

    Write-Host "3/4 Reset demo source to seed content..."
    Set-Content -Encoding utf8 docs/vhs/demo-src/app.py $seedApp

    Write-Host "4/4 Clean generated artifacts..."
    Remove-Item docs/vhs/findings.json -ErrorAction SilentlyContinue
    Remove-Item docs/vhs/incident.md -ErrorAction SilentlyContinue
    Remove-Item docs/assets/demo-vhs-base.gif -ErrorAction SilentlyContinue
    Remove-Item docs/assets/demo-vhs-v6-palette.png -ErrorAction SilentlyContinue

    Write-Host "Done: docs/assets/demo-vhs-v6.gif"
}
finally {
    Pop-Location
}
