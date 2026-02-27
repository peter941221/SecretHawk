#!/usr/bin/env python3
"""Generate a terminal demo GIF from real SecretHawk outputs (replay style)."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

from PIL import Image, ImageDraw, ImageFont


WIDTH = 1100
HEIGHT = 620
PADDING = 24
LINE_HEIGHT = 28
FRAME_MS = 85
WRAP_WIDTH = 110
MAX_OUTPUT_LINES_PER_COMMAND = 8
CMD_TIMEOUT_SEC = 90

BG = (12, 17, 30)
PANEL = (19, 26, 43)
PANEL_BORDER = (61, 84, 123)
TEXT = (220, 233, 255)
MUTED = (128, 149, 186)
GREEN = (133, 225, 161)
YELLOW = (246, 209, 126)
RED = (255, 138, 128)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
USER_PATH_RE = re.compile(r"[A-Za-z]:[\\/](?:Users|home)[\\/][^\\/]+")


@dataclass
class Event:
    kind: str  # command | output | info
    text: str
    hold: int = 2


def load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\CascadiaMono.ttf",
        r"C:\Windows\Fonts\lucon.ttf",
    ]
    for path in candidates:
        p = Path(path)
        if p.exists():
            return ImageFont.truetype(str(p), size=size)
    return ImageFont.load_default()


def sanitize(text: str) -> str:
    text = ANSI_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip("\n")


def redact_paths(text: str, workspace: Path) -> str:
    # Hide local username/home path and transient temp directory details.
    redacted = text.replace(str(workspace), "%TEMP%/secrethawk-demo")
    redacted = redacted.replace(str(workspace).replace("\\", "/"), "%TEMP%/secrethawk-demo")
    redacted = USER_PATH_RE.sub("C:/Users/<user>", redacted.replace("\\", "/"))
    return redacted


def wrap_line(line: str, width: int = WRAP_WIDTH) -> List[str]:
    if len(line) <= width:
        return [line]
    chunks: list[str] = []
    current = line
    while len(current) > width:
        split = current.rfind(" ", 0, width)
        if split <= 0:
            split = width
        chunks.append(current[:split])
        current = current[split:].lstrip()
    if current:
        chunks.append(current)
    return chunks


def ensure_binary(repo_root: Path) -> Path:
    exe = repo_root / "secrethawk.exe"
    skip_build = os.getenv("SECRETHAWK_DEMO_SKIP_BUILD", "0") == "1"
    if not skip_build or not exe.exists():
        cmd = ["go", "build", "./cmd/secrethawk"]
        result = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"go build failed:\n{result.stdout}\n{result.stderr}")
    if not exe.exists():
        raise RuntimeError("secrethawk.exe not found after build")
    return exe


def create_demo_workspace(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    demo = root / "demo-src"
    demo.mkdir(parents=True, exist_ok=True)

    key_prefix = "AKIA"
    key_suffix = "A1B2C3D4E5F6G7H8"
    aws_key = key_prefix + key_suffix

    content = (
        '"""demo file for gif generation"""\n'
        f'AWS_ACCESS_KEY_ID = "{aws_key}"\n'
        "SERVICE_URL = \"https://example.internal\"\n"
    )
    (demo / "app.py").write_text(content, encoding="utf-8")
    return demo


def run(cmd: list[str], cwd: Path) -> tuple[int, str, float]:
    start = time.perf_counter()
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=CMD_TIMEOUT_SEC)
    elapsed = time.perf_counter() - start
    combined = (result.stdout or "") + (result.stderr or "")
    return result.returncode, sanitize(combined), elapsed


def build_events(exe: Path, workspace: Path) -> tuple[list[Event], str]:
    findings = workspace / "findings.json"
    report = workspace / "incident.md"

    commands = [
        (
            [str(exe), "scan", str(workspace / "demo-src"), "--format", "human", "--fail-on", "high"],
            ".\\secrethawk.exe scan %TEMP%\\secrethawk-demo\\demo-src --format human --fail-on high",
        ),
        (
            [str(exe), "scan", str(workspace / "demo-src"), "--format", "json", "--output", str(findings)],
            ".\\secrethawk.exe scan %TEMP%\\secrethawk-demo\\demo-src --format json --output %TEMP%\\secrethawk-demo\\findings.json",
        ),
        (
            [str(exe), "remediate", "--input", str(findings), "--auto", "--dry-run"],
            ".\\secrethawk.exe remediate --input %TEMP%\\secrethawk-demo\\findings.json --auto --dry-run",
        ),
        (
            [str(exe), "report", "--input", str(findings), "--output", str(report)],
            ".\\secrethawk.exe report --input %TEMP%\\secrethawk-demo\\findings.json --output %TEMP%\\secrethawk-demo\\incident.md",
        ),
    ]

    events: list[Event] = [Event("info", "SecretHawk demo: real command output replay", hold=8)]
    transcript: list[str] = []

    for cmd, display in commands:
        code, output, elapsed = run(cmd, cwd=exe.parent)
        output = redact_paths(output, workspace)
        transcript.append(f"$ {display}\n{output}\n[exit={code}] [duration={elapsed:.2f}s]\n")

        events.append(Event("command", f"PS C:\\repo\\SecretHawk> {display}", hold=2))
        events.append(Event("output", f"[duration: {elapsed:.2f}s]", hold=1))
        if not output.strip():
            output_lines = ["(no output)"]
        else:
            output_lines = []
            for line in output.splitlines():
                output_lines.extend(wrap_line(line))
        if len(output_lines) > MAX_OUTPUT_LINES_PER_COMMAND:
            output_lines = output_lines[:MAX_OUTPUT_LINES_PER_COMMAND] + ["... (truncated)"]
        for line in output_lines:
            events.append(Event("output", line, hold=1))
        if code != 0:
            events.append(Event("output", f"[exit code: {code}]", hold=2))

    events.append(Event("info", "Done. Replay rendered from real command outputs.", hold=10))
    return events, "\n".join(transcript)


def line_color(kind: str, text: str) -> tuple[int, int, int]:
    if kind == "command":
        return GREEN
    if "exit code" in text.lower():
        return RED
    if "error:" in text.lower():
        return RED
    if kind == "info":
        return YELLOW
    return TEXT


def render_frame(lines: List[tuple[str, str]], font: ImageFont.ImageFont) -> Image.Image:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    x0, y0 = 16, 16
    x1, y1 = WIDTH - 16, HEIGHT - 16
    draw.rounded_rectangle((x0, y0, x1, y1), radius=16, fill=PANEL, outline=PANEL_BORDER, width=2)

    draw.ellipse((36, 32, 48, 44), fill=(255, 95, 86))
    draw.ellipse((56, 32, 68, 44), fill=(255, 189, 46))
    draw.ellipse((76, 32, 88, 44), fill=(39, 201, 63))
    draw.text((104, 28), "secrethawk-real-demo", font=font, fill=MUTED)

    y = 68
    max_lines = (HEIGHT - 110) // LINE_HEIGHT
    visible = lines[-max_lines:]
    for text, kind in visible:
        draw.text((PADDING + 12, y), text, font=font, fill=line_color(kind, text))
        y += LINE_HEIGHT

    return img


def build_frames(events: list[Event]) -> list[Image.Image]:
    font = load_font(19)
    frames: list[Image.Image] = []
    lines: list[tuple[str, str]] = []

    for event in events:
        lines.append((event.text, event.kind))
        for _ in range(event.hold):
            frames.append(render_frame(lines, font))

    for _ in range(12):
        frames.append(render_frame(lines, font))
    return frames


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    out_dir = repo_root / "assets"
    out_dir.mkdir(parents=True, exist_ok=True)

    exe = ensure_binary(repo_root)

    with tempfile.TemporaryDirectory(prefix="secrethawk-gif-") as tmp:
        workspace = Path(tmp)
        create_demo_workspace(workspace)
        events, transcript = build_events(exe, workspace)

        frames = build_frames(events)
        gif_path = out_dir / "demo-terminal-real.gif"
        frames[0].save(
            gif_path,
            save_all=True,
            append_images=frames[1:],
            optimize=True,
            duration=FRAME_MS,
            loop=0,
            disposal=2,
        )

        transcript_path = out_dir / "demo-terminal-real.txt"
        transcript_path.write_text(transcript, encoding="utf-8")

        print(f"generated: {gif_path}")
        print(f"generated: {transcript_path}")


if __name__ == "__main__":
    main()
