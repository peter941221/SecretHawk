#!/usr/bin/env python3
"""Generate a terminal-style demo GIF for README."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from PIL import Image, ImageDraw, ImageFont


WIDTH = 960
HEIGHT = 540
PADDING = 24
LINE_HEIGHT = 28
FPS_MS = 90

BG = (11, 16, 32)
PANEL = (17, 24, 39)
PANEL_BORDER = (54, 74, 109)
TEXT = (216, 231, 255)
MUTED = (125, 148, 186)
GREEN = (140, 224, 161)
YELLOW = (246, 209, 126)
RED = (255, 138, 128)

PROMPT = "PS C:\\repo\\SecretHawk> "


@dataclass
class Event:
    kind: str  # command | output | info
    text: str
    hold: int = 2


EVENTS = [
    Event("info", "SecretHawk Demo (simulated run)", hold=6),
    Event("command", "./secrethawk.exe scan . --validate --fail-on high --fail-on-active", hold=3),
    Event("output", "[scan] files=42 rules=5 findings=1 active=1", hold=3),
    Event("output", "[gate] blocked: active high-severity secret found", hold=4),
    Event("command", "./secrethawk.exe remediate --auto --dry-run", hold=3),
    Event("output", "[remediate] connector=aws action=rotate (simulated)", hold=3),
    Event("output", "[remediate] patch plan: 1 file -> env reference", hold=3),
    Event("output", "[remediate] report: .secrethawk/reports/inc-2026-03-02.md", hold=4),
    Event("command", "./secrethawk.exe report --input findings.json", hold=3),
    Event("output", "report generated: .secrethawk/reports/2026-03-02-090500.md", hold=3),
    Event("info", "Done. CI can now fail only on verified active findings.", hold=8),
]


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


def line_color(text: str, kind: str) -> tuple[int, int, int]:
    if kind == "command":
        return GREEN
    if "blocked" in text:
        return RED
    if "Done." in text:
        return GREEN
    if kind == "info":
        return YELLOW
    return TEXT


def render_frame(
    lines: List[tuple[str, str]],
    font: ImageFont.ImageFont,
    cursor: bool,
    partial: str = "",
) -> Image.Image:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    panel_x0, panel_y0 = 16, 16
    panel_x1, panel_y1 = WIDTH - 16, HEIGHT - 16
    draw.rounded_rectangle((panel_x0, panel_y0, panel_x1, panel_y1), radius=16, fill=PANEL, outline=PANEL_BORDER, width=2)

    # Window dots
    draw.ellipse((36, 32, 48, 44), fill=(255, 95, 86))
    draw.ellipse((56, 32, 68, 44), fill=(255, 189, 46))
    draw.ellipse((76, 32, 88, 44), fill=(39, 201, 63))
    draw.text((104, 28), "secrethawk-demo", font=font, fill=MUTED)

    y = 64
    max_lines = (HEIGHT - 100) // LINE_HEIGHT
    visible = lines[-max_lines:]
    for text, kind in visible:
        draw.text((PADDING + 16, y), text, font=font, fill=line_color(text, kind))
        y += LINE_HEIGHT

    if partial:
        cursor_char = "_" if cursor else " "
        draw.text((PADDING + 16, y), partial + cursor_char, font=font, fill=GREEN)

    return img


def build_frames() -> list[Image.Image]:
    font = load_font(20)
    frames: list[Image.Image] = []
    lines: list[tuple[str, str]] = []

    for event in EVENTS:
        if event.kind == "command":
            full = PROMPT + event.text
            step = 4
            for i in range(1, len(full) + 1, step):
                partial = full[:i]
                frames.append(render_frame(lines, font, cursor=True, partial=partial))
            lines.append((full, "command"))
            for _ in range(event.hold):
                frames.append(render_frame(lines, font, cursor=False))
        else:
            lines.append((event.text, event.kind))
            for _ in range(event.hold):
                frames.append(render_frame(lines, font, cursor=False))

    # A short tail pause
    for _ in range(12):
        frames.append(render_frame(lines, font, cursor=False))
    return frames


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    out_dir = repo_root / "assets"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "demo-terminal.gif"

    frames = build_frames()
    frames[0].save(
        out_path,
        save_all=True,
        append_images=frames[1:],
        optimize=True,
        duration=FPS_MS,
        loop=0,
        disposal=2,
    )
    print(f"generated: {out_path}")


if __name__ == "__main__":
    main()
