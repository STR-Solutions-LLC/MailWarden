#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Generate app/resources/app_icon.icns from scratch.

Design: a cream envelope behind vertical jail bars on a navy squircle, with
the word "MailWarden" at the bottom. No external image dependencies.

Run once before build_installer.sh (build_installer.sh does NOT invoke this;
icon artwork is checked in). Re-run if the design needs to change.

Requires: Pillow (pip install pillow) and macOS's /usr/bin/iconutil.

Usage:
    python3 scripts/generate_icon.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:
    print("ERROR: Pillow is not installed. Run: pip install pillow", file=sys.stderr)
    sys.exit(1)


OUT = Path.home() / "MailWarden-installer" / "app" / "resources" / "app_icon.icns"
# Small menu bar PNG: 44px (22pt @2x retina). Template images for NSStatusBar
# should be 22pt @2x = 44px. macOS automatically inverts a template image for
# dark/light mode when template=True is set on the rumps App.
MENUBAR_PNG_OUT = Path.home() / "MailWarden-installer" / "app" / "resources" / "menubar_icon.png"

# Colors
NAVY = (28, 48, 82, 255)            # background squircle
NAVY_SHADOW = (18, 32, 56, 255)      # subtle inner-bottom shadow
ENVELOPE_CREAM = (248, 231, 180, 255)
ENVELOPE_CREAM_DARK = (210, 188, 130, 255)
ENVELOPE_LINE = (140, 118, 70, 255)
BAR_COLOR = (38, 38, 42, 255)
BAR_HIGHLIGHT = (80, 80, 84, 255)
TEXT_COLOR = (255, 255, 255, 255)
TEXT_SHADOW = (0, 0, 0, 160)

ICON_SIZES = [
    ("icon_16x16",        16),
    ("icon_16x16@2x",     32),
    ("icon_32x32",        32),
    ("icon_32x32@2x",     64),
    ("icon_128x128",      128),
    ("icon_128x128@2x",   256),
    ("icon_256x256",      256),
    ("icon_256x256@2x",   512),
    ("icon_512x512",      512),
    ("icon_512x512@2x",   1024),
]


def _find_bold_sans(size: int) -> ImageFont.FreeTypeFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/System/Library/Fonts/HelveticaNeue.ttc",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial Bold.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def draw_envelope(draw: ImageDraw.ImageDraw, cx: int, cy: int, w: int, h: int) -> None:
    left = cx - w // 2
    top = cy - h // 2
    right = left + w
    bottom = top + h

    # Envelope body
    draw.rectangle([left, top, right, bottom], fill=ENVELOPE_CREAM,
                    outline=ENVELOPE_LINE, width=max(2, w // 120))

    # Flap (triangle from top-left to top-middle to top-right, converging at center)
    flap_bottom = top + int(h * 0.58)
    draw.polygon([
        (left, top),
        (right, top),
        (cx, flap_bottom),
    ], fill=ENVELOPE_CREAM_DARK, outline=ENVELOPE_LINE)

    # Subtle fold lines from corners to center (letter-fold look)
    draw.line([(left, top), (cx, flap_bottom)], fill=ENVELOPE_LINE, width=max(1, w // 200))
    draw.line([(right, top), (cx, flap_bottom)], fill=ENVELOPE_LINE, width=max(1, w // 200))


def draw_bars(draw: ImageDraw.ImageDraw, cx: int, cy: int, w: int, h: int,
              bar_count: int = 4, canvas_size: int = 1024) -> None:
    """Thin bars with wide gaps so the envelope behind stays readable."""
    # Fixed bar width ~3% of canvas, remaining space split as gaps
    bar_w = max(4, int(canvas_size * 0.032))
    total_bars_w = bar_w * bar_count
    remaining = w - total_bars_w
    gap = remaining // (bar_count + 1)
    top_y = cy - h // 2
    bot_y = cy + h // 2
    start_x = cx - w // 2 + gap
    for i in range(bar_count):
        x = start_x + i * (bar_w + gap)
        draw.rectangle([x, top_y, x + bar_w, bot_y], fill=BAR_COLOR)
        # thin highlight stripe on the left edge of each bar for metallic feel
        draw.rectangle([x, top_y, x + max(1, bar_w // 5), bot_y],
                       fill=BAR_HIGHLIGHT)

    # Top and bottom crossbars — extend slightly past the last bar
    cross_h = max(6, int(canvas_size * 0.018))
    cross_left = start_x - gap // 2
    cross_right = start_x + (bar_count - 1) * (bar_w + gap) + bar_w + gap // 2
    draw.rectangle([cross_left, top_y - cross_h, cross_right, top_y],
                   fill=BAR_COLOR)
    draw.rectangle([cross_left, bot_y, cross_right, bot_y + cross_h],
                   fill=BAR_COLOR)


def make_master(size: int = 1024) -> Image.Image:
    """Return the 1024×1024 master at full fidelity; scale down for each target."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Rounded-square background (approximates macOS squircle with rounded_rectangle)
    pad = size // 16              # 6% padding around squircle
    radius = int(size * 0.22)
    draw.rounded_rectangle(
        [pad, pad, size - pad, size - pad],
        radius=radius, fill=NAVY)

    # Subtle bottom shadow inside the squircle
    shadow_band = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow_band)
    sd.rounded_rectangle(
        [pad, size // 2, size - pad, size - pad],
        radius=radius, fill=(18, 32, 56, 110))
    shadow_band = shadow_band.filter(ImageFilter.GaussianBlur(radius=size // 32))
    img.alpha_composite(shadow_band)

    # Envelope (roughly centered, top-weighted so text has room)
    env_cx = size // 2
    env_cy = int(size * 0.47)
    env_w = int(size * 0.60)
    env_h = int(size * 0.42)
    draw_envelope(draw, env_cx, env_cy, env_w, env_h)

    # Jail bars covering the envelope, slightly wider than the envelope
    bar_w = int(env_w * 1.05)
    bar_h = int(env_h * 1.14)
    draw_bars(draw, env_cx, env_cy, bar_w, bar_h, bar_count=4, canvas_size=size)

    # "MailWarden" text at bottom
    text = "MailWarden"
    font_size = int(size * 0.11)
    font = _find_bold_sans(font_size)
    # Measure text
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    tx = (size - tw) // 2 - bbox[0]
    ty = int(size * 0.78) - bbox[1]

    # Soft drop shadow
    shadow_img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    sdraw = ImageDraw.Draw(shadow_img)
    sdraw.text((tx + 2, ty + 4), text, font=font, fill=TEXT_SHADOW)
    shadow_img = shadow_img.filter(ImageFilter.GaussianBlur(radius=size // 220))
    img.alpha_composite(shadow_img)

    draw.text((tx, ty), text, font=font, fill=TEXT_COLOR)

    return img


def main() -> int:
    master = make_master(1024)

    with tempfile.TemporaryDirectory() as td:
        iconset = Path(td) / "MailWarden.iconset"
        iconset.mkdir()
        for name, px in ICON_SIZES:
            resized = master.resize((px, px), Image.LANCZOS)
            resized.save(iconset / f"{name}.png", "PNG")

        OUT.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["/usr/bin/iconutil", "-c", "icns", str(iconset), "-o", str(OUT)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print("iconutil failed:", result.stderr, file=sys.stderr)
            return 1

    # Also save a preview PNG for quick visual check
    preview = OUT.with_suffix(".preview.png")
    master.save(preview, "PNG")
    print(f"Wrote {OUT} ({OUT.stat().st_size:,} bytes)")
    print(f"Preview: {preview}")

    # Generate 44x44 menu bar template PNG.
    # We draw a simplified version: just the bars on a transparent background
    # so it reads as a clean template image at menu-bar size. macOS will
    # invert it for dark/light mode when template=True is set.
    menubar_size = 44
    mb_img = Image.new("RGBA", (menubar_size, menubar_size), (0, 0, 0, 0))
    mb_draw = ImageDraw.Draw(mb_img)
    # Draw a simplified envelope + bars at this size
    env_cx = menubar_size // 2
    env_cy = menubar_size // 2 - 2
    env_w = int(menubar_size * 0.72)
    env_h = int(menubar_size * 0.52)
    # Envelope
    left = env_cx - env_w // 2
    top = env_cy - env_h // 2
    right = left + env_w
    bottom = top + env_h
    mb_draw.rectangle([left, top, right, bottom], fill=(0, 0, 0, 255))
    # Bars (white on black so template inversion works)
    bar_count = 4
    bar_w = max(2, env_w // (bar_count * 3))
    total_bars_w = bar_w * bar_count
    gap = (env_w - total_bars_w) // (bar_count + 1)
    start_x = left + gap
    for i in range(bar_count):
        bx = start_x + i * (bar_w + gap)
        mb_draw.rectangle([bx, top - 2, bx + bar_w, bottom + 2],
                          fill=(255, 255, 255, 255))
    MENUBAR_PNG_OUT.parent.mkdir(parents=True, exist_ok=True)
    mb_img.save(MENUBAR_PNG_OUT, "PNG")
    print(f"Wrote {MENUBAR_PNG_OUT} ({MENUBAR_PNG_OUT.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
