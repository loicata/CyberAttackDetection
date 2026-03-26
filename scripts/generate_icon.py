"""Generate the Cyber Attack Detection application icon.

Creates a professional cybersecurity-themed .ico file with multiple sizes
for Windows (16x16, 32x32, 48x48, 64x64, 128x128, 256x256).

The icon features a shield with a network eye motif in dark blue/cyan.
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def _draw_shield(draw: ImageDraw.ImageDraw, size: int) -> None:
    """Draw a shield shape.

    Args:
        draw: PIL ImageDraw instance.
        size: Canvas size in pixels.
    """
    cx = size // 2
    margin = int(size * 0.08)
    top = margin
    bottom = int(size * 0.92)
    left = margin
    right = size - margin
    mid_y = int(size * 0.55)

    # Shield outline points
    points = [
        (cx, top),
        (right, int(size * 0.18)),
        (right, mid_y),
        (cx, bottom),
        (left, mid_y),
        (left, int(size * 0.18)),
    ]

    # Dark background shield
    draw.polygon(points, fill="#0a1628", outline="#00d4ff", width=max(1, size // 64))

    # Inner gradient effect — slightly lighter inner shield
    inner_margin = int(size * 0.14)
    inner_top = inner_margin
    inner_bottom = int(size * 0.86)
    inner_left = inner_margin
    inner_right = size - inner_margin
    inner_mid_y = int(size * 0.52)

    inner_points = [
        (cx, inner_top + 2),
        (inner_right, int(size * 0.22)),
        (inner_right, inner_mid_y),
        (cx, inner_bottom),
        (inner_left, inner_mid_y),
        (inner_left, int(size * 0.22)),
    ]
    draw.polygon(inner_points, fill="#0d1f3c")


def _draw_eye(draw: ImageDraw.ImageDraw, size: int) -> None:
    """Draw a cyber eye / scanning motif in the center.

    Args:
        draw: PIL ImageDraw instance.
        size: Canvas size in pixels.
    """
    cx = size // 2
    cy = int(size * 0.45)
    radius = int(size * 0.18)
    lw = max(1, size // 80)

    # Outer ring — scanning circle
    draw.ellipse(
        [cx - radius, cy - radius, cx + radius, cy + radius],
        outline="#00d4ff",
        width=lw,
    )

    # Inner filled circle — iris
    inner_r = int(radius * 0.45)
    draw.ellipse(
        [cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r],
        fill="#00d4ff",
    )

    # Pupil
    pupil_r = int(radius * 0.18)
    draw.ellipse(
        [cx - pupil_r, cy - pupil_r, cx + pupil_r, cy + pupil_r],
        fill="#0a1628",
    )

    # Scanning lines radiating outward
    for angle_deg in range(0, 360, 45):
        angle = math.radians(angle_deg)
        x1 = cx + int(radius * 0.65 * math.cos(angle))
        y1 = cy + int(radius * 0.65 * math.sin(angle))
        x2 = cx + int(radius * 1.3 * math.cos(angle))
        y2 = cy + int(radius * 1.3 * math.sin(angle))
        draw.line([(x1, y1), (x2, y2)], fill="#00a0cc", width=max(1, lw - 1))

    # Small dots at the end of scanning lines (network nodes)
    for angle_deg in [0, 90, 180, 270]:
        angle = math.radians(angle_deg)
        nx = cx + int(radius * 1.35 * math.cos(angle))
        ny = cy + int(radius * 1.35 * math.sin(angle))
        dot_r = max(1, size // 60)
        draw.ellipse(
            [nx - dot_r, ny - dot_r, nx + dot_r, ny + dot_r],
            fill="#00ffcc",
        )


def _draw_text(draw: ImageDraw.ImageDraw, size: int) -> None:
    """Draw 'CAD' text at the bottom of the shield.

    Args:
        draw: PIL ImageDraw instance.
        size: Canvas size in pixels.
    """
    if size < 32:
        return

    cx = size // 2
    text_y = int(size * 0.68)
    font_size = max(8, int(size * 0.14))

    try:
        font = ImageFont.truetype("arial.ttf", font_size)
    except (OSError, IOError):
        try:
            font = ImageFont.truetype("C:/Windows/Fonts/arialbd.ttf", font_size)
        except (OSError, IOError):
            font = ImageFont.load_default()

    text = "CAD"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw // 2, text_y), text, fill="#00d4ff", font=font)


def generate_icon(output_path: Path) -> None:
    """Generate a multi-size .ico file.

    Args:
        output_path: Destination path for the .ico file.
    """
    sizes = [16, 32, 48, 64, 128, 256]
    images: list[Image.Image] = []

    for s in sizes:
        img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        _draw_shield(draw, s)
        _draw_eye(draw, s)
        _draw_text(draw, s)

        images.append(img)

    # Save as .ico with all sizes
    images[-1].save(
        str(output_path),
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[:-1],
    )
    print(f"Icon saved to: {output_path}")
    print(f"  Sizes: {', '.join(f'{s}x{s}' for s in sizes)}")


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "assets" / "icon.ico"
    out.parent.mkdir(parents=True, exist_ok=True)
    generate_icon(out)
