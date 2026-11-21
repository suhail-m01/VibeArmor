"""Generate crisp Indigo Shield PNG icons & package the Manifest V3 Browser Extension (.zip)."""

from __future__ import annotations

import struct
import zipfile
import zlib
from pathlib import Path

EXT_DIR = Path(__file__).resolve().parent


def _make_shield_png(size: int) -> bytes:
    """Create a valid RGBA PNG icon (Indigo #4F46E5 rounded square with white shield silhouette)."""
    rows = []
    cx = (size - 1) / 2.0
    cy = (size - 1) / 2.0
    radius = size * 0.44
    for y in range(size):
        row = bytearray([0])  # filter type 0
        ny = (y - cy) / radius
        for x in range(size):
            nx = (x - cx) / radius
            # Superellipse rounded background
            in_bg = (abs(nx) ** 3.2 + abs(ny) ** 3.2) <= 1.0
            if not in_bg:
                row.extend((0, 0, 0, 0))
                continue
            # White shield glyph in center
            in_shield_top = -0.52 <= ny <= 0.05 and abs(nx) <= 0.44
            in_shield_bot = 0.05 < ny <= 0.56 and abs(nx) <= 0.44 * (1.0 - ((ny - 0.05) / 0.54) ** 1.15)
            in_inner_cut = (
                (-0.36 <= ny <= 0.03 and abs(nx) <= 0.28)
                or (0.03 < ny <= 0.38 and abs(nx) <= 0.28 * (1.0 - ((ny - 0.03) / 0.38) ** 1.15))
            )
            if (in_shield_top or in_shield_bot) and not in_inner_cut:
                row.extend((255, 255, 255, 255))
            else:
                row.extend((79, 70, 229, 255))  # #4F46E5 Indigo
        rows.append(bytes(row))

    raw = b"".join(rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def main() -> Path:
    icons_dir = EXT_DIR / "icons"
    icons_dir.mkdir(parents=True, exist_ok=True)
    for sz in (16, 48, 128):
        (icons_dir / f"icon{sz}.png").write_bytes(_make_shield_png(sz))

    zip_out = EXT_DIR / "vibearmor-browser-guard-3.0.0.zip"
    include_files = [
        "manifest.json",
        "background.js",
        "content_guard.css",
        "content_guard.js",
        "popup.html",
        "popup.css",
        "popup.js",
        "README.md",
        "icons/icon16.png",
        "icons/icon48.png",
        "icons/icon128.png",
    ]
    with zipfile.ZipFile(zip_out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in include_files:
            zf.write(EXT_DIR / rel, f"vibearmor-browser-guard/{rel}")

    print(f"Built Browser Extension ZIP: {zip_out} ({zip_out.stat().st_size} bytes)")
    return zip_out


if __name__ == "__main__":
    main()
