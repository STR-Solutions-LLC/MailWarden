#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Attach a custom Finder icon to a .pkg file.

productbuild does NOT set a Finder icon on its output, so the .pkg appears
with macOS's generic brown-box installer glyph. This script calls
NSWorkspace.setIcon_forFile_options_ which writes the custom icon into
com.apple.ResourceFork / com.apple.FinderInfo so Finder displays it.

Usage:
    python3 scripts/set_pkg_icon.py <path-to-pkg> <path-to-icon.icns-or-png>
"""
import sys
from pathlib import Path

try:
    from AppKit import NSImage, NSWorkspace
except ImportError:
    print("ERROR: PyObjC not available. On /usr/bin/python3 it ships by default.",
          file=sys.stderr)
    sys.exit(1)


def set_icon(pkg_path: Path, icon_path: Path) -> int:
    if not pkg_path.exists():
        print(f"ERROR: {pkg_path} not found", file=sys.stderr)
        return 1
    if not icon_path.exists():
        print(f"ERROR: {icon_path} not found", file=sys.stderr)
        return 1

    image = NSImage.alloc().initWithContentsOfFile_(str(icon_path))
    if image is None:
        print(f"ERROR: could not read image from {icon_path}", file=sys.stderr)
        return 1

    ok = NSWorkspace.sharedWorkspace().setIcon_forFile_options_(
        image, str(pkg_path), 0)
    if not ok:
        print("ERROR: setIcon call returned False", file=sys.stderr)
        return 1

    print(f"Set Finder icon on {pkg_path}")
    return 0


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    return set_icon(Path(sys.argv[1]), Path(sys.argv[2]))


if __name__ == "__main__":
    sys.exit(main())
