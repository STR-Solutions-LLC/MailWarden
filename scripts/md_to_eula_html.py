#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Convert EULA.md (markdown) to eula.html for use in the .pkg click-through screen.

Not a full markdown renderer — only the subset our EULA actually uses:
  - headings (# ## ###)
  - paragraphs
  - bullet lists (- or *)
  - fenced code blocks (```)
  - horizontal rules (---)
  - bold (**), inline code (`)
"""
import re
import sys
from pathlib import Path

SRC = Path.home() / "MailWarden-installer" / "resources" / "defaults" / "EULA.md"
DST = Path.home() / "MailWarden-installer" / "resources" / "eula.html"

HEAD = """<!-- (c) 2026 STR Solutions, LLC. All rights reserved. -->
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body { font-family: -apple-system, Helvetica, Arial, sans-serif;
       line-height: 1.5; margin: 16px 20px; font-size: 13px; }
h1 { font-size: 20px; }
h2 { font-size: 16px; margin-top: 22px; }
h3 { font-size: 14px; margin-top: 16px; }
pre { font-family: Menlo, Monaco, monospace; font-size: 12px;
      margin: 8px 0; padding-left: 12px; }
code { font-family: Menlo, Monaco, monospace; font-size: 12px; }
hr { border: none; margin: 18px 0; }
ul { padding-left: 22px; }
li { margin-bottom: 4px; }
</style>
</head>
<body>
"""
TAIL = "\n</body>\n</html>\n"


def _inline(text: str) -> str:
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    return text


def md_to_html(md: str) -> str:
    out: list[str] = []
    in_code = False
    in_list = False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    for raw in md.splitlines():
        line = raw.rstrip()

        if line.strip().startswith("```"):
            close_list()
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                out.append("<pre><code>")
                in_code = True
            continue
        if in_code:
            out.append(line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
            continue

        if not line.strip():
            close_list()
            continue

        if line.strip() == "---":
            close_list()
            out.append("<hr>")
            continue

        if line.startswith("### "):
            close_list()
            out.append(f"<h3>{_inline(line[4:])}</h3>")
            continue
        if line.startswith("## "):
            close_list()
            out.append(f"<h2>{_inline(line[3:])}</h2>")
            continue
        if line.startswith("# "):
            close_list()
            out.append(f"<h1>{_inline(line[2:])}</h1>")
            continue

        m = re.match(r"^[-*]\s+(.*)$", line)
        if m:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(m.group(1))}</li>")
            continue

        close_list()
        out.append(f"<p>{_inline(line)}</p>")

    close_list()
    if in_code:
        out.append("</code></pre>")

    return HEAD + "\n".join(out) + TAIL


def main() -> int:
    if not SRC.exists():
        print(f"ERROR: {SRC} missing", file=sys.stderr)
        return 1
    DST.write_text(md_to_html(SRC.read_text()))
    print(f"Wrote {DST} ({DST.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
