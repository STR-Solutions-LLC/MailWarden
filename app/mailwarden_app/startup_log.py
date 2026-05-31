# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Structured startup log written to ~/MailWarden/logs/app_startup.log.

Every launch stamps a fresh block and calls `step()` at each milestone
(bootstrap, dispatch, Dashboard init, mainloop entry, etc.) so we can tell
exactly where the app got to if it never shows a window.

Any unhandled exception in main() is written to the same file with a full
traceback before the process exits.
"""
from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime
from pathlib import Path

_LOG_PATH = Path.home() / "MailWarden" / "logs" / "app_startup.log"


def _write(line: str) -> None:
    try:
        _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {line}\n")
    except Exception:
        # Logging must never crash the app.
        pass


def session_start() -> None:
    _write("=" * 60)
    _write(f"session start  pid={os.getpid()}  argv={sys.argv}")
    _write(f"  python={sys.executable}  arch={os.uname().machine}")
    _write(f"  sys.path[0:3]={sys.path[0:3]}")
    _write(f"  PYTHONUTF8={os.environ.get('PYTHONUTF8')!r}  "
           f"LC_ALL={os.environ.get('LC_ALL')!r}  "
           f"LANG={os.environ.get('LANG')!r}")
    try:
        import locale
        _write(f"  preferredencoding={locale.getpreferredencoding(False)!r}")
    except Exception:
        pass


def step(label: str) -> None:
    _write(f"  step: {label}")


def fatal(exc: BaseException) -> None:
    _write(f"FATAL: {type(exc).__name__}: {exc}")
    for line in traceback.format_exception(type(exc), exc, exc.__traceback__):
        for sub in line.rstrip().splitlines():
            _write(f"  | {sub}")
