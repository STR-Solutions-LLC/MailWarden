# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Single-instance bookkeeping for the Dashboard window.

The menu bar agent and the Dashboard run from the SAME bundle (same bundle id),
so LaunchServices coalesces a plain `open -a MailWarden.app` onto whichever
process is already running — usually the windowless menu bar agent. The old
`open -n` workaround forced a brand-new Dock-bearing process on every click,
which piled up orphan Dock tiles.

This module centralises the fix: a pidfile at ~/MailWarden/run/dashboard.pid
records the live Dashboard process. Both the launch guard (app_entrypoint) and
the menu bar "Open Dashboard" action consult it so a second request ACTIVATES
the existing window instead of spawning another process.

All paths come from paths.py (Path.home()-derived) — never a launchd literal.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

from . import paths
from . import startup_log


def _read_pid() -> int | None:
    try:
        text = paths.DASHBOARD_PID.read_text(encoding="utf-8").strip()
        return int(text) if text else None
    except (FileNotFoundError, ValueError, OSError):
        return None


def _pid_is_alive(pid: int) -> bool:
    """True if a process with this pid exists and we may signal it.

    os.kill(pid, 0) raises ProcessLookupError when the pid is dead (the stale
    pidfile case) and PermissionError when the pid exists but is owned by
    another user (still 'alive' for our purposes — treat as running)."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def live_dashboard_pid() -> int | None:
    """Return the pid of a currently-running Dashboard, or None.

    A pidfile naming a dead process (crash, kill -9, reboot) is stale and is
    treated as 'not running' so a fresh instance may start."""
    pid = _read_pid()
    if pid is None:
        return None
    if pid == os.getpid():
        # Our own pidfile from earlier in this same process.
        return pid
    return pid if _pid_is_alive(pid) else None


def write_pidfile() -> None:
    """Record this process as the live Dashboard. Best-effort; a filesystem
    glitch must not stop the Dashboard from opening."""
    try:
        paths.RUN_DIR.mkdir(parents=True, exist_ok=True)
        paths.DASHBOARD_PID.write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        pass


def remove_pidfile() -> None:
    """Remove the pidfile on clean exit, but only if it still names us — never
    delete a newer instance's pidfile."""
    try:
        if _read_pid() == os.getpid():
            paths.DASHBOARD_PID.unlink()
    except (FileNotFoundError, OSError):
        pass


def activate_pid(pid: int) -> bool:
    """Bring the process `pid` to the foreground (raise its windows).

    Uses NSRunningApplication, available in the bundled PyObjC. Returns True on
    success. Degrades to False (caller decides what to do) when AppKit is
    unavailable, e.g. a dev checkout running under system python."""
    try:
        from AppKit import (  # type: ignore
            NSRunningApplication,
            NSApplicationActivateIgnoringOtherApps,
        )
        app = NSRunningApplication.runningApplicationWithProcessIdentifier_(pid)
        if app is None:
            return False
        app.activateWithOptions_(NSApplicationActivateIgnoringOtherApps)
        return True
    except Exception:
        return False


def bundled_python_and_launcher() -> tuple[Path, Path] | None:
    """Return (python, launcher.py) inside the installed .app, or None when the
    bundle is missing (dev checkout). Mirrors menu_bar.run_filter_subprocess."""
    app_bundle = Path("/Applications/MailWarden.app")
    bundled_python = app_bundle / "Contents" / "MacOS" / "python"
    launcher = app_bundle / "Contents" / "Resources" / "launcher.py"
    if bundled_python.exists() and launcher.exists():
        return bundled_python, launcher
    return None


def _read_port() -> int | None:
    try:
        text = paths.DASHBOARD_PORT.read_text(encoding="utf-8").strip()
        return int(text) if text else None
    except (FileNotFoundError, ValueError, OSError):
        return None


def raise_existing(pid: int | None = None) -> bool:
    """Ask the running Dashboard to un-minimize and raise itself by sending
    "RAISE" over its loopback socket (see dashboard_ipc.py).

    This is the ONLY reliable cross-process un-minimize: another process can
    only raise an app's *visible* windows via AppKit; deiconify() must run in
    the Dashboard's own process, which is exactly what the socket triggers.

    The `pid` argument is accepted for caller symmetry/logging but the channel
    is the port file, not the pid. Returns True if the RAISE was delivered."""
    port = _read_port()
    if port is None:
        return False
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as conn:
            conn.sendall(b"RAISE")
        startup_log.step(
            f"dashboard_instance: RAISE sent to 127.0.0.1:{port} (pid={pid})")
        return True
    except OSError as e:
        startup_log.step(
            f"dashboard_instance: RAISE to 127.0.0.1:{port} failed "
            f"({type(e).__name__}: {e})")
        return False


def _spawn_dashboard() -> None:
    """Spawn exactly one fresh Dashboard process via the bundled python with
    --dashboard. Launching the binary directly (not through `open`) bypasses
    LaunchServices coalescing onto the windowless menu bar agent, so we
    reliably get one new Dashboard the single-instance guard then tracks."""
    bundle = bundled_python_and_launcher()
    if bundle is not None:
        bundled_python, launcher = bundle
        env = dict(os.environ)
        env["PYTHONUTF8"] = "1"
        env["LC_ALL"] = "en_US.UTF-8"
        env["LANG"] = "en_US.UTF-8"
        try:
            subprocess.Popen(
                [str(bundled_python), str(launcher), "--dashboard"],
                cwd=str(paths.MAILWARDEN_ROOT),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            startup_log.step("dashboard_instance: spawned fresh Dashboard")
            return
        except OSError as e:
            startup_log.step(f"dashboard_instance: spawn failed: {e}")

    # Dev fallback (no installed bundle, or spawn failed above).
    try:
        subprocess.Popen(
            [sys.executable, "-m", "mailwarden_app.app_entrypoint", "--dashboard"])
    except OSError as e:
        startup_log.step(f"dashboard_instance: dev-fallback spawn failed: {e}")


def reopen_or_spawn() -> None:
    """Single reopen channel shared by the menu bar, the Applications launch
    guard, and the Dock-click delegate.

    Order, weakest assumption last:
      1. RAISE over the loopback socket — un-minimizes AND raises an existing
         Dashboard (the only cross-process un-minimize that works).
      2. AppKit activate_pid — raises a live Dashboard's visible windows when
         the socket isn't answering (e.g. older Dashboard without the server).
      3. Spawn a fresh Dashboard — nothing is running.
    """
    pid = live_dashboard_pid()
    if pid is not None and pid != os.getpid():
        if raise_existing(pid):
            return
        if activate_pid(pid):
            startup_log.step(
                f"dashboard_instance: RAISE failed; fell back to activate_pid "
                f"({pid})")
            return
    _spawn_dashboard()
