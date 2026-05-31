# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Menu bar agent (rumps). Lightweight status indicator + quick actions.

Runs as its own process under com.mailwarden.menubar. Does NOT run the
filter itself — it reads log timestamps and config to determine status,
and launches the filter via subprocess when the user clicks Run Now
(respecting the same lock file the Dashboard uses).
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import rumps
except ImportError:  # rumps is only present in the bundled .app
    rumps = None  # type: ignore

from . import config_io
from . import paths
from . import startup_log


POLL_INTERVAL_SEC = 30
LOCK_MAX_AGE_SEC = 600

# Menu bar indicator: prefer a real image file (the app icon) because
# text glyphs have repeatedly failed the font-fallback lottery on Sonoma
# — both "▮▮▮▮" (U+25AE) and "❚❚❚❚" (U+275A) have rendered as
# zero-width blanks on some user installs. The app_icon.icns ships with
# every bundle, macOS knows how to render it at menu-bar size, and it
# matches what the user sees in the Dock + Finder.
MENUBAR_ICON_TEXT_FALLBACK = "MW"


def _find_bundled_icon() -> tuple[Path | None, bool]:
    """Locate the best available menu bar icon inside the running .app bundle
    or in the dev checkout.

    Returns (path, is_template) where is_template=True means the PNG should be
    passed with template=True to rumps (macOS auto-inverts for dark/light mode).
    Returns (None, False) if no icon file exists at all.

    Priority:
      1. menubar_icon.png (small 44pt PNG, template-compatible) — preferred.
         Smaller image, faster NSStatusBar render, adapts to dark/light mode.
      2. app_icon.icns (373 KB multi-rep) — fallback when PNG not built yet.
    """
    # Inside the bundle: sys.executable is Contents/MacOS/python
    try:
        exe = Path(sys.executable).resolve()
        resources = exe.parent.parent / "Resources"
        png = resources / "menubar_icon.png"
        if png.exists():
            return png, True
        icns = resources / "app_icon.icns"
        if icns.exists():
            return icns, False
    except Exception:
        pass

    # Python module path fallback (Contents/Resources/lib/python3.12/
    # mailwarden_app/menu_bar.py → Contents/Resources/)
    try:
        here = Path(__file__).resolve()
        resources = here.parent.parent.parent.parent
        png = resources / "menubar_icon.png"
        if png.exists():
            return png, True
        icns = resources / "app_icon.icns"
        if icns.exists():
            return icns, False
    except Exception:
        pass

    # Dev checkout
    dev_resources = Path.home() / "MailWarden-installer" / "app" / "resources"
    png = dev_resources / "menubar_icon.png"
    if png.exists():
        return png, True
    icns = dev_resources / "app_icon.icns"
    if icns.exists():
        return icns, False

    return None, False

STATE_GREEN = ("●", "MailWarden: running")
STATE_YELLOW = ("◐", "MailWarden: stale")
STATE_RED = ("○", "MailWarden: attention needed")


def last_filter_run() -> datetime | None:
    """Read mtime of the filter log as a proxy for last-run time."""
    if not paths.FILTER_LOG.exists():
        return None
    return datetime.fromtimestamp(paths.FILTER_LOG.stat().st_mtime)


def recent_log_has_errors() -> bool:
    if not paths.FILTER_LOG.exists():
        return False
    try:
        # Tail ~4KB — enough to see the last run's summary without reading the
        # whole log.
        size = paths.FILTER_LOG.stat().st_size
        with paths.FILTER_LOG.open("rb") as f:
            if size > 4096:
                f.seek(-4096, 2)
            tail = f.read().decode("utf-8", errors="replace")
        lower = tail.lower()
        return ("error" in lower or "traceback" in lower
                or "authentication failed" in lower)
    except OSError:
        return False


def determine_state() -> tuple[str, str, str]:
    """Return (shape, short_status, long_status_line)."""
    last = last_filter_run()
    now = datetime.now()
    if last is None:
        return STATE_RED[0], STATE_RED[1], "No run recorded yet."

    age_sec = (now - last).total_seconds()
    errored = recent_log_has_errors()
    last_fmt = last.strftime("%Y-%m-%d %H:%M")

    if age_sec <= 20 * 60 and not errored:
        return STATE_GREEN[0], STATE_GREEN[1], f"Last run: {last_fmt}"
    if age_sec <= 60 * 60 or (age_sec <= 20 * 60 and errored):
        return STATE_YELLOW[0], STATE_YELLOW[1], f"Last run: {last_fmt} (warnings)"
    return STATE_RED[0], STATE_RED[1], (
        f"Last run: {last_fmt}"
        + (" (errors in log)" if errored else " (stale)")
    )


def lock_is_active() -> bool:
    if not paths.FILTER_LOCK.exists():
        return False
    try:
        age = time.time() - paths.FILTER_LOCK.stat().st_mtime
        return age < LOCK_MAX_AGE_SEC
    except OSError:
        return False


def run_filter_subprocess() -> tuple[bool, str]:
    """Spawn a headless filter run via LaunchServices -g -n -a --args, so
    we never collide with the single-instance semantics that bit us when
    invoking the .app binary directly."""
    if lock_is_active():
        return False, "Filter is already running. Please wait a moment."

    app_bundle = Path("/Applications/MailWarden.app")
    bundled_python = app_bundle / "Contents" / "MacOS" / "python"
    launcher = app_bundle / "Contents" / "Resources" / "launcher.py"
    if not bundled_python.exists() or not launcher.exists():
        return False, f"App bundle incomplete: {app_bundle}"

    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["LC_ALL"] = "en_US.UTF-8"
    env["LANG"] = "en_US.UTF-8"
    try:
        subprocess.Popen(
            [str(bundled_python), str(launcher), "--run-filter"],
            cwd=str(paths.MAILWARDEN_ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        return False, f"Could not launch filter: {e}"
    return True, "Filter started."


def open_dashboard() -> None:
    """Open the Dashboard, reusing an existing one instead of spawning.

    Background: the menu bar agent is itself a running instance of
    MailWarden.app (same bundle ID), so a plain `open -a MailWarden.app`
    coalesces onto this windowless agent and shows nothing, while the old
    `open -n` workaround forced a brand-new Dock-bearing process on every
    click — the orphan-Dock-tile pileup bug.

    All reopen logic now lives in dashboard_instance.reopen_or_spawn(), the
    single channel shared by the menu bar, the Applications launch guard, and
    the Dock-click delegate: try a cross-process RAISE over the loopback
    socket (the ONLY thing that un-minimizes another process's window) →
    else AppKit activate → else spawn exactly one fresh Dashboard process.
    """
    from . import dashboard_instance
    dashboard_instance.reopen_or_spawn()


_DECISIONS_SEP = "  ---"


def _split_decision_blocks(raw: str) -> list[str]:
    """Split decisions.log content into individual decision blocks.

    The file uses '  ---' (two-space prefix) as the record separator,
    written at the end of each block. Split on that pattern, strip blank
    blocks, and return each block without its trailing separator so we can
    rejoin cleanly after reversing.
    """
    import re
    # Normalise: split on any line that is just optional whitespace + '---'
    # with optional trailing whitespace. Tolerates both '  ---' and '---'.
    parts = re.split(r'\n[ \t]*---[ \t]*\n?', raw)
    return [p.strip() for p in parts if p.strip()]


def open_decisions_log() -> None:
    import tempfile
    if not paths.DECISIONS_LOG.exists():
        if rumps is not None:
            rumps.alert(
                "No decisions yet",
                "MailWarden hasn't processed any emails yet. The "
                "decisions log will appear after the first filter run.",
            )
        return
    try:
        raw = paths.DECISIONS_LOG.read_text(encoding="utf-8", errors="replace")
        blocks = _split_decision_blocks(raw)
        reversed_text = ("\n" + _DECISIONS_SEP + "\n").join(blocks[::-1])
        tmp_path = Path(tempfile.gettempdir()) / "mailwarden-decisions-reversed.log"
        header = (
            "# Decisions log — most recent first.\n"
            "# Source: ~/MailWarden/memory/decisions.log (written in chronological order)\n"
            "# This is a generated, reversed copy for easy reading.\n\n"
        )
        tmp_path.write_text(header + reversed_text, encoding="utf-8")
        subprocess.Popen(
            ["open", str(tmp_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        if rumps is not None:
            rumps.alert("Could not open decisions log", str(e))


def toggle_pause() -> tuple[bool, str]:
    """Toggle global pause by enabling/disabling every account. Returns (paused_now, msg).

    Uses the same _pre_pause_enabled_list index-keyed schema as the Dashboard's
    _on_pause_toggle. Using a different key caused silent data loss: pausing from
    the Dashboard and resuming from the menu bar (or vice-versa) would lose the
    per-account enabled state for accounts that were already disabled before the
    pause.
    """
    config = config_io.load_config()
    accounts = config.get("accounts", [])
    if not accounts:
        return False, "No accounts configured."

    currently_paused = not any(a.get("enabled") for a in accounts)
    ui = config.setdefault("ui", {})

    if currently_paused:
        # Restore per-position (index-keyed to survive duplicate/empty names).
        pre_list = ui.get("_pre_pause_enabled_list")
        if isinstance(pre_list, list) and len(pre_list) == len(accounts):
            for a, was_enabled in zip(accounts, pre_list):
                a["enabled"] = bool(was_enabled)
        else:
            # Fall back to legacy name-keyed map (older configs) or enable all.
            legacy = ui.get("_pre_pause_enabled", {})
            for a in accounts:
                a["enabled"] = bool(legacy.get(a.get("name", ""), True))
        ui.pop("_pre_pause_enabled_list", None)
        ui.pop("_pre_pause_enabled", None)
        ui["paused"] = False
        config_io.save_config(config)
        return False, "Filtering resumed."
    else:
        ui["_pre_pause_enabled_list"] = [bool(a.get("enabled")) for a in accounts]
        ui.pop("_pre_pause_enabled", None)  # clear any legacy key
        for a in accounts:
            a["enabled"] = False
        ui["paused"] = True
        config_io.save_config(config)
        return True, "Filtering paused."


# ---------------------------------------------------------------------------
# Hide the menu bar agent from the Dock.
# ---------------------------------------------------------------------------
# The menu bar agent must have ZERO Dock presence. The bundle ships with
# LSUIElement=False (so the Dashboard, sharing this bundle, keeps its Dock
# tile), which means the menu bar process would otherwise show a Dock icon.
# rumps does NOT set an activation policy itself, so we must.
#
# Timing is the whole bug: an earlier attempt called setActivationPolicy_
# at the --menu-bar dispatch in app_entrypoint, BEFORE rumps created
# NSApplication.sharedApplication(). NSApp() was nil there, so the message
# went to nil and silently did nothing. rumps emits `before_start` AFTER
# NSApp creation and BEFORE the event loop (rumps.py:1204), so registering
# the policy change there is the first moment NSApp() is real.
#
# rumps' EventEmitter.emit() swallows exceptions (it only prints a traceback
# to stderr, which the bundled agent has redirected to /dev/null), so this
# handler logs its own outcome LOUDLY to the startup log — a future failure
# must never be silent the way the old `except Exception: pass` was.
if rumps is not None:
    @rumps.events.before_start
    def _hide_menubar_from_dock():
        try:
            from AppKit import (  # type: ignore
                NSApp,
                NSApplicationActivationPolicyAccessory,
            )
            ns_app = NSApp()
            if ns_app is None:
                startup_log.step(
                    "menu bar: setActivationPolicy SKIPPED — NSApp() is None "
                    "at before_start (unexpected); Dock icon may appear")
                return
            ns_app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
            startup_log.step(
                "menu bar: setActivationPolicy_(Accessory) OK — no Dock icon")
        except Exception as e:  # noqa: BLE001
            startup_log.step(
                f"menu bar: setActivationPolicy FAILED (Dock icon may appear): "
                f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Route a Finder double-click on MailWarden.app into the Dashboard.
# ---------------------------------------------------------------------------
# The menu bar agent is KeepAlive, so MailWarden.app is ALWAYS a running
# application (same bundle id as the Dashboard). When the user double-clicks
# MailWarden.app in Applications, LaunchServices does NOT spawn a new process —
# it sends an applicationShouldHandleReopen:hasVisibleWindows: Apple Event to
# the already-running menu bar process's NSApplication delegate. rumps sets its
# own delegate (rumps.py: NSApp class) which does NOT implement that selector,
# so the event is dropped and nothing happens. (On-device logs confirm: no
# no-arg launch session appears on double-click — macOS routes to this process.)
#
# Fix: in before_start (after rumps has created NSApplication and called
# setDelegate_, rumps.py:1190, and before the run loop at 1205), inject the
# reopen selector onto the rumps delegate's CLASS via objc.classAddMethods.
# The handler routes through dashboard_instance.reopen_or_spawn() — the same
# working RAISE-socket-else-spawn channel the menu's "Open Dashboard" uses.
# This is the ONE reliable place to catch the double-click, because macOS
# delivers reopen to the running process, and that process is this one.
if rumps is not None:
    @rumps.events.before_start
    def _install_app_reopen_handler():
        try:
            import objc  # type: ignore
            from AppKit import NSApp  # type: ignore

            ns_app = NSApp()
            if ns_app is None:
                startup_log.step(
                    "menu bar: reopen handler SKIPPED — NSApp() is None "
                    "at before_start")
                return
            delegate = ns_app.delegate()
            if delegate is None:
                startup_log.step(
                    "menu bar: reopen handler SKIPPED — no delegate set yet")
                return

            def _handle_reopen(self, sender, has_visible):
                # LOUD: proves on-device whether macOS delivers the double-click
                # reopen to the menu bar process (the high-confidence theory).
                try:
                    startup_log.step(
                        f"menu bar: applicationShouldHandleReopen fired "
                        f"(has_visible={has_visible}) — routing to "
                        f"reopen_or_spawn")
                except Exception:
                    pass
                try:
                    from . import dashboard_instance
                    dashboard_instance.reopen_or_spawn()
                except Exception as exc:  # noqa: BLE001
                    try:
                        startup_log.step(
                            f"menu bar: reopen_or_spawn failed: "
                            f"{type(exc).__name__}: {exc}")
                    except Exception:
                        pass
                # Return True: we handled the reopen; macOS need not do more.
                return True

            # signature c@:@c == BOOL return, (id self, SEL _cmd, id sender,
            # BOOL hasVisibleWindows). Add to the delegate's class so the live
            # delegate instance starts responding to the selector immediately.
            reopen_sel = objc.selector(
                _handle_reopen,
                selector=b"applicationShouldHandleReopen:hasVisibleWindows:",
                signature=b"c@:@c",
            )
            objc.classAddMethods(type(delegate), [reopen_sel])
            startup_log.step(
                "menu bar: applicationShouldHandleReopen handler installed "
                "on rumps delegate")
        except Exception as e:  # noqa: BLE001
            startup_log.step(
                f"menu bar: reopen handler install FAILED (Applications "
                f"double-click won't open Dashboard): "
                f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# rumps app
# ---------------------------------------------------------------------------

class MailWardenMenuBar(rumps.App if rumps else object):
    def __init__(self):
        # Prefer the bundled app_icon.icns for the menu bar indicator.
        # Text-only titles have been unreliable on Sonoma 14.x (font
        # fallback sometimes renders the glyph as zero-width), so we
        # default to the image and only fall back to text if the image
        # file is missing entirely (shouldn't happen in a shipped .pkg).
        icon_path, is_template = _find_bundled_icon()
        if icon_path is not None:
            super().__init__(
                "MailWarden",
                icon=str(icon_path),
                template=is_template,
                quit_button=None,
            )
        else:
            super().__init__(MENUBAR_ICON_TEXT_FALLBACK, quit_button=None)
        self.status_item = rumps.MenuItem("MailWarden: starting…")
        self.last_run_item = rumps.MenuItem("Last run: —")
        self.pause_item = rumps.MenuItem("Pause Filtering", callback=self.on_pause_toggle)
        self.menu = [
            self.status_item,
            self.last_run_item,
            None,
            rumps.MenuItem("Run Now", callback=self.on_run_now),
            rumps.MenuItem("Open Dashboard", callback=self.on_open_dashboard),
            rumps.MenuItem("View Recent Decisions", callback=self.on_view_decisions),
            self.pause_item,
            None,
            rumps.MenuItem("Quit MailWarden Menu Bar", callback=self.on_quit),
        ]
        self.refresh_status()

    def refresh_status(self, _timer=None):
        shape, short, long_line = determine_state()
        # When using the image icon we leave the title empty so only the
        # icon appears in the menu bar. When falling back to text, we
        # keep the text title visible.
        if self.icon is None:
            self.title = MENUBAR_ICON_TEXT_FALLBACK
        else:
            self.title = None
        self.status_item.title = f"{shape}  {short}"
        self.last_run_item.title = long_line

        config = config_io.load_config()
        paused = config.get("ui", {}).get("paused", False) or not any(
            a.get("enabled") for a in config.get("accounts", []))
        self.pause_item.title = "Resume Filtering" if paused else "Pause Filtering"

    def on_run_now(self, _sender):
        ok, msg = run_filter_subprocess()
        rumps.notification("MailWarden", "Run Now", msg, sound=False)
        self.refresh_status()

    def on_open_dashboard(self, _sender):
        open_dashboard()

    def on_view_decisions(self, _sender):
        open_decisions_log()

    def on_pause_toggle(self, _sender):
        paused_now, msg = toggle_pause()
        rumps.notification(
            "MailWarden",
            "Paused" if paused_now else "Resumed",
            msg,
            sound=False,
        )
        self.refresh_status()

    def on_quit(self, _sender):
        # NOTE: The plist has KeepAlive=true, so launchd WILL respawn the
        # menu bar agent within ~5 seconds of this call. This menu item is
        # effectively a momentary restart, not a permanent quit. To disable
        # the menu bar agent permanently, use Dashboard → Settings → Menu bar.
        rumps.quit_application()


def main() -> int:
    if rumps is None:
        print("rumps is required to run the menu bar agent.", file=sys.stderr)
        return 1
    app = MailWardenMenuBar()
    rumps.Timer(app.refresh_status, POLL_INTERVAL_SEC).start()

    # PIECE 5 (menu-bar side) — auto-open the Dashboard ONCE per update so the
    # one-time "MailWarden is running" message gets a chance to show. Best
    # effort, non-fatal: only when the welcome stamp version differs from the
    # bundled version AND no live Dashboard is already running. The Dashboard
    # itself shows the message and writes the stamp (see
    # dashboard._maybe_show_welcome_once) — we deliberately do NOT write the
    # stamp here, so a manual open before the menu bar loads still shows the
    # message exactly once.
    try:
        from . import bootstrap, config_io, dashboard_instance
        current = bootstrap.BUNDLED_FILTER_VERSION
        stamp = config_io.load_json(paths.WELCOME_SHOWN_PATH, {})
        shown_for = stamp.get("version") if isinstance(stamp, dict) else None
        already_live = dashboard_instance.live_dashboard_pid() is not None
        if shown_for != current and not already_live:
            startup_log.step(
                f"menu bar: welcome not shown for {current} and no live "
                f"Dashboard — auto-opening once via reopen_or_spawn()")
            dashboard_instance.reopen_or_spawn()
        else:
            startup_log.step(
                f"menu bar: welcome auto-open skipped "
                f"(shown_for={shown_for}, current={current}, "
                f"live_dashboard={already_live})")
    except Exception as e:  # noqa: BLE001
        startup_log.step(
            f"menu bar: welcome auto-open FAILED (non-fatal): "
            f"{type(e).__name__}: {e}")

    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
