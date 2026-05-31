# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Register / unregister MailWarden's background helpers (LaunchAgents) via
Apple's SMAppService API (macOS 13 Ventura+, stable in 14 Sonoma+).

Plists live inside the .app bundle at
  Contents/Library/LaunchAgents/com.mailwarden.{filter,report,menubar}.plist

Registration is done by calling
  SMAppService.agentServiceWithPlistName_(plist_name).registerAndReturnError_()
No launchctl commands are invoked — the self-bootout bug class
(root cause of v1.5.11-v1.5.13 silent-reject saga) is STRUCTURALLY
IMPOSSIBLE here because our code never touches launchctl at all.

SMAppService status integer mapping:
  0 (notRegistered)  -> "Not registered — click Restart all background services"
  1 (enabled)        -> "Running and approved"
  2 (requiresApproval) -> "Approved pending — open System Settings -> Login Items"
  3 (notFound)       -> "Installation incomplete — reinstall MailWarden.pkg"

Defense-in-depth: a non-blocking fcntl.flock on
  ~/MailWarden/logs/.smappservice_install.lock
prevents concurrent register_all() calls (e.g. from Dashboard + first-launch
racing) from interleaving. Cheap insurance carried forward from v1.5.14.

Public surface mirrors launchd_install.py so Dashboard/setup_assistant.py
callers need minimal changes:
  register_all()        analogous to install_agents()
  register_all_if_needed()  skips if all three already show status==enabled
  unregister_all()      analogous to unload_all()
  status_filter(), status_report(), status_menubar()  per-agent status strings
  status_int_filter(), status_int_report(), status_int_menubar()  raw ints
"""
from __future__ import annotations

import fcntl
import os
from datetime import datetime
from pathlib import Path

from . import paths

_PLIST_FILTER = "com.mailwarden.filter.plist"
_PLIST_REPORT = "com.mailwarden.report.plist"
_PLIST_MENUBAR = "com.mailwarden.menubar.plist"

_STATUS_TEXT = {
    0: "Not registered — click Restart all background services",
    1: "Running and approved",
    2: "Approved pending — open System Settings, General, Login Items and Extensions, and enable MailWarden",
    3: "Installation incomplete — reinstall MailWarden.pkg",
}

_SMAPP_LOG = paths.LOGS_DIR / "smappservice_install.log"


def _log(line: str) -> None:
    try:
        _SMAPP_LOG.parent.mkdir(parents=True, exist_ok=True)
        # Self-heal: if the log file already exists but is owned by a
        # different uid (e.g. root, from a debug run launched via sudo),
        # subsequent user-mode appends raise PermissionError and we lose
        # every diagnostic. Best-effort: delete the stale file so this
        # process can recreate it as the current user. Append-only history
        # loss here is acceptable — the lines we're trying to write now
        # are strictly more useful than preserving root-written history we
        # can't append to anyway.
        try:
            if _SMAPP_LOG.exists() and _SMAPP_LOG.stat().st_uid != os.getuid():
                _SMAPP_LOG.unlink()
        except OSError:
            pass
        with _SMAPP_LOG.open("a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {line}\n")
    except Exception:
        pass


def _svc(plist_name: str):
    """Return an SMAppService instance for the given plist filename."""
    from ServiceManagement import SMAppService  # type: ignore
    return SMAppService.agentServiceWithPlistName_(plist_name)


def _status_int(plist_name: str) -> int:
    """Return the raw SMAppService status integer (0-3) for a plist."""
    try:
        return _svc(plist_name).status()
    except Exception as e:
        _log(f"status_int({plist_name}) error: {e}")
        return 0  # treat as notRegistered on error


def _status_text(plist_name: str) -> str:
    return _STATUS_TEXT.get(_status_int(plist_name), f"unknown (check smappservice_install.log)")


def _register(plist_name: str) -> tuple[bool, str | None]:
    """Register one agent. Returns (success, error_message_or_None)."""
    try:
        import objc  # type: ignore
        svc = _svc(plist_name)
        err_ptr = objc.nil
        ok, err_ptr = svc.registerAndReturnError_(err_ptr)
        if ok:
            _log(f"register OK: {plist_name}  status={_status_int(plist_name)}")
            return True, None
        # Build a readable error message from the NSError
        err_msg = str(err_ptr) if err_ptr else "unknown error"
        _log(f"register FAIL: {plist_name}  err={err_msg!r}")
        return False, err_msg
    except Exception as e:
        _log(f"register EXCEPTION: {plist_name}  {type(e).__name__}: {e}")
        return False, str(e)


def _unregister(plist_name: str) -> tuple[bool, str | None]:
    """Unregister one agent. Returns (success, error_message_or_None)."""
    try:
        import objc  # type: ignore
        svc = _svc(plist_name)
        err_ptr = objc.nil
        ok, err_ptr = svc.unregisterAndReturnError_(err_ptr)
        if ok:
            _log(f"unregister OK: {plist_name}")
            return True, None
        err_msg = str(err_ptr) if err_ptr else "unknown error"
        _log(f"unregister FAIL: {plist_name}  err={err_msg!r}")
        return False, err_msg
    except Exception as e:
        _log(f"unregister EXCEPTION: {plist_name}  {type(e).__name__}: {e}")
        return False, str(e)


# ---------------------------------------------------------------------------
# Per-agent public API
# ---------------------------------------------------------------------------

def status_int_filter() -> int:
    return _status_int(_PLIST_FILTER)

def status_int_report() -> int:
    return _status_int(_PLIST_REPORT)

def status_int_menubar() -> int:
    return _status_int(_PLIST_MENUBAR)

def status_filter() -> str:
    return _status_text(_PLIST_FILTER)

def status_report() -> str:
    return _status_text(_PLIST_REPORT)

def status_menubar() -> str:
    return _status_text(_PLIST_MENUBAR)

def register_filter() -> tuple[bool, str | None]:
    return _register(_PLIST_FILTER)

def register_report() -> tuple[bool, str | None]:
    return _register(_PLIST_REPORT)

def register_menubar() -> tuple[bool, str | None]:
    return _register(_PLIST_MENUBAR)

def unregister_filter() -> tuple[bool, str | None]:
    return _unregister(_PLIST_FILTER)

def unregister_report() -> tuple[bool, str | None]:
    return _unregister(_PLIST_REPORT)

def unregister_menubar() -> tuple[bool, str | None]:
    return _unregister(_PLIST_MENUBAR)


# ---------------------------------------------------------------------------
# Aggregate operations
# ---------------------------------------------------------------------------

def register_all(install_menubar: bool = True) -> dict:
    """Register all agents. Returns {"registered": [...], "failed": [...], "skipped": str|None}.

    Uses a non-blocking fcntl.flock on .smappservice_install.lock so concurrent
    calls from Dashboard + first-launch entrypoint don't interleave.
    Defense-in-depth carried forward from v1.5.14 fcntl.flock pattern.
    """
    paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = paths.LOGS_DIR / ".smappservice_install.lock"
    lock_fd = None
    try:
        if not lock_path.exists():
            lock_path.touch(mode=0o644, exist_ok=True)
        lock_fd = os.open(str(lock_path), os.O_RDWR)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            _log("register_all: another process holds the lock, skipping")
            return {"registered": [], "failed": [], "skipped": "lock_contention"}

        _log("=" * 60)
        _log(f"register_all(install_menubar={install_menubar})")

        registered: list[str] = []
        failed: list[str] = []

        for name, plist in [("filter", _PLIST_FILTER), ("report", _PLIST_REPORT)]:
            ok, err = _register(plist)
            (registered if ok else failed).append(name)

        if install_menubar:
            ok, err = _register(_PLIST_MENUBAR)
            (registered if ok else failed).append("menubar")

        _log(f"register_all done: registered={registered} failed={failed}")
        return {"registered": registered, "failed": failed, "skipped": None}
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(lock_fd)
            except OSError:
                pass


def register_all_if_needed() -> dict:
    """Register only the agents that are not already enabled (status == 1).

    Called from app_entrypoint.py after bootstrap, Dashboard-only. Does
    nothing if all three are already enabled; re-registers any that are
    notRegistered or notFound. Agents with requiresApproval (2) are left
    alone — re-registering them before the user approves in Settings would
    be redundant.
    """
    needed: list[tuple[str, str]] = []
    for name, plist in [
        ("filter", _PLIST_FILTER),
        ("report", _PLIST_REPORT),
        ("menubar", _PLIST_MENUBAR),
    ]:
        s = _status_int(plist)
        if s not in (1, 2):  # not enabled, not awaiting approval
            needed.append((name, plist))

    if not needed:
        _log("register_all_if_needed: all agents already enabled or awaiting approval")
        return {"registered": [], "failed": [], "skipped": "already_ok"}

    _log(f"register_all_if_needed: registering {[n for n, _ in needed]}")
    registered: list[str] = []
    failed: list[str] = []
    for name, plist in needed:
        ok, _ = _register(plist)
        (registered if ok else failed).append(name)
    return {"registered": registered, "failed": failed, "skipped": None}


def unregister_all() -> None:
    """Unregister all three agents. Non-fatal if any are not registered."""
    _log("unregister_all()")
    for plist in (_PLIST_FILTER, _PLIST_REPORT, _PLIST_MENUBAR):
        _unregister(plist)


def all_enabled() -> bool:
    """Return True iff all three agents report status == 1 (enabled)."""
    return all(
        _status_int(p) == 1
        for p in (_PLIST_FILTER, _PLIST_REPORT, _PLIST_MENUBAR)
    )


def any_requires_approval() -> bool:
    """Return True iff any agent is in requiresApproval state (status == 2)."""
    return any(
        _status_int(p) == 2
        for p in (_PLIST_FILTER, _PLIST_REPORT, _PLIST_MENUBAR)
    )
