# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Shared cross-process file-lock helper (advisory flock).

This module is DELIBERATELY duplicated byte-for-byte in two trees that cannot
import each other — the engine at payload/MailWarden/src/file_lock.py and the
app package at app/mailwarden_app/file_lock.py. It imports nothing from the
project (no paths.py, no sibling modules); that self-containment is exactly
what keeps the two copies identical. Engine call sites do `import file_lock`;
app call sites do `from . import file_lock`. Both resolve to this same content.

ADVISORY LOCKING: fcntl.flock is advisory. It only excludes other processes
that ALSO take the lock through this module. A writer that ignores the lock is
not blocked. Every read-modify-write of a shared file must go through here for
the guarantee to hold.

TWO LOCK STYLES:
  * SIDECAR locks for data files. lock_path_for()/locked() lock a sidecar file
    next to the data file (".<name>.lock"), NEVER the data file itself —
    atomic saves os.replace() the data file, swapping the inode out from under
    any lock held on it. The sidecar inode is stable, so its lock survives the
    replace.
  * RUN locks for "is a run in progress" flags (e.g. .filter.lock). try_acquire()
    / release() / is_locked() operate directly on the named lock file.

NEVER UNLINK A LOCK FILE. Deleting a lock file on release creates the classic
flock race: a second process opens-and-locks a fresh inode at the same path
while a first process still holds the lock on the now-unlinked old inode, so
both "hold" the lock at once. Lock files persist; that is fine — they live
alongside the existing .filter.lock / .learner.lock sidecars.
"""
from __future__ import annotations

import contextlib
import fcntl
import os
import time
from pathlib import Path
from typing import Iterator


def lock_path_for(data_path: Path) -> Path:
    """Return the sidecar lock path for a data file.

    The sidecar lives in the same directory as the data file and is named
    ".<data filename>.lock". We lock the sidecar, never the data file, because
    atomic saves os.replace() the data file (new inode) and a lock held on the
    old inode would no longer guard the live file.
    """
    data_path = Path(data_path)
    return data_path.parent / ("." + data_path.name + ".lock")


@contextlib.contextmanager
def locked(*data_paths: Path, timeout: float = 30.0) -> Iterator[None]:
    """Hold exclusive sidecar locks for one or more data files for the block.

    Paths are sorted into a fixed global acquisition order so two operations
    that each need the same pair of files (e.g. pending_signals.json +
    signals.json) can never deadlock by grabbing them in opposite orders.

    For each file we open its sidecar (O_CREAT|O_RDWR, 0o644) and acquire
    fcntl.flock LOCK_EX via a non-blocking retry loop, sleeping ~50ms between
    attempts until the deadline (flock has no native timeout). On timeout we
    release everything already held and raise TimeoutError — we NEVER proceed
    without the lock (no fail-open). All locks are released (LOCK_UN, close) in
    the finally, in reverse order.
    """
    # Sort by resolved sidecar path string for a stable, deterministic order.
    sidecars = sorted(
        {str(lock_path_for(p)) for p in data_paths}
    )
    held: list[int] = []
    deadline = time.monotonic() + timeout
    try:
        for sidecar in sidecars:
            Path(sidecar).parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(sidecar, os.O_CREAT | os.O_RDWR, 0o644)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    held.append(fd)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        os.close(fd)
                        raise TimeoutError(
                            "Timed out after %.1fs waiting for lock on %s"
                            % (timeout, sidecar))
                    time.sleep(0.05)
        yield
    finally:
        for fd in reversed(held):
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass


def try_acquire(lock_file_path: Path) -> int | None:
    """Non-blocking exclusive acquire ON the given path (a run-lock, not a
    sidecar). Returns the held fd on success — the caller keeps it open for the
    whole duration the lock should be held — or None if another process already
    holds it. On any unexpected OSError, return None (fail CLOSED: skip the run
    rather than run unguarded). On success the file is truncated and the current
    pid written into it for diagnostics.
    """
    lock_file_path = Path(lock_file_path)
    fd = None
    try:
        lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_file_path), os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            # Another process holds it — not an error, just contention.
            os.close(fd)
            return None
        try:
            os.ftruncate(fd, 0)
            os.write(fd, str(os.getpid()).encode("ascii"))
        except OSError:
            # Diagnostics-only; the lock itself is already held.
            pass
        return fd
    except OSError:
        # Could not even open/create the lock file — fail closed.
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        return None


def release(fd: int) -> None:
    """Release a fd returned by try_acquire (LOCK_UN + close), tolerating
    errors. Never unlinks the lock file."""
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def is_locked(lock_file_path: Path) -> bool:
    """Probe whether a run-lock is currently held by a live process.

    Open the lock file and try a non-blocking shared lock. If that fails, an
    exclusive holder is alive → True. Otherwise immediately unlock and close →
    False. The shared probe never blocks and never disturbs the exclusive
    holder. On any error, return False (treat as not-locked for status display).
    """
    lock_file_path = Path(lock_file_path)
    fd = None
    try:
        lock_file_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_file_path), os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            return True
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        return False
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
