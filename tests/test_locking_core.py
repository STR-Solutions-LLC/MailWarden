#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Core locking tests for the shared file_lock helper and the app's filter lock
(audit findings C7 / R3). Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_locking_core.py -v

These prove the new flock-based lock actually serialises cross-process writes,
detects liveness with no staleness window, and that the app_entrypoint filter
lock holds/releases correctly. All file activity happens in pytest tmp_path;
the real ~/MailWarden/ directory is never touched.
"""
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time

import pytest

# Replicate the dual sys.path setup from tests/test_fixes.py: the engine tree
# (flat modules) and the app/ root (mailwarden_app package) both go on the path.
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402  (engine copy; byte-identical to the app copy)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE_SRC = os.path.abspath(SRC)
APP_ROOT = os.path.abspath(APP)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _wait_for(predicate, timeout=10.0, interval=0.01):
    """Poll predicate() until it returns truthy or timeout elapses.

    Used instead of arbitrary sleeps for inter-process synchronisation.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _run_python(code: str, *, timeout=30.0) -> subprocess.CompletedProcess:
    """Run a snippet in a fresh interpreter with the engine src on sys.path."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [ENGINE_SRC, APP_ROOT, env.get("PYTHONPATH", "")]
    )
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


# Worker that does N read-modify-write increments of a JSON counter, optionally
# guarding each RMW with file_lock.locked(). A tiny sleep between read and write
# forces interleaving so the unlocked variant reliably loses updates.
_INCREMENT_WORKER = r"""
import json, os, sys, time
sys.path.insert(0, {engine!r})
import file_lock

counter_path = {counter!r}
n = {n}
use_lock = {use_lock}

def rmw():
    with open(counter_path) as f:
        data = json.load(f)
    data["count"] += 1
    time.sleep(0.001)  # widen the race window between read and write
    tmp = counter_path + ".tmp." + str(os.getpid())
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, counter_path)

for _ in range(n):
    if use_lock:
        with file_lock.locked(counter_path):
            rmw()
    else:
        rmw()
"""


def _increment_worker_code(counter_path, n, use_lock):
    return _INCREMENT_WORKER.format(
        engine=ENGINE_SRC, counter=str(counter_path), n=n,
        use_lock="True" if use_lock else "False",
    )


# Worker that acquires a run-lock via try_acquire, writes a ready-marker, then
# holds the lock until a stop-marker appears (or a max lifetime elapses).
_HOLDER_WORKER = r"""
import os, sys, time
sys.path.insert(0, {engine!r})
import file_lock

lock_path = {lock!r}
ready = {ready!r}
stop = {stop!r}

fd = file_lock.try_acquire(lock_path)
if fd is None:
    # Could not get the lock; signal failure via a distinct marker.
    with open(ready + ".failed", "w") as f:
        f.write("no-lock")
    sys.exit(3)

with open(ready, "w") as f:
    f.write(str(os.getpid()))

deadline = time.monotonic() + 30.0
while time.monotonic() < deadline:
    if os.path.exists(stop):
        break
    time.sleep(0.01)

file_lock.release(fd)
"""


def _holder_code(lock_path, ready, stop):
    return _HOLDER_WORKER.format(
        engine=ENGINE_SRC, lock=str(lock_path),
        ready=str(ready), stop=str(stop),
    )


# ---------------------------------------------------------------------------
# (a) cross-process lost-update proof
# ---------------------------------------------------------------------------

def _write_counter(path):
    import json
    with open(path, "w") as f:
        json.dump({"count": 0}, f)


def _read_counter(path):
    import json
    with open(path) as f:
        return json.load(f)["count"]


def test_a_locked_rmw_no_lost_updates_cross_process(tmp_path):
    """Two real subprocesses each do 50 locked increments → final == 100."""
    counter = tmp_path / "counter.json"
    _write_counter(counter)

    p1 = subprocess.Popen(
        [sys.executable, "-c", _increment_worker_code(counter, 50, True)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    p2 = subprocess.Popen(
        [sys.executable, "-c", _increment_worker_code(counter, 50, True)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    out1 = p1.communicate(timeout=60)
    out2 = p2.communicate(timeout=60)
    assert p1.returncode == 0, out1
    assert p2.returncode == 0, out2

    assert _read_counter(counter) == 100


def test_a_unlocked_rmw_loses_updates_cross_process(tmp_path):
    """Failing-first demonstration: the SAME workload with the lock disabled
    reliably loses updates → final < 100. This proves the locked variant above
    is actually doing the serialising work (revert the lock and this is what
    you'd get)."""
    counter = tmp_path / "counter.json"
    _write_counter(counter)

    p1 = subprocess.Popen(
        [sys.executable, "-c", _increment_worker_code(counter, 50, False)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    p2 = subprocess.Popen(
        [sys.executable, "-c", _increment_worker_code(counter, 50, False)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    p1.communicate(timeout=60)
    p2.communicate(timeout=60)

    assert _read_counter(counter) < 100


# ---------------------------------------------------------------------------
# (b) two simultaneous try_acquire on one path: exactly one wins
# ---------------------------------------------------------------------------

_TRY_WORKER = r"""
import os, sys, time
sys.path.insert(0, {engine!r})
import file_lock
lock_path = {lock!r}
start = {start!r}
result = {result!r}
# Spin until the start gate appears so both processes race at once.
while not os.path.exists(start):
    time.sleep(0.005)
fd = file_lock.try_acquire(lock_path)
with open(result, "w") as f:
    f.write("WON" if fd is not None else "LOST")
if fd is not None:
    # Hold briefly so the other process definitely sees contention.
    time.sleep(0.5)
    file_lock.release(fd)
"""


def test_b_two_simultaneous_try_acquire_exactly_one_wins(tmp_path):
    lock_path = tmp_path / ".run.lock"
    start = tmp_path / "start"
    r1 = tmp_path / "r1"
    r2 = tmp_path / "r2"

    def code(result):
        return _TRY_WORKER.format(
            engine=ENGINE_SRC, lock=str(lock_path),
            start=str(start), result=str(result),
        )

    p1 = subprocess.Popen([sys.executable, "-c", code(r1)])
    p2 = subprocess.Popen([sys.executable, "-c", code(r2)])
    # Both are spinning on the start gate; open it to make them race.
    assert _wait_for(lambda: p1.pid and p2.pid)
    start.write_text("go")
    p1.communicate(timeout=30)
    p2.communicate(timeout=30)

    results = {r1.read_text().strip(), r2.read_text().strip()}
    assert results == {"WON", "LOST"}, results


# ---------------------------------------------------------------------------
# (c) liveness: SIGKILL the holder → parent can immediately acquire
# ---------------------------------------------------------------------------

def test_c_sigkilled_holder_releases_immediately(tmp_path):
    lock_path = tmp_path / ".run.lock"
    ready = tmp_path / "ready"
    stop = tmp_path / "stop"  # never created; we SIGKILL instead

    holder = subprocess.Popen(
        [sys.executable, "-c", _holder_code(lock_path, ready, stop)],
    )
    assert _wait_for(ready.exists), "holder never acquired the lock"
    # Parent cannot acquire while the holder is alive.
    assert file_lock.try_acquire(lock_path) is None

    holder.send_signal(signal.SIGKILL)
    holder.wait(timeout=10)

    # No staleness window, no manual cleanup: the OS dropped the flock on death.
    assert _wait_for(lambda: file_lock.is_locked(lock_path) is False), \
        "lock still appears held after holder was killed"
    fd = file_lock.try_acquire(lock_path)
    assert fd is not None, "could not acquire after holder death"
    file_lock.release(fd)


# ---------------------------------------------------------------------------
# (d) no staleness window: backdated mtime does not free a live lock
# ---------------------------------------------------------------------------

def test_d_backdated_mtime_does_not_free_live_lock(tmp_path):
    lock_path = tmp_path / ".run.lock"
    ready = tmp_path / "ready"
    stop = tmp_path / "stop"

    holder = subprocess.Popen(
        [sys.executable, "-c", _holder_code(lock_path, ready, stop)],
    )
    try:
        assert _wait_for(ready.exists), "holder never acquired the lock"
        # Backdate the lock file's mtime to hours ago — the old mtime check
        # would have declared it stale and stolen it. flock does not care.
        old = time.time() - 6 * 3600
        os.utime(str(lock_path), (old, old))

        assert file_lock.try_acquire(lock_path) is None, \
            "acquired a lock whose holder is still alive (staleness bug)"
        assert file_lock.is_locked(lock_path) is True
    finally:
        stop.write_text("stop")
        holder.wait(timeout=10)


# ---------------------------------------------------------------------------
# (e) is_locked: True while held, False after release/death
# ---------------------------------------------------------------------------

def test_e_is_locked_true_while_held_false_after(tmp_path):
    lock_path = tmp_path / ".run.lock"
    ready = tmp_path / "ready"
    stop = tmp_path / "stop"

    assert file_lock.is_locked(lock_path) is False  # nothing holds it yet

    holder = subprocess.Popen(
        [sys.executable, "-c", _holder_code(lock_path, ready, stop)],
    )
    assert _wait_for(ready.exists)
    assert file_lock.is_locked(lock_path) is True

    stop.write_text("stop")
    holder.wait(timeout=10)
    assert _wait_for(lambda: file_lock.is_locked(lock_path) is False)


# ---------------------------------------------------------------------------
# (f) locked() timeout: a held lock + timeout raises and nothing proceeds
# ---------------------------------------------------------------------------

def test_f_locked_timeout_raises_and_does_not_proceed(tmp_path):
    data = tmp_path / "data.json"
    sidecar = file_lock.lock_path_for(data)

    # Hold the sidecar exclusively, the way locked() would.
    import fcntl
    holder_fd = os.open(str(sidecar), os.O_CREAT | os.O_RDWR, 0o644)
    fcntl.flock(holder_fd, fcntl.LOCK_EX)

    entered = {"value": False}
    try:
        with pytest.raises(TimeoutError):
            with file_lock.locked(data, timeout=0.2):
                entered["value"] = True
        assert entered["value"] is False, "block ran despite the lock being held"
    finally:
        fcntl.flock(holder_fd, fcntl.LOCK_UN)
        os.close(holder_fd)


# ---------------------------------------------------------------------------
# (g) multi-path ordering: opposite orders do not deadlock
# ---------------------------------------------------------------------------

def test_g_multi_path_opposite_orders_no_deadlock(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    errors: list[str] = []
    done = threading.Event()

    def worker(p1, p2):
        try:
            for _ in range(30):
                with file_lock.locked(p1, p2, timeout=10.0):
                    time.sleep(0.001)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    t1 = threading.Thread(target=worker, args=(a, b))
    t2 = threading.Thread(target=worker, args=(b, a))  # opposite order
    t1.start()
    t2.start()

    def finished():
        t1.join(timeout=0.01)
        t2.join(timeout=0.01)
        if not t1.is_alive() and not t2.is_alive():
            done.set()
        return done.is_set()

    assert _wait_for(finished, timeout=20.0), "threads deadlocked"
    assert errors == [], errors


# ---------------------------------------------------------------------------
# (h) copy-drift guard: both file_lock.py files are byte-for-byte identical
# ---------------------------------------------------------------------------

def test_h_file_lock_copies_byte_identical():
    engine_copy = os.path.join(ENGINE_SRC, "file_lock.py")
    app_copy = os.path.join(APP_ROOT, "mailwarden_app", "file_lock.py")
    with open(engine_copy, "rb") as f:
        engine_bytes = f.read()
    with open(app_copy, "rb") as f:
        app_bytes = f.read()
    assert engine_bytes == app_bytes, (
        "file_lock.py copies have drifted — they MUST stay byte-identical "
        "(engine: %s, app: %s)" % (engine_copy, app_copy)
    )


# ---------------------------------------------------------------------------
# (i) app_entrypoint filter-lock behaviour
# ---------------------------------------------------------------------------

@pytest.fixture()
def entrypoint(monkeypatch, tmp_path):
    """Import app_entrypoint and point its filter lock at a tmp file."""
    from mailwarden_app import app_entrypoint
    lock_path = tmp_path / ".filter.lock"
    monkeypatch.setattr(app_entrypoint.paths, "FILTER_LOCK", lock_path,
                        raising=True)
    # Make sure no fd leaks between tests.
    if getattr(app_entrypoint, "_FILTER_LOCK_FD", None) is not None:
        app_entrypoint._release_filter_lock()
    yield app_entrypoint, lock_path
    if getattr(app_entrypoint, "_FILTER_LOCK_FD", None) is not None:
        app_entrypoint._release_filter_lock()


def test_i_acquire_returns_true_and_holds(entrypoint, tmp_path):
    app_entrypoint, lock_path = entrypoint
    assert app_entrypoint._acquire_filter_lock() is True
    # While held, a separate process cannot take the same lock.
    res = _run_python(f"""
        import sys
        sys.path.insert(0, {ENGINE_SRC!r})
        import file_lock
        fd = file_lock.try_acquire({str(lock_path)!r})
        print("ACQUIRED" if fd is not None else "BLOCKED")
    """)
    assert "BLOCKED" in res.stdout, (res.stdout, res.stderr)
    app_entrypoint._release_filter_lock()


def test_i_acquire_returns_false_while_other_holds(entrypoint, tmp_path):
    app_entrypoint, lock_path = entrypoint
    ready = tmp_path / "ready"
    stop = tmp_path / "stop"
    holder = subprocess.Popen(
        [sys.executable, "-c", _holder_code(lock_path, ready, stop)],
        env={**os.environ,
             "PYTHONPATH": os.pathsep.join([ENGINE_SRC, APP_ROOT])},
    )
    try:
        assert _wait_for(ready.exists), "external holder never acquired"
        assert app_entrypoint._acquire_filter_lock() is False
    finally:
        stop.write_text("stop")
        holder.wait(timeout=10)


def test_i_reacquirable_after_release(entrypoint, tmp_path):
    app_entrypoint, lock_path = entrypoint
    assert app_entrypoint._acquire_filter_lock() is True
    app_entrypoint._release_filter_lock()
    # After release, an external process CAN take it (proving real release).
    res = _run_python(f"""
        import sys
        sys.path.insert(0, {ENGINE_SRC!r})
        import file_lock
        fd = file_lock.try_acquire({str(lock_path)!r})
        print("ACQUIRED" if fd is not None else "BLOCKED")
    """)
    assert "ACQUIRED" in res.stdout, (res.stdout, res.stderr)
