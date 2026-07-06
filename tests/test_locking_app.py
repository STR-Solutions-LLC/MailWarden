#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
App-side locking / lost-update tests for Phase C of audit finding C7
(instances G3 / D3 / R5 — Dashboard list & config edits racing the filter's
command handlers / the learner). These exercise the real APP IO layer
(config_io) and the menu-bar pause toggle against tmp files, proving a
concurrent writer's change is no longer silently erased by an app-side save.

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_locking_app.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/
directory and the repo's payload/MailWarden/memory/ are never read or written.
The app resolves its paths through the `paths` module at call time, so we
redirect paths.*_PATH (and paths.MEMORY_DIR) to tmp copies — the app-side
analogue of the engine suite's module-PATH monkeypatch convention.
"""
import json
import os
import subprocess
import sys
import threading

import pytest

# Replicate the dual sys.path setup from tests/test_fixes.py: the engine tree
# (flat modules) and the app/ root (mailwarden_app package) both go on the path.
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402  (engine copy — proves cross-tree interop in T5)
from mailwarden_app import config_io  # noqa: E402
from mailwarden_app import menu_bar  # noqa: E402
from mailwarden_app import paths as app_paths  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def _read_json(path):
    with open(path, "r") as f:
        return json.load(f)


@pytest.fixture
def tmp_memory(tmp_path, monkeypatch):
    """Redirect every app data-file path the tests touch into tmp_path.

    config_io reads paths.<NAME>_PATH at call time, so patching the module
    attributes here is sufficient — no call site caches a path. MEMORY_DIR is
    redirected too so any incidental mkdir lands in tmp.
    """
    mem = tmp_path / "memory"
    cfg = tmp_path / "config"
    mem.mkdir()
    cfg.mkdir()
    monkeypatch.setattr(app_paths, "MEMORY_DIR", mem)
    monkeypatch.setattr(app_paths, "CONFIG_DIR", cfg)
    monkeypatch.setattr(app_paths, "CONFIG_PATH", cfg / "config.json")
    monkeypatch.setattr(app_paths, "SIGNALS_PATH", mem / "signals.json")
    monkeypatch.setattr(app_paths, "WHITELIST_PATH", mem / "whitelist.json")
    monkeypatch.setattr(app_paths, "BLACKLIST_PATH", mem / "blacklist.json")
    monkeypatch.setattr(app_paths, "PENDING_SIGNALS_PATH",
                        mem / "pending_signals.json")
    monkeypatch.setattr(app_paths, "REFINEMENTS_LOG",
                        mem / "signal_refinements.log")
    return tmp_path


# ===========================================================================
# Test 1 [FAILING-FIRST, the centerpiece — C3 menu_bar.toggle_pause / C7 G3]
#
# The lost update C7 fixes: a writer loads config, mutates ONE key, and blindly
# saves the WHOLE document — reverting any OTHER key that a concurrent process
# changed in between. menu_bar.toggle_pause and dashboard._on_pause_toggle both
# had this shape (load -> flip pause keys -> save_config).
#
# This single-process test makes the lost update DETERMINISTIC by separating
# "what was loaded" from "what is on disk at save time":
#
#   1a. [FAILING-FIRST evidence] The OLD blind pattern — mutate a stale snapshot
#       and save_config(snapshot) — REVERTS a value a peer wrote to disk after
#       the snapshot was taken. We assert that revert happens (captures the bug).
#   1b. [POST-FIX] config_io.update_config(mutator) re-reads FRESH under the
#       lock, so the peer's value SURVIVES alongside the mutation.
#   1c. [STRUCTURAL] menu_bar.toggle_pause routes its save through
#       config_io.update_config (source inspection), so the real pause toggle
#       inherits 1b's guarantee. (Driving the GIL-free interleave through the
#       real toggle_pause single-threaded can't distinguish the fix, because the
#       fix is cross-process mutual exclusion; the engine suite's test_t7 uses
#       this same stale-snapshot-vs-newer-disk model for the EULA save.)
# ===========================================================================

def _seed_two_account_config(cfg_path, dry_run=True):
    _write_json(cfg_path, {
        "accounts": [
            {"name": "A", "username": "a@x.com", "enabled": True},
            {"name": "B", "username": "b@x.com", "enabled": True},
        ],
        "filter": {"dry_run": dry_run, "interval_minutes": 15},
        "ui": {},
    })


def test_t1a_blind_snapshot_save_reverts_concurrent_change(tmp_memory):
    """FAILING-FIRST evidence: the OLD pattern loses the concurrent update."""
    cfg_path = app_paths.CONFIG_PATH
    _seed_two_account_config(cfg_path, dry_run=True)

    # A writer takes a snapshot (dry_run=True at this instant).
    snapshot = config_io.load_config()

    # MEANWHILE a peer (the filter's command handler) writes dry_run=False.
    disk = _read_json(cfg_path)
    disk["filter"]["dry_run"] = False
    _write_json(cfg_path, disk)

    # The writer mutates its OWN key on the stale snapshot and blindly saves.
    snapshot["ui"]["paused"] = True
    config_io.save_config(snapshot)

    saved = _read_json(cfg_path)
    assert saved["ui"]["paused"] is True
    # The blind save reverted the peer's change — this is the bug C7 fixes.
    assert saved["filter"]["dry_run"] is True, (
        "the OLD blind snapshot save must revert the peer's dry_run=False "
        "(this is the lost update; update_config fixes it in test_t1b)")


def test_t1b_update_config_preserves_concurrent_change(tmp_memory):
    """POST-FIX: update_config re-reads fresh under the lock, so the peer's
    change AND the mutation both survive."""
    cfg_path = app_paths.CONFIG_PATH
    _seed_two_account_config(cfg_path, dry_run=True)

    # A peer (the filter) has already committed dry_run=False to disk.
    disk = _read_json(cfg_path)
    disk["filter"]["dry_run"] = False
    _write_json(cfg_path, disk)

    # The writer applies ONLY its own key via update_config.
    def _mutate(cfg):
        cfg.setdefault("ui", {})["paused"] = True

    config_io.update_config(_mutate)

    saved = _read_json(cfg_path)
    assert saved["ui"]["paused"] is True, "the mutation must be applied"
    assert saved["filter"]["dry_run"] is False, (
        "update_config's fresh read under the lock must preserve the peer's "
        "dry_run=False")


def test_t1c_toggle_pause_routes_through_update_config():
    """STRUCTURAL: menu_bar.toggle_pause persists via config_io.update_config,
    so the real pause toggle inherits the test_t1b guarantee. Also assert it no
    longer uses the blind config_io.save_config (which caused the lost update)."""
    import inspect
    src = inspect.getsource(menu_bar.toggle_pause)
    assert "config_io.update_config(" in src, \
        "toggle_pause must persist through config_io.update_config"
    assert "config_io.save_config(" not in src, \
        "toggle_pause must NOT call the blind save_config any more"


def test_t1d_toggle_pause_real_round_trip_preserves_peer_change(tmp_memory):
    """End-to-end on the REAL toggle_pause: a peer's dry_run=False already on
    disk must survive a real pause flip (post-fix re-reads fresh under lock)."""
    cfg_path = app_paths.CONFIG_PATH
    _seed_two_account_config(cfg_path, dry_run=False)  # peer already set False

    paused_now, _msg = menu_bar.toggle_pause()

    saved = _read_json(cfg_path)
    assert paused_now is True
    assert all(a["enabled"] is False for a in saved["accounts"]), \
        "toggle_pause must pause (disable) both accounts"
    assert saved["ui"].get("paused") is True
    assert saved["filter"]["dry_run"] is False, \
        "the peer's dry_run=False must survive the real pause save"


# ===========================================================================
# Test 2 [FAILING-FIRST — C2 representative Dashboard config-save handler].
#
# Dashboard config handlers (here _on_toggle_dry_run, the simplest adjacent
# load->modify->save) had the same blind-save lost-update shape as toggle_pause.
# Exercising the real handler needs a live Tk root + Tk vars, so per the Phase C
# brief we test (a) the update_config SEMANTICS the handler routes through —
# already covered structurally by test_t1b — and (b) STRUCTURALLY that the
# handler now persists through config_io.update_config (or a locked helper) and
# no longer calls the blind config_io.save_config. (We assert the structural
# routing; the preserve-concurrent-change behavior is proven by test_t1b.)
# ===========================================================================

from mailwarden_app import dashboard  # noqa: E402


def test_t2_dashboard_dry_run_handler_routes_through_update_config():
    import inspect
    src = inspect.getsource(dashboard.HomeTab._on_toggle_dry_run)
    assert "config_io.update_config(" in src, (
        "_on_toggle_dry_run must persist through config_io.update_config so the "
        "load->modify->save runs fresh under the lock")
    assert "config_io.save_config(" not in src, (
        "_on_toggle_dry_run must NOT use the blind save_config (lost update)")


# ===========================================================================
# Test 3 — concurrent list edits: two writers each through the REAL
# config_io.add_blocklist_entry, racing on the SAME tmp blacklist.json. Each
# thread opens its OWN fd for the sidecar, so flock genuinely contends in one
# process (two fds do NOT share a flock — verified behavior). Without the lock,
# the classic load-load-append-save-save interleave drops one entry; with it,
# BOTH entries survive.
# ===========================================================================

def test_t3_concurrent_add_blocklist_entry_both_survive(tmp_memory):
    bl_path = app_paths.BLACKLIST_PATH
    _write_json(bl_path, {"version": "1.0", "addresses": [], "display_names": [],
                          "domains": [], "subject_keywords": [], "last_updated": ""})

    start = threading.Barrier(2)
    errors: list[Exception] = []

    def worker(domain):
        try:
            start.wait(timeout=10)
            # Each thread does many adds to widen the race window.
            for i in range(25):
                config_io.add_blocklist_entry(f"{domain}-{i}.example.com",
                                              "domain", "all")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    t1 = threading.Thread(target=worker, args=("alpha",))
    t2 = threading.Thread(target=worker, args=("beta",))
    t1.start()
    t2.start()
    t1.join(timeout=60)
    t2.join(timeout=60)

    assert not errors, f"worker raised: {errors}"
    data = _read_json(bl_path)
    values = {item["value"] if isinstance(item, dict) else item
              for item in data.get("domains", [])}
    # All 50 distinct entries (25 from each writer) must be present — none lost.
    for dom in ("alpha", "beta"):
        for i in range(25):
            assert f"{dom}-{i}.example.com" in values, (
                f"{dom}-{i}.example.com was lost to a concurrent-write race")
    assert len(values) == 50


# ===========================================================================
# Test 4 — multi-file lock ordering / no deadlock. apply_refinement_from_pending
# takes locked(PENDING, SIGNALS); a peer thread repeatedly takes the SAME pair
# in the OPPOSITE order via file_lock.locked(SIGNALS, PENDING). file_lock sorts
# the sidecar paths internally, so neither can hold one while waiting on the
# other — the apply must COMPLETE (no deadlock) and produce the active
# refinement. A hang would blow the join timeout and fail the test.
# ===========================================================================

def test_t4_apply_refinement_multifile_lock_no_deadlock(tmp_memory):
    sig_path = app_paths.SIGNALS_PATH
    pend_path = app_paths.PENDING_SIGNALS_PATH
    _write_json(sig_path, {"signals": {}, "ai_refinements": []})
    _write_json(pend_path, {"version": "1.0", "conversations": [{
        "id": "SF-1",
        "status": "awaiting_reply",
        "kind": "spam_example_proposal",
        "forwarder": "owner@x.com",
        "proposed_refinement": {"id": "R-1", "headline": "h", "kind": "new_pattern"},
        "conversation_history": [],
    }]})

    stop = threading.Event()
    peer_errors: list[Exception] = []

    def opposite_order_peer():
        # Grab the same two sidecars in the REVERSED order, briefly, many times.
        try:
            while not stop.is_set():
                with file_lock.locked(app_paths.SIGNALS_PATH,
                                      app_paths.PENDING_SIGNALS_PATH):
                    pass
        except Exception as e:  # noqa: BLE001
            peer_errors.append(e)

    peer = threading.Thread(target=opposite_order_peer)
    peer.start()
    try:
        # If lock ordering were unsafe this could deadlock; it must return.
        applied = config_io.apply_refinement_from_pending("SF-1", source="dashboard")
    finally:
        stop.set()
        peer.join(timeout=10)

    assert not peer_errors, f"peer raised: {peer_errors}"
    assert applied is not None and applied.get("id") == "R-1"
    sig = _read_json(sig_path)
    assert any(r.get("id") == "R-1" for r in sig.get("ai_refinements", [])), \
        "the refinement must be active after apply"
    pend = _read_json(pend_path)
    conv = next(c for c in pend["conversations"] if c["id"] == "SF-1")
    assert conv["status"] == "approved"


# ===========================================================================
# Test 4b — re-entrancy regression. apply_blocklist_proposal_from_pending holds
# locked(PENDING, BLACKLIST), then writes the block entry. flock is NOT
# re-entrant across two fds in one process (verified), so calling the LOCKING
# add_blocklist_entry from inside that held lock would block on the blacklist
# sidecar until the 30s timeout and raise TimeoutError. The fix calls the
# UNLOCKED core (_add_blocklist_entry_locked) instead. This test proves the
# whole approval returns promptly (no self-deadlock) and the block is written.
# ===========================================================================

def test_t4b_apply_blocklist_proposal_no_self_deadlock(tmp_memory):
    import time
    bl_path = app_paths.BLACKLIST_PATH
    pend_path = app_paths.PENDING_SIGNALS_PATH
    _write_json(bl_path, {"version": "1.0", "addresses": [], "display_names": [],
                          "domains": [], "subject_keywords": [], "last_updated": ""})
    _write_json(pend_path, {"version": "1.0", "conversations": [{
        "id": "SF-9",
        "status": "awaiting_reply",
        "kind": "block_sender_proposal",
        "blocklist_entry": {"value": "spam.example.com", "kind": "domain",
                            "scope": "all"},
        "conversation_history": [],
    }]})

    t0 = time.monotonic()
    entry = config_io.apply_blocklist_proposal_from_pending("SF-9",
                                                            source="dashboard")
    elapsed = time.monotonic() - t0

    # Must return WELL under the 30s lock timeout — a self-deadlock would hang
    # ~30s and then raise. A few seconds of slack absorbs slow CI.
    assert elapsed < 5.0, (
        f"apply_blocklist_proposal_from_pending took {elapsed:.1f}s — a "
        f"self-deadlock on the blacklist sidecar (must use the unlocked core)")
    assert entry is not None and entry.get("value") == "spam.example.com"
    bl = _read_json(bl_path)
    vals = {it["value"] if isinstance(it, dict) else it
            for it in bl.get("domains", [])}
    assert "spam.example.com" in vals, "the block entry must be written"
    pend = _read_json(pend_path)
    conv = next(c for c in pend["conversations"] if c["id"] == "SF-9")
    assert conv["status"] == "approved"


# ===========================================================================
# Test 5 — cross-tree integration smoke test. One writer uses the ENGINE copy of
# file_lock (imported as the flat `file_lock` module from payload/.../src), the
# other uses the APP's config_io.add_blocklist_entry (which locks via the
# app-package copy). Both RMW the SAME tmp blacklist.json sidecar concurrently.
# This proves the two byte-identical file_lock copies interoperate on the SAME
# sidecar inode — no lost update across the tree boundary.
# ===========================================================================

def test_t5_cross_tree_file_lock_interop_no_lost_update(tmp_memory):
    bl_path = app_paths.BLACKLIST_PATH
    _write_json(bl_path, {"version": "1.0", "addresses": [], "display_names": [],
                          "domains": [], "subject_keywords": [], "last_updated": ""})

    start = threading.Barrier(2)
    errors: list[Exception] = []

    def app_writer():
        # Uses the APP copy of file_lock (inside config_io.add_blocklist_entry).
        try:
            start.wait(timeout=10)
            for i in range(20):
                config_io.add_blocklist_entry(f"app-{i}.example.com", "domain", "all")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def engine_writer():
        # Uses the ENGINE copy of file_lock directly on the SAME sidecar, doing
        # its own load->append->atomic-save RMW of blacklist.json.
        import json as _json
        import os as _os
        import tempfile as _tempfile
        try:
            start.wait(timeout=10)
            for i in range(20):
                with file_lock.locked(bl_path):  # engine copy
                    with open(bl_path) as f:
                        doc = _json.load(f)
                    doc.setdefault("domains", []).append(
                        {"value": f"engine-{i}.example.com", "scope": "all"})
                    # atomic save, same shape as save_json_atomic
                    fd, tmp = _tempfile.mkstemp(dir=str(bl_path.parent), suffix=".tmp")
                    with _os.fdopen(fd, "w") as wf:
                        _json.dump(doc, wf, indent=2)
                    _os.replace(tmp, str(bl_path))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    t1 = threading.Thread(target=app_writer)
    t2 = threading.Thread(target=engine_writer)
    t1.start()
    t2.start()
    t1.join(timeout=60)
    t2.join(timeout=60)

    assert not errors, f"writer raised: {errors}"
    data = _read_json(bl_path)
    values = {item["value"] if isinstance(item, dict) else item
              for item in data.get("domains", [])}
    for i in range(20):
        assert f"app-{i}.example.com" in values, \
            f"app-{i} lost — app copy didn't interoperate with engine copy"
        assert f"engine-{i}.example.com" in values, \
            f"engine-{i} lost — engine copy didn't interoperate with app copy"
    assert len(values) == 40


# ===========================================================================
# Test 6 — STRUCTURAL guard against future drift: every save_config /
# save_whitelist / save_blacklist call site in dashboard.py is either routed
# through config_io.update_config (which locks) or sits inside a
# file_lock.locked(...) block. Cheap insurance that a future edit can't
# reintroduce an unlocked app-side save. Scoped loosely (line-window scan) so it
# is not brittle to formatting.
# ===========================================================================

def test_t6_all_dashboard_saves_are_locked():
    import inspect
    src_lines = inspect.getsource(dashboard).splitlines()

    # No blind save_config anywhere in dashboard — all config writes go through
    # config_io.update_config (which holds the lock).
    blind_config = [i + 1 for i, ln in enumerate(src_lines)
                    if "config_io.save_config(" in ln]
    assert not blind_config, (
        "dashboard.py must not call config_io.save_config directly (use "
        f"config_io.update_config); found at lines {blind_config}")

    # Every save_whitelist / save_blacklist must have an enclosing
    # `with file_lock.locked(` within a small window above it (same handler).
    def _locked_above(idx, window=40):
        for j in range(idx, max(idx - window, -1), -1):
            stripped = src_lines[j].lstrip()
            if stripped.startswith("def ") and j != idx:
                # Hit the enclosing def without seeing a lock — not locked.
                # (keep scanning is wrong; the lock must be inside this def)
                return False
            if "with file_lock.locked(" in src_lines[j]:
                return True
        return False

    unlocked = []
    for i, ln in enumerate(src_lines):
        if ("config_io.save_whitelist(" in ln
                or "config_io.save_blacklist(" in ln):
            if not _locked_above(i):
                unlocked.append(i + 1)
    assert not unlocked, (
        "every dashboard save_whitelist/save_blacklist must sit inside a "
        f"file_lock.locked(...) block; unlocked at lines {unlocked}")


# ===========================================================================
# Test 7 — menu-bar report-health helpers (audit Session 9A, finding C10).
# last_report_success() / count_overdue_reports() read report_state.json and the
# ENABLED-account set, so we redirect paths.REPORT_STATE_PATH to a tmp file and
# stub config_io.load_config for the enabled list. These exercise the real
# menu_bar helpers — no mocking of file_lock (the helpers don't lock).
# ===========================================================================

from datetime import datetime, timedelta  # noqa: E402


@pytest.fixture
def report_state_env(tmp_path, monkeypatch):
    state_path = tmp_path / "report_state.json"
    monkeypatch.setattr(app_paths, "REPORT_STATE_PATH", state_path)
    return state_path


def _set_enabled_accounts(monkeypatch, names):
    cfg = {"accounts": [{"name": n, "enabled": True} for n in names]}
    monkeypatch.setattr(config_io, "load_config", lambda: cfg)


def test_t7_last_report_success_returns_freshest_enabled(report_state_env, monkeypatch):
    state_path = report_state_env
    now = datetime.now()
    older = (now - timedelta(hours=30)).isoformat()
    newer = (now - timedelta(hours=2)).isoformat()
    _write_json(state_path, {"accounts": {
        "A": {"last_report_through": "x", "last_success_at": older},
        "B": {"last_report_through": "x", "last_success_at": newer},
    }})
    _set_enabled_accounts(monkeypatch, ["A", "B"])

    best = menu_bar.last_report_success()
    assert best == datetime.fromisoformat(newer), \
        "last_report_success must return the freshest enabled-account success"


def test_t7_last_report_success_none_when_no_state(report_state_env, monkeypatch):
    # No file at all, enabled accounts present → None.
    _set_enabled_accounts(monkeypatch, ["A"])
    assert menu_bar.last_report_success() is None


def test_t7_count_overdue_reports(report_state_env, monkeypatch):
    """One enabled account >25h stale (overdue), one fresh, one missing
    (pending, NOT overdue) → exactly 1 overdue."""
    state_path = report_state_env
    now = datetime.now()
    stale = (now - timedelta(hours=26)).isoformat()
    fresh = (now - timedelta(hours=1)).isoformat()
    _write_json(state_path, {"accounts": {
        "A": {"last_report_through": "x", "last_success_at": stale},   # overdue
        "B": {"last_report_through": "x", "last_success_at": fresh},   # fresh
        # C has no entry at all → missing → pending, not overdue.
    }})
    _set_enabled_accounts(monkeypatch, ["A", "B", "C"])

    assert menu_bar.count_overdue_reports() == 1


def test_t7_menu_bar_source_has_report_health():
    """STRUCTURAL: menu_bar wires the report-health UI + helpers in."""
    import inspect
    src = inspect.getsource(menu_bar)
    assert "report_item" in src, "menu_bar must define a report_item menu entry"
    assert "count_overdue_reports" in src, \
        "menu_bar must define count_overdue_reports"
    assert "last_report_success" in src, \
        "menu_bar must define last_report_success"
