#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
persist_pending_merge — touched/created id scoping (audit finding #2 fix,
2026-07-03).

Covers the concurrency bug in the integration audit: the OLD merge overlaid
EVERY conversation in the filter's run-start snapshot onto the fresh file
("filter's whole snapshot wins"), so a concurrent Dashboard approval/reject or
a Dashboard withdraw (delete) landing mid-run was silently reverted the next
time the filter called persist_pending_merge — even for ids the filter itself
never touched this call. The fix scopes the overlay to exactly the ids the
caller says it changed THIS call (`touched_ids` for existing conversations,
`created_ids` for brand-new ones); everything else comes verbatim from the
fresh on-disk file, and a touched id missing from fresh (a concurrent
withdraw) is never resurrected.

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_persist_merge.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/
directory is never read or written. spam_filter.PENDING_SIGNALS_PATH is
monkeypatched to a tmp copy (the suite's convention — see test_session9b.py's
_redirect_filter_memory). file_lock is the REAL flock — never mocked.
"""
import json
import os
import sys

# Replicate the dual sys.path setup from tests/test_fixes.py: the engine tree
# (flat modules) and the app/ root (mailwarden_app package) both go on the path.
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import spam_filter  # noqa: E402


def _redirect_pending(monkeypatch, tmp_path):
    """Point spam_filter's pending-signals path at a tmp file (real flock,
    real load/save round-trip through the module's own functions)."""
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    p = mem / "pending_signals.json"
    monkeypatch.setattr(spam_filter, "PENDING_SIGNALS_PATH", p)
    return p


def _conv(cid, status="awaiting_reply", resolution=None, **extra):
    d = {"id": cid, "status": status, "resolution": resolution}
    d.update(extra)
    return d


def _write(path, convs):
    path.write_text(json.dumps({"version": "1.0", "conversations": convs}))


def _read(path):
    return json.loads(path.read_text())


# ===========================================================================
# 1. The exact scenario the audit finding asks for: Dashboard resolves X
#    mid-run; the filter's stale snapshot still has X pending; a merge for a
#    DIFFERENT id must not revert X.
# ===========================================================================

def test_dashboard_resolution_not_reverted_by_unrelated_merge(monkeypatch, tmp_path):
    path = _redirect_pending(monkeypatch, tmp_path)

    # Run start: X and Y both awaiting_reply.
    _write(path, [_conv("X"), _conv("Y")])

    # Filter's in-memory snapshot, loaded at run start.
    pending = {"conversations": [_conv("X"), _conv("Y")]}

    # Mid-run: the Dashboard approves X (concurrent writer — simulated by
    # rewriting the file directly, exactly what apply_refinement_from_pending
    # does under its own lock).
    _write(path, [_conv("X", status="approved", resolution="approved"),
                  _conv("Y")])

    # The filter, unaware of the Dashboard's change, resolves a DIFFERENT
    # conversation (Y) this call and persists only Y.
    for c in pending["conversations"]:
        if c["id"] == "Y":
            c["status"] = "rejected"
            c["resolution"] = "rejected"
    spam_filter.persist_pending_merge(pending, {"Y"})

    on_disk = {c["id"]: c for c in _read(path)["conversations"]}
    assert on_disk["X"]["status"] == "approved", (
        "Dashboard's concurrent approval of X must survive a merge that "
        "only touched Y")
    assert on_disk["Y"]["status"] == "rejected"

    # In-memory snapshot must also reflect the Dashboard's change for the
    # rest of this run.
    in_mem = {c["id"]: c for c in pending["conversations"]}
    assert in_mem["X"]["status"] == "approved"


# ===========================================================================
# 2. Edge case (c): a conversation the filter touched was WITHDRAWN (deleted,
#    not just status-changed) by a concurrent writer before the merge.
#    Deletion must win — the filter must not resurrect it.
# ===========================================================================

def test_concurrent_withdraw_not_resurrected(monkeypatch, tmp_path):
    path = _redirect_pending(monkeypatch, tmp_path)

    _write(path, [_conv("X")])
    pending = {"conversations": [_conv("X")]}

    # Concurrent Dashboard withdraw: X is deleted entirely from the file
    # (mirrors config_io.withdraw_pending).
    _write(path, [])

    # The filter, still holding its stale copy of X, resolves it this call.
    for c in pending["conversations"]:
        if c["id"] == "X":
            c["status"] = "approved"
            c["resolution"] = "approved"
    spam_filter.persist_pending_merge(pending, {"X"})

    on_disk = _read(path)["conversations"]
    assert on_disk == [], "a withdrawn (deleted) conversation must not be resurrected"
    assert pending["conversations"] == [], (
        "in-memory snapshot must also drop the withdrawn conversation")


# ===========================================================================
# 3. Baseline: the filter's overlay DOES win for an id it actually touched
#    (no concurrent writer involved).
# ===========================================================================

def test_merge_overlays_touched_id(monkeypatch, tmp_path):
    path = _redirect_pending(monkeypatch, tmp_path)

    _write(path, [_conv("X")])
    pending = {"conversations": [_conv("X")]}

    for c in pending["conversations"]:
        if c["id"] == "X":
            c["status"] = "rejected"
            c["resolution"] = "rejected"
    spam_filter.persist_pending_merge(pending, {"X"})

    on_disk = _read(path)["conversations"]
    assert len(on_disk) == 1
    assert on_disk[0]["status"] == "rejected"


# ===========================================================================
# 4. New conversations the filter created this call are appended, and a
#    concurrent learner addition already on disk is preserved.
# ===========================================================================

def test_merge_appends_created_conv_and_keeps_learner_addition(monkeypatch, tmp_path):
    path = _redirect_pending(monkeypatch, tmp_path)

    # A learner-appended conversation lands on disk between run start and
    # this persist call.
    _write(path, [_conv("L", kind="spam_example_proposal")])

    # Filter's snapshot never saw L; it creates a brand-new FP proposal Z.
    pending = {"conversations": [_conv("Z", kind="false_positive")]}
    spam_filter.persist_pending_merge(pending, created_ids={"Z"})

    on_disk_ids = {c["id"] for c in _read(path)["conversations"]}
    assert on_disk_ids == {"L", "Z"}, (
        "created conv must be appended and the concurrent learner addition "
        "must survive untouched")


# ===========================================================================
# 5. Edge case (d): touched_ids/created_ids are per-call, not accumulated —
#    a concurrent resolution landing AFTER an earlier persist call for the
#    same id must still survive a LATER call that only touches a different id.
# ===========================================================================

def test_merge_keeps_concurrent_resolution_across_two_calls(monkeypatch, tmp_path):
    path = _redirect_pending(monkeypatch, tmp_path)

    _write(path, [_conv("X"), _conv("Y")])
    pending = {"conversations": [_conv("X"), _conv("Y")]}

    # Call 1: filter resolves X.
    for c in pending["conversations"]:
        if c["id"] == "X":
            c["status"] = "approved"
            c["resolution"] = "approved"
    spam_filter.persist_pending_merge(pending, {"X"})

    # Between call 1 and call 2, the Dashboard overrides X (e.g. owner
    # rejects what the filter just auto-applied) directly on disk.
    on_disk = _read(path)["conversations"]
    for c in on_disk:
        if c["id"] == "X":
            c["status"] = "rejected"
            c["resolution"] = "rejected"
    _write(path, on_disk)

    # Call 2: filter resolves a DIFFERENT id, Y. X must not be re-asserted
    # from the (now stale) in-memory copy of X still sitting in `pending`.
    for c in pending["conversations"]:
        if c["id"] == "Y":
            c["status"] = "rejected"
            c["resolution"] = "rejected"
    spam_filter.persist_pending_merge(pending, {"Y"})

    final = {c["id"]: c for c in _read(path)["conversations"]}
    assert final["X"]["status"] == "rejected", (
        "a persist call scoped to Y must not re-assert a stale in-memory "
        "copy of X over the Dashboard's post-call-1 change")
    assert final["Y"]["status"] == "rejected"


# ===========================================================================
# 6. The in-memory `pending` snapshot after a merge reflects every concurrent
#    writer's current state, not just the filter's own edits.
# ===========================================================================

def test_merge_in_memory_snapshot_reflects_others(monkeypatch, tmp_path):
    path = _redirect_pending(monkeypatch, tmp_path)

    _write(path, [_conv("X"), _conv("W")])
    pending = {"conversations": [_conv("X"), _conv("W")]}

    # Concurrent: X gets approved, W gets withdrawn (deleted) — neither
    # touched by the filter this call.
    _write(path, [_conv("X", status="approved", resolution="approved")])

    # Filter touches an unrelated new conv Z this call.
    pending["conversations"].append(_conv("Z"))
    spam_filter.persist_pending_merge(pending, created_ids={"Z"})

    in_mem = {c["id"]: c for c in pending["conversations"]}
    assert in_mem["X"]["status"] == "approved", (
        "in-memory snapshot must pick up the concurrent approval of X")
    assert "W" not in in_mem, (
        "in-memory snapshot must drop the concurrently withdrawn W")
    assert "Z" in in_mem, "the filter's own new conversation must be present"
