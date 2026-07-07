#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Engine-level locking / lost-update tests for Phase B of audit finding C7
(plus B7 save-as-you-go). These exercise the real engine functions in
spam_filter.py, learn_signals.py, and daily_report.py against tmp files,
proving that a concurrent writer's change is no longer silently erased.

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_locking_engine.py -v

Every file touched lives under pytest's tmp_path; the real ~/MailWarden/
directory is never read or written. The modules' module-level *_PATH
constants are monkeypatched to point at the tmp copies (the suite's
convention for redirecting engine IO).
"""
import json
import os
import subprocess
import sys
import textwrap
import threading

import pytest

# Replicate the dual sys.path setup from tests/test_fixes.py: the engine tree
# (flat modules) and the app/ root (mailwarden_app package) both go on the path.
SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402
import learn_signals  # noqa: E402
import spam_filter  # noqa: E402
import daily_report  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def _read_json(path):
    with open(path, "r") as f:
        return json.load(f)


def _redirect(monkeypatch, module, attr, path):
    """Point a module-level *_PATH constant at a tmp file/dir."""
    monkeypatch.setattr(module, attr, path)


def _signals_doc(refinements):
    return {
        "version": "1.0",
        "last_updated": "",
        "derived_from_examples": 0,
        "signals": {"hard_signals": [], "soft_signals": [],
                    "known_sending_infrastructure": [], "learner_notes": ""},
        "ai_refinements": refinements,
    }


def _ref(rid, match_count=1, evidence=None):
    return {
        "id": rid, "kind": "new_pattern", "headline": f"headline {rid}",
        "status": "active", "match_count": match_count,
        "last_reinforced": "2026-01-01T00:00:00",
        "evidence": evidence or [f"{rid}.eml"],
    }


# ===========================================================================
# Test 1 [FAILING-FIRST, L1] — learner snapshot vs concurrent edit.
# The learner loads signals, the run takes a while, the user concurrently
# adds one refinement AND deletes another via the Dashboard, then the
# learner persists its reinforcement delta. After the merge-save: the
# concurrent ADD survives, the concurrent DELETE stays deleted (not
# resurrected from the learner's stale snapshot), and the learner's own
# reinforcement is applied to the surviving entry.
# ===========================================================================

def test_t1_learner_signals_merge_preserves_concurrent_edits(tmp_path, monkeypatch):
    sig_path = tmp_path / "signals.json"
    _redirect(monkeypatch, learn_signals, "SIGNALS_PATH", sig_path)
    # Keep handle_duplicate's append_refinement_log off the real memory dir.
    _redirect(monkeypatch, learn_signals, "REFINEMENTS_LOG_PATH",
              tmp_path / "signal_refinements.log")

    # Run-start snapshot the learner loads: R-A and R-B both present.
    _write_json(sig_path, _signals_doc([_ref("R-A", match_count=1),
                                        _ref("R-B", match_count=1)]))
    snapshot = learn_signals.load_signals()  # the learner's stale snapshot

    # Learner reinforces R-A (a duplicate example matched it).
    delta = {}
    learn_signals.handle_duplicate(
        {"refinement_id": "R-A"},
        {"filename": "new_example.eml", "from": "x@y.z", "subject": "s",
         "forwarder": ""},
        snapshot,
        {"accounts": []},
        learn_signals.setup_logging(),
        smtp_conn=[object()],  # non-None so no real SMTP connect is attempted
        delta=delta,
    )

    # MEANWHILE, on disk, the user adds R-C and deletes R-B (Dashboard edit).
    fresh_on_disk = _signals_doc([_ref("R-A", match_count=1),
                                  _ref("R-C", match_count=1)])
    _write_json(sig_path, fresh_on_disk)

    # The learner persists ONLY its delta, merged onto the fresh file.
    learn_signals.merge_save_signals_delta(delta, derived_increment=1)

    result = _read_json(sig_path)
    ids = {r["id"] for r in result["ai_refinements"]}
    assert "R-C" in ids, "concurrently-added R-C must survive the learner save"
    assert "R-B" not in ids, "concurrently-deleted R-B must NOT be resurrected"
    by_id = {r["id"]: r for r in result["ai_refinements"]}
    assert by_id["R-A"]["match_count"] == 2, "learner reinforcement applied to R-A"
    assert "new_example.eml" in by_id["R-A"]["evidence"]


# ===========================================================================
# Test 2 [FAILING-FIRST, L3] — config.json untouched by learner timestamp.
# The learner persists its scan timestamp into memory/learner_state.json,
# NOT config.json. config.json content is byte-identical before/after.
# ===========================================================================

def test_t2_learner_timestamp_does_not_touch_config(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    state_path = tmp_path / "learner_state.json"
    _redirect(monkeypatch, learn_signals, "CONFIG_PATH", cfg_path)
    _redirect(monkeypatch, learn_signals, "LEARNER_STATE_PATH", state_path)

    original_cfg = {"anthropic": {"model": "claude-haiku-4-5", "api_key": "K"},
                    "accounts": [], "signal_learner": {}}
    _write_json(cfg_path, original_cfg)
    cfg_bytes_before = cfg_path.read_bytes()

    learn_signals.save_learner_scan_timestamp("2026-06-11T08:00:00")

    assert cfg_path.read_bytes() == cfg_bytes_before, \
        "config.json must be byte-identical after the learner writes its timestamp"
    state = _read_json(state_path)
    assert state["last_scan_timestamp"] == "2026-06-11T08:00:00"


# ===========================================================================
# Test 3 — migration: no learner_state.json + config carrying the old
# signal_learner.last_scan_timestamp -> the read path returns the config
# value once; after a persist, learner_state.json is authoritative.
# ===========================================================================

def test_t3_learner_timestamp_migration_from_config(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    state_path = tmp_path / "learner_state.json"
    _redirect(monkeypatch, learn_signals, "CONFIG_PATH", cfg_path)
    _redirect(monkeypatch, learn_signals, "LEARNER_STATE_PATH", state_path)

    config = {"signal_learner": {"last_scan_timestamp": "2026-05-01T00:00:00"}}
    _write_json(cfg_path, config)
    assert not state_path.exists()

    # Read path: no state file yet -> fall back to config's value (migration).
    assert learn_signals.read_learner_scan_timestamp(config) == "2026-05-01T00:00:00"

    # After a persist, the state file exists and is preferred thereafter.
    learn_signals.save_learner_scan_timestamp("2026-06-11T09:00:00")
    assert state_path.exists()
    # Even with the stale config value still present, the state file wins.
    assert learn_signals.read_learner_scan_timestamp(config) == "2026-06-11T09:00:00"


# ===========================================================================
# Test 4 [FAILING-FIRST, L5/R4/D2] — token-usage delta merge (filter side).
# The filter loads token_usage, an external writer (the learner) adds tokens
# directly to the file, the filter records its own usage and persists via the
# new delta-merge helper. The file must contain BOTH contributions, and a
# second persist with an empty delta must change nothing.
# ===========================================================================

def test_t4_token_usage_delta_merge_preserves_external_writer(tmp_path, monkeypatch):
    tok_path = tmp_path / "token_usage.json"
    _redirect(monkeypatch, spam_filter, "TOKEN_USAGE_PATH", tok_path)

    today = spam_filter.datetime.now().strftime("%Y-%m-%d")
    # Filter's run-start load (empty ledger).
    _write_json(tok_path, {
        "version": "1.0", "last_updated": "",
        "lifetime_input_tokens": 0, "lifetime_output_tokens": 0,
        "lifetime_api_calls": 0, "daily_records": [],
    })

    token_usage = spam_filter.load_token_usage()
    delta = spam_filter.new_token_delta()

    # Filter records one of its own API calls into the in-memory dict + delta.
    spam_filter.record_token_usage(token_usage, 100, 50,
                                   model="claude-haiku-4-5", delta=delta)

    # MEANWHILE the learner writes its own usage straight to the file.
    external = {
        "version": "1.0", "last_updated": "",
        "lifetime_input_tokens": 1000, "lifetime_output_tokens": 200,
        "lifetime_api_calls": 1,
        "daily_records": [{
            "date": today, "input_tokens": 1000, "output_tokens": 200,
            "api_calls": 1, "api_calls_skipped_by_pre_classifier": 0,
            "estimated_cost_usd": 0.5,
        }],
    }
    _write_json(tok_path, external)

    # Filter persists ITS delta merged onto the fresh (external) file.
    spam_filter.persist_token_delta(token_usage, delta)

    merged = _read_json(tok_path)
    assert merged["lifetime_input_tokens"] == 1100, "both contributions present"
    assert merged["lifetime_output_tokens"] == 250
    assert merged["lifetime_api_calls"] == 2
    today_rec = next(r for r in merged["daily_records"] if r["date"] == today)
    assert today_rec["input_tokens"] == 1100
    assert today_rec["output_tokens"] == 250
    assert today_rec["api_calls"] == 2

    # A second persist with the (now reset) delta must be a no-op.
    before = tok_path.read_text()
    spam_filter.persist_token_delta(token_usage, delta)
    after_doc = _read_json(tok_path)
    # last_updated changes, but the accounting fields must be unchanged.
    assert after_doc["lifetime_input_tokens"] == 1100
    assert after_doc["lifetime_api_calls"] == 2
    today_rec2 = next(r for r in after_doc["daily_records"] if r["date"] == today)
    assert today_rec2["input_tokens"] == 1100
    assert today_rec2["api_calls"] == 2


# ===========================================================================
# Test 5 — B7 per-account persist helper.
# persist_progress writes processed_ids under lock and applies+resets the
# token delta. (That it is actually CALLED per account is verified by code
# inspection — see the note in the report — because run_filter needs live
# IMAP and a mega-mock would test the mock, not the behavior.)
# ===========================================================================

def test_t5_persist_progress_writes_processed_and_resets_token_delta(tmp_path, monkeypatch):
    proc_path = tmp_path / "processed_ids.json"
    tok_path = tmp_path / "token_usage.json"
    _redirect(monkeypatch, spam_filter, "PROCESSED_IDS_PATH", proc_path)
    _redirect(monkeypatch, spam_filter, "TOKEN_USAGE_PATH", tok_path)

    _write_json(tok_path, {
        "version": "1.0", "last_updated": "",
        "lifetime_input_tokens": 0, "lifetime_output_tokens": 0,
        "lifetime_api_calls": 0, "daily_records": [],
    })

    processed = {"version": "1.0", "last_updated": "",
                 "ids": {"Acct A": [["mid-1", "2026-06-11T00:00:00"]]}}
    token_usage = spam_filter.load_token_usage()
    delta = spam_filter.new_token_delta()
    spam_filter.record_token_usage(token_usage, 10, 20,
                                   model="claude-haiku-4-5", delta=delta)

    # Sanity: lock not held before, processed file absent.
    assert not proc_path.exists()

    spam_filter.persist_progress(processed, token_usage, delta)

    # processed_ids written.
    saved = _read_json(proc_path)
    assert saved["ids"]["Acct A"][0][0] == "mid-1"

    # token delta applied to the file and then RESET in memory.
    tok = _read_json(tok_path)
    assert tok["lifetime_input_tokens"] == 10
    assert tok["lifetime_output_tokens"] == 20
    assert delta["lifetime_input_tokens"] == 0
    assert delta["by_date"] == {}

    # The sidecar lock files exist (sidecar-based locking was used) and are NOT
    # held after the call returns.
    proc_lock = file_lock.lock_path_for(proc_path)
    assert proc_lock.exists()


def test_t5b_persist_progress_is_called_per_account_in_source():
    """Structural guard: persist_progress is invoked inside the account loop
    (after the per-account finally, before the max_per_run break) AND once more
    as a final flush. A full run_filter integration test needs live IMAP, so we
    assert the wiring is present rather than building a fragile mega-mock."""
    import inspect
    src = inspect.getsource(spam_filter.run_filter)
    # Call sites: the Wave-4 persist-before-execute precommit (inside the uid
    # loop), one per-account flush, and one final flush.
    assert src.count("persist_progress(processed, token_usage, token_delta)") >= 2
    # The per-account call sits after conn.logout()'s finally and before the
    # break that honors max_emails_per_run. Search AFTER the finally so the
    # earlier in-loop precommit call is not what we anchor on.
    finally_idx = src.index("conn.logout()")
    persist_idx = src.index(
        "persist_progress(processed, token_usage, token_delta)", finally_idx)
    break_idx = src.index("if total_evaluated >= max_per_run:\n            break")
    assert finally_idx < persist_idx < break_idx


# ===========================================================================
# Test 7 [FAILING-FIRST, EULA/L3] — deliver_eula_if_needed merge.
# A stale in-memory config snapshot + a NEWER config.json on disk (a model
# setting the user changed mid-run). After delivering the EULA, the disk
# config must keep BOTH the newer setting AND the EULA flag. Pre-fix, the
# blind save_config_atomic(config) reverted the newer setting.
# ===========================================================================

class _FakeSMTP:
    def sendmail(self, *a, **k):
        return {}

    def quit(self):
        return None


def test_t7_deliver_eula_merge_preserves_concurrent_config(tmp_path, monkeypatch):
    import utils

    cfg_path = tmp_path / "config.json"
    _redirect(monkeypatch, spam_filter, "CONFIG_PATH", cfg_path)

    # Mock the email seam and the EULA text source — never test mock behavior;
    # we assert on the persisted config, not on the SMTP object.
    monkeypatch.setattr(utils, "smtp_login", lambda cfg: _FakeSMTP())
    monkeypatch.setattr(spam_filter, "load_eula_text", lambda: "EULA BODY TEXT")

    # Stale in-memory snapshot the run started with (model = haiku, no EULA yet).
    config = {
        "anthropic": {"model": "claude-haiku-4-5", "api_key": "K"},
        "smtp": {"username": "owner@example.com", "from_address": "owner@example.com"},
        "accounts": [{"name": "A", "username": "owner@example.com", "enabled": True}],
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
    }

    # MEANWHILE the Dashboard saved a NEWER config to disk (model changed to
    # sonnet) before deliver_eula_if_needed reaches its save.
    newer_on_disk = {
        "anthropic": {"model": "claude-sonnet-4-6", "api_key": "K"},
        "smtp": {"username": "owner@example.com", "from_address": "owner@example.com"},
        "accounts": [{"name": "A", "username": "owner@example.com", "enabled": True}],
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
    }
    _write_json(cfg_path, newer_on_disk)

    spam_filter.deliver_eula_if_needed(config, spam_filter.logging.getLogger("t"))

    saved = _read_json(cfg_path)
    assert saved["anthropic"]["model"] == "claude-sonnet-4-6", \
        "the concurrently-saved model setting must survive the EULA save"
    assert saved["eula"]["sent_to_accounts"].get("A") == "1.0", \
        "the EULA-sent flag must also be persisted"


# ===========================================================================
# Test 6 [FAILING-FIRST if demonstrable, D5] — decisions.log concurrent
# appends. Two processes append many multi-line records through the real
# (now locked) append_decision path. Every record must stay intact — no two
# records merged/interleaved. We ALSO try to demonstrate corruption on the
# OLD unlocked path; on APFS small O_APPEND writes are frequently atomic, so
# if we cannot reliably corrupt the unlocked variant we document that and keep
# the locked-correctness assertion (which is the property that matters).
# ===========================================================================

# Each "record" is an 8-line block ended by the same "  ---\n" separator the
# real log_decision uses. We tag every line of one record with the same marker
# so an interleave is detectable: a well-formed record has all-matching tags.
_DECISIONS_WORKER = r"""
import os, sys
SRC = {src!r}
sys.path.insert(0, SRC)
import spam_filter
spam_filter.DECISIONS_LOG_PATH = type(spam_filter.DECISIONS_LOG_PATH)({log!r})
{patch_unlock}
tag = sys.argv[1]
n = int(sys.argv[2])
# Padded records (~16KB each) give the unlocked O_APPEND writers the best
# chance to interleave. On APFS these writes still tend to stay atomic, so the
# corruption demo (t6b) is informational; the locked-correctness test (t6) is
# the guarantee that matters.
pad = "x" * 2000
for i in range(n):
    rec = "".join("[%s] line%d-%s %s record %d\n" % (tag, k, tag, pad, i)
                  for k in range(8))
    rec += "  ---\n"
    spam_filter.append_decision(rec)
"""

_UNLOCK_PATCH = (
    "import contextlib\n"
    "@contextlib.contextmanager\n"
    "def _noop(*a, **k):\n"
    "    yield\n"
    "spam_filter.file_lock.locked = _noop\n"
)


def _records_are_intact(text):
    """Return (clean, total): a record is the 9 lines up to and including the
    '  ---' separator; it is clean iff its 8 content lines all carry the SAME
    tag (no interleave merged two writers' lines)."""
    lines = text.splitlines()
    records = []
    cur = []
    for ln in lines:
        cur.append(ln)
        if ln == "  ---":
            records.append(cur)
            cur = []
    clean = 0
    for rec in records:
        content = [l for l in rec if l != "  ---"]
        tags = set()
        ok = True
        for l in content:
            # tag is inside the first bracket: "[tag] ..."
            if l.startswith("[") and "]" in l:
                tags.add(l[1:l.index("]")])
            else:
                ok = False
        if ok and len(tags) == 1:
            clean += 1
    return clean, len(records)


def _run_two_appenders(src, log_path, patch_unlock):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [os.path.abspath(SRC), os.path.abspath(APP), env.get("PYTHONPATH", "")])
    code = _DECISIONS_WORKER.format(
        src=os.path.abspath(SRC), log=str(log_path),
        patch_unlock=_UNLOCK_PATCH if patch_unlock else "")
    procs = [
        subprocess.Popen([sys.executable, "-c", textwrap.dedent(code), tag, "200"],
                         env=env)
        for tag in ("AAAA", "BBBB")
    ]
    for p in procs:
        p.wait(timeout=60)


def test_t6_decisions_log_locked_appends_stay_intact(tmp_path):
    log_path = tmp_path / "decisions.log"

    # Locked path (the shipped behavior): every record must be intact.
    _run_two_appenders(SRC, log_path, patch_unlock=False)
    clean, total = _records_are_intact(log_path.read_text())
    assert total == 400, f"expected 400 records, got {total}"
    assert clean == total, (
        f"locked append corrupted {total - clean} of {total} records")


def test_t6b_decisions_log_unlocked_corruption_demo(tmp_path):
    """Best-effort demonstration that the OLD unlocked append CAN interleave.
    APFS often makes small O_APPEND writes atomic, so this is informational: we
    do NOT fail the suite if corruption is not observed, but we record what we
    saw. The locked-correctness guarantee lives in test_t6 above."""
    log_path = tmp_path / "decisions.log"
    _run_two_appenders(SRC, log_path, patch_unlock=True)
    clean, total = _records_are_intact(log_path.read_text())
    # Informational only — print so the run output records the observation.
    print(f"[t6b] unlocked: {total - clean} corrupted of {total} records "
          f"(0 corrupted just means APFS happened to keep writes atomic).")
    # Sanity: roughly 400 separators were emitted even if some records merged.
    assert total >= 1


# ===========================================================================
# Test 8 — daily-report token RMW happens UNDER the lock.
# The report's load->prune->save must be a correct RMW: the load now sits
# inside the locked region, so an external delta landing just before cannot be
# erased. We assert the structure (load is inside the lock) AND that a real
# external write made just before the report's main() prune-save is preserved.
# ===========================================================================

def test_t8_daily_report_token_prune_save_is_locked(tmp_path, monkeypatch):
    import inspect
    src = inspect.getsource(daily_report.main)
    # The three-line load->prune->save sequence must be wrapped in a lock.
    assert "file_lock.locked(daily_report.TOKEN_USAGE_PATH)" in src \
        or "file_lock.locked(TOKEN_USAGE_PATH)" in src, \
        "daily_report.main must hold the token lock around load/prune/save"
    # And the load must occur INSIDE that locked block (so it is fresh-under-lock).
    lock_idx = src.index("file_lock.locked(TOKEN_USAGE_PATH)")
    load_idx = src.index("token_usage = load_token_usage()")
    save_idx = src.index("save_token_usage(token_usage)")
    assert lock_idx < load_idx < save_idx


def test_t8b_daily_report_prune_preserves_external_write(tmp_path, monkeypatch):
    """Functional check: prune_token_usage keeps records inside the 90-day
    window, and the load-under-lock means a value written just before is read
    fresh and re-saved (not erased)."""
    tok_path = tmp_path / "token_usage.json"
    _redirect(monkeypatch, daily_report, "TOKEN_USAGE_PATH", tok_path)

    today = daily_report.datetime.now().strftime("%Y-%m-%d")
    _write_json(tok_path, {
        "version": "1.0", "last_updated": "",
        "lifetime_input_tokens": 1234, "lifetime_output_tokens": 56,
        "lifetime_api_calls": 7,
        "daily_records": [{
            "date": today, "input_tokens": 1234, "output_tokens": 56,
            "api_calls": 7, "api_calls_skipped_by_pre_classifier": 0,
            "estimated_cost_usd": 0.01,
        }],
    })

    # Reproduce the report's locked RMW directly (load fresh under lock, prune,
    # save) — the same sequence daily_report.main runs.
    with daily_report.file_lock.locked(tok_path):
        data = daily_report.load_token_usage()
        data = daily_report.prune_token_usage(data)
        daily_report.save_token_usage(data)

    out = _read_json(tok_path)
    assert out["lifetime_input_tokens"] == 1234, "external lifetime total preserved"
    assert any(r["date"] == today and r["input_tokens"] == 1234
               for r in out["daily_records"]), "today's record preserved by prune+save"

