#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Feature 4, Option B ("Instant + safety guard") — the Train-folder reinforcement
CONTRADICTION GUARD in learn_signals.handle_duplicate.

Today, when a Train drop matches an existing active learned rule, the learner
SILENTLY strengthens it (match_count++, evidence, last_reinforced) even when
the matched rule is one the owner explicitly taught as "legitimate" via the
dashboard's Check an Email flow. This guard refuses that write and instead
logs+emails a contradiction notice; benign reinforcement (no verdict, or
rule_class curate/protect) still happens instantly, with FYI copy reworded to
say MailWarden "guessed".

Follows the tests/test_locking_engine.py harness convention: monkeypatch the
module-level *_PATH constants to tmp files, real file_lock/flock, and (here)
a stubbed ``_send`` so the FYI subject/body can be captured and inspected.

Run with the dedicated test venv:

  tests/.venv/bin/python -m pytest tests/test_train_reinforce_gate.py -v
"""
import json
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import learn_signals  # noqa: E402


# ---------------------------------------------------------------------------
# helpers (mirrors tests/test_locking_engine.py's conventions)
# ---------------------------------------------------------------------------

def _write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)


def _read_json(path):
    with open(path, "r") as f:
        return json.load(f)


def _signals_doc(refinements):
    return {
        "version": "1.0",
        "last_updated": "",
        "derived_from_examples": 0,
        "signals": {"hard_signals": [], "soft_signals": [],
                    "known_sending_infrastructure": [], "learner_notes": ""},
        "ai_refinements": refinements,
    }


def _ref(rid, match_count=1, evidence=None, verdict=None, rule_class=None,
         status="active"):
    r = {
        "id": rid, "kind": "new_pattern", "headline": f"headline {rid}",
        "status": status, "match_count": match_count,
        "last_reinforced": "2026-01-01T00:00:00",
        "evidence": evidence or [f"{rid}.eml"],
    }
    if verdict is not None:
        r["verdict"] = verdict
    if rule_class is not None:
        r["rule_class"] = rule_class
    return r


def _example(filename="new_example.eml"):
    return {"filename": filename, "from": "x@y.z", "subject": "s",
            "forwarder": ""}


@pytest.fixture
def redirected(tmp_path, monkeypatch):
    """Point SIGNALS_PATH + REFINEMENTS_LOG_PATH at tmp files, and stub _send
    to capture every FYI email instead of touching real SMTP. Returns a dict
    with 'sig_path', 'log_path', and 'sent' (list of {to,subject,body})."""
    sig_path = tmp_path / "signals.json"
    log_path = tmp_path / "signal_refinements.log"
    monkeypatch.setattr(learn_signals, "SIGNALS_PATH", sig_path)
    monkeypatch.setattr(learn_signals, "REFINEMENTS_LOG_PATH", log_path)

    sent = []

    def _fake_send(config, to_addr, subject, body, logger, smtp_conn=None):
        sent.append({"to": to_addr, "subject": subject, "body": body})
        return True

    monkeypatch.setattr(learn_signals, "_send", _fake_send)
    return {"sig_path": sig_path, "log_path": log_path, "sent": sent}


def _log_events(log_path):
    if not log_path.exists():
        return []
    events = []
    for line in log_path.read_text().splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


# ===========================================================================
# 1. Contradiction blocked: active rule verdict="legitimate".
# ===========================================================================

def test_contradiction_blocked_no_write(redirected):
    sig_path = redirected["sig_path"]
    signals_data = _signals_doc([_ref("R-LEGIT", match_count=3,
                                      evidence=["old.eml"],
                                      verdict="legitimate")])
    _write_json(sig_path, signals_data)

    delta = {}
    result = learn_signals.handle_duplicate(
        {"refinement_id": "R-LEGIT", "note": "looks similar"},
        _example("contra.eml"),
        signals_data,
        {"accounts": []},
        learn_signals.setup_logging(),
        smtp_conn=None,
        delta=delta,
    )

    assert result is False, "a blocked contradiction must return False (no write)"
    target = signals_data["ai_refinements"][0]
    assert target["match_count"] == 3, "match_count must be UNCHANGED"
    assert target["evidence"] == ["old.eml"], "evidence must be UNCHANGED"
    assert delta == {}, "no reinforced delta may be recorded for a blocked example"

    events = _log_events(redirected["log_path"])
    kinds = [e["event"] for e in events]
    assert "reinforce_blocked_contradiction" in kinds
    blocked = next(e for e in events if e["event"] == "reinforce_blocked_contradiction")
    assert blocked["id"] == "R-LEGIT"
    assert blocked["example"] == "contra.eml"
    assert "reinforced" not in kinds, "must NOT also log a reinforced event"

    assert len(redirected["sent"]) == 1
    fyi = redirected["sent"][0]
    assert "legitimate" in fyi["body"].lower()
    assert "guessed" in fyi["body"].lower()


@pytest.mark.parametrize("verdict_variant", ["Legitimate", " legitimate "])
def test_contradiction_guard_normalizes_verdict(redirected, verdict_variant):
    """The guard must match on a NORMALIZED verdict (.strip().lower()), not an
    exact string. The prompt renderer _build_learned_lines normalizes verdict
    the same way, so a legacy/hand-edited record like "Legitimate" or
    " legitimate " is treated as legitimate BY THE CLASSIFIER — the guard must
    block it too, or the classifier and the learner disagree. This FAILS against
    the old exact-match guard (`verdict == "legitimate"`) and PASSES with the
    normalized one."""
    sig_path = redirected["sig_path"]
    signals_data = _signals_doc([_ref("R-LEGIT", match_count=3,
                                      evidence=["old.eml"],
                                      verdict=verdict_variant)])
    _write_json(sig_path, signals_data)

    delta = {}
    result = learn_signals.handle_duplicate(
        {"refinement_id": "R-LEGIT"}, _example("contra.eml"),
        signals_data, {"accounts": []}, learn_signals.setup_logging(),
        smtp_conn=None, delta=delta,
    )

    assert result is False, (
        f"a mixed-case/whitespace verdict {verdict_variant!r} must STILL be "
        f"blocked (no write)")
    target = signals_data["ai_refinements"][0]
    assert target["match_count"] == 3, "match_count must be UNCHANGED"
    assert target["evidence"] == ["old.eml"], "evidence must be UNCHANGED"
    assert delta == {}, "no reinforced delta may be recorded for a blocked example"

    events = _log_events(redirected["log_path"])
    assert any(e["event"] == "reinforce_blocked_contradiction" for e in events)
    assert len(redirected["sent"]) == 1


def test_contradiction_blocked_not_counted_as_derived(redirected):
    """The caller (_run) increments signals_needs_save/derived_count only on a
    True return from handle_duplicate. A blocked contradiction returning False
    must not be counted as reinforced/derived."""
    sig_path = redirected["sig_path"]
    signals_data = _signals_doc([_ref("R-LEGIT", verdict="legitimate")])
    _write_json(sig_path, signals_data)

    signals_needs_save = False
    derived_count = 0
    delta = {}
    if learn_signals.handle_duplicate(
            {"refinement_id": "R-LEGIT"}, _example(), signals_data,
            {"accounts": []}, learn_signals.setup_logging(), delta=delta):
        signals_needs_save = True
        derived_count += 1

    assert signals_needs_save is False
    assert derived_count == 0


# ===========================================================================
# 2. Benign reinforce still works: active rule with NO verdict.
# ===========================================================================

def test_benign_reinforce_still_works(redirected):
    sig_path = redirected["sig_path"]
    signals_data = _signals_doc([_ref("R-PLAIN", match_count=1)])
    _write_json(sig_path, signals_data)

    delta = {}
    result = learn_signals.handle_duplicate(
        {"refinement_id": "R-PLAIN", "note": "matches"},
        _example("plain.eml"),
        signals_data,
        {"accounts": []},
        learn_signals.setup_logging(),
        delta=delta,
    )

    assert result is True
    target = signals_data["ai_refinements"][0]
    assert target["match_count"] == 2, "match_count must bump 1 -> 2"
    assert "plain.eml" in target["evidence"]
    assert delta["R-PLAIN"]["increment"] == 1

    events = _log_events(redirected["log_path"])
    assert any(e["event"] == "reinforced" for e in events)

    assert len(redirected["sent"]) == 1
    body = redirected["sent"][0]["body"]
    assert "guessed" in body.lower()
    # Finding 6: the FYI must point the owner at the action that WORKS
    # (Dashboard -> Signal History -> Delete), not the dead "reply 'not a
    # match'" instruction (that reply carries no SFID/MWR token, so it is
    # unroutable).
    assert "not a match" not in body.lower()
    assert "Signal History" in body
    assert "Delete" in body


# ===========================================================================
# 3. curate NOT blocked: rule_class="curate", no verdict -> reinforces normally.
# ===========================================================================

def test_curate_rule_class_not_blocked(redirected):
    sig_path = redirected["sig_path"]
    signals_data = _signals_doc([_ref("R-CURATE", match_count=1,
                                      rule_class="curate")])
    _write_json(sig_path, signals_data)

    delta = {}
    result = learn_signals.handle_duplicate(
        {"refinement_id": "R-CURATE"}, _example("curate.eml"),
        signals_data, {"accounts": []}, learn_signals.setup_logging(),
        delta=delta,
    )

    assert result is True, "curate is NOT a contradiction — must reinforce normally"
    target = signals_data["ai_refinements"][0]
    assert target["match_count"] == 2
    assert delta["R-CURATE"]["increment"] == 1


# ===========================================================================
# 4. new_pattern unchanged: creates a pending proposal, writes nothing active.
# ===========================================================================

def test_new_pattern_creates_pending_proposal_only(tmp_path, monkeypatch):
    sig_path = tmp_path / "signals.json"
    pending_path = tmp_path / "pending_signals.json"
    log_path = tmp_path / "signal_refinements.log"
    monkeypatch.setattr(learn_signals, "SIGNALS_PATH", sig_path)
    monkeypatch.setattr(learn_signals, "PENDING_SIGNALS_PATH", pending_path)
    monkeypatch.setattr(learn_signals, "REFINEMENTS_LOG_PATH", log_path)

    signals_data = _signals_doc([])
    _write_json(sig_path, signals_data)

    result = learn_signals.handle_new_pattern(
        {"kind": "new_pattern", "headline": "a new spam pattern",
         "rationale": "because", "what_this_doesnt_cover": "",
         "confidence": "medium"},
        _example("newpat.eml"),
        signals_data,
        {"accounts": [], "smtp": {}},
        learn_signals.setup_logging(),
    )

    assert result is True
    pending = _read_json(pending_path)
    assert len(pending["conversations"]) == 1
    conv = pending["conversations"][0]
    assert conv["kind"] == "spam_example_proposal"
    assert conv["proposed_refinement"]["headline"] == "a new spam pattern"

    # signals.json's ACTIVE refinements list must be untouched.
    on_disk_signals = _read_json(sig_path)
    assert on_disk_signals["ai_refinements"] == []


# ===========================================================================
# Audit 2026-07-06 C1: the batch/forward learner must be able to produce a
# CURATE rule (legitimate mail the owner is sick of), not only "protect".
# A protect rule can never override an authenticated brand-matched sender, so
# before this fix, training on an unwanted-but-legitimate sender silently did
# nothing. handle_new_pattern already honored rule_class; the prompt now
# supplies it. These tests pin the through-flow and backward-compat.
# ===========================================================================

def _new_pattern_proposal(tmp_path, monkeypatch, classification):
    sig_path = tmp_path / "signals.json"
    pending_path = tmp_path / "pending_signals.json"
    log_path = tmp_path / "signal_refinements.log"
    monkeypatch.setattr(learn_signals, "SIGNALS_PATH", sig_path)
    monkeypatch.setattr(learn_signals, "PENDING_SIGNALS_PATH", pending_path)
    monkeypatch.setattr(learn_signals, "REFINEMENTS_LOG_PATH", log_path)
    signals_data = _signals_doc([])
    _write_json(sig_path, signals_data)
    learn_signals.handle_new_pattern(
        classification, _example("newpat.eml"), signals_data,
        {"accounts": [], "smtp": {}}, learn_signals.setup_logging(),
    )
    return _read_json(pending_path)["conversations"][0]["proposed_refinement"]


def test_c1_learner_curate_classification_produces_curate_rule(tmp_path, monkeypatch):
    ref = _new_pattern_proposal(tmp_path, monkeypatch, {
        "kind": "new_pattern", "headline": "political fundraising from PartyX",
        "rationale": "legit but unwanted", "what_this_doesnt_cover": "",
        "confidence": "high", "rule_class": "curate", "apply_scope": "all"})
    assert ref["rule_class"] == "curate"
    assert ref["scope"] == "all"


def test_c1_learner_omitting_rule_class_defaults_to_protect(tmp_path, monkeypatch):
    # Backward-compat: a model response without rule_class still yields a valid
    # protect rule (pre-fix behavior preserved).
    ref = _new_pattern_proposal(tmp_path, monkeypatch, {
        "kind": "new_pattern", "headline": "phishing pattern",
        "rationale": "credential theft", "what_this_doesnt_cover": "",
        "confidence": "high"})
    assert ref["rule_class"] == "protect"


# ===========================================================================
# 5. retired rule not matched: handle_duplicate returns False, no write.
# ===========================================================================

def test_retired_rule_not_matched(redirected):
    sig_path = redirected["sig_path"]
    signals_data = _signals_doc([_ref("R-RETIRED", match_count=5,
                                      evidence=["old.eml"],
                                      status="retired")])
    _write_json(sig_path, signals_data)

    delta = {}
    result = learn_signals.handle_duplicate(
        {"refinement_id": "R-RETIRED"}, _example("stale.eml"),
        signals_data, {"accounts": []}, learn_signals.setup_logging(),
        delta=delta,
    )

    assert result is False, "a retired rule must not be reinforced"
    target = signals_data["ai_refinements"][0]
    assert target["match_count"] == 5, "retired rule's match_count must be UNCHANGED"
    assert target["evidence"] == ["old.eml"]
    assert delta == {}
    assert len(redirected["sent"]) == 0, "no FYI email for a plain not-found/retired miss"


# ===========================================================================
# 6. Accounting: a run whose SOLE example is a blocked contradiction derives
#    nothing but still advances the watermark.
# ===========================================================================

def _drive_run(monkeypatch, tmp_path, classifications, refinements):
    """Minimal _run harness (mirrors test_phase1a.py's _drive_learner_run):
    fakes config/IO except the real .eml folder scan. Returns (folder, captured)
    where captured collects the persisted watermark and merge_save_signals_delta
    calls, so a test can assert accounting without touching real signals.json."""
    folder = tmp_path / "spam_examples"
    folder.mkdir()
    captured = {"watermark": [], "merge": []}
    monkeypatch.setattr(learn_signals, "load_config", lambda: {
        "signal_learner": {"examples_folder": str(folder)},
        "anthropic": {"api_key": "k", "model": "m"},
        "accounts": [{"username": "owner@example.com"}],
        "smtp": {},
    })
    monkeypatch.setattr(learn_signals, "read_learner_scan_timestamp",
                        lambda cfg: None)
    monkeypatch.setattr(learn_signals, "load_signals",
                        lambda: _signals_doc(refinements))
    monkeypatch.setattr(learn_signals, "parse_eml", lambda f: {
        "filename": os.path.basename(str(f)), "from": "s@x.com",
        "subject": "subj", "received_headers": [], "plain_text_body": "body",
        "user_explanation": "", "forwarder": "owner@example.com"})
    monkeypatch.setattr(learn_signals, "call_claude",
                        lambda prompt, api_config, logger, system=None:
                            {"classifications": classifications})
    monkeypatch.setattr(learn_signals, "save_learner_scan_timestamp",
                        lambda ts: captured["watermark"].append(ts))
    monkeypatch.setattr(
        learn_signals, "merge_save_signals_delta",
        lambda delta, derived_increment=0: captured["merge"].append(
            {"delta": delta, "derived_increment": derived_increment}))
    monkeypatch.setattr(learn_signals, "append_refinement_log", lambda event: None)
    monkeypatch.setattr(learn_signals, "_send", lambda *a, **k: True)
    monkeypatch.setattr(learn_signals.time, "sleep", lambda *a, **k: None)
    return folder, captured


def test_run_sole_blocked_contradiction_derives_nothing_but_advances(
        monkeypatch, tmp_path):
    import logging
    refinements = [_ref("R-LEGIT", match_count=1, verdict="legitimate")]
    classifications = [{"example": "only.eml", "kind": "duplicate_of",
                        "refinement_id": "R-LEGIT"}]
    folder, captured = _drive_run(monkeypatch, tmp_path, classifications,
                                  refinements)
    (folder / "only.eml").write_bytes(b"x")

    rc = learn_signals._run(logging.getLogger("t"))

    assert rc == 0
    assert captured["watermark"], (
        "the watermark must still advance — the example WAS processed")
    assert captured["merge"] == [], (
        "a run whose sole example is a blocked contradiction must persist "
        "NOTHING to signals.json (no merge_save_signals_delta call)")
