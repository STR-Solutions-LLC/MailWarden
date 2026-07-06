#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Integration-audit finding #17: legacy false-positive "narrowings" (created by
the main email-teach path) were UNSCOPED (global soft_signals), MISLABELED (spam
header though the content is a not-spam exclusion), INVISIBLE/UNDELETABLE in the
Dashboard, and exempt from item-(b) review.

The fix routes approved FP narrowings through the MODERN ai_refinements store and
migrates existing legacy narrowings there once, at live filter startup:
  - verdict "legitimate"  -> rendered as a NOT_SPAM exclusion (relabel fixed)
  - scope "all"           -> SAME global reach preserved (effect preserved)
  - real R- id            -> Dashboard-manageable + item-(b) eligible

These tests are the regression gate. No real owner email content is embedded;
the narrowing strings are structure-identical dummy content.
"""
import copy
import json
import logging
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(SRC))
sys.path.insert(0, os.path.abspath(APP))

import spam_filter  # noqa: E402  (engine tree)
from mailwarden_app import config_io  # noqa: E402  (app tree)
from mailwarden_app import paths as app_paths  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# The path tools/eval_run.py actually reads (REPO/resources/defaults/signals.json).
DEFAULT_SIGNALS = os.path.join(REPO_ROOT, "resources", "defaults", "signals.json")

_LOG = logging.getLogger("fp_migration_test")


def _signals_with_one_narrowing():
    return {"signals": {"soft_signals": [
        "Artificial scarcity claims with round numbers",
        "REFINEMENT (from_analysis): Do not junk authenticated mail from "
        "principal@lincoln-elementary.example (the owner's child's school).",
        "Body offering premium gifts as apology",
    ]}}


# ===========================================================================
# (1) EFFECT PRESERVED ACROSS ACCOUNTS + RELABEL CORRECT
# ===========================================================================

def test_migrated_narrowing_still_suppresses_junk_on_every_account():
    """The migrated narrowing must keep GLOBAL reach: it renders into BOTH
    acctA's and acctB's classifier prompt (scope 'all' -> _refinement_in_scope
    True for every account). This is the hard effect-preservation gate."""
    sig = _signals_with_one_narrowing()
    assert spam_filter.migrate_fp_narrowings(sig, _LOG) is True

    pa = spam_filter.build_classifier_prompt(sig, "acctA@example.test")
    pb = spam_filter.build_classifier_prompt(sig, "acctB@example.test")
    for p in (pa, pb):
        assert "LEARNED LEGITIMATE PATTERN" in p
        assert "lincoln-elementary" in p


def test_migration_relabels_from_spam_signal_to_notspam_exclusion():
    """Before: the narrowing rendered under the spam-signal header as
    'LEARNED SOFT SIGNAL: REFINEMENT (...)'. After: it is a NOT_SPAM steer with
    no REFINEMENT-label leakage."""
    sig = _signals_with_one_narrowing()
    before = spam_filter.build_classifier_prompt(
        copy.deepcopy(sig), "acctA@example.test")
    assert "LEARNED SOFT SIGNAL: REFINEMENT (" in before  # the old mislabel

    spam_filter.migrate_fp_narrowings(sig, _LOG)
    after = spam_filter.build_classifier_prompt(sig, "acctA@example.test")
    assert "REFINEMENT (" not in after
    assert "LEARNED LEGITIMATE PATTERN" in after


def test_migrated_record_shape():
    sig = _signals_with_one_narrowing()
    spam_filter.migrate_fp_narrowings(sig, _LOG)
    refs = sig["ai_refinements"]
    assert len(refs) == 1
    r = refs[0]
    assert r["verdict"] == "legitimate"
    assert r["rule_class"] is None
    assert r["kind"] == "fp_narrowing"
    assert r["scope"] == "all"
    assert r["status"] == "active"
    assert r["id"].startswith("R-")
    assert r["headline"].strip() != ""
    assert r["evidence"] == ["migrated-legacy-narrowing"]


# ===========================================================================
# (2) $0 EVAL GATE — the default config prompt is byte-identical
# ===========================================================================

def test_default_config_prompt_is_byte_identical_after_migration():
    """The shipped-default signals (0 ai_refinements, 0 REFINEMENT soft_signals)
    must migrate to a no-op and leave the classifier prompt byte-identical — so
    the offline eval baseline is unchanged and no paid eval is needed."""
    with open(DEFAULT_SIGNALS) as f:
        defaults = json.load(f)

    before = spam_filter.build_classifier_prompt(
        copy.deepcopy(defaults), "owner@example.test")
    changed = spam_filter.migrate_fp_narrowings(defaults, _LOG)
    after = spam_filter.build_classifier_prompt(defaults, "owner@example.test")

    assert changed is False            # nothing to migrate
    assert before == after             # byte-identical
    assert "[R-" not in after and "matched_rules" not in after
    assert "- LEARNED SOFT SIGNAL:" in after  # defaults still render as before


# ===========================================================================
# (3) IDEMPOTENT + LOSSLESS
# ===========================================================================

def test_migration_is_idempotent():
    sig = _signals_with_one_narrowing()
    assert spam_filter.migrate_fp_narrowings(sig, _LOG) is True
    snapshot = copy.deepcopy(sig)
    # second pass finds no REFINEMENT( entries -> no change, no growth
    assert spam_filter.migrate_fp_narrowings(sig, _LOG) is False
    assert sig == snapshot
    assert len(sig["ai_refinements"]) == 1


def test_migration_is_lossless_keeps_defaults_and_unparseable_entries():
    sig = {"signals": {"soft_signals": [
        "shipped default one",
        "REFINEMENT (from_analysis):    ",           # empty body -> keep, don't drop
        "REFINEMENT (from_analysis): real narrowing text",  # valid -> migrate
        "shipped default two",
    ]}}
    assert spam_filter.migrate_fp_narrowings(sig, _LOG) is True
    remaining = sig["signals"]["soft_signals"]
    # both shipped defaults AND the empty/malformed REFINEMENT line are preserved
    assert "shipped default one" in remaining
    assert "shipped default two" in remaining
    assert "REFINEMENT (from_analysis):    " in remaining
    # exactly one real narrowing became exactly one refinement
    assert len(sig["ai_refinements"]) == 1
    assert sig["ai_refinements"][0]["headline"] == "real narrowing text"


def test_migration_no_soft_signals_is_safe_noop():
    assert spam_filter.migrate_fp_narrowings({"signals": {}}, _LOG) is False
    assert spam_filter.migrate_fp_narrowings({}, _LOG) is False


def test_batch_migration_mints_unique_ids():
    sig = {"signals": {"soft_signals": [
        "REFINEMENT (from_analysis): first",
        "REFINEMENT (from_analysis): second",
        "REFINEMENT (from_analysis): third",
    ]}}
    spam_filter.migrate_fp_narrowings(sig, _LOG)
    ids = [r["id"] for r in sig["ai_refinements"]]
    assert len(ids) == 3
    assert len(set(ids)) == 3


# ===========================================================================
# (4) DASHBOARD: a migrated entry is visible + deletable (via config_io, the
#     exact code the Dashboard's Active-refinements card + Delete button use)
# ===========================================================================

def test_migrated_entry_visible_and_deletable_via_config_io(monkeypatch, tmp_path):
    mem = tmp_path / "memory"
    mem.mkdir()
    monkeypatch.setattr(app_paths, "SIGNALS_PATH", mem / "signals.json")
    monkeypatch.setattr(app_paths, "REFINEMENTS_LOG",
                        mem / "signal_refinements.log")

    sig = {"signals": {"soft_signals": [
        "REFINEMENT (from_analysis): keep my accountant's monthly invoices",
        "a shipped default",
    ]}}
    spam_filter.migrate_fp_narrowings(sig, _LOG)
    (mem / "signals.json").write_text(json.dumps(sig))

    # Dashboard READ path (config_io.list_active_refinements feeds _render_active)
    active = config_io.list_active_refinements()
    assert len(active) == 1
    rid = active[0]["id"]
    assert active[0]["verdict"] == "legitimate"
    assert active[0]["kind"] == "fp_narrowing"

    # Dashboard DELETE path — identical to deleting a modern refinement
    assert config_io.delete_active_refinement(rid) is True
    assert config_io.list_active_refinements() == []
    log_txt = (mem / "signal_refinements.log").read_text()
    assert '"event": "deleted"' in log_txt


# ===========================================================================
# (5) run_filter LIVE-TICK e2e — migration is wired into live startup and is
#     S4-gated (never runs / never writes in dry-run)
# ===========================================================================

def test_migration_runs_in_live_startup_and_triggers_save(monkeypatch):
    from test_fixes import _dry_run_filter_harness  # noqa: E402
    calls = {"n": 0}

    def _spy_migrate(signals, logger):
        calls["n"] += 1
        return True  # report "changed" so the startup block must persist

    monkeypatch.setattr(spam_filter, "migrate_fp_narrowings", _spy_migrate)
    harness_calls = _dry_run_filter_harness(monkeypatch, dry_run=False)

    assert calls["n"] == 1                       # ran once, at live startup
    assert harness_calls["save_signals"] >= 1    # dirty -> signals persisted


def test_migration_skipped_and_no_write_in_dry_run(monkeypatch):
    from test_fixes import _dry_run_filter_harness  # noqa: E402
    calls = {"n": 0}

    def _spy_migrate(signals, logger):
        calls["n"] += 1
        return True

    monkeypatch.setattr(spam_filter, "migrate_fp_narrowings", _spy_migrate)
    harness_calls = _dry_run_filter_harness(monkeypatch, dry_run=True)

    assert calls["n"] == 0                        # S4: never runs in dry-run
    assert harness_calls["save_signals"] == 0     # dry-run never writes signals
