#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Provenance-aware undo copy + teach-legitimate honesty warning + junk-cap
default + dashboard whitelist upgrade parity (design-intent audit 2026-07-06).

Covers five fixes:

  Item 1  _entry_provenance_kind classifies every store-entry shape (rule vs
          approve vs typed), in BOTH the engine and the dashboard twin.
  Item 2  Acks/reports name the real "Whitelist / Blacklist" tab (never the
          non-existent "Blacklist tab") and point rule-created blocks at the
          Unwanted Categories tab.
  Item 3  Teaching a sender "legitimate" while a standing blacklist entry still
          blocks it appends an honest warning, branched by provenance — a rule
          entry is NEVER described as a removable entry.
  Item 4  DEFAULT_CONFIG carries max_junk_actions_per_run in lockstep with the
          engine's fallback.
  Item 5  Hand-adding a whitelist address that exists only as an APPROVE dict
          upgrades it to full trust; a plain-string dup is a no-op; a rule dict
          is never flattened.
"""
import logging
import os
import sys
from datetime import datetime

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import spam_filter  # noqa: E402
import daily_report  # noqa: E402
from mailwarden_app import dashboard  # noqa: E402
from mailwarden_app.config_io import DEFAULT_CONFIG  # noqa: E402

_LOG = logging.getLogger("test_provenance_ack_copy")
_LOG.addHandler(logging.NullHandler())

_REAL_WL_BL_TAB = "Whitelist / Blacklist"
_REAL_UNWANTED_TAB = "Unwanted Categories"


# ── Item 1: provenance classifier (engine + dashboard twin, identical) ───────

@pytest.mark.parametrize("classifier", [
    spam_filter._entry_provenance_kind,
    dashboard._entry_provenance_kind,
])
class TestProvenanceKind:
    def test_plain_string_is_typed(self, classifier):
        assert classifier("spammer@evil.test") == "typed"

    def test_dict_without_provenance_is_typed(self, classifier):
        assert classifier({"value": "x@evil.test"}) == "typed"

    def test_scoped_block_dict_is_typed(self, classifier):
        # block-sender / list-command entry: scope but no provenance.
        assert classifier({"value": "x@evil.test", "scope": "all"}) == "typed"

    def test_approve_is_approve(self, classifier):
        assert classifier(
            {"value": "a@gmail.com", "provenance": "approve"}) == "approve"

    def test_rule_owner_list_is_rule(self, classifier):
        assert classifier(
            {"value": "x@evil.test", "scope": "all",
             "provenance": [{"id": "R-20260706-abc", "scope": "all"}]}) == "rule"

    def test_legacy_single_rule_id_string_is_rule(self, classifier):
        assert classifier(
            {"value": "x@evil.test", "provenance": "R-legacy-1"}) == "rule"

    def test_empty_provenance_list_is_typed(self, classifier):
        assert classifier({"value": "x@evil.test", "provenance": []}) == "typed"

    def test_non_dict_non_string_is_typed(self, classifier):
        assert classifier(None) == "typed"


def test_engine_and_dashboard_classifiers_agree():
    shapes = [
        "plain",
        {"value": "v"},
        {"value": "v", "scope": "all"},
        {"value": "v", "provenance": "approve"},
        {"value": "v", "provenance": [{"id": "R-1"}]},
        {"value": "v", "provenance": "R-legacy"},
        {"value": "v", "provenance": []},
        None,
    ]
    for s in shapes:
        assert (spam_filter._entry_provenance_kind(s)
                == dashboard._entry_provenance_kind(s))


# ── Item 3: teach-legitimate honesty warning (engine helper) ─────────────────

def _load_bl(tmp_path, monkeypatch, store: dict):
    """Persist a blacklist.json and load it through the real engine loader so
    the returned store carries the normalized sets check_blacklist consults."""
    import json
    p = tmp_path / "blacklist.json"
    p.write_text(json.dumps(store))
    monkeypatch.setattr(spam_filter, "BLACKLIST_PATH", p)
    return spam_filter.load_blacklist(_LOG)


def test_warning_typed_address_points_to_wl_bl_tab(tmp_path, monkeypatch):
    bl = _load_bl(tmp_path, monkeypatch, {"addresses": ["spammer@evil.test"]})
    warn = spam_filter._teach_legit_blacklist_warning(
        "Spammer <spammer@evil.test>", bl)
    assert warn == spam_filter._TEACH_LEGIT_BL_WARNING_TYPED
    assert _REAL_WL_BL_TAB in warn
    # never the non-existent standalone "the Blacklist tab" name
    assert "the Blacklist tab" not in warn


def test_warning_rule_entry_points_to_unwanted_categories(tmp_path, monkeypatch):
    bl = _load_bl(tmp_path, monkeypatch, {"addresses": [
        {"value": "ruled@evil.test", "scope": "all",
         "provenance": [{"id": "R-20260706-x", "scope": "all"}]}]})
    warn = spam_filter._teach_legit_blacklist_warning(
        "Ruled <ruled@evil.test>", bl)
    assert warn == spam_filter._TEACH_LEGIT_BL_WARNING_RULE
    assert _REAL_UNWANTED_TAB in warn
    # A rule entry must NEVER be described as a removable entry.
    assert "remove that entry" not in warn.lower()
    assert "select" not in warn.lower()


def test_warning_domain_subdomain_match_typed(tmp_path, monkeypatch):
    bl = _load_bl(tmp_path, monkeypatch, {"domains": ["evil.test"]})
    warn = spam_filter._teach_legit_blacklist_warning(
        "Sub <promo@mail.evil.test>", bl)
    assert warn == spam_filter._TEACH_LEGIT_BL_WARNING_TYPED


def test_warning_empty_when_not_blacklisted(tmp_path, monkeypatch):
    bl = _load_bl(tmp_path, monkeypatch, {"addresses": ["other@evil.test"]})
    warn = spam_filter._teach_legit_blacklist_warning(
        "Clean <good@example.org>", bl)
    assert warn == ""


def test_warning_constants_wording():
    typed = spam_filter._TEACH_LEGIT_BL_WARNING_TYPED
    rule = spam_filter._TEACH_LEGIT_BL_WARNING_RULE
    assert _REAL_WL_BL_TAB in typed and "keep going to Junk" in typed
    assert _REAL_UNWANTED_TAB in rule and "still blocking this sender" in rule


# ── Item 3: engine FP corridor end-to-end (real run_filter, seeded blacklist) ─

# Reuse the proven dry-run driver from the FP-teach regression suite so the
# warning is verified on the ACTUAL analysis-email send path, not just the
# helper. _fresh_fp_teach_msg forwards a message from vendor@example.com.
from test_fixes import _dry_run_filter_harness  # noqa: E402
from test_batch2_fixes import _fresh_fp_teach_msg  # noqa: E402


def _seeded_bl(tmp_path, monkeypatch, store):
    import json
    p = tmp_path / "blacklist.json"
    p.write_text(json.dumps(store))
    monkeypatch.setattr(spam_filter, "BLACKLIST_PATH", p)
    return spam_filter.load_blacklist(_LOG)


def _fp_analysis_body(monkeypatch, tmp_path, store):
    monkeypatch.setattr(spam_filter, "lookup_decision", lambda *a, **k: None)
    bl = _seeded_bl(tmp_path, monkeypatch, store)
    calls = _dry_run_filter_harness(
        monkeypatch, uids=[b"1"], msg_data=_fresh_fp_teach_msg(),
        dry_run=False, pending={"conversations": []}, blacklist=bl)
    bodies = [b for (s, b) in calls["send_email_args"]
              if "False Positive Analysis" in s]
    assert bodies, "the FP analysis email must have been sent"
    return bodies[0]


def test_fp_corridor_appends_typed_warning_when_sender_blacklisted(
        monkeypatch, tmp_path):
    body = _fp_analysis_body(
        monkeypatch, tmp_path, {"addresses": ["vendor@example.com"]})
    assert spam_filter._TEACH_LEGIT_BL_WARNING_TYPED in body


def test_fp_corridor_appends_rule_warning_for_rule_block(monkeypatch, tmp_path):
    body = _fp_analysis_body(monkeypatch, tmp_path, {"addresses": [
        {"value": "vendor@example.com", "scope": "all",
         "provenance": [{"id": "R-20260706-x", "scope": "all"}]}]})
    assert spam_filter._TEACH_LEGIT_BL_WARNING_RULE in body


def test_fp_corridor_no_warning_when_not_blacklisted(monkeypatch, tmp_path):
    body = _fp_analysis_body(
        monkeypatch, tmp_path, {"addresses": ["someone-else@example.com"]})
    assert spam_filter._TEACH_LEGIT_BL_WARNING_TYPED not in body
    assert spam_filter._TEACH_LEGIT_BL_WARNING_RULE not in body


# ── Item 2: daily-report unblock sentence names the real tabs ────────────────

def _render_report(bl_blocked, monkeypatch, tmp_path):
    monkeypatch.setattr(daily_report, "LEARNER_STATE_PATH",
                        tmp_path / "no_learner.json")
    config = {"accounts": [{"name": "acct"}],
              "filter": {"dry_run": False}, "signal_learner": {}}
    decisions = {"per_account": {}, "evaluated": 0, "spam_moved": 0,
                 "spam_dry_run": 0, "not_spam": 0, "errors": 0,
                 "spam_entries": []}
    return daily_report.build_report_body(
        config, decisions, datetime.now(), 0, {"derived_from_examples": 0},
        bl_blocked=bl_blocked, bl_totals=(1, 0))


def test_report_unblock_sentence_names_real_tabs(monkeypatch, tmp_path):
    blocked = (1, [{"time": "9:00 AM", "from": "spammer@evil.test",
                    "subject": "hi", "match_type": "address"}])
    body = _render_report(blocked, monkeypatch, tmp_path)
    assert _REAL_WL_BL_TAB in body
    assert _REAL_UNWANTED_TAB in body
    # The old, non-existent tab name must be gone.
    assert "Dashboard's Blacklist tab" not in body


# ── Item 2: engine subject-keyword ack no longer names a fictional tab ───────

def test_no_source_references_to_fictional_blacklist_tab():
    # The real notebook tab is "Whitelist / Blacklist"; nothing should tell an
    # owner to open a "Blacklist tab" / "go to the Blacklist tab".
    for mod in (spam_filter, daily_report):
        src = open(mod.__file__).read()
        assert "go to the Blacklist" not in src, mod.__name__
        assert "Dashboard's Blacklist tab" not in src, mod.__name__


def test_both_teach_paths_wire_the_warning_helper():
    # Item 3 is a thin pass-through around _teach_legit_blacklist_warning, whose
    # branching logic is unit-tested above. Guard the wiring so neither the
    # engine (Fwd: False Positive) nor the dashboard (Check-an-Email legitimate)
    # path can silently drop the honesty warning.
    engine_src = open(spam_filter.__file__).read()
    assert engine_src.count("_teach_legit_blacklist_warning") >= 2  # def + call
    dash_src = open(dashboard.__file__).read()
    assert "_teach_legit_blacklist_warning" in dash_src
    assert "blacklist_warning" in dash_src  # attached + rendered


# ── Item 4: junk-cap default present and in lockstep with the engine ─────────

def test_max_junk_actions_default_present():
    assert DEFAULT_CONFIG["filter"]["max_junk_actions_per_run"] == 25


# ── Item 5: dashboard whitelist hand-add upgrade parity ──────────────────────

def test_whitelist_add_new_value_added():
    items = []
    assert dashboard._whitelist_apply_add(items, "new@example.org") == "added"
    assert items == ["new@example.org"]


def test_whitelist_add_upgrades_approve_dict_to_string():
    items = [{"value": "a@gmail.com", "provenance": "approve"}]
    assert dashboard._whitelist_apply_add(items, "a@gmail.com") == "upgraded"
    assert items == ["a@gmail.com"]  # flattened to full hand-typed trust


def test_whitelist_add_plain_string_duplicate_is_noop():
    items = ["a@gmail.com"]
    assert dashboard._whitelist_apply_add(items, "a@gmail.com") == "duplicate"
    assert items == ["a@gmail.com"]


def test_whitelist_add_rule_dict_never_flattened():
    rule_entry = {"value": "a@gmail.com", "scope": "all",
                  "provenance": [{"id": "R-1", "scope": "all"}]}
    items = [rule_entry]
    assert dashboard._whitelist_apply_add(items, "a@gmail.com") == "duplicate"
    assert items == [rule_entry]  # untouched, still a rule-owned dict


def test_whitelist_add_upgrade_is_case_insensitive():
    items = [{"value": "a@gmail.com", "provenance": "approve"}]
    assert dashboard._whitelist_apply_add(items, "A@Gmail.com") == "upgraded"
    assert items == ["A@Gmail.com"]
