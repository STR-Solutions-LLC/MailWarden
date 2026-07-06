#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Batch C — owner-authored "Unwanted Categories" curate rules + a
_min_cacheable_for_model version-boundary fix.

The feature reuses the EXISTING curate mechanism end-to-end: an authored rule
is a normal curate ai_refinement (verdict "spam", rule_class "curate") that the
owner typed directly instead of teaching from an example. Provenance is marked
with source==config_io.AUTHORED_SOURCE so the editor can manage authored rules
on their own and the learner/contradiction guard is never surprised.

What these tests pin:
  * the authored record round-trips through config_io storage with the
    provenance marker and the learned-curate shape;
  * it reaches the classifier on the SAME spam_filter._build_learned_lines
    "USER PREFERENCE (curate)" path as a learned curate rule (byte-identical
    rendered body);
  * the Feature-4 contradiction guard (learn_signals.handle_duplicate) does NOT
    treat an authored curate rule as a contradiction — it reinforces normally;
  * enable / disable / delete via the config_io twins keep the engine reader
    (spam_filter._build_learned_lines) and the app writer in sync;
  * the Dashboard filters authored rules out of the Signal-History surfaces;
  * _min_cacheable_for_model matches only on a version boundary (a future
    claude-sonnet-4-50 can't prefix-match claude-sonnet-4-5).

All Anthropic calls are fully mocked / absent; NO real API calls (including
count_tokens) are made. file_lock is the REAL flock — never mocked. Every file
touched lives under pytest's tmp_path.

Run with the dedicated test venv:
  tests/.venv/bin/python -m pytest tests/test_batchC_unwanted_categories.py -v
"""
import copy
import inspect
import logging
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

import file_lock  # noqa: E402,F401  (REAL flock — never mocked)
import learn_signals  # noqa: E402
import spam_filter  # noqa: E402
from mailwarden_app import breadth_advisor  # noqa: E402
from mailwarden_app import config_io  # noqa: E402
from mailwarden_app import dashboard  # noqa: E402
from mailwarden_app import help_content  # noqa: E402
from mailwarden_app import paths as app_paths  # noqa: E402

_LOG = logging.getLogger("test_batchC")
_LOG.addHandler(logging.NullHandler())

_EXAMPLE_HEADLINE = "political fundraising from Republican campaigns"

# The exact curate body spam_filter._build_learned_lines renders for a curate
# rule with the example headline and an empty rationale. Pinned verbatim so a
# wording change to the shared curate path is caught here too.
_EXPECTED_CURATE_BODY = (
    f"USER PREFERENCE (curate): {_EXAMPLE_HEADLINE} — the user has "
    "chosen NOT to receive this kind of LEGITIMATE mail; for "
    "this account, treat mail that clearly matches as unwanted "
    "(junk it) EVEN THOUGH it is not bad-actor spam. Apply ONLY "
    "to mail that unmistakably matches this narrow preference; "
    "NEVER extend it to adjacent legitimate mail, and never junk "
    "an authenticated sender over a single keyword."
)


@pytest.fixture
def signals_env(monkeypatch, tmp_path):
    """Point config_io's signals + refinement-log paths at a tmp dir so
    create/list/toggle/delete write real files under pytest's tmp_path."""
    mem = tmp_path / "memory"
    mem.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(app_paths, "SIGNALS_PATH", mem / "signals.json")
    monkeypatch.setattr(app_paths, "REFINEMENTS_LOG",
                        mem / "signal_refinements.log")
    return mem


# ---------------------------------------------------------------------------
# _min_cacheable_for_model — version-boundary match (Batch B review note)
# ---------------------------------------------------------------------------

def test_min_cacheable_matches_only_on_version_boundary():
    t = spam_filter.resolve_min_cacheable_tokens()
    # Whole-id and dated-suffix ids still resolve to their table entry.
    assert spam_filter._min_cacheable_for_model("claude-sonnet-4-5", t) == 1024
    assert spam_filter._min_cacheable_for_model(
        "claude-haiku-4-5-20251001", t) == 4096
    # A future point/dated release that merely PREFIXES an entry must NOT borrow
    # it — "claude-sonnet-4-50" is not "claude-sonnet-4-5" on a boundary, so it
    # falls through to the conservative default instead of inheriting 1024.
    assert spam_filter._min_cacheable_for_model(
        "claude-sonnet-4-50", t) == spam_filter._CONSERVATIVE_MIN_CACHEABLE_TOKENS
    assert spam_filter._min_cacheable_for_model(
        "claude-sonnet-4-50", t) != 1024
    # A digit-run extension of a haiku id likewise does not match the haiku key.
    assert spam_filter._min_cacheable_for_model(
        "claude-haiku-4-50", t) == spam_filter._CONSERVATIVE_MIN_CACHEABLE_TOKENS


def test_min_cacheable_unknown_model_still_conservative():
    t = spam_filter.resolve_min_cacheable_tokens()
    assert spam_filter._min_cacheable_for_model("brand-new-thing", t) == \
        spam_filter._CONSERVATIVE_MIN_CACHEABLE_TOKENS


# ---------------------------------------------------------------------------
# build_authored_curate_refinement — pure shape + provenance
# ---------------------------------------------------------------------------

def test_build_authored_curate_shape_and_provenance():
    rec = config_io.build_authored_curate_refinement(
        "R-TEST-1", _EXAMPLE_HEADLINE, "all")
    assert rec["id"] == "R-TEST-1"
    assert rec["headline"] == _EXAMPLE_HEADLINE
    assert rec["verdict"] == "spam"
    assert rec["rule_class"] == "curate"
    assert rec["status"] == "active"
    assert rec["scope"] == "all"
    assert rec["source"] == config_io.AUTHORED_SOURCE == "user_authored"
    # No example / no Claude rationale on an authored rule.
    assert rec["evidence"] == []
    assert rec["rationale"] == ""


def test_build_authored_curate_rejects_blank():
    assert config_io.build_authored_curate_refinement("R", "   ", "all") is None
    assert config_io.build_authored_curate_refinement("R", "", "all") is None


# ---------------------------------------------------------------------------
# create_authored_refinement — round-trips through storage with provenance
# ---------------------------------------------------------------------------

def test_create_authored_round_trips_with_provenance(signals_env):
    rec = config_io.create_authored_refinement(_EXAMPLE_HEADLINE, "all")
    assert rec is not None
    assert rec["id"].startswith("R-")
    # It is persisted and readable back with the provenance marker intact.
    stored = config_io.load_signals().get("ai_refinements", [])
    assert len(stored) == 1
    saved = stored[0]
    assert saved["id"] == rec["id"]
    assert saved["source"] == config_io.AUTHORED_SOURCE
    assert saved["rule_class"] == "curate"
    assert saved["verdict"] == "spam"
    assert saved["status"] == "active"


def test_create_authored_blank_writes_nothing(signals_env):
    assert config_io.create_authored_refinement("   ", "all") is None
    assert config_io.load_signals().get("ai_refinements", []) == []


def test_create_authored_scoped_to_subset(signals_env):
    rec = config_io.create_authored_refinement(
        _EXAMPLE_HEADLINE, ["me@example.com"])
    assert rec["scope"] == ["me@example.com"]


# ---------------------------------------------------------------------------
# Prompt injection — SAME path as a learned curate rule
# ---------------------------------------------------------------------------

def test_authored_curate_renders_on_curate_prompt_path():
    """An authored curate record fed to the ENGINE's _build_learned_lines
    renders the exact 'USER PREFERENCE (curate)' body (attribution ON prefixes
    the id)."""
    rec = config_io.build_authored_curate_refinement(
        "R-20260705-abc", _EXAMPLE_HEADLINE, "all")
    signals = {"signals": {}, "ai_refinements": [rec]}
    lines, injected_ids, attribution_on = spam_filter._build_learned_lines(
        signals, account_name=None)
    assert attribution_on is True
    assert "R-20260705-abc" in injected_ids
    assert lines == [f"- [R-20260705-abc] {_EXPECTED_CURATE_BODY}"]


def test_authored_and_learned_curate_render_identically():
    """Provenance does NOT change the prompt: an authored curate rule and a
    LEARNED curate rule with the same headline render byte-identical bodies."""
    authored = config_io.build_authored_curate_refinement(
        "R-A", _EXAMPLE_HEADLINE, "all")
    learned = dict(authored)
    learned["id"] = "R-A"                       # same id -> compare bodies only
    learned["source"] = "check_screen"          # learned provenance
    learned["evidence"] = ["some-example.eml"]  # learned rules carry an example
    a_lines = spam_filter._build_learned_lines(
        {"signals": {}, "ai_refinements": [authored]}, None)[0]
    l_lines = spam_filter._build_learned_lines(
        {"signals": {}, "ai_refinements": [learned]}, None)[0]
    assert a_lines == l_lines


def test_authored_curate_is_not_the_legitimate_branch():
    """Regression guard: a curate rule must NOT render as a LEARNED LEGITIMATE
    PATTERN (that branch is gated on verdict=='legitimate', which an authored
    curate rule never has)."""
    rec = config_io.build_authored_curate_refinement("R", _EXAMPLE_HEADLINE, "all")
    lines = spam_filter._build_learned_lines(
        {"signals": {}, "ai_refinements": [rec]}, None)[0]
    assert "USER PREFERENCE (curate)" in lines[0]
    assert "LEARNED LEGITIMATE PATTERN" not in lines[0]
    assert "LEARNED THREAT PATTERN" not in lines[0]


# ---------------------------------------------------------------------------
# Contradiction guard (Feature 4) treats an authored curate rule sanely
# ---------------------------------------------------------------------------

def test_contradiction_guard_reinforces_authored_curate(monkeypatch):
    """learn_signals.handle_duplicate blocks reinforcement ONLY for a rule the
    owner taught as verdict=='legitimate'. An authored curate rule is
    verdict=='spam', so a matching Train drop reinforces it normally (bumps
    match_count, records the delta) — no surprise contradiction block."""
    sent = []
    monkeypatch.setattr(learn_signals, "_send",
                        lambda *a, **k: sent.append(a))
    monkeypatch.setattr(learn_signals, "append_refinement_log",
                        lambda *a, **k: None)

    rec = config_io.build_authored_curate_refinement(
        "R-CURATE", _EXAMPLE_HEADLINE, "all")
    signals_data = {"signals": {}, "ai_refinements": [rec]}
    config = {"accounts": [{"username": "owner@example.com"}]}
    classification = {"refinement_id": "R-CURATE", "note": "another one"}
    example = {"filename": "drop-1.eml"}
    delta = {}

    ok = learn_signals.handle_duplicate(
        classification, example, signals_data, config, _LOG,
        smtp_conn=None, delta=delta)

    assert ok is True                       # reinforced, NOT blocked
    assert rec["match_count"] == 1          # 0 -> 1
    assert "R-CURATE" in delta              # persistent delta recorded


def test_contradiction_guard_still_blocks_legitimate(monkeypatch):
    """Parity check: the guard still blocks a verdict=='legitimate' rule (so the
    curate carve-out above is specific, not a hole in the guard)."""
    monkeypatch.setattr(learn_signals, "_send", lambda *a, **k: None)
    monkeypatch.setattr(learn_signals, "append_refinement_log",
                        lambda *a, **k: None)
    legit = {"id": "R-LEGIT", "verdict": "legitimate", "status": "active",
             "headline": "receipts from my bank", "match_count": 3}
    signals_data = {"signals": {}, "ai_refinements": [legit]}
    config = {"accounts": [{"username": "owner@example.com"}]}
    ok = learn_signals.handle_duplicate(
        {"refinement_id": "R-LEGIT"}, {"filename": "x.eml"},
        signals_data, config, _LOG, smtp_conn=None, delta={})
    assert ok is False
    assert legit["match_count"] == 3        # untouched


# ---------------------------------------------------------------------------
# Enable / disable / delete via config_io twins — engine + app stay in sync
# ---------------------------------------------------------------------------

def _curate_line_present(account=None) -> bool:
    signals = config_io.load_signals()
    lines = spam_filter._build_learned_lines(signals, account)[0]
    return any("USER PREFERENCE (curate)" in ln for ln in lines)


def test_toggle_and_delete_keep_engine_and_app_in_sync(signals_env):
    rec = config_io.create_authored_refinement(_EXAMPLE_HEADLINE, "all")
    rid = rec["id"]

    # ACTIVE -> the engine reader injects it.
    assert _curate_line_present() is True

    # DISABLE (config_io.retire_refinement twin) -> status retired, engine drops it.
    assert config_io.retire_refinement(rid) is True
    disabled = config_io.load_signals()["ai_refinements"][0]
    assert disabled["status"] == "retired"
    assert "retired_at" in disabled
    assert _curate_line_present() is False

    # Re-disabling is idempotent (already inactive).
    assert config_io.retire_refinement(rid) is False

    # ENABLE (existing restore_refinement twin) -> active again, engine injects it.
    assert config_io.restore_refinement(rid) is not None
    assert config_io.load_signals()["ai_refinements"][0]["status"] == "active"
    assert _curate_line_present() is True

    # DELETE (existing delete_active_refinement) -> gone from storage + engine.
    assert config_io.delete_active_refinement(rid) is True
    assert config_io.load_signals().get("ai_refinements", []) == []
    assert _curate_line_present() is False


def test_delete_works_on_a_disabled_authored_rule(signals_env):
    rec = config_io.create_authored_refinement(_EXAMPLE_HEADLINE, "all")
    rid = rec["id"]
    assert config_io.retire_refinement(rid) is True     # disabled first
    assert config_io.delete_active_refinement(rid) is True
    assert config_io.load_signals().get("ai_refinements", []) == []


# ---------------------------------------------------------------------------
# list_authored_refinements — authored only, active + disabled, newest first
# ---------------------------------------------------------------------------

def test_list_authored_returns_authored_active_and_disabled_only(signals_env):
    a = config_io.create_authored_refinement("first category", "all")
    b = config_io.create_authored_refinement("second category", "all")
    # A learned (non-authored) refinement must NOT appear in the authored list.
    data = config_io.load_signals()
    data["ai_refinements"].append({
        "id": "R-LEARNED", "source": "check_screen", "rule_class": "curate",
        "verdict": "spam", "status": "active", "headline": "learned one",
        "first_learned": "2020-01-01T00:00:00",
    })
    config_io.save_signals(data)
    # Disable one authored rule — it must still be listed (editor shows off rules).
    assert config_io.retire_refinement(a["id"]) is True

    out = config_io.list_authored_refinements()
    ids = [r["id"] for r in out]
    assert "R-LEARNED" not in ids
    assert set(ids) == {a["id"], b["id"]}
    # Newest first by first_learned (b created after a).
    assert ids[0] == b["id"]


# ---------------------------------------------------------------------------
# Dashboard wiring (headless source inspection — no Tk instantiation)
# ---------------------------------------------------------------------------

def test_dashboard_registers_unwanted_categories_tab():
    src = inspect.getsource(dashboard.Dashboard.__init__)
    assert "UnwantedCategoriesTab" in src
    assert '"Unwanted Categories"' in src


def test_unwanted_tab_wires_the_data_path():
    # Creation now lives in _create_rule (reached directly or via the breadth
    # advisor's add-anyway / fail-open paths); _on_add kicks off the check.
    create_src = inspect.getsource(dashboard.UnwantedCategoriesTab._create_rule)
    assert "create_authored_refinement" in create_src
    dis_src = inspect.getsource(dashboard.UnwantedCategoriesTab._on_disable)
    assert "retire_refinement" in dis_src
    en_src = inspect.getsource(dashboard.UnwantedCategoriesTab._on_enable)
    assert "restore_refinement" in en_src
    del_src = inspect.getsource(dashboard.UnwantedCategoriesTab._on_delete)
    assert "delete_active_refinement" in del_src
    list_src = inspect.getsource(dashboard.UnwantedCategoriesTab._render_list)
    assert "list_authored_refinements" in list_src


def test_signal_history_excludes_authored_rules():
    """Authored rules are managed only in the Unwanted Categories tab, so the
    Signal-History active + dropped renders filter them out (avoids a second
    management surface for the same rule)."""
    active_src = inspect.getsource(dashboard.SignalsTab._render_active)
    assert "AUTHORED_SOURCE" in active_src
    dropped_src = inspect.getsource(dashboard.SignalsTab._render_dropped)
    assert "AUTHORED_SOURCE" in dropped_src


def test_help_documents_unwanted_categories():
    titles = [t for (t, _b) in help_content.HELP_TAB_SECTIONS]
    assert any("Unwanted Categories" in t for t in titles)
    body = help_content.UNWANTED_CATEGORIES_HELP
    # Must document the essentials in plain English.
    assert "only affects mail" in body.lower() or "after you add" in body.lower()
    assert "whitelist" in body.lower()
    assert "delete" in body.lower()


# ===========================================================================
# Breadth advisor — authoring-time heads-up for broad category rules
# (Matt's constraint-3 decision: keep classification behavior; advise at
# rule-CREATION time instead. App-side only; NEVER blocks rule creation.)
# ===========================================================================

class _FakeContentBlock:
    def __init__(self, text):
        self.text = text


class _FakeResp:
    def __init__(self, text):
        self.content = [_FakeContentBlock(text)]


class _FakeMessages:
    def __init__(self, text=None, exc=None):
        self._text = text
        self._exc = exc
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self._exc is not None:
            raise self._exc
        return _FakeResp(self._text)


class _FakeClient:
    """Stand-in for anthropic.Anthropic — NO real API call is ever made."""
    def __init__(self, text=None, exc=None):
        self.messages = _FakeMessages(text=text, exc=exc)


# ---- _parse_breadth_verdict (pure) ----

def test_parse_verdict_clean_json():
    v = breadth_advisor._parse_breadth_verdict(
        '{"broad": true, "concern": "hides wanted news", "suggestion": "name senders"}')
    assert v == {"broad": True, "concern": "hides wanted news",
                 "suggestion": "name senders"}


def test_parse_verdict_strips_code_fence_and_prose():
    fenced = "```json\n{\"broad\": false, \"concern\": \"\", \"suggestion\": \"\"}\n```"
    assert breadth_advisor._parse_breadth_verdict(fenced)["broad"] is False
    prosed = 'Sure! Here is my answer: {"broad": true, "concern": "x", "suggestion": "y"} — hope that helps'
    assert breadth_advisor._parse_breadth_verdict(prosed)["broad"] is True


def test_parse_verdict_rejects_garbage():
    assert breadth_advisor._parse_breadth_verdict("") is None
    assert breadth_advisor._parse_breadth_verdict("not json at all") is None
    # Valid JSON but missing the required 'broad' key -> unusable.
    assert breadth_advisor._parse_breadth_verdict('{"concern": "x"}') is None


# ---- check_category_breadth (mock client) ----

def test_check_breadth_broad_verdict_passes_through():
    client = _FakeClient(
        text='{"broad": true, "concern": "might hide a newsletter you like", "suggestion": "name the specific senders"}')
    out = breadth_advisor.check_category_breadth(
        "newsletters", "sk-ant-x", "claude-haiku-4-5", client=client)
    assert out["reason"] == "ok"
    assert out["broad"] is True
    assert out["concern"] == "might hide a newsletter you like"
    assert out["suggestion"] == "name the specific senders"
    # The description was sent as data, not as a system instruction.
    assert "newsletters" in client.messages.calls[0]["messages"][0]["content"]


def test_check_breadth_not_broad_verdict():
    client = _FakeClient(text='{"broad": false, "concern": "", "suggestion": ""}')
    out = breadth_advisor.check_category_breadth(
        _EXAMPLE_HEADLINE, "sk-ant-x", "claude-haiku-4-5", client=client)
    assert out["reason"] == "ok"
    assert out["broad"] is False


def test_check_breadth_no_key_fails_open_without_calling():
    # client=None + empty key -> no network, reason "no_key".
    out = breadth_advisor.check_category_breadth(
        "newsletters", "", "claude-haiku-4-5")
    assert out["reason"] == "no_key"
    assert out["broad"] is False


def test_check_breadth_api_error_fails_open():
    client = _FakeClient(exc=RuntimeError("network down"))
    out = breadth_advisor.check_category_breadth(
        "newsletters", "sk-ant-x", "claude-haiku-4-5", client=client)
    assert out["reason"] == "error"
    assert out["broad"] is False


def test_check_breadth_unparseable_response_fails_open():
    client = _FakeClient(text="the model rambled without any JSON")
    out = breadth_advisor.check_category_breadth(
        "newsletters", "sk-ant-x", "claude-haiku-4-5", client=client)
    assert out["reason"] == "error"
    assert out["broad"] is False


# ---- should_warn gate ----

def test_should_warn_only_for_ok_and_broad():
    assert breadth_advisor.should_warn(
        {"reason": "ok", "broad": True}) is True
    assert breadth_advisor.should_warn(
        {"reason": "ok", "broad": False}) is False
    assert breadth_advisor.should_warn(
        {"reason": "error", "broad": True}) is False    # fail-open never warns
    assert breadth_advisor.should_warn(
        {"reason": "no_key", "broad": True}) is False
    assert breadth_advisor.should_warn({}) is False


# ---- stored rule is identical regardless of advisor path ----

def test_stored_rule_identical_regardless_of_advisor_path(signals_env):
    """The advisor is read-only: whatever path the GUI takes (direct add, add
    anyway, or fail-open), the SAME (desc, scope) reach create_authored_refinement,
    so the stored record is identical apart from its minted id/timestamps."""
    r1 = config_io.create_authored_refinement(_EXAMPLE_HEADLINE, "all")
    config_io.delete_active_refinement(r1["id"])
    r2 = config_io.create_authored_refinement(_EXAMPLE_HEADLINE, "all")
    drop = {"id", "first_learned", "last_reinforced"}
    assert {k: v for k, v in r1.items() if k not in drop} == \
           {k: v for k, v in r2.items() if k not in drop}


def test_breadth_advisor_never_writes_storage():
    """The advisor must not touch the refinement store — creation stays the sole
    responsibility of config_io, so the stored rule can't differ by path."""
    import mailwarden_app.breadth_advisor as mod
    src = inspect.getsource(mod)
    assert "create_authored_refinement" not in src
    assert "save_signals" not in src
    assert "signals.json" not in src


# ---- Dashboard wiring (headless source inspection) ----

def test_add_flow_runs_breadth_check_then_gates():
    add_src = inspect.getsource(dashboard.UnwantedCategoriesTab._on_add)
    # Resolves the screen model and hands off to the worker breadth check.
    assert "screen_model" in add_src
    assert "_do_breadth_check" in add_src
    do_src = inspect.getsource(dashboard.UnwantedCategoriesTab._do_breadth_check)
    assert "check_category_breadth" in do_src
    after_src = inspect.getsource(
        dashboard.UnwantedCategoriesTab._after_breadth_check)
    assert "should_warn" in after_src               # broad -> warn gate
    assert '"error"' in after_src or "'error'" in after_src   # fail-open note


def test_broad_warning_has_both_buttons_and_prefills():
    warn_src = inspect.getsource(
        dashboard.UnwantedCategoriesTab._show_broad_warning)
    assert "Add it anyway" in warn_src
    assert "Let me revise" in warn_src
    assert "_create_rule" in warn_src               # add-anyway creates the rule
    assert "self._desc_var.set(suggestion)" in warn_src   # revise prefills


def test_create_rule_is_the_single_write_point():
    create_src = inspect.getsource(dashboard.UnwantedCategoriesTab._create_rule)
    assert "create_authored_refinement" in create_src


def test_help_documents_breadth_heads_up():
    body = help_content.UNWANTED_CATEGORIES_HELP.lower()
    assert "broad" in body
    assert "add it anyway" in body or "revise" in body
