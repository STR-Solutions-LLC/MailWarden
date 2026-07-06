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

# The exact body spam_filter._build_learned_lines renders for a USER-AUTHORED
# curate rule (source=="user_authored") with the example headline and an empty
# rationale. The hybrid rework makes the owner's own written rule OUTRANK
# authenticated-sender protection, so its wording differs from a LEARNED curate
# rule's. Pinned verbatim so a wording change to this path is caught here.
_EXPECTED_AUTHORED_BODY = (
    "USER PREFERENCE (curate, the user's own written rule): "
    f"{_EXAMPLE_HEADLINE} — the user WROTE this rule to stop "
    "receiving this kind of LEGITIMATE mail; for this "
    "account, junk any mail that clearly matches what the "
    "user described, EVEN from an authenticated, brand-"
    "matched sender. The user's own rule OUTRANKS "
    "authenticated-sender protection here, because the user "
    "explicitly asked for this mail to be removed. Match it "
    "as the user described (for example the exact subject "
    "tag or sender they named); NEVER extend it to adjacent "
    "legitimate mail the user did not describe. This is the "
    "user's preference, not a bad-actor threat."
)

# The exact body for a LEARNED curate rule (any source other than
# "user_authored"). This is the CAUTIOUS wording, byte-identical to before the
# rework — it must NEVER junk an authenticated sender over a single keyword.
_EXPECTED_LEARNED_CURATE_BODY = (
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


@pytest.fixture
def stores_env(monkeypatch, signals_env):
    """signals_env PLUS the blacklist.json path, so the deterministic-entry
    cascade (create/retire/restore/delete) writes real files under tmp_path."""
    monkeypatch.setattr(app_paths, "BLACKLIST_PATH",
                        signals_env / "blacklist.json")
    return signals_env


@pytest.fixture
def cross_tree_env(monkeypatch, stores_env):
    """stores_env (config_io/app side) PLUS the ENGINE (spam_filter) pointed at
    the SAME signals.json + blacklist.json + refinement log, so an authored rule
    created via config_io (dashboard) can be DROPped/RESTOREd via the engine
    (email corridor) against one shared set of files — the real cross-tree path."""
    monkeypatch.setattr(spam_filter, "SIGNALS_PATH", stores_env / "signals.json")
    monkeypatch.setattr(spam_filter, "BLACKLIST_PATH",
                        stores_env / "blacklist.json")
    monkeypatch.setattr(spam_filter, "REFINEMENTS_LOG_PATH",
                        stores_env / "signal_refinements.log")
    # spam_filter.save_signals is imported FROM learn_signals, which writes to
    # its OWN SIGNALS_PATH — point that at the same tmp file so the engine's
    # retire/unretire round-trips through the shared store.
    monkeypatch.setattr(learn_signals, "SIGNALS_PATH", stores_env / "signals.json")
    return stores_env


def _read_blacklist(mem) -> dict:
    import json
    p = mem / "blacklist.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _owner_ids(entry) -> list:
    """Rule ids owning a blacklist entry across every provenance shape (list of
    {"id","scope"}, list of id strings, or a legacy single string)."""
    prov = entry.get("provenance") if isinstance(entry, dict) else None
    if isinstance(prov, str):
        return [prov] if prov.strip() else []
    ids = []
    for p in (prov or []):
        if isinstance(p, dict):
            ids.append(p.get("id"))
        elif isinstance(p, str):
            ids.append(p)
    return ids


def _entry_scope_for(mem, value, field="subject_keywords"):
    """The stored scope of the blacklist entry with ``value`` (or None)."""
    for i in _read_blacklist(mem).get(field, []):
        if isinstance(i, dict) and i.get("value") == value:
            return i.get("scope")
    return None


def _det(subject_tokens=(), addresses=(), domains=(), residual="",
         enforcement="deterministic"):
    """Build an enforcement dict the way breadth_advisor.extract_enforcement
    would, for feeding straight into create_authored_refinement in tests."""
    entries = ([{"kind": "subject_keyword", "value": t} for t in subject_tokens]
               + [{"kind": "address", "value": a} for a in addresses]
               + [{"kind": "domain", "value": d} for d in domains])
    return {"enforcement": enforcement, "residual_text": residual,
            "subject_tokens": list(subject_tokens),
            "sender_addresses": list(addresses),
            "sender_domains": list(domains),
            "deterministic_entries": entries, "list_like": False,
            "source": "advisor"}


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
    renders the exact USER-AUTHORED 'USER PREFERENCE (curate)' body (attribution
    ON prefixes the id). A legacy authored rule with no enforcement field still
    injects its full headline (behaves as before for injection)."""
    rec = config_io.build_authored_curate_refinement(
        "R-20260705-abc", _EXAMPLE_HEADLINE, "all")
    signals = {"signals": {}, "ai_refinements": [rec]}
    lines, injected_ids, attribution_on = spam_filter._build_learned_lines(
        signals, account_name=None)
    assert attribution_on is True
    assert "R-20260705-abc" in injected_ids
    assert lines == [f"- [R-20260705-abc] {_EXPECTED_AUTHORED_BODY}"]


def test_authored_and_learned_curate_render_differently():
    """The rework INTENTIONALLY splits the two curate wordings by provenance: a
    user-authored rule OUTRANKS authenticated-sender protection; a learned rule
    keeps the cautious wording. Same headline, different body — and each is the
    pinned verbatim string."""
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
    assert a_lines != l_lines
    # User-authored: the rule OUTRANKS authenticated-sender protection.
    assert a_lines == [f"- [R-A] {_EXPECTED_AUTHORED_BODY}"]
    assert "OUTRANKS" in a_lines[0]
    assert "never junk an authenticated sender over a single keyword" \
        not in a_lines[0]
    # Learned: cautious wording, byte-identical to before the rework.
    assert l_lines == [f"- [R-A] {_EXPECTED_LEARNED_CURATE_BODY}"]
    assert "never junk an authenticated sender over a single keyword" \
        in l_lines[0]
    assert "OUTRANKS" not in l_lines[0]


def test_authored_curate_is_not_the_legitimate_branch():
    """Regression guard: a curate rule must NOT render as a LEARNED LEGITIMATE
    PATTERN (that branch is gated on verdict=='legitimate', which an authored
    curate rule never has)."""
    rec = config_io.build_authored_curate_refinement("R", _EXAMPLE_HEADLINE, "all")
    lines = spam_filter._build_learned_lines(
        {"signals": {}, "ai_refinements": [rec]}, None)[0]
    # "(curate" (no closing paren) matches both the authored "(curate, the
    # user's own written rule)" and the learned "(curate)" wording.
    assert "USER PREFERENCE (curate" in lines[0]
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
    return any("USER PREFERENCE (curate" in ln for ln in lines)


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


# ===========================================================================
# Hybrid deterministic + AI enforcement (the rework):
#   authoring-time marker extraction, provenance store writes, injection
#   routing, retire/restore/delete cascade, per-account scope, guardrail.
# ===========================================================================

# ---- extraction: advisor payload + local fallback ----

def test_extract_enforcement_advisor_deterministic():
    """The advisor payload names an exact subject tag and leaves no residual ->
    deterministic; the tag becomes a lowercased subject_keyword entry."""
    verdict = {"reason": "ok", "broad": False, "concern": "", "suggestion": "",
               "subject_tokens": ["[PSIAN]"], "sender_addresses": [],
               "sender_domains": [], "residual_text": "", "list_like": False}
    e = breadth_advisor.extract_enforcement(
        "Emails from the [PSIAN] listserve.", verdict)
    assert e["enforcement"] == "deterministic"
    assert e["source"] == "advisor"
    assert e["deterministic_entries"] == [
        {"kind": "subject_keyword", "value": "[psian]"}]
    assert e["residual_text"] == ""


def test_extract_enforcement_advisor_mixed_keeps_residual():
    verdict = {"reason": "ok", "subject_tokens": ["webinar"],
               "sender_addresses": [], "sender_domains": [],
               "residual_text": "from vendors I don't know", "list_like": False}
    e = breadth_advisor.extract_enforcement("webinar invites", verdict)
    assert e["enforcement"] == "mixed"
    assert e["residual_text"] == "from vendors I don't know"
    assert {"kind": "subject_keyword", "value": "webinar"} in \
        e["deterministic_entries"]


def test_extract_enforcement_local_fallback_bracket_quote_address():
    """Advisor unavailable (verdict None) -> local regex pulls a [bracketed] tag,
    a "quoted" phrase, and an email address out of the rule text."""
    e = breadth_advisor.extract_enforcement(
        'block "webinar" mail and [ACME] tagged mail from noreply@vendor.com',
        None)
    assert e["source"] == "local"
    kinds = {(x["kind"], x["value"]) for x in e["deterministic_entries"]}
    assert ("subject_keyword", "[acme]") in kinds
    assert ("subject_keyword", "webinar") in kinds
    assert ("address", "noreply@vendor.com") in kinds
    # Fail-open with markers -> mixed (AI still sees the whole rule; nothing
    # the user described is silently dropped).
    assert e["enforcement"] == "mixed"


def test_extract_enforcement_ai_when_no_markers():
    verdict = {"reason": "ok", "subject_tokens": [], "sender_addresses": [],
               "sender_domains": [], "residual_text": _EXAMPLE_HEADLINE,
               "list_like": False}
    e = breadth_advisor.extract_enforcement(_EXAMPLE_HEADLINE, verdict)
    assert e["enforcement"] == "ai"
    assert e["deterministic_entries"] == []


def test_check_breadth_returns_marker_fields():
    """The SINGLE breadth call now also returns the marker fields (same client,
    same response) so authoring gets breadth + extraction from one API call."""
    client = _FakeClient(text=(
        '{"broad": false, "concern": "", "suggestion": "", '
        '"subject_tokens": ["[PSIAN]"], "sender_addresses": [], '
        '"sender_domains": [], "residual_text": "", "list_like": false}'))
    out = breadth_advisor.check_category_breadth(
        "Emails from the [PSIAN] listserve.", "sk-ant-x",
        "claude-haiku-4-5", client=client)
    assert out["reason"] == "ok"
    assert out["subject_tokens"] == ["[PSIAN]"]
    assert out["residual_text"] == ""
    # Exactly ONE API call was made for both jobs.
    assert len(client.messages.calls) == 1


# ---- store writes with provenance + old-format entries still readable ----

def test_create_writes_provenance_entries_and_engine_reads_old_format(stores_env):
    import json
    # Seed a legacy plain-string entry AND an old {"value","scope"} entry (no
    # provenance) — both must keep working after the new writer runs.
    (stores_env / "blacklist.json").write_text(json.dumps({
        "subject_keywords": ["legacyword", {"value": "[old]", "scope": "all"}]}))
    enf = _det(subject_tokens=["[psian]"])
    rec = config_io.create_authored_refinement(
        "Emails from the [PSIAN] listserve.", "all", enforcement=enf)
    bl = _read_blacklist(stores_env)
    kws = bl["subject_keywords"]
    # Old entries untouched, new one carries provenance == rule id.
    assert "legacyword" in kws
    assert {"value": "[old]", "scope": "all"} in kws
    new = [i for i in kws if isinstance(i, dict) and i.get("value") == "[psian]"]
    assert new and _owner_ids(new[0]) == [rec["id"]]     # per-owner provenance
    assert new[0]["provenance"] == [{"id": rec["id"], "scope": "all"}]
    # The ENGINE reader normalizes all three shapes into one membership set.
    d = spam_filter._ensure_list_sets(bl)
    assert set(d["_subject_keywords_lower"]) == {"legacyword", "[old]", "[psian]"}


def test_create_does_not_clobber_hand_added_entry(stores_env):
    import json
    (stores_env / "blacklist.json").write_text(json.dumps({
        "subject_keywords": ["[psian]"]}))     # hand-added, plain string
    config_io.create_authored_refinement(
        "kill [PSIAN]", "all", enforcement=_det(subject_tokens=["[psian]"]))
    kws = _read_blacklist(stores_env)["subject_keywords"]
    # The value already existed -> left as the plain string; NO provenance dict
    # was added, so a later delete of this rule can't take the hand entry.
    assert kws == ["[psian]"]


# ---- injection routing ----

def test_deterministic_rule_not_injected(stores_env):
    config_io.create_authored_refinement(
        "Emails from the [PSIAN] listserve.", "all",
        enforcement=_det(subject_tokens=["[psian]"]))
    lines = spam_filter._build_learned_lines(config_io.load_signals(), None)[0]
    assert lines == []            # deterministic-only -> nothing in the prompt


def test_mixed_rule_injects_residual_only(stores_env):
    config_io.create_authored_refinement(
        "webinar invites from unknown vendors", "all",
        enforcement=_det(subject_tokens=["webinar"],
                         residual="from vendors I don't know",
                         enforcement="mixed"))
    lines = spam_filter._build_learned_lines(config_io.load_signals(), None)[0]
    assert len(lines) == 1
    # Only the residual is injected — never the full headline.
    assert "from vendors I don't know" in lines[0]
    assert "webinar invites from unknown vendors" not in lines[0]


# ---- retire / restore / delete cascade ----

def test_retire_cascade_removes_only_provenance_and_restore_readds(stores_env):
    import json
    (stores_env / "blacklist.json").write_text(json.dumps({
        "subject_keywords": ["handmade"]}))    # hand entry: must survive both ops
    rec = config_io.create_authored_refinement(
        "list [ACME] stuff", "all", enforcement=_det(subject_tokens=["[acme]"]))
    rid = rec["id"]

    def _acme_present():
        kws = _read_blacklist(stores_env).get("subject_keywords", [])
        return any(isinstance(i, dict) and i.get("value") == "[acme]"
                   and rid in _owner_ids(i) for i in kws)

    assert _acme_present() is True
    # Disable -> its provenance entry goes; the hand entry stays.
    assert config_io.retire_refinement(rid) is True
    assert _acme_present() is False
    assert "handmade" in _read_blacklist(stores_env)["subject_keywords"]
    # Re-enable -> the entry comes back (with provenance + scope).
    assert config_io.restore_refinement(rid) is not None
    assert _acme_present() is True
    # Delete -> gone again; hand entry still there.
    assert config_io.delete_active_refinement(rid) is True
    assert _acme_present() is False
    assert "handmade" in _read_blacklist(stores_env)["subject_keywords"]


def test_two_rules_share_token_delete_one_keeps_enforcement(stores_env):
    """FINDING 2 (multi-owner): two authored rules extract the SAME token. The
    entry is owned by BOTH; deleting one leaves it in place (still enforced,
    both surviving cards truthful); deleting the last owner drops it. A hand
    entry present the whole time is never touched."""
    import json
    (stores_env / "blacklist.json").write_text(json.dumps({
        "subject_keywords": ["handmade"]}))
    r1 = config_io.create_authored_refinement(
        "first [ACME] rule", "all", enforcement=_det(subject_tokens=["[acme]"]))
    r2 = config_io.create_authored_refinement(
        "second [ACME] rule", "all", enforcement=_det(subject_tokens=["[acme]"]))

    def _acme():
        for i in _read_blacklist(stores_env).get("subject_keywords", []):
            if isinstance(i, dict) and i.get("value") == "[acme]":
                return i
        return None

    # One entry, owned by both rules.
    assert sorted(_owner_ids(_acme())) == sorted([r1["id"], r2["id"]])
    # Delete rule 1 -> entry stays, now owned by rule 2 only (still enforced).
    assert config_io.delete_active_refinement(r1["id"]) is True
    assert _acme() is not None
    assert _owner_ids(_acme()) == [r2["id"]]
    # Delete rule 2 -> last owner gone -> entry removed.
    assert config_io.delete_active_refinement(r2["id"]) is True
    assert _acme() is None
    # Hand entry untouched throughout.
    assert "handmade" in _read_blacklist(stores_env)["subject_keywords"]


def test_write_provenance_migrates_legacy_single_id_string(stores_env):
    """A legacy single-id STRING provenance is read as one owner and migrated to
    a list when a second rule adopts the token."""
    import json
    (stores_env / "blacklist.json").write_text(json.dumps({
        "subject_keywords": [{"value": "[acme]", "scope": "all",
                              "provenance": "R-LEGACY"}]}))
    r2 = config_io.create_authored_refinement(
        "adopt [ACME]", "all", enforcement=_det(subject_tokens=["[acme]"]))
    entry = next(i for i in _read_blacklist(stores_env)["subject_keywords"]
                 if isinstance(i, dict) and i.get("value") == "[acme]")
    assert sorted(_owner_ids(entry)) == sorted(["R-LEGACY", r2["id"]])


def test_shared_token_unions_scope(stores_env):
    """Two rules with different scopes sharing a token union the entry scope so
    both accounts stay covered while both rules are active."""
    config_io.create_authored_refinement(
        "a [ACME]", ["a@x.com"], enforcement=_det(subject_tokens=["[acme]"]))
    config_io.create_authored_refinement(
        "b [ACME]", ["b@x.com"], enforcement=_det(subject_tokens=["[acme]"]))
    entry = next(i for i in _read_blacklist(stores_env)["subject_keywords"]
                 if isinstance(i, dict) and i.get("value") == "[acme]")
    assert set(entry["scope"]) == {"a@x.com", "b@x.com"}


def test_delete_narrows_scope_to_survivor_no_overblock(stores_env):
    """FINDING A: rule A (account X) and rule B (account Y) share a token → entry
    scope unions to [X,Y]. Deleting A must NARROW the entry to B's scope [Y] — NOT
    leave it at [X,Y] junking account X mail under a rule that never covered X.
    Verified at the ENGINE gate: after the delete, an [ACME] subject on account X
    is no longer junked; on account Y it still is."""
    a = config_io.create_authored_refinement(
        "a [ACME]", ["x@corp.com"], enforcement=_det(subject_tokens=["[acme]"]))
    config_io.create_authored_refinement(
        "b [ACME]", ["y@corp.com"], enforcement=_det(subject_tokens=["[acme]"]))
    assert set(_entry_scope_for(stores_env, "[acme]")) == {"x@corp.com",
                                                           "y@corp.com"}
    # Delete A -> scope recomputed to the survivor B's scope only.
    assert config_io.delete_active_refinement(a["id"]) is True
    assert _entry_scope_for(stores_env, "[acme]") == ["y@corp.com"]
    # Engine gate proof: X mail no longer junked; Y mail still junked.
    bl = spam_filter._ensure_list_sets(_read_blacklist(stores_env))
    assert spam_filter.check_subject_keywords(
        "[ACME] hi", bl, account_name="x@corp.com") is None   # the fixed bug
    assert spam_filter.check_subject_keywords(
        "[ACME] hi", bl, account_name="y@corp.com") == "[acme]"


def test_add_remove_readd_cycles_keep_scope_correct(stores_env):
    """Add/remove/re-add cycles keep the entry scope = union of CURRENT owners."""
    a = config_io.create_authored_refinement(
        "a [ACME]", ["x@corp.com"], enforcement=_det(subject_tokens=["[acme]"]))
    b = config_io.create_authored_refinement(
        "b [ACME]", ["y@corp.com"], enforcement=_det(subject_tokens=["[acme]"]))
    assert set(_entry_scope_for(stores_env, "[acme]")) == {"x@corp.com",
                                                           "y@corp.com"}
    # Disable B -> narrows to A's scope; its provenance entry is removed.
    assert config_io.retire_refinement(b["id"]) is True
    assert _entry_scope_for(stores_env, "[acme]") == ["x@corp.com"]
    # Re-enable B -> scope widens back to the union.
    assert config_io.restore_refinement(b["id"]) is not None
    assert set(_entry_scope_for(stores_env, "[acme]")) == {"x@corp.com",
                                                           "y@corp.com"}
    # Delete A -> narrows to B; delete B -> entry gone entirely.
    assert config_io.delete_active_refinement(a["id"]) is True
    assert _entry_scope_for(stores_env, "[acme]") == ["y@corp.com"]
    assert config_io.delete_active_refinement(b["id"]) is True
    assert _entry_scope_for(stores_env, "[acme]") is None


def test_legacy_list_of_ids_provenance_read_and_narrowed(stores_env):
    """A legacy list-of-id-STRINGS provenance is read as owners inheriting the
    entry scope; removing one owner keeps the entry (other owner) and migrates
    the shape, never touching a hand entry."""
    import json
    (stores_env / "blacklist.json").write_text(json.dumps({
        "subject_keywords": ["handmade",
                             {"value": "[acme]", "scope": "all",
                              "provenance": ["R-1", "R-2"]}]}))
    assert config_io.remove_provenance_entries("R-1") == 0   # R-2 still owns it
    entry = next(i for i in _read_blacklist(stores_env)["subject_keywords"]
                 if isinstance(i, dict) and i.get("value") == "[acme]")
    assert _owner_ids(entry) == ["R-2"]
    assert config_io.remove_provenance_entries("R-2") == 1   # last owner -> gone
    kws = _read_blacklist(stores_env)["subject_keywords"]
    assert not any(isinstance(i, dict) and i.get("value") == "[acme]" for i in kws)
    assert "handmade" in kws                                 # hand entry untouched


def test_engine_drop_corridor_removes_provenance_entries(cross_tree_env):
    """FINDING 1: the engine-side DROP twin (spam_filter.retire_ai_refinement),
    reached for a MIXED authored rule via the email report's rule-review DROP,
    must run the same provenance cascade — else the deterministic entries keep
    junking while the UI says the rule is off. RESTORE re-adds them."""
    def _acme_present():
        kws = _read_blacklist(cross_tree_env).get("subject_keywords", [])
        return any(isinstance(i, dict) and i.get("value") == "[acme]"
                   for i in kws)

    rec = config_io.create_authored_refinement(
        "webinar [ACME] invites", "all",
        enforcement=_det(subject_tokens=["[acme]"],
                         residual="from vendors I don't know",
                         enforcement="mixed"))
    rid = rec["id"]
    assert _acme_present() is True

    # DROP via the ENGINE corridor.
    assert spam_filter.retire_ai_refinement(rid, _LOG) is True
    assert spam_filter.load_signals()["ai_refinements"][0]["status"] == "retired"
    assert _acme_present() is False        # <-- the bug: previously stayed True

    # RESTORE via the ENGINE corridor re-adds the entry.
    restored = spam_filter.unretire_ai_refinement(rid, _LOG)
    assert restored is not None
    assert _acme_present() is True


def test_engine_drop_learned_rule_leaves_authored_entries(cross_tree_env):
    """A learned (non-authored) rule dropped via the engine corridor must NOT
    touch another authored rule's provenance entry."""
    authored = config_io.create_authored_refinement(
        "list [ACME]", "all", enforcement=_det(subject_tokens=["[acme]"]))
    # Add a learned rule sharing nothing; drop it via the engine.
    data = config_io.load_signals()
    data["ai_refinements"].append({
        "id": "R-LEARNED", "source": "check_screen", "rule_class": "curate",
        "verdict": "spam", "status": "active", "headline": "learned"})
    config_io.save_signals(data)
    assert spam_filter.retire_ai_refinement("R-LEARNED", _LOG) is True
    kws = _read_blacklist(cross_tree_env).get("subject_keywords", [])
    assert any(isinstance(i, dict) and i.get("value") == "[acme]"
               and authored["id"] in _owner_ids(i) for i in kws)


def test_delete_learned_rule_never_touches_blacklist(stores_env):
    import json
    (stores_env / "blacklist.json").write_text(json.dumps({
        "subject_keywords": [{"value": "[x]", "scope": "all",
                              "provenance": "R-OTHER"}]}))
    # A non-authored refinement with a colliding id must not cascade-remove
    # another rule's provenance entry.
    data = config_io.load_signals()
    data.setdefault("ai_refinements", []).append({
        "id": "R-OTHER", "source": "check_screen", "rule_class": "curate",
        "verdict": "spam", "status": "active", "headline": "learned"})
    config_io.save_signals(data)
    assert config_io.delete_active_refinement("R-OTHER") is True
    kws = _read_blacklist(stores_env)["subject_keywords"]
    assert any(i.get("value") == "[x]" for i in kws if isinstance(i, dict))


# ---- deterministic subject-keyword gate: case-insensitivity + scope (#9) ----

def test_subject_keyword_gate_case_insensitive_regression():
    """A rule extracting [PSIAN] must catch a [PsiAN] subject (the gate lowercases
    both sides)."""
    bl = spam_filter._ensure_list_sets(
        {"subject_keywords": [{"value": "[psian]", "scope": "all"}]})
    assert spam_filter.check_subject_keywords(
        "[PsiAN] Weekly digest", bl, account_name="anyone@x.com") == "[psian]"


def test_scoped_keyword_junks_only_selected_account():
    """A rule scoped to one account writes its keyword with that scope; the gate
    fires on the selected account and NOT on others (#9)."""
    bl = spam_filter._ensure_list_sets({"subject_keywords": [
        {"value": "[acme]", "scope": ["me@x.com"], "provenance": "R-1"}]})
    assert spam_filter.check_subject_keywords(
        "[ACME] hi", bl, account_name="me@x.com") == "[acme]"
    assert spam_filter.check_subject_keywords(
        "[ACME] hi", bl, account_name="other@x.com") is None


def test_all_scope_keyword_and_hand_entry_are_global():
    """'all' scope and a legacy hand-added plain string both apply on every
    account — scoping logic never narrows them (#9)."""
    bl = spam_filter._ensure_list_sets({"subject_keywords": [
        "handmade", {"value": "[acme]", "scope": "all", "provenance": "R-1"}]})
    for acct in ("me@x.com", "other@x.com"):
        assert spam_filter.check_subject_keywords(
            "[ACME] hi", bl, account_name=acct) == "[acme]"
        assert spam_filter.check_subject_keywords(
            "re: handmade goods", bl, account_name=acct) == "handmade"


def test_create_scoped_rule_writes_entry_with_scope(stores_env):
    rec = config_io.create_authored_refinement(
        "list [ACME]", ["me@x.com"], enforcement=_det(subject_tokens=["[acme]"]))
    kws = _read_blacklist(stores_env)["subject_keywords"]
    acme = [i for i in kws if isinstance(i, dict) and i.get("value") == "[acme]"]
    assert acme and acme[0]["scope"] == ["me@x.com"]
    assert _owner_ids(acme[0]) == [rec["id"]]            # per-owner provenance
    assert acme[0]["provenance"] == [{"id": rec["id"], "scope": ["me@x.com"]}]


# ---- record shape: enforcement fields ----

def test_build_authored_record_carries_enforcement_fields():
    enf = _det(subject_tokens=["[psian]"])
    rec = config_io.build_authored_curate_refinement(
        "R-1", "Emails from the [PSIAN] listserve.", "all", enforcement=enf)
    assert rec["enforcement"] == "deterministic"
    assert rec["deterministic_entries"] == [
        {"kind": "subject_keyword", "value": "[psian]"}]
    assert rec["residual_text"] == ""


def test_build_authored_record_legacy_has_no_enforcement_fields():
    """No enforcement passed -> legacy shape (behaves as today)."""
    rec = config_io.build_authored_curate_refinement("R-1", _EXAMPLE_HEADLINE, "all")
    assert "enforcement" not in rec
    assert "deterministic_entries" not in rec


# ---- help + dashboard wiring for the rework ----

def test_help_documents_enforcement_and_scope():
    body = help_content.UNWANTED_CATEGORIES_HELP.lower()
    assert "enforced instantly" in body           # deterministic display
    assert "subject" in body and "tag" in body     # the subject-tag prompt
    assert "account" in body                        # per-account scope selector


def test_dashboard_threads_enforcement_and_list_tag():
    after_src = inspect.getsource(
        dashboard.UnwantedCategoriesTab._after_breadth_check)
    assert "extract_enforcement" in after_src       # markers pulled from verdict
    assert "_prompt_list_tag" in after_src          # mailing-list tag prompt
    create_src = inspect.getsource(dashboard.UnwantedCategoriesTab._create_rule)
    assert "enforcement=enforcement" in create_src  # passed through to storage
    prompt_src = inspect.getsource(
        dashboard.UnwantedCategoriesTab._prompt_list_tag)
    assert "Skip" in prompt_src                     # skippable
    assert "_enforcement_for_tag" in prompt_src
    card_src = inspect.getsource(dashboard.UnwantedCategoriesTab._render_card)
    assert "_enforcement_text" in card_src          # per-rule enforcement line


def test_dashboard_enforcement_text_reads_plainly():
    txt = dashboard.UnwantedCategoriesTab._enforcement_text(
        {"enforcement": "deterministic",
         "deterministic_entries": [{"kind": "subject_keyword",
                                    "value": "[psian]"}]})
    assert "Enforced instantly by subject keyword: [psian]" == txt
    assert dashboard.UnwantedCategoriesTab._enforcement_text(
        {"enforcement": "ai"}) == "Enforced by AI judgment"
    # Legacy authored rule (no enforcement field) reads as AI judgment.
    assert dashboard.UnwantedCategoriesTab._enforcement_text({}) == \
        "Enforced by AI judgment"
