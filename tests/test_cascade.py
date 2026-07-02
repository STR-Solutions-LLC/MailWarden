#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Two-model cascade (Step A) — screen -> confirm, rescue-only.

Covers, with a fully mocked Anthropic client (NO paid calls):
  1. classify_email_cascade control flow: pass-through, confirmed junk,
     rescue, confirm-failure fail-open, screen-failure fail-open,
     below-threshold screen verdict, and the STRUCTURAL rescue-only rule
     (the confirm stage is never called when the screen delivers).
  2. Determinism + hardening: temperature=0 pinned on BOTH stages; the
     confirm stage judges the EXACT same sanitized user message as the
     screen stage (single build_user_message).
  3. The temperature-rejection fallback in _classify_create (a model that
     400-rejects sampling params gets ONE retry without temperature).
  4. classify_eml_offline cascade mode (usage + usage_confirm + cascade
     meta) and single-mode default back-compat.
  5. _cascade_action_suffix decisions.log attribution (sanitized).

Run with the test venv:
  tests/.venv/bin/python -c "import pytest; raise SystemExit(pytest.main(['tests/test_cascade.py','-q']))"
"""
import json
import logging
import os
import sys
import types

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402

LOG = logging.getLogger("test_cascade")
LOG.addHandler(logging.NullHandler())

SIGNALS = {"signals": {}, "ai_refinements": []}

SCREEN = "claude-haiku-4-5-20251001"
CONFIRM = "claude-sonnet-4-6"
THRESHOLD = 0.85

# Same shape as test_phase1a.RAW_NORMAL: no hard signals, so the AI decides.
RAW_NORMAL = (
    b"From: Promo <promo@evil.com>\r\n"
    b"To: me@example.org\r\n"
    b"Subject: Win a prize today\r\n"
    b"Message-ID: <abc123@evil.com>\r\n"
    b"\r\n"
    b"Hello friend, this is a perfectly normal length body with plenty of real "
    b"words in it. Thanks for reading.\r\n"
)


def _msg_data():
    return spam_filter.extract_email_data(RAW_NORMAL)


def _resp(payload):
    """A canned API response whose text is ``payload`` (dict -> JSON)."""
    text = json.dumps(payload) if isinstance(payload, dict) else payload
    return types.SimpleNamespace(
        content=[types.SimpleNamespace(type="text", text=text)],
        usage=types.SimpleNamespace(input_tokens=100, output_tokens=10),
    )


class _Client:
    """Mock Anthropic client: answers messages.create per model id.

    ``by_model[model]`` may be a dict (returned as JSON), a raw string
    (returned verbatim — use for unparseable responses), or an Exception
    instance (raised). Every create() call's kwargs are recorded."""

    def __init__(self, by_model):
        self.by_model = by_model
        self.calls = []
        self.messages = types.SimpleNamespace(create=self._create)

    def _create(self, **kw):
        self.calls.append(kw)
        v = self.by_model[kw["model"]]
        if isinstance(v, Exception):
            raise v
        return _resp(v)


def _cascade(client, threshold=THRESHOLD):
    return spam_filter.classify_email_cascade(
        client, "system prompt", _msg_data(), SCREEN, CONFIRM,
        500, threshold, LOG)


# ---------------------------------------------------------------------------
# 1. Control flow
# ---------------------------------------------------------------------------

def test_screen_pass_never_calls_confirm():
    """Rescue-only, structurally: when the screen delivers, the confirm model
    is never consulted — even though it is stubbed to say SPAM."""
    client = _Client({
        SCREEN: {"decision": "NOT_SPAM", "confidence": 0.9,
                 "signals_hit": [], "reasoning": "fine"},
        CONFIRM: {"decision": "SPAM", "confidence": 0.99,
                  "signals_hit": [], "reasoning": "never asked"},
    })
    result, calls, meta = _cascade(client)
    assert result["decision"] == "NOT_SPAM"
    assert len(client.calls) == 1, "confirm must NOT be called on a screen pass"
    assert client.calls[0]["model"] == SCREEN
    assert meta["confirm_called"] is False
    assert meta["rescued"] is False
    assert calls == [(SCREEN, calls[0][1])]


def test_both_junk_confirms_junk():
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": ["S1"], "reasoning": "screen junk"},
        CONFIRM: {"decision": "SPAM", "confidence": 0.95,
                  "signals_hit": ["S2"], "reasoning": "confirm junk"},
    })
    result, calls, meta = _cascade(client)
    assert len(client.calls) == 2
    assert client.calls[1]["model"] == CONFIRM
    # Both agree -> junk, reported with the CONFIRM verdict.
    assert result["decision"] == "SPAM"
    assert result["confidence"] == 0.95
    assert meta["confirm_called"] is True
    assert meta["rescued"] is False
    assert meta["screen_decision"] == "SPAM"
    assert meta["confirm_decision"] == "SPAM"
    assert [m for m, _ in calls] == [SCREEN, CONFIRM]


def test_confirm_not_spam_rescues():
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": ["S1"], "reasoning": "screen junk"},
        CONFIRM: {"decision": "NOT_SPAM", "confidence": 0.9,
                  "signals_hit": [], "reasoning": "actually fine"},
    })
    result, calls, meta = _cascade(client)
    assert result["decision"] == "NOT_SPAM", "rescue must deliver"
    assert meta["rescued"] is True
    assert meta["confirm_called"] is True
    assert "Rescued by cascade confirm stage" in result["reasoning"]
    assert CONFIRM in result["reasoning"]
    # Screen's signals kept so the log shows what the screen saw.
    assert result["signals_hit"] == ["S1"]


def test_confirm_below_threshold_rescues():
    """SPAM below threshold from the confirm stage would not junk in
    single-model mode either — the cascade must deliver."""
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": [], "reasoning": "screen junk"},
        CONFIRM: {"decision": "SPAM", "confidence": 0.5,
                  "signals_hit": [], "reasoning": "not sure"},
    })
    result, _, meta = _cascade(client)
    assert result["decision"] == "NOT_SPAM"
    assert meta["rescued"] is True


def test_confirm_unparseable_fails_open_to_rescue():
    """The confirm call failing (unparseable response — the '$149 Slim Down'
    class of failure) must fail OPEN: rescue -> deliver, never junk."""
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": [], "reasoning": "screen junk"},
        CONFIRM: "this is not json at all",
    })
    result, calls, meta = _cascade(client)
    assert result["decision"] == "NOT_SPAM"
    assert meta["rescued"] is True
    assert meta["confirm_decision"] is None
    assert "failing open" in result["reasoning"]


def test_screen_failure_fails_open_and_skips_confirm():
    """A screen failure returns None (caller delivers / retries) and must not
    burn a confirm call."""
    client = _Client({
        SCREEN: "garbage, not json",
        CONFIRM: {"decision": "SPAM", "confidence": 0.99,
                  "signals_hit": [], "reasoning": "never asked"},
    })
    result, calls, meta = _cascade(client)
    assert result is None
    assert len(client.calls) == 1
    assert meta["confirm_called"] is False
    assert [m for m, _ in calls] == [SCREEN]


def test_screen_spam_below_threshold_skips_confirm():
    """A screen SPAM below threshold would DELIVER in single-model mode, so
    the confirm stage must not run (no cost, byte-identical verdict)."""
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.5,
                 "signals_hit": [], "reasoning": "meh"},
        CONFIRM: {"decision": "SPAM", "confidence": 0.99,
                  "signals_hit": [], "reasoning": "never asked"},
    })
    result, _, meta = _cascade(client)
    assert len(client.calls) == 1
    assert meta["confirm_called"] is False
    assert result["decision"] == "SPAM"  # caller's threshold check delivers
    assert result["confidence"] == 0.5


# ---------------------------------------------------------------------------
# 2. Determinism + shared sanitized message
# ---------------------------------------------------------------------------

def test_both_stages_pin_temperature_zero():
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": [], "reasoning": "junk"},
        CONFIRM: {"decision": "NOT_SPAM", "confidence": 0.9,
                  "signals_hit": [], "reasoning": "fine"},
    })
    _cascade(client)
    assert len(client.calls) == 2
    for kw in client.calls:
        assert kw.get("temperature") == 0


def test_confirm_judges_identical_user_message():
    """No new unsanitized surface: the confirm stage must receive the exact
    user message the screen stage judged (one build_user_message call)."""
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": [], "reasoning": "junk"},
        CONFIRM: {"decision": "NOT_SPAM", "confidence": 0.9,
                  "signals_hit": [], "reasoning": "fine"},
    })
    _cascade(client)
    assert client.calls[0]["messages"] == client.calls[1]["messages"]
    assert client.calls[0]["system"] == client.calls[1]["system"]


def test_single_model_wrapper_unchanged():
    """classify_email keeps its exact pre-cascade contract: one call,
    temperature=0, parsed dict + raw response."""
    client = _Client({
        SCREEN: {"decision": "NOT_SPAM", "confidence": 0.9,
                 "signals_hit": [], "reasoning": "fine"},
    })
    result, response = spam_filter.classify_email(
        client, "system prompt", _msg_data(), SCREEN, 500, LOG)
    assert result["decision"] == "NOT_SPAM"
    assert response is not None
    assert len(client.calls) == 1
    assert client.calls[0].get("temperature") == 0


# ---------------------------------------------------------------------------
# 3. Temperature-rejection fallback (_classify_create)
# ---------------------------------------------------------------------------

def _bad_request_error(message):
    import anthropic
    import httpx
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    resp = httpx.Response(400, request=req,
                          json={"error": {"type": "invalid_request_error",
                                          "message": message}})
    return anthropic.BadRequestError(message, response=resp, body=None)


class _TempRejectingClient:
    """Rejects any create() that carries a temperature kwarg (400), accepts
    the same call without it — models that 400-reject sampling params."""

    def __init__(self, payload):
        self.payload = payload
        self.calls = []
        self.messages = types.SimpleNamespace(create=self._create)

    def _create(self, **kw):
        self.calls.append(kw)
        if "temperature" in kw:
            raise _bad_request_error(
                "temperature is not supported by this model")
        return _resp(self.payload)


def test_temperature_rejected_retries_once_without_it():
    client = _TempRejectingClient(
        {"decision": "NOT_SPAM", "confidence": 0.9,
         "signals_hit": [], "reasoning": "fine"})
    result, response = spam_filter.classify_email(
        client, "system prompt", _msg_data(), "claude-opus-4-7", 500, LOG)
    assert result is not None and result["decision"] == "NOT_SPAM"
    assert len(client.calls) == 2
    assert client.calls[0].get("temperature") == 0
    assert "temperature" not in client.calls[1]


def test_non_temperature_bad_request_still_fails_open():
    """A 400 unrelated to sampling params must NOT trigger the fallback —
    it propagates to the existing APIError handler and fails open (None)."""
    class _AlwaysBad:
        def __init__(self):
            self.calls = []
            self.messages = types.SimpleNamespace(create=self._create)

        def _create(self, **kw):
            self.calls.append(kw)
            raise _bad_request_error("max_tokens is too large")

    client = _AlwaysBad()
    result, response = spam_filter.classify_email(
        client, "system prompt", _msg_data(), SCREEN, 500, LOG)
    assert result is None
    assert len(client.calls) == 1, "no blind retry on an unrelated 400"


# ---------------------------------------------------------------------------
# 4. classify_eml_offline cascade mode
# ---------------------------------------------------------------------------

def _patch_client(monkeypatch, client):
    monkeypatch.setattr(spam_filter.anthropic, "Anthropic",
                        lambda *a, **k: client)


def test_offline_cascade_confirmed_junk(monkeypatch):
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": [], "reasoning": "junk"},
        CONFIRM: {"decision": "SPAM", "confidence": 0.95,
                  "signals_hit": [], "reasoning": "junk too"},
    })
    _patch_client(monkeypatch, client)
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="k",
        classify_mode="cascade", confirm_model=CONFIRM)
    assert res["final_decision"] == "JUNK"
    assert res["cascade"]["confirm_called"] is True
    assert res["cascade"]["rescued"] is False
    # usage keeps its pre-cascade shape (screen call); confirm gets its own.
    assert res["usage"]["model"] == SCREEN
    assert res["usage_confirm"]["model"] == CONFIRM
    assert res["usage_confirm"]["input_tokens"] == 100


def test_offline_cascade_rescue_passes(monkeypatch):
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": [], "reasoning": "junk"},
        CONFIRM: {"decision": "NOT_SPAM", "confidence": 0.9,
                  "signals_hit": [], "reasoning": "fine"},
    })
    _patch_client(monkeypatch, client)
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="k",
        classify_mode="cascade", confirm_model=CONFIRM)
    assert res["final_decision"] == "PASS"
    assert res["cascade"]["rescued"] is True
    assert "usage_confirm" in res


def test_offline_cascade_screen_pass_no_confirm_usage(monkeypatch):
    client = _Client({
        SCREEN: {"decision": "NOT_SPAM", "confidence": 0.9,
                 "signals_hit": [], "reasoning": "fine"},
        CONFIRM: {"decision": "SPAM", "confidence": 0.99,
                  "signals_hit": [], "reasoning": "never asked"},
    })
    _patch_client(monkeypatch, client)
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="k",
        classify_mode="cascade", confirm_model=CONFIRM)
    assert res["final_decision"] == "PASS"
    assert res["cascade"]["confirm_called"] is False
    assert "usage_confirm" not in res
    assert len(client.calls) == 1


def test_offline_default_is_single_mode(monkeypatch):
    """No classify_mode kwarg -> exactly one call, no cascade keys: the
    pre-cascade contract for every existing caller."""
    client = _Client({
        SCREEN: {"decision": "NOT_SPAM", "confidence": 0.9,
                 "signals_hit": [], "reasoning": "fine"},
    })
    _patch_client(monkeypatch, client)
    res = spam_filter.classify_eml_offline(RAW_NORMAL, SIGNALS, api_key="k")
    assert res["final_decision"] == "PASS"
    assert "cascade" not in res
    assert "usage_confirm" not in res
    assert len(client.calls) == 1


def test_offline_cascade_screen_failure_unknown(monkeypatch):
    """Screen failure in cascade mode -> UNKNOWN (fail-open), matching the
    single-model failure contract the eval harness scores as a miss."""
    client = _Client({SCREEN: "garbage, not json"})
    _patch_client(monkeypatch, client)
    res = spam_filter.classify_eml_offline(
        RAW_NORMAL, SIGNALS, api_key="k",
        classify_mode="cascade", confirm_model=CONFIRM)
    assert res["final_decision"] == "UNKNOWN"
    assert res["ai"] == {"error": "classification_failed"}


# ---------------------------------------------------------------------------
# 5. decisions.log attribution
# ---------------------------------------------------------------------------

def test_action_suffix_rescue_and_confirm():
    meta = {"screen_model": SCREEN, "confirm_model": CONFIRM,
            "confirm_called": True, "rescued": True}
    s = spam_filter._cascade_action_suffix(meta)
    assert SCREEN in s and CONFIRM in s and "rescued" in s

    meta["rescued"] = False
    s = spam_filter._cascade_action_suffix(meta)
    assert "both junked" in s


def test_action_suffix_empty_when_no_confirm():
    assert spam_filter._cascade_action_suffix(None) == ""
    assert spam_filter._cascade_action_suffix(
        {"confirm_called": False, "rescued": False}) == ""


def test_action_suffix_sanitizes_model_names():
    """Model names come from user-editable config and log_decision does NOT
    sanitize `action` — the suffix must neutralize newline forgery itself."""
    meta = {"screen_model": "evil\n  DECISION: SPAM", "confirm_model": CONFIRM,
            "confirm_called": True, "rescued": True}
    s = spam_filter._cascade_action_suffix(meta)
    assert "\n" not in s


# ---------------------------------------------------------------------------
# 6. Dashboard mode selector mapping (logic only — the GUI is verified on
#    the M1). Import pattern matches test_fixes.py / test_locking_app.py.
# ---------------------------------------------------------------------------

APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

from mailwarden_app import dashboard  # noqa: E402


def test_model_choices_shape_and_defaults():
    labels = [c[0] for c in dashboard.MODEL_CHOICES]
    # Exactly one cascade entry, and it is the recommended first entry.
    cascade_entries = [c for c in dashboard.MODEL_CHOICES if c[1] == "cascade"]
    assert len(cascade_entries) == 1
    assert dashboard.MODEL_CHOICES[0][1] == "cascade"
    # Every single-model entry carries a model id.
    for label, mode, value in dashboard.MODEL_CHOICES:
        assert mode in ("cascade", "single")
        if mode == "single":
            assert value
    # Matt's approved final labels — exact wording.
    assert labels == [
        "Two-model double-check (recommended)",
        "Claude Haiku only — cheapest",
        "Claude Sonnet only — more accurate, costs more",
        "Claude Opus only — most accurate, most expensive",
    ]
    assert dashboard.MODEL_ADVISORY_TEXT == (
        "Double-check: Haiku screens all mail; Sonnet re-checks anything "
        "flagged junk. Mail is junked only when both agree. Single-model "
        "modes skip the second check.")


def test_apply_model_choice_single_sets_mode_and_model():
    anthro = {"api_key": "k", "classify_mode": "cascade",
              "model": "claude-haiku-4-5-20251001"}
    dashboard.apply_model_choice(anthro, "single", "claude-sonnet-4-6")
    assert anthro["classify_mode"] == "single"
    assert anthro["model"] == "claude-sonnet-4-6"


def test_apply_model_choice_cascade_preserves_single_model_pick():
    """Selecting the cascade must not clobber the user's remembered
    single-model choice (switching back restores it)."""
    anthro = {"api_key": "k", "classify_mode": "single",
              "model": "claude-sonnet-4-6"}
    dashboard.apply_model_choice(anthro, "cascade", None)
    assert anthro["classify_mode"] == "cascade"
    assert anthro["model"] == "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# 7. run_filter cascade branch (all IO/network mocked — harness modeled on
#    test_sender_approval._approve_harness). Covers routing by classify_mode,
#    per-call token recording, and the decisions.log action attribution.
# ---------------------------------------------------------------------------

_LOGGER = logging.getLogger("test_cascade_run_filter")
_LOGGER.addHandler(logging.NullHandler())


def _run_filter_cascade_harness(monkeypatch, client):
    """Drive spam_filter.run_filter(force=True) in cascade mode with one
    normal email and the given mock Anthropic client. Returns captured
    {decisions: [(result, action)], token_usage, spam_actions}."""
    captured = {"decisions": [], "token_usage": None, "spam_actions": 0}
    # Snapshot the parsed message BEFORE extract_email_data is patched below
    # (the stub must not call back into the patched module function).
    msg_data = _msg_data()

    cfg = {
        "filter": {"dry_run": False, "confidence_threshold": 0.85,
                   "max_emails_per_run": 50, "log_level": "INFO"},
        "anthropic": {"api_key": "k", "model": "unused-in-cascade",
                      "max_tokens": 500,
                      "classify_mode": "cascade",
                      "screen_model": SCREEN,
                      "confirm_model": CONFIRM},
        "smtp": {"host": "smtp.example.com", "username": "owner@example.com",
                 "from_address": "owner@example.com"},
        "summary": {"recipient_address": "owner@example.com"},
        "eula": {"current_version": "1.0", "sent_to_accounts": {}},
        "accounts": [{
            "name": "Acct", "enabled": True,
            "username": "owner@example.com",
            "imap_host": "imap.example.com",
            "junk_folder": "Junk",
            "folders_to_scan": ["INBOX"],
        }],
    }

    monkeypatch.setattr(spam_filter, "load_config", lambda: cfg)
    monkeypatch.setattr(spam_filter, "setup_logging", lambda level: _LOGGER)
    monkeypatch.setattr(spam_filter, "save_last_filter_run", lambda when: None)
    monkeypatch.setattr(spam_filter, "load_processed_ids", lambda: {"ids": {}})
    monkeypatch.setattr(spam_filter, "load_signals", lambda: {"signals": {}})
    monkeypatch.setattr(spam_filter, "load_whitelist",
                        lambda logger: {"domains": [], "addresses": [],
                                        "_addresses_set": set(),
                                        "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "load_blacklist",
                        lambda logger: {"addresses": [], "domains": [],
                                        "display_names": [],
                                        "subject_keywords": []})
    monkeypatch.setattr(spam_filter, "load_approved_senders",
                        lambda logger: {"domains": [], "_domains_set": set()})
    monkeypatch.setattr(spam_filter, "detect_conflicts",
                        lambda wl, bl, logger: [])
    monkeypatch.setattr(spam_filter, "load_token_usage",
                        lambda: {"lifetime_input_tokens": 0,
                                 "lifetime_output_tokens": 0,
                                 "lifetime_api_calls": 0,
                                 "daily_records": []})
    # new_token_delta left REAL (pure dict factory).
    monkeypatch.setattr(spam_filter, "load_pending_signals",
                        lambda: {"conversations": []})

    def _persist(processed, tu, td):
        captured["token_usage"] = tu
    monkeypatch.setattr(spam_filter, "persist_progress", _persist)

    monkeypatch.setattr(spam_filter, "build_classifier_prompt",
                        lambda signals, username=None,
                        approvals_active=False: "PROMPT")
    monkeypatch.setattr(spam_filter, "_maybe_send_dry_run_reminder",
                        lambda config, accounts, logger: None)
    monkeypatch.setattr(spam_filter, "prune_decisions_log", lambda: None)
    monkeypatch.setattr(spam_filter, "prune_pending_signals", lambda: None)
    monkeypatch.setattr(spam_filter, "autoseed_trusted_infra",
                        lambda signals, config: False)
    monkeypatch.setattr(spam_filter, "scan_train_folder",
                        lambda conn, account, config, logger: None)
    monkeypatch.setattr(spam_filter, "deliver_eula_if_needed",
                        lambda *a, **k: True)
    monkeypatch.setattr(spam_filter, "send_email", lambda *a, **k: None)
    monkeypatch.setattr(spam_filter, "load_report_approvals_store",
                        lambda logger: {})

    def _log_decision(account_name, msg_data, result, action):
        captured["decisions"].append((result, action))
    monkeypatch.setattr(spam_filter, "log_decision", _log_decision)

    def _exec(*a, **k):
        captured["spam_actions"] += 1
        return "Moved to Junk"
    monkeypatch.setattr(spam_filter, "execute_spam_action", _exec)

    class _FakeConn:
        def logout(self):
            pass
    monkeypatch.setattr(spam_filter, "connect_imap",
                        lambda account, logger: _FakeConn())
    monkeypatch.setattr(spam_filter, "fetch_unseen_uids",
                        lambda conn, folder, logger: [b"1"])
    monkeypatch.setattr(spam_filter, "fetch_raw_email",
                        lambda conn, uid, logger: RAW_NORMAL)
    monkeypatch.setattr(spam_filter, "extract_email_data",
                        lambda raw, own_hosts=None: dict(msg_data))

    monkeypatch.setattr(spam_filter.anthropic, "Anthropic",
                        lambda *a, **k: client)

    spam_filter.run_filter(force=True)
    return captured


def test_run_filter_cascade_rescue_delivers_and_attributes(monkeypatch):
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": ["S1"], "reasoning": "screen junk"},
        CONFIRM: {"decision": "NOT_SPAM", "confidence": 0.9,
                  "signals_hit": [], "reasoning": "fine"},
    })
    captured = _run_filter_cascade_harness(monkeypatch, client)
    assert len(client.calls) == 2
    assert captured["spam_actions"] == 0, "a rescued message must NOT be moved"
    assert len(captured["decisions"]) == 1
    result, action = captured["decisions"][0]
    assert result["decision"] == "NOT_SPAM"
    assert "cascade:" in action and "rescued" in action
    assert SCREEN in action and CONFIRM in action
    # BOTH calls recorded into token usage (100 in / 10 out each).
    tu = captured["token_usage"]
    assert tu["lifetime_api_calls"] == 2
    assert tu["lifetime_input_tokens"] == 200
    assert tu["lifetime_output_tokens"] == 20


def test_run_filter_cascade_confirmed_junk_moves_mail(monkeypatch):
    client = _Client({
        SCREEN: {"decision": "SPAM", "confidence": 0.99,
                 "signals_hit": [], "reasoning": "junk"},
        CONFIRM: {"decision": "SPAM", "confidence": 0.95,
                  "signals_hit": [], "reasoning": "junk too"},
    })
    captured = _run_filter_cascade_harness(monkeypatch, client)
    assert captured["spam_actions"] == 1
    result, action = captured["decisions"][0]
    assert result["decision"] == "SPAM"
    assert "both junked" in action
    assert captured["token_usage"]["lifetime_api_calls"] == 2


def test_run_filter_cascade_screen_pass_single_call_no_suffix(monkeypatch):
    client = _Client({
        SCREEN: {"decision": "NOT_SPAM", "confidence": 0.9,
                 "signals_hit": [], "reasoning": "fine"},
        CONFIRM: {"decision": "SPAM", "confidence": 0.99,
                  "signals_hit": [], "reasoning": "never asked"},
    })
    captured = _run_filter_cascade_harness(monkeypatch, client)
    assert len(client.calls) == 1
    assert captured["spam_actions"] == 0
    result, action = captured["decisions"][0]
    assert "cascade:" not in action, "no attribution when confirm never ran"
    assert captured["token_usage"]["lifetime_api_calls"] == 1
