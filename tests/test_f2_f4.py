#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Step B — F4 (classification hardening).

All mocked, NO paid calls. Covers:
  F4(a): _validate_classification strictness + normalization, applied on both
      the direct-parse and prose-salvage paths; invalid = fail-open.
  F4(b): exactly ONE retry on transient APIError subclasses
      (APIConnectionError incl. APITimeoutError, InternalServerError 5xx);
      non-transient behavior unchanged.
  F4(c): raw-capture debug artifacts — written on parse/validation failure,
      collision-proof filenames, size-capped, and NEVER able to raise or
      change the verdict (capture-dir failure swallowed).

Run with the test venv:
  tests/.venv/bin/python -c "import pytest; raise SystemExit(pytest.main(['tests/test_f2_f4.py','-q']))"
"""
import json
import logging
import os
import sys
import types

import httpx

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import anthropic  # noqa: E402
import spam_filter  # noqa: E402

LOG = logging.getLogger("test_f2_f4")
LOG.addHandler(logging.NullHandler())

MODEL = "claude-haiku-4-5-20251001"

RAW_NORMAL = (
    b"From: Promo <promo@evil.com>\r\n"
    b"To: me@example.org\r\n"
    b"Subject: Win a prize today\r\n"
    b"Message-ID: <abc123@evil.com>\r\n"
    b"\r\n"
    b"Hello friend, this is a perfectly normal length body with plenty of real "
    b"words in it. Thanks for reading.\r\n"
)


def _msg_data(raw=RAW_NORMAL):
    return spam_filter.extract_email_data(raw)


def _resp(payload):
    text = json.dumps(payload) if isinstance(payload, dict) else payload
    return types.SimpleNamespace(
        content=[types.SimpleNamespace(type="text", text=text)],
        usage=types.SimpleNamespace(input_tokens=100, output_tokens=10),
    )


class _ScriptedClient:
    """messages.create pops the next item from ``script``: an Exception
    instance is raised, anything else is returned as a canned response
    (dict -> JSON text, str -> verbatim text)."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.messages = types.SimpleNamespace(create=self._create)

    def _create(self, **kw):
        self.calls.append(kw)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return _resp(item)


def _classify(client):
    return spam_filter.classify_email(
        client, "system prompt", _msg_data(), MODEL, 500, LOG)


VALID = {"decision": "NOT_SPAM", "confidence": 0.9,
         "signals_hit": [], "reasoning": "fine"}


def _httpx_request():
    return httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def _conn_error():
    return anthropic.APIConnectionError(request=_httpx_request())


def _timeout_error():
    return anthropic.APITimeoutError(request=_httpx_request())


def _server_error():
    resp = httpx.Response(
        500, request=_httpx_request(),
        json={"error": {"type": "internal_server_error", "message": "boom"}})
    return anthropic.InternalServerError("boom", response=resp, body=None)


def _bad_request(message):
    resp = httpx.Response(
        400, request=_httpx_request(),
        json={"error": {"type": "invalid_request_error", "message": message}})
    return anthropic.BadRequestError(message, response=resp, body=None)


# ---------------------------------------------------------------------------
# F4(a) — strict validation
# ---------------------------------------------------------------------------

def test_validate_accepts_and_normalizes_valid():
    out = spam_filter._validate_classification(
        {"decision": "SPAM", "confidence": "0.97"})
    assert out["decision"] == "SPAM"
    assert out["confidence"] == 0.97
    assert out["signals_hit"] == []
    assert out["reasoning"] == ""


def test_validate_clamps_out_of_range_confidence():
    assert spam_filter._validate_classification(
        {"decision": "SPAM", "confidence": 1.5})["confidence"] == 1.0
    assert spam_filter._validate_classification(
        {"decision": "SPAM", "confidence": None})["confidence"] == 0.0


def test_validate_rejects_unknown_decision_and_shapes():
    v = spam_filter._validate_classification
    assert v({"decision": "MAYBE", "confidence": 0.9}) is None
    assert v({"decision": "JUNK", "confidence": 0.9}) is None
    assert v({"confidence": 0.9}) is None                    # missing decision
    assert v({"decision": "SPAM"}) is None                   # missing confidence
    assert v(["decision", "confidence"]) is None             # not a dict
    assert v("decision confidence") is None


def test_validate_normalizes_malformed_optional_fields():
    out = spam_filter._validate_classification(
        {"decision": "NOT_SPAM", "confidence": 0.5,
         "signals_hit": "S1", "reasoning": ["not", "a", "string"]})
    assert out["signals_hit"] == []
    assert out["reasoning"] == ""


def test_invalid_decision_fails_open_with_response():
    """A hallucinated verdict is a parse failure: (None, response) — the
    caller delivers, and the burned call's tokens stay recordable."""
    client = _ScriptedClient([{"decision": "JUNK", "confidence": 0.99}])
    result, response = _classify(client)
    assert result is None
    assert response is not None
    assert len(client.calls) == 1


def test_salvage_path_is_validated_too():
    good = ('Sure! Here you go:\n'
            '{"decision": "NOT_SPAM", "confidence": "0.8"}\nHope that helps.')
    client = _ScriptedClient([good])
    result, _ = _classify(client)
    assert result["decision"] == "NOT_SPAM"
    assert result["confidence"] == 0.8          # coerced by validation

    bad = ('Sure! Here you go:\n'
           '{"decision": "MAYBE", "confidence": 0.8}\nHope that helps.')
    client = _ScriptedClient([bad])
    result, response = _classify(client)
    assert result is None, "salvaged-but-invalid must fail open"
    assert response is not None


# ---------------------------------------------------------------------------
# F4(b) — one retry on transient APIError
# ---------------------------------------------------------------------------

def test_connection_error_retried_once_then_success():
    client = _ScriptedClient([_conn_error(), VALID])
    result, _ = _classify(client)
    assert result is not None and result["decision"] == "NOT_SPAM"
    assert len(client.calls) == 2


def test_timeout_error_retried_once_then_success():
    client = _ScriptedClient([_timeout_error(), VALID])
    result, _ = _classify(client)
    assert result is not None
    assert len(client.calls) == 2


def test_server_error_retried_once_then_success():
    client = _ScriptedClient([_server_error(), VALID])
    result, _ = _classify(client)
    assert result is not None
    assert len(client.calls) == 2


def test_persistent_transient_error_fails_open_after_one_retry():
    client = _ScriptedClient([_conn_error(), _server_error(), VALID])
    result, response = _classify(client)
    assert result is None and response is None
    assert len(client.calls) == 2, "exactly ONE retry — never a third call"


def test_non_transient_400_still_fails_open_without_retry():
    """Unrelated 400s keep the pre-F4 immediate fail-open (the temperature
    fallback landed in Step A is the only 400 that retries)."""
    client = _ScriptedClient([_bad_request("max_tokens is too large")])
    result, response = _classify(client)
    assert result is None and response is None
    assert len(client.calls) == 1


# ---------------------------------------------------------------------------
# F4(c) — raw-capture debug artifacts
# ---------------------------------------------------------------------------
# NOTE: tests/conftest.py redirects spam_filter.PARSE_FAILURES_DIR to a
# per-test tmp dir (autouse), so these never touch the repo tree.

def test_parse_failure_writes_capture_artifact():
    client = _ScriptedClient(["this is not json at all"])
    result, response = _classify(client)
    assert result is None and response is not None      # fail-open unchanged
    files = list(spam_filter.PARSE_FAILURES_DIR.glob("*.txt"))
    assert len(files) == 1
    body = files[0].read_text()
    assert "this is not json at all" in body
    assert f"model: {MODEL}" in body
    assert "kind: json_decode" in body


def test_validation_failure_writes_capture_artifact():
    client = _ScriptedClient([{"decision": "MAYBE", "confidence": 0.9}])
    _classify(client)
    files = list(spam_filter.PARSE_FAILURES_DIR.glob("*.txt"))
    assert len(files) == 1
    assert "kind: validation" in files[0].read_text()


def test_rapid_failures_never_collide():
    client = _ScriptedClient(["garbage one", "garbage two"])
    _classify(client)
    _classify(client)
    files = list(spam_filter.PARSE_FAILURES_DIR.glob("*.txt"))
    assert len(files) == 2, "same-second captures must get distinct filenames"


def test_capture_is_size_capped():
    client = _ScriptedClient(["x" * 50_000])
    _classify(client)
    files = list(spam_filter.PARSE_FAILURES_DIR.glob("*.txt"))
    assert len(files) == 1
    assert len(files[0].read_text()) < 21_000


def test_capture_failure_never_raises_or_changes_verdict(tmp_path, monkeypatch):
    """An un-creatable capture dir (parent is a FILE) must be swallowed:
    same fail-open verdict, no exception."""
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file, not a directory")
    monkeypatch.setattr(spam_filter, "PARSE_FAILURES_DIR",
                        blocker / "classify_parse_failures")
    client = _ScriptedClient(["still not json"])
    result, response = _classify(client)
    assert result is None and response is not None


def test_capture_retention_guard_keeps_newest_100():
    d = spam_filter.PARSE_FAILURES_DIR
    d.mkdir(parents=True, exist_ok=True)
    for i in range(105):
        (d / f"00000000-000000-{i:04d}.txt").write_text("old")
    spam_filter._capture_parse_failure("newest", MODEL, "classify", "test")
    files = sorted(d.glob("*.txt"))
    assert len(files) == 100
    assert any("newest" in f.read_text() for f in files)


# ---------------------------------------------------------------------------
# Step A interplay — the confirm-failure rescue still works with F4 active
# ---------------------------------------------------------------------------

def test_cascade_confirm_validation_failure_still_rescues():
    """'$149 Slim Down' class: the confirm stage returning an invalid
    verdict is a parse failure -> fail-open -> RESCUE (deliver), and the
    raw response is captured for diagnosis."""
    screen = "claude-haiku-4-5-20251001"
    confirm = "claude-sonnet-4-6"

    class _ByModel:
        def __init__(self):
            self.messages = types.SimpleNamespace(create=self._create)

        def _create(self, **kw):
            if kw["model"] == screen:
                return _resp({"decision": "SPAM", "confidence": 0.99,
                              "signals_hit": [], "reasoning": "junk"})
            return _resp("")   # empty confirm response (empty-render artifact)

    result, calls, meta = spam_filter.classify_email_cascade(
        _ByModel(), "system prompt", _msg_data(), screen, confirm,
        500, 0.85, LOG)
    assert result["decision"] == "NOT_SPAM"
    assert meta["rescued"] is True
    files = list(spam_filter.PARSE_FAILURES_DIR.glob("*.txt"))
    assert len(files) == 1
    assert "site: classify_confirm" in files[0].read_text()
