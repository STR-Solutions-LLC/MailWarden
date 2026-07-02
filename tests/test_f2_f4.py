#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Step B — F2 (deterministic RULE 1 line) + F4 (classification hardening).

All mocked, NO paid calls. Covers:
  F2: the RULE 1 SATISFIED line in _format_authentication_block — present
      exactly when is_authenticated_brand_matched(auth) is True, restates the
      concrete-threat override, explicitly preserves RULE 2 (the eponanfc-
      class own-throwaway-domain phish trips the gate but must stay RULE 2),
      rides build_user_message OUTSIDE <untrusted_email>, and is absent for
      unauthenticated mail (prompt unchanged there).
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

# Same message but cryptographically authenticated for its own From domain
# (dkim=pass evil.com) — trips the deterministic RULE 1 gate. The Received
# "by" host anchors the Authentication-Results as trusted (C5b: authserv-id
# must share a registrable domain with the delivering host).
RAW_AUTHED = (
    b"From: Promo <promo@evil.com>\r\n"
    b"To: me@example.org\r\n"
    b"Subject: Win a prize today\r\n"
    b"Message-ID: <abc123@evil.com>\r\n"
    b"Received: from mail.evil.com by mx.example.org; "
    b"Wed, 1 Jul 2026 10:00:00 +0000\r\n"
    b"Authentication-Results: mx.example.org; dkim=pass header.d=evil.com\r\n"
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
# F2 — deterministic RULE 1 line
# ---------------------------------------------------------------------------

def _auth(dkim="pass", dmarc="none", from_domain="example.com",
          authed=("example.com",)):
    return {"spf": "none", "dkim": dkim, "dmarc": dmarc,
            "from_domain": from_domain,
            "authenticated_domains": list(authed)}


def test_f2_line_present_when_gate_true():
    block = spam_filter._format_authentication_block(_auth(), {})
    assert "RULE 1 SATISFIED" in block
    # Concrete-threat override restated verbatim from RULE 1.
    assert "a link whose domain is unrelated to the sender" in block
    assert "send money/credentials to an unrelated party" in block
    # The gate proves From-alignment only — RULE 2 must be left intact for
    # the eponanfc-class own-throwaway-domain phish.
    assert "does NOT bypass RULE 2" in block


def test_f2_line_absent_without_authentication():
    block = spam_filter._format_authentication_block(
        _auth(dkim="none", authed=()), {})
    assert "RULE 1 SATISFIED" not in block


def test_f2_line_absent_when_domains_do_not_align():
    block = spam_filter._format_authentication_block(
        _auth(from_domain="other.org"), {})
    assert "RULE 1 SATISFIED" not in block


def test_f2_line_matches_deterministic_gate_exactly():
    """The line must fire IFF is_authenticated_brand_matched fires — same
    gate, no re-derivation drift."""
    cases = [
        _auth(),                                      # dkim pass, aligned
        _auth(dkim="none", dmarc="pass"),             # dmarc pass, aligned
        _auth(authed=("sub.example.com",)),           # subdomain alignment
        _auth(dkim="none", dmarc="none"),             # no auth
        _auth(from_domain="brand.com"),               # not aligned
        _auth(authed=()),                             # nothing authenticated
    ]
    for auth in cases:
        expected = spam_filter.is_authenticated_brand_matched(auth)
        block = spam_filter._format_authentication_block(auth, {})
        assert ("RULE 1 SATISFIED" in block) is expected, auth


def test_f2_rides_build_user_message_outside_untrusted_tags():
    msg = spam_filter.build_user_message(_msg_data(RAW_AUTHED))
    assert "RULE 1 SATISFIED" in msg
    # Trusted framing: the line sits in the auth block BEFORE the untrusted
    # content opens. (The preamble MENTIONS the tag name in prose, so anchor
    # on the actual opening tag on its own line.)
    open_tag = msg.index("\n<untrusted_email>")
    assert msg.index("RULE 1 SATISFIED") < open_tag


def test_f2_unauthenticated_prompt_unchanged():
    msg = spam_filter.build_user_message(_msg_data(RAW_NORMAL))
    assert "RULE 1 SATISFIED" not in msg


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
