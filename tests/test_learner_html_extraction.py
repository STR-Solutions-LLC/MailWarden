#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""C1 — the learner must read the body the CLASSIFIER reads.

learn_signals._get_plain_body walked text/plain ONLY, so a spammer's empty or
decoy plain part starved the learner of the words the AI actually judged (the
classifier prefers HTML-derived visible text via build_user_message). The
learner now routes every body producer through _get_body_text, which mirrors
that precedence: HTML visible text when present, plain part otherwise.
"""
import os
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import learn_signals  # noqa: E402
import spam_filter    # noqa: E402
import utils          # noqa: E402


def _multipart(plain, html):
    m = MIMEMultipart("alternative")
    m["From"] = "Sender <s@example.com>"
    m["Subject"] = "Hi"
    m.attach(MIMEText(plain, "plain"))
    m.attach(MIMEText(html, "html"))
    return m


def _plain_only(plain):
    m = MIMEText(plain, "plain")
    m["From"] = "Sender <s@example.com>"
    m["Subject"] = "Hi"
    return m


def _html_only(html):
    m = MIMEText(html, "html")
    m["From"] = "Sender <s@example.com>"
    m["Subject"] = "Hi"
    return m


def test_decoy_empty_plain_extracts_html_text():
    # A blank/decoy plain part with the real message hidden in the HTML.
    msg = _multipart("   \n  ", "<p>REAL CONTENT the recipient sees</p>")
    body = learn_signals._get_body_text(msg)
    assert "REAL CONTENT the recipient sees" in body
    assert body.strip()  # not the empty plain decoy


def test_plain_only_is_byte_identical_to_old_behavior():
    # No HTML part -> _get_body_text falls back to the plain part EXACTLY.
    msg = _plain_only("Just an ordinary plain-text message.")
    assert learn_signals._get_body_text(msg) == learn_signals._get_plain_body(msg)
    assert "ordinary plain-text" in learn_signals._get_body_text(msg)


def test_html_only_extracts_visible_text():
    msg = _html_only("<html><body><p>HTMLONLY body words</p></body></html>")
    assert "HTMLONLY body words" in learn_signals._get_body_text(msg)


def test_parse_eml_uses_html_preferring_extraction(tmp_path):
    p = tmp_path / "decoy.eml"
    p.write_bytes(_multipart("", "<p>Decoy hidden REAL_XYZ text</p>").as_bytes())
    parsed = learn_signals.parse_eml(p)
    assert "REAL_XYZ" in parsed["plain_text_body"]


def test_learner_and_classifier_share_one_html_to_text():
    # No fork: the learner must call the SAME converter the classifier uses.
    assert utils.html_to_text is spam_filter.html_to_text
