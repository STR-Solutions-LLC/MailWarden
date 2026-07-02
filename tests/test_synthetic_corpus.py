#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Validate the 16 synthetic eval fixtures (tools/make_synthetics.py).

These tests check the FIXTURES themselves — that they parse, carry the headers
their class needs, and that the DKIM-signed / authenticated-brand-matched ones
actually exercise the real crypto + auth code paths through the injected
_dnsfunc seam. NO network, NO Anthropic calls, NO paid classifier.
"""
import email as _email_stdlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "payload" / "MailWarden" / "src"))
sys.path.insert(0, str(REPO / "tools"))

import utils  # noqa: E402
import spam_filter  # noqa: E402
from make_synthetics import (  # noqa: E402
    SYNTHETICS, write_synthetics, dkim_test_dnsfunc, TEST_DKIM_SELECTOR,
)


def _built(tmp_path):
    """Generate the fixtures into a tmp dir and return {filename: bytes}."""
    write_synthetics(tmp_path)
    return {spec["filename"]: (tmp_path / spec["filename"]).read_bytes()
            for spec in SYNTHETICS}


def _auth(raw, local=False):
    md = spam_filter.extract_email_data(raw)
    hdrs = {"Authentication-Results": md.get("auth_results", ""),
            "Received-SPF": md.get("received_spf", ""),
            "DKIM-Signature": md.get("dkim_signature", "")}
    lv = (utils.verify_dkim_locally(raw, _dnsfunc=dkim_test_dnsfunc)
          if local else None)
    fd = md["from_email"].split("@")[-1] if "@" in md["from_email"] else ""
    return spam_filter.summarize_authentication(hdrs, from_domain=fd,
                                                locally_verified=lv)


def test_manifest_has_16_with_expected_label_split():
    labels = [s["label"] for s in SYNTHETICS]
    assert len(SYNTHETICS) == 16
    assert labels.count("spam") == 13
    assert labels.count("legit") == 3


def test_all_fixtures_parse_with_core_headers(tmp_path):
    files = _built(tmp_path)
    for name, raw in files.items():
        msg = _email_stdlib.message_from_bytes(raw)
        assert msg.get("From"), f"{name} missing From"
        assert msg.get("Subject"), f"{name} missing Subject"
        assert msg.get("Message-ID"), f"{name} missing Message-ID"


def test_regeneration_is_deterministic(tmp_path):
    a = _built(tmp_path / "a")
    b = _built(tmp_path / "b")
    assert a == b, "synthetic generation must be byte-deterministic"


def test_signed_fixtures_verify_locally(tmp_path):
    files = _built(tmp_path)
    for spec in SYNTHETICS:
        if not spec["dkim_domain"]:
            continue
        doms = utils.verify_dkim_locally(files[spec["filename"]],
                                         _dnsfunc=dkim_test_dnsfunc)
        assert spec["dkim_domain"] in doms, (
            f"{spec['filename']} DKIM did not verify: {doms}")


def test_unsigned_fixtures_carry_no_verifiable_signature(tmp_path):
    files = _built(tmp_path)
    for spec in SYNTHETICS:
        if spec["dkim_domain"]:
            continue
        doms = utils.verify_dkim_locally(files[spec["filename"]],
                                         _dnsfunc=dkim_test_dnsfunc)
        assert doms == [], f"{spec['filename']} unexpectedly verified: {doms}"


def test_authenticated_legit_fixtures_are_brand_matched(tmp_path):
    """14 & 15 (provider-stamped) exercise the authenticated+brand-matched
    LEGIT path that real harvested mail never triggers."""
    files = _built(tmp_path)
    for name in ("14-legit-transactional-receipt.eml",
                 "15-legit-authenticated-newsletter.eml"):
        auth = _auth(files[name])
        assert spam_filter.is_authenticated_brand_matched(auth), name


def test_bluehost_legit_brand_matched_only_via_local_dkim(tmp_path):
    """16 has NO Authentication-Results; it must brand-match ONLY once local
    DKIM verification supplies the proven domain."""
    files = _built(tmp_path)
    raw = files["16-legit-bluehost-local-dkim.eml"]
    assert not spam_filter.is_authenticated_brand_matched(_auth(raw, local=False))
    assert spam_filter.is_authenticated_brand_matched(_auth(raw, local=True))


def test_signed_phish_is_not_brand_matched(tmp_path):
    """06 carries a VALID signature for mailblastpro.net but claims From
    paypal.com — must NOT be treated as authenticated-brand-matched."""
    files = _built(tmp_path)
    auth = _auth(files["06-dkim-signed-phish-misaligned.eml"], local=True)
    assert auth["authenticated_domains"] == ["mailblastpro.net"]
    assert not spam_filter.is_authenticated_brand_matched(auth)


def test_provider_flagged_fixture_marks_source_provider(tmp_path):
    """11 carries X-Spam-Status: Yes — build_corpus must tag it provider."""
    from eval_corpus import build_corpus
    spam_dir = tmp_path / "1-Spam"
    spam_dir.mkdir()
    write_synthetics(tmp_path / "_syn")
    raw = (tmp_path / "_syn" / "11-provider-flagged-pills.eml").read_bytes()
    (spam_dir / "11.eml").write_bytes(raw)
    items = build_corpus(tmp_path)
    assert items[0]["source"] == "provider"


def test_test_dnsfunc_only_serves_test_selector():
    """The seam must not answer for arbitrary selectors (fail-closed)."""
    good = f"{TEST_DKIM_SELECTOR}._domainkey.example.com.".encode()
    bad = b"default._domainkey.example.com."
    assert dkim_test_dnsfunc(good) is not None
    assert dkim_test_dnsfunc(bad) is None
