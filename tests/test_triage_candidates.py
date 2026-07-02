#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Tests for tools/triage_candidates.py — heuristics (pure) + the interactive
loop with input() mocked. NO network (DKIM uses the synthetic fixtures'
embedded-key seam via full local verify), NO Anthropic, NO real mail.
"""
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "payload" / "MailWarden" / "src"))
sys.path.insert(0, str(REPO / "tools"))

from make_synthetics import write_synthetics, dkim_test_dnsfunc  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location(
        "triage_candidates", REPO / "tools" / "triage_candidates.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _synth(tmp_path):
    """Write synthetics and return {filename: bytes}."""
    d = tmp_path / "_syn"
    write_synthetics(d)
    return {p.name: p.read_bytes() for p in d.glob("*.eml")}


# ─── heuristics ─────────────────────────────────────────────────────────────────

def test_provider_stamped_auth_flags_candidate(tmp_path):
    """14 (dkim=pass+dmarc=pass, brand-matched) must flag via prime/aligned."""
    mod = _load()
    files = _synth(tmp_path)
    ev = mod.evaluate_candidate(files["14-legit-transactional-receipt.eml"])
    assert ev["is_candidate"]
    assert "dkim_brand_matched" in ev["reasons"] or "spf_dmarc_aligned" in ev["reasons"]


def test_list_unsubscribe_flags_candidate(tmp_path):
    mod = _load()
    files = _synth(tmp_path)
    ev = mod.evaluate_candidate(files["15-legit-authenticated-newsletter.eml"])
    assert ev["is_candidate"]
    assert "list_unsubscribe" in ev["reasons"]


def test_local_dkim_brand_match_flags_bluehost(tmp_path, monkeypatch):
    """16 (no A-R, local DKIM) must flag via the prime heuristic once local
    verification resolves through the embedded test key. In production
    evaluate_candidate calls verify_dkim_locally() with the real resolver; here
    we route it through the fixture's test dnsfunc so no network is touched."""
    import utils
    real_verify = utils.verify_dkim_locally
    monkeypatch.setattr(
        utils, "verify_dkim_locally",
        lambda raw, **kw: real_verify(raw, _dnsfunc=dkim_test_dnsfunc))
    mod = _load()
    files = _synth(tmp_path)
    ev = mod.evaluate_candidate(files["16-legit-bluehost-local-dkim.eml"])
    assert ev["is_candidate"]
    assert "dkim_brand_matched" in ev["reasons"]


def test_dictionary_domain_heuristic():
    mod = _load()
    assert mod._looks_dictionaryish("harborviewdental") is True
    assert mod._looks_dictionaryish("bkzvqrelay") is False
    assert mod._looks_dictionaryish("qntrvxz") is False


def test_random_domain_unauth_not_candidate(tmp_path, monkeypatch):
    """A gibberish, unauthenticated spam with no unsubscribe / no valid auth
    is NOT flagged (heuristics stay off)."""
    mod = _load()
    raw = (
        b"From: sales@qzxvbktr.biz\r\n"
        b"To: me@example.com\r\n"
        b"Subject: buy now\r\n"
        b"Message-ID: <1@qzxvbktr.biz>\r\n"
        b"\r\nbuy now\r\n"
    )
    ev = mod.evaluate_candidate(raw)
    assert ev["is_candidate"] is False


# ─── interactive loop ───────────────────────────────────────────────────────────

def _benchmark(tmp_path):
    b = tmp_path / "bench"
    b.mkdir()
    return b


def _harvest_with(tmp_path, name, raw):
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True, exist_ok=True)
    (h / name).write_bytes(raw)
    return tmp_path / "_harvest"


def test_verdict_y_moves_to_newsletter(tmp_path):
    mod = _load()
    files = _synth(tmp_path)
    harvest = _harvest_with(tmp_path, "cand.eml",
                            files["15-legit-authenticated-newsletter.eml"])
    bench = _benchmark(tmp_path)
    answers = iter(["y", "n"])  # y = legit, n = newsletter (not personal)
    res = mod.run_triage(harvest, bench, prompt=lambda *_: next(answers),
                         out=lambda *_: None)
    assert res["counts"]["y"] == 1
    assert (bench / mod.FOLDER_NEWSLETTER / "cand.eml").exists()
    # moved out of harvest
    assert not (harvest / "acct" / "cand.eml").exists()


def test_verdict_y_personal_subfolder(tmp_path):
    mod = _load()
    files = _synth(tmp_path)
    harvest = _harvest_with(tmp_path, "cand.eml",
                            files["14-legit-transactional-receipt.eml"])
    bench = _benchmark(tmp_path)
    answers = iter(["y", "p"])
    mod.run_triage(harvest, bench, prompt=lambda *_: next(answers),
                   out=lambda *_: None)
    assert (bench / mod.FOLDER_PERSONAL / "cand.eml").exists()


def test_verdict_n_moves_to_spam(tmp_path):
    mod = _load()
    files = _synth(tmp_path)
    harvest = _harvest_with(tmp_path, "cand.eml",
                            files["15-legit-authenticated-newsletter.eml"])
    bench = _benchmark(tmp_path)
    res = mod.run_triage(harvest, bench, prompt=lambda *_: "n",
                         out=lambda *_: None)
    assert res["counts"]["n"] == 1
    assert (bench / mod.FOLDER_SPAM / "cand.eml").exists()


def test_verdict_skip_leaves_in_place(tmp_path):
    mod = _load()
    files = _synth(tmp_path)
    harvest = _harvest_with(tmp_path, "cand.eml",
                            files["15-legit-authenticated-newsletter.eml"])
    bench = _benchmark(tmp_path)
    res = mod.run_triage(harvest, bench, prompt=lambda *_: "skip",
                         out=lambda *_: None)
    assert res["counts"]["skip"] == 1
    assert (harvest / "acct" / "cand.eml").exists()
    # nothing entered the corpus
    assert not any(bench.rglob("*.eml"))


def test_question_wording_is_exact():
    mod = _load()
    assert mod.QUESTION == ("Is this a real company that legitimately has "
                            "this address?")


def test_one_prompt_per_email_no_bulk(tmp_path):
    """HARD RULE: exactly one identity-question prompt per email — never a
    single answer applied to many. Two candidates => two identity prompts."""
    mod = _load()
    files = _synth(tmp_path)
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    (h / "a.eml").write_bytes(files["14-legit-transactional-receipt.eml"])
    (h / "b.eml").write_bytes(files["15-legit-authenticated-newsletter.eml"])
    bench = _benchmark(tmp_path)

    prompts_seen = []
    answers = iter(["skip", "skip"])

    def rec(msg):
        prompts_seen.append(msg)
        return next(answers)

    res = mod.run_triage(h.parent, bench, prompt=rec, out=lambda *_: None)
    assert res["processed"] == 2
    identity_prompts = [p for p in prompts_seen if mod.QUESTION in p]
    assert len(identity_prompts) == 2  # one per email, never fewer


def test_source_has_no_bulk_approval_flag():
    """Guard: the CLI exposes no --all / --bulk / per-sender approval path."""
    src = (REPO / "tools" / "triage_candidates.py").read_text()
    for token in ("--all", "--bulk", "--approve-sender", "approve_all",
                  "bulk_approve"):
        assert token not in src, f"bulk token {token!r} present"


def test_resume_skips_logged(tmp_path):
    mod = _load()
    files = _synth(tmp_path)
    harvest = _harvest_with(tmp_path, "cand.eml",
                            files["15-legit-authenticated-newsletter.eml"])
    bench = _benchmark(tmp_path)
    # pre-seed the log as if cand.eml was already handled
    mod.append_triage_log(bench, "cand.eml", "spam", mod.FOLDER_SPAM)
    res = mod.run_triage(harvest, bench, resume=True,
                         prompt=lambda *_: (_ for _ in ()).throw(
                             AssertionError("should not prompt")),
                         out=lambda *_: None)
    assert res["processed"] == 0


def test_limit_caps_candidates(tmp_path):
    mod = _load()
    files = _synth(tmp_path)
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    for i in range(4):
        (h / f"c{i}.eml").write_bytes(
            files["15-legit-authenticated-newsletter.eml"])
    bench = _benchmark(tmp_path)
    res = mod.run_triage(h.parent, bench, limit=2, prompt=lambda *_: "skip",
                         out=lambda *_: None)
    assert res["processed"] == 2
