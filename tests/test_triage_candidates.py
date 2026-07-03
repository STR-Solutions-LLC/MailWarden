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


# ─── sandboxed browser preview ─────────────────────────────────────────────────

_HTML_EMAIL = (
    b"From: Promo Sender <promo@bigbrand.com>\r\n"
    b"To: me@example.com\r\n"
    b"Subject: Big <Sale> Today\r\n"
    b"Date: Wed, 1 Jul 2026 10:00:00 -0400\r\n"
    b"Message-ID: <m1@bigbrand.com>\r\n"
    b"List-Unsubscribe: <mailto:u@bigbrand.com>\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><head><meta http-equiv=\"refresh\" content=\"0;url=https://evil.example/\">"
    b"<base href=\"https://evil.example/\"></head>"
    b"<body><script>alert('pwn')</script>"
    b"<p style=\"color:red\">HUGE deal</p>"
    b"<img src=\"https://tracker.example/pixel.gif\">"
    b"</body></html>\r\n"
)

_PLAIN_EMAIL = (
    b"From: Plain Person <p@plainco.com>\r\n"
    b"To: me@example.com\r\n"
    b"Subject: hello\r\n"
    b"Date: Wed, 1 Jul 2026 11:00:00 -0400\r\n"
    b"Message-ID: <m2@plainco.com>\r\n"
    b"List-Unsubscribe: <mailto:u@plainco.com>\r\n"
    b"\r\n"
    b"Just words here. 1 < 2 & so on.\r\n"
)


def _preview(mod, raw):
    ev = mod.evaluate_candidate(raw)
    return mod.build_preview_html(raw, ev)


def test_preview_csp_wrapper_present():
    """The strict CSP meta must be injected in <head>, before any email
    content: remote img/script/css/fonts are blocked (default-src 'none' +
    img-src data: only) while inline styles still render (style-src
    'unsafe-inline'). Blank remote images are the intended behavior."""
    mod = _load()
    doc = _preview(mod, _HTML_EMAIL)
    assert 'http-equiv="Content-Security-Policy"' in doc
    assert "default-src 'none'" in doc
    assert "img-src data:" in doc
    assert "style-src 'unsafe-inline'" in doc
    assert "form-action 'none'" in doc
    # CSP is in OUR head, before the email's (neutralized) markup begins.
    assert doc.index("Content-Security-Policy") < doc.index("HUGE deal")
    # The inline style the email carries survives (renders under the CSP).
    assert 'style="color:red"' in doc


def test_preview_script_neutralized():
    mod = _load()
    doc = _preview(mod, _HTML_EMAIL)
    assert "<script" not in doc.lower()
    assert "alert('pwn')" not in doc


def test_preview_script_unclosed_dropped():
    """An unclosed <script> must not leak its contents into the preview."""
    mod = _load()
    out = mod._remove_script_blocks("safe<script>evil= tail with no close")
    assert out == "safe"
    # And closed blocks vanish while surrounding content stays.
    assert mod._remove_script_blocks("a<SCRIPT src=x>b</sCrIpT>c") == "ac"


def test_preview_script_splice_bypass_removed():
    """A single linear pass over "<scr<script>DUMMY</script>ipt>alert(1)
    </script>" deletes the inner <script>...</script> span and glues the
    surrounding text into a brand-new, live "<script>alert(1)</script>" that
    a one-shot scan never re-examines. _remove_script_blocks must run to a
    fixed point so the reconstructed tag gets caught on a follow-up pass."""
    mod = _load()
    probe = "<scr<script>DUMMY</script>ipt>alert(1)</script>"
    out = mod._remove_script_blocks(probe)
    assert "<script" not in out.lower()

    # Doubly-nested variant — two layers of splicing must both be defeated.
    probe2 = ("<scr<scr<script>D1</script>D2</script>ipt>alert(2)</script>"
              "ipt>alert(1)</script>")
    out2 = mod._remove_script_blocks(probe2)
    assert "<script" not in out2.lower()


def test_preview_script_splice_bypass_removed_in_full_pipeline():
    """The same splice payload, delivered as an email's HTML body, must not
    surface a live <script> anywhere in the rendered preview.html output."""
    mod = _load()
    raw = (
        b"From: Promo Sender <promo@bigbrand.com>\r\n"
        b"To: me@example.com\r\n"
        b"Subject: splice test\r\n"
        b"Date: Wed, 1 Jul 2026 10:00:00 -0400\r\n"
        b"Message-ID: <m3@bigbrand.com>\r\n"
        b"List-Unsubscribe: <mailto:u@bigbrand.com>\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<html><body><p>hi</p>"
        b"<scr<script>DUMMY</script>ipt>alert(1)</script>"
        b"</body></html>\r\n"
    )
    doc = _preview(mod, raw)
    assert "<script" not in doc.lower()


def test_preview_links_neutralized():
    """href targets must never survive as a live navigable href, across
    quoting styles (double/single/unquoted/whitespace) and dangerous
    schemes (javascript:) — while the anchor's visible text is preserved."""
    mod = _load()
    cases = [
        '<a href="http://evil.example/steal">click here</a>',
        "<a href='javascript:alert(1)'>js here</a>",
        "<a href=http://evil.example/bare>bare here</a>",
        '<A   HrEf  =  "HTTP://Evil.Example/Mixed"  >mixed here</A>',
    ]
    for html_fragment in cases:
        out = mod._neutralize_links(html_fragment)
        assert "evil.example" not in out.lower()
        assert "javascript:" not in out.lower()
        # visible anchor text survives
        assert "here</a" in out.lower() or "here</A" in out


def test_preview_link_click_disabled_full_pipeline():
    """A live http(s) link in an email body must not survive into the
    rendered preview as a clickable href, and the header bar must warn Matt
    that links are disabled."""
    mod = _load()
    raw = (
        b"From: Promo Sender <promo@bigbrand.com>\r\n"
        b"To: me@example.com\r\n"
        b"Subject: link test\r\n"
        b"Date: Wed, 1 Jul 2026 10:00:00 -0400\r\n"
        b"Message-ID: <m4@bigbrand.com>\r\n"
        b"List-Unsubscribe: <mailto:u@bigbrand.com>\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b'<html><body><a href="http://evil.example/steal">click me</a>'
        b"</body></html>\r\n"
    )
    doc = _preview(mod, raw)
    assert "evil.example" not in doc.lower()
    assert "click me" in doc  # anchor text preserved
    assert "links are disabled" in doc  # header bar warns Matt


def test_preview_meta_refresh_and_base_neutralized():
    """meta-refresh and <base> are renamed to inert unknown elements; no
    live <meta ...> or <base ...> from the EMAIL remains (our own wrapper
    metas — charset + CSP — are the only real ones)."""
    mod = _load()
    doc = _preview(mod, _HTML_EMAIL)
    assert "x-meta" in doc and "x-base" in doc
    body_part = doc.split("</head>", 1)[1]
    assert "<meta" not in body_part.lower()
    assert "<base" not in body_part.lower()


def test_preview_remote_img_stays_but_csp_blocks():
    """The remote <img> tag remains in the markup (the CSP is what blocks
    the load — a blank box is the tracking-pixel protection working)."""
    mod = _load()
    doc = _preview(mod, _HTML_EMAIL)
    assert "tracker.example/pixel.gif" in doc
    assert "img-src data:" in doc  # …and nothing but data: may load


def test_preview_header_bar_fields_escaped():
    mod = _load()
    doc = _preview(mod, _HTML_EMAIL)
    assert "MailWarden triage preview" in doc
    assert "Promo Sender" in doc
    # Subject's <Sale> must be HTML-escaped in the header bar, not raw markup.
    assert "Big &lt;Sale&gt; Today" in doc
    assert "Wed, 1 Jul 2026 10:00:00" in doc
    assert "Auth:" in doc and "SPF=" in doc
    assert "list_unsubscribe" in doc  # heuristics fired


def test_preview_plain_fallback_pre():
    mod = _load()
    doc = _preview(mod, _PLAIN_EMAIL)
    assert "<pre" in doc
    assert "Just words here. 1 &lt; 2 &amp; so on." in doc
    assert 'http-equiv="Content-Security-Policy"' in doc  # same wrapper


def test_preview_loop_unique_file_per_candidate(tmp_path):
    """Preview ON: each candidate gets its OWN fresh filename (never a single
    reused name) inside one temp dir — never repo, never benchmark. A stale
    cached browser tab for a reused URL is a labeling-correctness risk, so
    every `open` call must target a distinct path Matt hasn't visited before."""
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    (h / "a.eml").write_bytes(_HTML_EMAIL)
    (h / "b.eml").write_bytes(_PLAIN_EMAIL)
    bench = _benchmark(tmp_path)
    opened = []
    res = mod.run_triage(h.parent, bench, prompt=lambda *_: "skip",
                         out=lambda *_: None, preview=True,
                         opener=lambda p: opened.append(Path(p)))
    assert res["processed"] == 2
    assert len(opened) == 2
    assert opened[0] != opened[1], "each candidate must get a distinct preview file"
    assert opened[0].exists()
    assert opened[1].exists()
    assert opened[0].parent == opened[1].parent, "same temp dir, different filenames"
    assert not str(opened[0]).startswith(str(REPO))
    assert not str(opened[0]).startswith(str(bench))
    assert not str(opened[1]).startswith(str(REPO))
    assert not str(opened[1]).startswith(str(bench))
    # Each file holds its OWN candidate's preview (not overwritten by the next).
    assert "HUGE deal" in opened[0].read_text()
    assert "Just words here" in opened[1].read_text()


def test_preview_open_failure_never_breaks_loop(tmp_path):
    """`open` blowing up must not crash triage; the verdict still lands."""
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    (h / "a.eml").write_bytes(_HTML_EMAIL)
    bench = _benchmark(tmp_path)
    msgs = []

    def boom(_):
        raise OSError("no browser here")

    res = mod.run_triage(h.parent, bench, prompt=lambda *_: "n",
                         out=msgs.append, preview=True, opener=boom)
    assert res["counts"]["n"] == 1
    assert (bench / mod.FOLDER_SPAM / "a.eml").exists()
    assert any("preview unavailable" in m for m in msgs)
    # Terminal text view was still shown (fallback path).
    assert any("Subject:" in m for m in msgs)


def test_preview_off_never_opens(tmp_path):
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    (h / "a.eml").write_bytes(_HTML_EMAIL)
    bench = _benchmark(tmp_path)
    opened = []
    mod.run_triage(h.parent, bench, prompt=lambda *_: "skip",
                   out=lambda *_: None, preview=False,
                   opener=lambda p: opened.append(p))
    assert opened == []


def test_cli_has_no_preview_flag():
    """--no-preview exists and the CLI default is preview ON."""
    src = (REPO / "tools" / "triage_candidates.py").read_text()
    assert "--no-preview" in src
    assert "preview=not args.no_preview" in src
