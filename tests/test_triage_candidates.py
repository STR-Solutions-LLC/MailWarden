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


# ─── interleave / per-sender cap / graymail (defect fixes + delta) ──────────────

def _cand(domain, name="X", subj="s"):
    """A minimal candidate: List-Unsubscribe fires the heuristic regardless of
    domain/name, so tests can freely vary From-domain and display-name."""
    frm = f'"{name}" <x@{domain}>' if name else f"x@{domain}"
    return (f"From: {frm}\r\nTo: me@e.com\r\nSubject: {subj}\r\n"
            f"Message-ID: <1@{domain}>\r\n"
            f"List-Unsubscribe: <mailto:u@{domain}>\r\n"
            f"\r\nbody\r\n").encode()


def test_interleave_round_robin_across_subdirs(tmp_path):
    """Candidates are surfaced round-robin across account subdirs, not drained
    one account at a time (the original single-sorted-rglob defect)."""
    mod = _load()
    h = tmp_path / "_harvest"
    for acct in ("Commerce", "Dad", "Mom"):
        (h / acct).mkdir(parents=True)
        for i in range(2):
            (h / acct / f"{acct}{i}.eml").write_bytes(_cand(f"{acct}{i}.com"))
    order = [p.parent.name for p in mod._ordered_eml_paths(h)]
    assert order == ["Commerce", "Dad", "Mom", "Commerce", "Dad", "Mom"]


def test_interleave_is_deterministic(tmp_path):
    mod = _load()
    h = tmp_path / "_harvest"
    for acct in ("A", "B"):
        (h / acct).mkdir(parents=True)
        for i in range(3):
            (h / acct / f"f{i}.eml").write_bytes(_cand(f"{acct}{i}.com"))
    assert mod._ordered_eml_paths(h) == mod._ordered_eml_paths(h)


def test_stray_toplevel_eml_included_last(tmp_path):
    """A stray .eml directly in _harvest (not in a subdir) is handled: included,
    ordered after the subdir bucket, and still asked."""
    mod = _load()
    h = tmp_path / "_harvest"
    (h / "acct").mkdir(parents=True)
    (h / "acct" / "sub.eml").write_bytes(_cand("sub.com"))
    (h / "stray.eml").write_bytes(_cand("stray.com"))
    names = [p.name for p in mod._ordered_eml_paths(h)]
    assert set(names) == {"sub.eml", "stray.eml"}
    assert names[0] == "sub.eml"      # subdir bucket first
    assert names[-1] == "stray.eml"   # stray bucket last
    bench = _benchmark(tmp_path)
    res = mod.run_triage(h, bench, prompt=lambda *_: "skip",
                         out=lambda *_: None)
    assert res["processed"] == 2


def test_per_domain_cap_defers_and_never_labels(tmp_path):
    """HARD-RULE guard: hitting the domain cap DEFERS the extras — never labels.
    Exactly `cap` are asked/labeled; the rest stay in _harvest, unlogged."""
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    for i in range(5):
        (h / f"c{i}.eml").write_bytes(_cand("blast.com", name=f"n{i}"))
    bench = _benchmark(tmp_path)
    res = mod.run_triage(h.parent, bench, per_domain_cap=2,
                         prompt=lambda *_: "n", out=lambda *_: None)
    assert res["processed"] == 2
    assert res["deferred"] == 3
    assert res["counts"]["n"] == 2
    # exactly 2 labeled into spam; 3 deferred NOT labeled
    assert len(list((bench / mod.FOLDER_SPAM).glob("*.eml"))) == 2
    assert len(list(h.glob("*.eml"))) == 3          # 2 moved out, 3 remain
    log_lines = (bench / mod.TRIAGE_LOG).read_text().splitlines()
    assert len(log_lines) == 1 + 2                  # header + 2 verdicts only


def test_no_cap_asks_all_same_domain(tmp_path):
    """Library default (per_domain_cap=None) never caps — guards direct callers
    (and every existing test) from a silent cap."""
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    for i in range(5):
        (h / f"c{i}.eml").write_bytes(_cand("blast.com", name=f"n{i}"))
    bench = _benchmark(tmp_path)
    res = mod.run_triage(h.parent, bench, prompt=lambda *_: "skip",
                         out=lambda *_: None)
    assert res["processed"] == 5
    assert res["deferred"] == 0


def test_cap_composes_with_resume(tmp_path):
    """resume-skip precedes cap counting: a prior-run label does not consume
    this run's per-domain budget."""
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    for i in range(4):
        (h / f"f{i}.eml").write_bytes(_cand("blast.com", name=f"n{i}"))
    bench = _benchmark(tmp_path)
    mod.append_triage_log(bench, "f0.eml", "spam", mod.FOLDER_SPAM)
    res = mod.run_triage(h.parent, bench, resume=True, per_domain_cap=2,
                         prompt=lambda *_: "skip", out=lambda *_: None)
    # f0 resume-skipped; f1,f2 asked (cap=2); f3 deferred.
    assert res["processed"] == 2
    assert res["deferred"] == 1


def test_cap_composes_with_limit(tmp_path):
    """limit-break precedes cap-defer: once the sitting quota is asked we stop,
    without inflating the deferred tally past the cutoff."""
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    for i in range(5):
        (h / f"c{i}.eml").write_bytes(_cand("blast.com", name=f"n{i}"))
    bench = _benchmark(tmp_path)
    res = mod.run_triage(h.parent, bench, limit=1, per_domain_cap=2,
                         prompt=lambda *_: "skip", out=lambda *_: None)
    assert res["processed"] == 1
    assert res["deferred"] == 0


def test_display_name_cap_bunches_across_rotated_domains(tmp_path):
    """DELTA: a blast that rotates the From-domain but keeps ONE display name is
    capped by the display-name counter even though every domain is unique."""
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    for i in range(5):
        (h / f"c{i}.eml").write_bytes(
            _cand(f"rotate{i}.com", name="Jamie Raskin"))
    bench = _benchmark(tmp_path)
    res = mod.run_triage(h.parent, bench, per_domain_cap=2,
                         prompt=lambda *_: "skip", out=lambda *_: None)
    assert res["processed"] == 2      # capped by display-name, not domain
    assert res["deferred"] == 3


def test_empty_display_names_never_bunch(tmp_path):
    """DELTA: bare-address senders (no display name) are never grouped — distinct
    empty-name emails across the cap are all asked."""
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    for i in range(4):
        (h / f"c{i}.eml").write_bytes(_cand(f"noname{i}.com", name=""))
    bench = _benchmark(tmp_path)
    res = mod.run_triage(h.parent, bench, per_domain_cap=2,
                         prompt=lambda *_: "skip", out=lambda *_: None)
    assert res["processed"] == 4      # distinct domains + empty names => no cap
    assert res["deferred"] == 0


def test_from_display_name_normalization():
    mod = _load()
    import email as _e

    def nm(frm):
        m = _e.message_from_bytes(f"From: {frm}\r\n\r\n".encode())
        return mod._from_display_name(m)

    assert nm('"Jamie Raskin" <a@b.com>') == "jamie raskin"
    assert nm('Jamie   Raskin <a@b.com>') == "jamie raskin"
    assert nm('"Jamie Raskin," <a@b.com>') == "jamie raskin"
    assert nm('a@b.com') == ""        # bare address -> empty, never grouped


def test_rfc2047_encodings_normalize_alike_and_bunch(tmp_path):
    """A blast that RFC 2047-encodes the same display name differently (base64
    vs quoted-printable vs plain ASCII) must normalize to one name and bunch
    together under the per-name cap."""
    mod = _load()
    import base64
    name = "Jamie Raskin"
    b64 = "=?UTF-8?B?" + base64.b64encode(name.encode()).decode() + "?="
    qp = "=?UTF-8?Q?Jamie_Raskin?="            # '_' is a QP-encoded space
    froms = [f'{b64} <x@d0.com>', f'{qp} <x@d1.com>', f'{name} <x@d2.com>']
    # all three decode to the same normalized name
    import email as _e
    names = {mod._from_display_name(_e.message_from_bytes(f"From: {f}\r\n\r\n"
             .encode())) for f in froms}
    assert names == {"jamie raskin"}
    # and they bunch: 3 distinct domains, one shared name, cap 2 => 1 deferred
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    for i, f in enumerate(froms):
        (h / f"c{i}.eml").write_bytes(
            (f"From: {f}\r\nTo: me@e.com\r\nSubject: s\r\n"
             f"Message-ID: <1@d{i}.com>\r\n"
             f"List-Unsubscribe: <mailto:u@d{i}.com>\r\n\r\nbody\r\n").encode())
    bench = _benchmark(tmp_path)
    res = mod.run_triage(h.parent, bench, per_domain_cap=2,
                         prompt=lambda *_: "skip", out=lambda *_: None)
    assert res["processed"] == 2
    assert res["deferred"] == 1


def test_malformed_encoded_word_does_not_crash():
    """A malformed encoded-word must never crash the loop — it falls back to the
    raw string path and still yields a usable normalized name."""
    mod = _load()
    import email as _e

    def nm(frm):
        m = _e.message_from_bytes(f"From: {frm}\r\n\r\n".encode())
        return mod._from_display_name(m)

    # truncated / bad-charset encoded-words: no exception, graceful fallback
    assert nm('=?UTF-8?B?not-valid-base64!!!?= <a@b.com>') != None  # no crash
    assert nm('=?bogus-charset?Q?Jamie?= <a@b.com>')  # non-empty, no crash
    assert nm('=?UTF-8?B?QW1p <a@b.com>') != None                  # truncated


def test_verdict_g_moves_to_graymail(tmp_path):
    mod = _load()
    files = _synth(tmp_path)
    harvest = _harvest_with(tmp_path, "cand.eml",
                            files["15-legit-authenticated-newsletter.eml"])
    bench = _benchmark(tmp_path)
    res = mod.run_triage(harvest, bench, prompt=lambda *_: "g",
                         out=lambda *_: None)
    assert res["counts"]["g"] == 1
    assert mod.FOLDER_GRAYMAIL == "4-Graymail"
    assert (bench / mod.FOLDER_GRAYMAIL / "cand.eml").exists()
    assert not (harvest / "acct" / "cand.eml").exists()   # moved out


def test_graymail_logged(tmp_path):
    mod = _load()
    files = _synth(tmp_path)
    harvest = _harvest_with(tmp_path, "cand.eml",
                            files["15-legit-authenticated-newsletter.eml"])
    bench = _benchmark(tmp_path)
    mod.run_triage(harvest, bench, prompt=lambda *_: "g", out=lambda *_: None)
    rows = (bench / mod.TRIAGE_LOG).read_text().splitlines()
    assert rows[0].startswith("filename\t")
    data = rows[1].split("\t")
    assert data[0] == "cand.eml"
    assert data[1] == "graymail"
    assert data[2] == "4-Graymail"


def test_graymail_folder_matches_corpus_reader():
    """The triage folder constant must equal the eval reader's graymail folder,
    or labeled graymail would be invisible to the eval."""
    mod = _load()
    spec = importlib.util.spec_from_file_location(
        "eval_corpus", REPO / "tools" / "eval_corpus.py")
    ec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ec)
    assert mod.FOLDER_GRAYMAIL == ec._GRAYMAIL_FOLDER


def test_summary_shape_has_deferred_and_graymail(tmp_path):
    mod = _load()
    h = tmp_path / "_harvest" / "acct"
    h.mkdir(parents=True)
    (h / "c0.eml").write_bytes(_cand("blast.com", name="Jamie Raskin"))
    (h / "c1.eml").write_bytes(_cand("blast.com", name="Jamie Raskin"))
    bench = _benchmark(tmp_path)
    res = mod.run_triage(h.parent, bench, per_domain_cap=1,
                         prompt=lambda *_: "g", out=lambda *_: None)
    assert "processed" in res and "deferred" in res
    assert "g" in res["counts"]
    assert res["deferred"] == 1       # c1 capped (same domain AND same name)
    assert res["counts"]["g"] == 1


def test_guidance_and_g_hint_shown_with_prompt(tmp_path):
    """QUESTION stays exact; the identity prompt carries the g hint and the
    approved guidance line is shown alongside it."""
    mod = _load()
    files = _synth(tmp_path)
    harvest = _harvest_with(tmp_path, "cand.eml",
                            files["15-legit-authenticated-newsletter.eml"])
    bench = _benchmark(tmp_path)
    seen_prompts, seen_out = [], []

    def rec(msg):
        seen_prompts.append(msg)
        return "skip"

    mod.run_triage(harvest, bench, prompt=rec, out=seen_out.append)
    assert mod.QUESTION == ("Is this a real company that legitimately has "
                            "this address?")
    id_prompt = [p for p in seen_prompts if mod.QUESTION in p][0]
    assert "g=graymail" in id_prompt
    assert any("relentless pitch mail" in m for m in seen_out)


def test_cli_has_per_domain_cap_flag():
    """--per-domain-cap exists and is wired into run_triage."""
    src = (REPO / "tools" / "triage_candidates.py").read_text()
    assert "--per-domain-cap" in src
    assert "per_domain_cap=" in src
