import importlib.util
import sys
import types
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

from test_eval_corpus import make_benchmark, SPAM_EML, LEGIT_EML  # noqa: E402


def _load_eval_run():
    """Fresh import of tools/eval_run.py, same pattern as test_eval_corpus.py."""
    spec = importlib.util.spec_from_file_location(
        "eval_run", REPO / "tools" / "eval_run.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fake_spam_filter(recorder=None):
    """Build a fake spam_filter module whose classify_eml_offline records kwargs."""
    fake_sf = types.ModuleType("spam_filter")

    def fake_classify(raw, signals, **kw):
        if recorder is not None:
            recorder.append(kw)
        import email as _e
        msg = _e.message_from_bytes(raw)
        if "spammer" in msg.get("From", ""):
            return {"final_decision": "JUNK", "decided_by": "ai",
                    "pre_classifier": {}, "ai": {"decision": "SPAM", "confidence": 0.99}}
        return {"final_decision": "PASS", "decided_by": "ai",
                "pre_classifier": {}, "ai": {"decision": "NOT_SPAM", "confidence": 0.99}}

    fake_sf.classify_eml_offline = fake_classify
    return fake_sf


# ─── --model threading ───────────────────────────────────────────────────────

def test_run_eval_default_model_is_shipped(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    calls = []
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter(calls))

    mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model=mod.SHIPPED_MODEL, threshold=0.85, offline=False,
    )
    assert calls[0]["model"] == mod.SHIPPED_MODEL


def test_run_eval_override_model_reaches_classifier(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    calls = []
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter(calls))

    mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model="claude-sonnet-4-6", threshold=0.85, offline=False,
    )
    assert calls[0]["model"] == "claude-sonnet-4-6"


def test_run_eval_report_header_reflects_actual_model(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())

    result = mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model="claude-sonnet-4-6", threshold=0.85, offline=False,
    )
    header = [ln for ln in result["lines"] if ln.startswith("Model:")][0]
    assert "claude-sonnet-4-6" in header
    assert mod.SHIPPED_MODEL not in header


def test_main_cli_model_flag_overrides_shipped_default(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())
    out_file = tmp_path / "report.txt"

    monkeypatch.setattr(sys, "argv", [
        "eval_run.py", "--offline", "--benchmark-dir", str(benchmark),
        "--model", "claude-sonnet-4-6", "--out", str(out_file),
    ])
    mod.main()
    text = out_file.read_text()
    assert "Model:  claude-sonnet-4-6" in text


def test_main_cli_no_model_flag_uses_shipped_default(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())
    out_file = tmp_path / "report.txt"

    monkeypatch.setattr(sys, "argv", [
        "eval_run.py", "--offline", "--benchmark-dir", str(benchmark),
        "--out", str(out_file),
    ])
    mod.main()
    text = out_file.read_text()
    assert f"Model:  {mod.SHIPPED_MODEL}" in text


# ─── pricing map / estimate_cost ─────────────────────────────────────────────

def test_estimate_cost_haiku_prefix_match():
    mod = _load_eval_run()
    cost, desc = mod.estimate_cost(10, "claude-haiku-4-5-20251001")
    assert cost is not None
    expected = (10 * mod.AVG_INPUT_TOKENS_PER_EMAIL / 1_000_000) * 1.0 + \
               (10 * mod.AVG_OUTPUT_TOKENS_PER_EMAIL / 1_000_000) * 5.0
    assert cost == expected
    assert "unknown" not in desc.lower()


def test_estimate_cost_sonnet_exact_match():
    mod = _load_eval_run()
    cost, desc = mod.estimate_cost(10, "claude-sonnet-4-6")
    assert cost is not None
    expected = (10 * mod.AVG_INPUT_TOKENS_PER_EMAIL / 1_000_000) * 3.0 + \
               (10 * mod.AVG_OUTPUT_TOKENS_PER_EMAIL / 1_000_000) * 15.0
    assert cost == expected
    assert "unknown" not in desc.lower()


def test_estimate_cost_unknown_model():
    mod = _load_eval_run()
    cost, desc = mod.estimate_cost(10, "claude-opus-9000")
    assert cost is None
    assert "unknown pricing" in desc.lower()
    # token estimate must still be present even though pricing is unknown
    assert str(10 * mod.AVG_INPUT_TOKENS_PER_EMAIL) in desc.replace(",", "")


def test_estimate_cost_sonnet_prefix_does_not_match_unrelated_suffix():
    """Spec: sonnet pricing is an exact match, unlike the haiku wildcard."""
    mod = _load_eval_run()
    cost, desc = mod.estimate_cost(10, "claude-sonnet-4-6-preview")
    assert cost is None
    assert "unknown pricing" in desc.lower()


# ─── --full section ───────────────────────────────────────────────────────────

def test_report_without_full_flag_is_byte_identical_to_baseline(tmp_path, monkeypatch):
    """Locks the pre-existing report format. If this breaks, --out diffs against
    old baseline reports will no longer match."""
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("sp.eml", SPAM_EML)],
        "2-Legitimate-Newsletters-and-Marketing": [("lg.eml", LEGIT_EML)],
    })
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())

    result = mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model="claude-haiku-4-5-20251001", threshold=0.85, offline=False,
    )

    expected = [
        "Corpus: 2 emails  —  1 spam (1 inbox, 0 provider-flagged), 1 legit",
        "Model:  claude-haiku-4-5-20251001   threshold: 0.85   offline: False",
        "=" * 80,
        "=" * 80,
        "\nRecall  (spam caught):      100.0%  (1/1)",
        "  Inbox spam:               100.0%  (1/1)",
        "  Provider-flagged spam:    0.0%  (0/0)  [best-effort: SpamAssassin "
        "marker only; most providers don't stamp this, so this split under-counts]",
        "Precision (of junked mail): 100.0%  (1/1  junked total)",
        "False positives:            0",
        "\nNo misclassifications.",
    ]
    assert result["lines"] == expected


def test_report_with_full_flag_appends_section_without_altering_prefix(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("sp.eml", SPAM_EML)],
        "2-Legitimate-Newsletters-and-Marketing": [("lg.eml", LEGIT_EML)],
    })
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())

    baseline = mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model="claude-haiku-4-5-20251001", threshold=0.85, offline=False,
        full=False,
    )
    with_full = mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model="claude-haiku-4-5-20251001", threshold=0.85, offline=False,
        full=True,
    )

    # everything before the new section is untouched
    assert with_full["lines"][:len(baseline["lines"])] == baseline["lines"]
    # new section present and after the baseline content
    tail = with_full["lines"][len(baseline["lines"]):]
    assert any("Full verdict listing (2):" in ln for ln in tail)
    assert any("sp.eml" in ln and "JUNK" in ln for ln in tail)
    assert any("lg.eml" in ln and "PASS" in ln for ln in tail)


def test_report_full_section_sorted_deterministically(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("z_spam.eml", SPAM_EML), ("a_spam.eml", SPAM_EML)],
    })
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())

    result = mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model="claude-haiku-4-5-20251001", threshold=0.85, offline=False,
        full=True,
    )
    listing = [ln for ln in result["lines"] if "spam.eml" in ln]
    filenames_in_order = [ln.strip().split()[-1] for ln in listing]
    assert filenames_in_order == sorted(filenames_in_order)
    assert filenames_in_order == ["a_spam.eml", "z_spam.eml"]


def test_main_cli_full_flag_appends_section_to_out_file(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())
    out_file = tmp_path / "report.txt"

    monkeypatch.setattr(sys, "argv", [
        "eval_run.py", "--offline", "--benchmark-dir", str(benchmark),
        "--full", "--out", str(out_file),
    ])
    mod.main()
    text = out_file.read_text()
    assert "Full verdict listing (1):" in text
    assert "sp.eml" in text


def test_main_cli_without_full_flag_omits_section_from_out_file(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())
    out_file = tmp_path / "report.txt"

    monkeypatch.setattr(sys, "argv", [
        "eval_run.py", "--offline", "--benchmark-dir", str(benchmark),
        "--out", str(out_file),
    ])
    mod.main()
    text = out_file.read_text()
    assert "Full verdict listing" not in text


# ─── --cascade ────────────────────────────────────────────────────────────────

def test_run_eval_cascade_threads_mode_and_confirm_model(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    calls = []
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter(calls))

    mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model=mod.SHIPPED_MODEL, threshold=0.85, offline=False,
        cascade=True, confirm_model="claude-sonnet-4-6",
    )
    assert calls[0]["classify_mode"] == "cascade"
    assert calls[0]["confirm_model"] == "claude-sonnet-4-6"
    assert calls[0]["model"] == mod.SHIPPED_MODEL


def test_run_eval_non_cascade_kwargs_unchanged(tmp_path, monkeypatch):
    """Without --cascade the classify kwargs are exactly the pre-cascade set —
    no classify_mode / confirm_model keys at all (back-compat contract)."""
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    calls = []
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter(calls))

    mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model=mod.SHIPPED_MODEL, threshold=0.85, offline=False,
    )
    assert "classify_mode" not in calls[0]
    assert "confirm_model" not in calls[0]


def test_run_eval_cascade_header_names_both_models(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())

    result = mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model=mod.SHIPPED_MODEL, threshold=0.85, offline=False,
        cascade=True, confirm_model="claude-sonnet-4-6",
    )
    header = [ln for ln in result["lines"] if ln.startswith("Model:")][0]
    assert mod.SHIPPED_MODEL in header
    assert "claude-sonnet-4-6" in header
    assert "cascade" in header


def test_main_cli_cascade_flag_reaches_classifier(tmp_path, monkeypatch):
    benchmark = make_benchmark(tmp_path, {"1-Spam": [("sp.eml", SPAM_EML)]})
    mod = _load_eval_run()
    calls = []
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter(calls))
    out_file = tmp_path / "report.txt"

    monkeypatch.setattr(sys, "argv", [
        "eval_run.py", "--offline", "--benchmark-dir", str(benchmark),
        "--cascade", "--out", str(out_file),
    ])
    mod.main()
    assert calls[0]["classify_mode"] == "cascade"
    assert calls[0]["confirm_model"] == mod.SHIPPED_CONFIRM_MODEL
    assert "cascade" in out_file.read_text()


def test_estimate_cost_cascade_adds_confirm_term():
    mod = _load_eval_run()
    single, _ = mod.estimate_cost(10, "claude-haiku-4-5-20251001")
    total, desc = mod.estimate_cost(
        10, "claude-haiku-4-5-20251001",
        cascade=True, confirm_model="claude-sonnet-4-6")
    n_confirm = 10 * mod.ASSUMED_CONFIRM_FRACTION
    expected_confirm = (
        (n_confirm * mod.AVG_INPUT_TOKENS_PER_EMAIL / 1_000_000) * 3.0
        + (n_confirm * mod.AVG_OUTPUT_TOKENS_PER_EMAIL / 1_000_000) * 15.0)
    assert total == single + expected_confirm
    assert "claude-sonnet-4-6" in desc
    assert "junk rate" in desc


def test_estimate_cost_non_cascade_output_byte_identical():
    """cascade=False must produce exactly the pre-cascade estimate text."""
    mod = _load_eval_run()
    cost, desc = mod.estimate_cost(10, "claude-haiku-4-5-20251001")
    cost2, desc2 = mod.estimate_cost(10, "claude-haiku-4-5-20251001",
                                     cascade=False, confirm_model=None)
    assert (cost, desc) == (cost2, desc2)


# ─── graymail (4-Graymail) report lines ───────────────────────────────────────

def test_report_no_graymail_folder_has_no_graymail_lines(tmp_path, monkeypatch):
    """Format guard: a graymail-free corpus report mentions graymail nowhere."""
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("sp.eml", SPAM_EML)],
        "2-Legitimate-Newsletters-and-Marketing": [("lg.eml", LEGIT_EML)],
    })
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())

    result = mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model="claude-haiku-4-5-20251001", threshold=0.85, offline=False,
        full=True,
    )
    assert not any("raymail" in ln for ln in result["lines"])


def test_report_graymail_folder_adds_separate_line(tmp_path, monkeypatch):
    from test_eval_corpus import GRAYMAIL_EML
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("sp.eml", SPAM_EML)],
        "2-Legitimate-Newsletters-and-Marketing": [("lg.eml", LEGIT_EML)],
        "4-Graymail": [("gray.eml", GRAYMAIL_EML)],
    })
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())

    result = mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model="claude-haiku-4-5-20251001", threshold=0.85, offline=False,
        full=True,
    )
    lines = result["lines"]
    # corpus summary names graymail separately
    corpus_line = [ln for ln in lines if ln.startswith("Corpus:")][0]
    assert "1 graymail" in corpus_line
    assert "1 legit" in corpus_line  # graymail must not inflate legit
    # dedicated metric line, and headline metrics untouched
    assert any(ln.startswith("Graymail (scored separately): 0/1 junked")
               for ln in lines)
    assert "False positives:            0" in lines
    # full listing tags it GRAY
    assert any("GRAY " in ln and "gray.eml" in ln for ln in lines)


def test_report_graymail_junked_is_not_false_positive(tmp_path, monkeypatch):
    """A junked graymail shows on the graymail line, never as an FP."""
    from test_eval_corpus import GRAYMAIL_EML
    # fake classifier junks 'spammer' Froms; craft graymail from 'spammer' so
    # the fake junks it.
    junky_graymail = GRAYMAIL_EML.replace(
        b"updates@graymailer.com", b"spammer@graymailer.com")
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("sp.eml", SPAM_EML)],
        "4-Graymail": [("gray.eml", junky_graymail)],
    })
    mod = _load_eval_run()
    monkeypatch.setitem(sys.modules, "spam_filter", _fake_spam_filter())

    result = mod.run_eval(
        benchmark_dir=benchmark, signals={}, api_key="fake",
        model="claude-haiku-4-5-20251001", threshold=0.85, offline=False,
    )
    lines = result["lines"]
    assert any(ln.startswith("Graymail (scored separately): 1/1 junked")
               for ln in lines)
    assert "False positives:            0" in lines
    assert "\nNo misclassifications." in lines
