import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))


# ─── synthetic .eml content (no real emails committed) ──────────────────────────

SPAM_EML = (
    b"From: spammer@evil.com\r\n"
    b"To: user@example.com\r\n"
    b"Subject: Win a prize\r\n"
    b"Message-ID: <s1@evil.com>\r\n"
    b"\r\n"
    b"Click here to claim your reward."
)

LEGIT_EML = (
    b"From: hello@newsletter.com\r\n"
    b"To: user@example.com\r\n"
    b"Subject: Weekly digest\r\n"
    b"Message-ID: <l1@newsletter.com>\r\n"
    b"\r\n"
    b"Here is your weekly update."
)

PROVIDER_CAUGHT_EML = (
    b"From: spammer2@junk.net\r\n"
    b"To: user@example.com\r\n"
    b"Subject: Buy pills\r\n"
    b"X-Spam-Status: Yes, score=9.5\r\n"
    b"Message-ID: <p1@junk.net>\r\n"
    b"\r\n"
    b"Cheap pills overnight."
)

SPAM_FLAG_EML = (
    b"From: bad@actor.com\r\n"
    b"To: user@example.com\r\n"
    b"Subject: Urgent\r\n"
    b"X-Spam-Flag: YES\r\n"
    b"Message-ID: <f1@actor.com>\r\n"
    b"\r\n"
    b"Wire money now."
)


# ─── helper ─────────────────────────────────────────────────────────────────────

def make_benchmark(tmp_path, files_by_folder: dict) -> Path:
    for folder, files in files_by_folder.items():
        d = tmp_path / folder
        d.mkdir(parents=True, exist_ok=True)
        for name, content in files:
            (d / name).write_bytes(content)
    return tmp_path


# ─── build_corpus tests ─────────────────────────────────────────────────────────

def test_build_corpus_spam_label(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("bad.eml", SPAM_EML)],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert len(items) == 1
    assert items[0]["label"] == "spam"
    assert items[0]["filename"] == "bad.eml"


def test_build_corpus_legit_labels(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "2-Legitimate-Newsletters-and-Marketing": [("news.eml", LEGIT_EML)],
        "3-Legitimate-Personal": [("personal.eml", LEGIT_EML)],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert len(items) == 2
    assert all(i["label"] == "legit" for i in items)


def test_build_corpus_skips_non_eml(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [
            ("real_spam.eml", SPAM_EML),
            ("notes.txt", b"ignore me"),
            ("archive.zip", b"PK"),
        ],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert len(items) == 1
    assert items[0]["filename"] == "real_spam.eml"


def test_build_corpus_skips_ds_store(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [
            ("bad.eml", SPAM_EML),
            (".DS_Store", b"\x00\x00\x00"),
        ],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert len(items) == 1


def test_build_corpus_skips_excluded_subfolder(tmp_path):
    spam_dir = tmp_path / "1-Spam"
    spam_dir.mkdir()
    (spam_dir / "real.eml").write_bytes(SPAM_EML)
    excluded = spam_dir / "_excluded"
    excluded.mkdir()
    (excluded / "skip.eml").write_bytes(SPAM_EML)
    from eval_corpus import build_corpus
    items = build_corpus(tmp_path)
    assert len(items) == 1
    assert items[0]["filename"] == "real.eml"


def test_build_corpus_provider_spam_via_x_spam_status(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("provider.eml", PROVIDER_CAUGHT_EML)],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert items[0]["source"] == "provider"


def test_build_corpus_provider_spam_via_x_spam_flag(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("flagged.eml", SPAM_FLAG_EML)],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert items[0]["source"] == "provider"


def test_build_corpus_inbox_spam_no_header(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("inbox.eml", SPAM_EML)],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert items[0]["source"] == "inbox"


def test_build_corpus_legit_source_always_inbox(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "2-Legitimate-Newsletters-and-Marketing": [("news.eml", LEGIT_EML)],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert items[0]["source"] == "inbox"


def test_build_corpus_parses_from_and_subject(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("bad.eml", SPAM_EML)],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert "spammer@evil.com" in items[0]["from_email"]
    assert "Win a prize" in items[0]["subject"]


def test_build_corpus_missing_folder_skipped(tmp_path):
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("bad.eml", SPAM_EML)],
    })
    from eval_corpus import build_corpus
    items = build_corpus(benchmark)
    assert len(items) == 1


# ─── score_results tests ────────────────────────────────────────────────────────

def _item(label, source="inbox"):
    return {"label": label, "source": source,
            "filename": f"{label}.eml", "from_email": "", "subject": ""}


def test_score_perfect():
    labeled = [_item("spam"), _item("spam"), _item("legit")]
    verdicts = ["JUNK", "JUNK", "PASS"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["recall"] == 1.0
    assert m["precision"] == 1.0
    assert m["false_positives"] == 0
    assert m["fn"] == 0
    assert m["misclassified"] == []


def test_score_false_positive():
    labeled = [_item("legit"), _item("spam")]
    verdicts = ["JUNK", "PASS"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["false_positives"] == 1
    assert m["tp"] == 0
    assert m["fn"] == 1
    assert m["precision"] == 0.0
    assert m["recall"] == 0.0
    assert len(m["misclassified"]) == 2
    kinds = {x["kind"] for x in m["misclassified"]}
    assert "false_positive" in kinds
    assert "missed_spam" in kinds


def test_score_unknown_verdict_counts_as_not_junked():
    labeled = [_item("spam")]
    verdicts = ["UNKNOWN"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["fn"] == 1
    assert m["tp"] == 0


def test_score_separates_inbox_and_provider_recall():
    labeled = [
        _item("spam", source="inbox"),
        _item("spam", source="provider"),
        _item("legit"),
    ]
    verdicts = ["PASS", "JUNK", "PASS"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["recall_inbox"] == 0.0
    assert m["recall_provider"] == 1.0
    assert m["false_positives"] == 0
    assert m["tp_inbox"] == 0
    assert m["tp_provider"] == 1


def test_score_all_zero_spam():
    labeled = [_item("legit"), _item("legit")]
    verdicts = ["PASS", "PASS"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["recall"] == 0.0
    assert m["total_spam"] == 0


def test_score_no_legit_all_spam():
    labeled = [_item("spam"), _item("spam")]
    verdicts = ["JUNK", "JUNK"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["false_positives"] == 0
    assert m["precision"] == 1.0


def test_score_misclassified_excludes_raw():
    labeled = [dict(_item("spam"), raw=b"big bytes")]
    verdicts = ["PASS"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    for entry in m["misclassified"]:
        assert "raw" not in entry


def test_score_precision_with_tp_and_fp():
    # tp=1 (spam junked), fp=1 (legit junked) — exercises the tp/(tp+fp) denominator
    labeled = [_item("spam"), _item("legit")]
    verdicts = ["JUNK", "JUNK"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["precision"] == 0.5
    assert m["recall"] == 1.0
    assert m["false_positives"] == 1


# ─── eval_run.py smoke tests (added after Task 1 passes) ────────────────────────

def test_eval_run_importable():
    """eval_run.py must be importable without raising."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "eval_run", REPO / "tools" / "eval_run.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "main")
    assert hasattr(mod, "run_eval")


def test_eval_run_end_to_end_mock(tmp_path, monkeypatch):
    """Full pipeline with mocked classify_eml_offline — no API calls."""
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("sp.eml", SPAM_EML)],
        "2-Legitimate-Newsletters-and-Marketing": [("lg.eml", LEGIT_EML)],
    })

    import types
    fake_sf = types.ModuleType("spam_filter")

    def fake_classify(raw, signals, **kw):
        import email as _e
        msg = _e.message_from_bytes(raw)
        if "spammer" in msg.get("From", ""):
            return {"final_decision": "JUNK", "decided_by": "ai",
                    "pre_classifier": {}, "ai": {"decision": "SPAM", "confidence": 0.99}}
        return {"final_decision": "PASS", "decided_by": "ai",
                "pre_classifier": {}, "ai": {"decision": "NOT_SPAM", "confidence": 0.99}}

    fake_sf.classify_eml_offline = fake_classify
    monkeypatch.setitem(sys.modules, "spam_filter", fake_sf)

    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "eval_run", REPO / "tools" / "eval_run.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    result = mod.run_eval(
        benchmark_dir=benchmark,
        signals={},
        api_key="fake",
        model="claude-haiku-4-5-20251001",
        threshold=0.85,
        offline=False,
        verbose=False,
    )
    assert result["metrics"]["recall"] == 1.0
    assert result["metrics"]["false_positives"] == 0
    assert result["metrics"]["precision"] == 1.0
