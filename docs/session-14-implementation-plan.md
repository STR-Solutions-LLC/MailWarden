# Session 14 — Private Eval Corpus & Scoring Harness Implementation Plan

> **Note:** Do NOT save this plan to `docs/superpowers/`. It is saved to `docs/` per project constraints.

**Goal:** Build a local offline eval harness that scores the real MailWarden filter against a hand-labeled corpus of real emails from three Desktop folders, reporting precision/recall/FP in plain English — plus regenerate the stale `tests/_out` baselines.

**Architecture:** Two new Python modules in `tools/` (corpus builder + scoring logic), one CLI entry-point script, and two committed test files that exercise everything without API calls or real email data (synthetic content via `tmp_path`). The `tests/_out` baseline scripts are local-only (gitignored); they need their hardcoded installer path updated so they can regenerate their reference `.txt` files.

**Tech Stack:** Python 3 stdlib only (`email`, `pathlib`, `argparse`, `re`, `json`); `classify_eml_offline` from `payload/MailWarden/src/spam_filter.py`; `pytest` + `tmp_path` for tests.

## Global Constraints

- All new files are in `tools/` or `tests/` — never under `payload/`, never in the installer payload allowlist.
- Built corpus and result files are local-only, git-ignored. The Desktop folders remain the source of truth.
- No changes to live filter, teaching, or learner code. Purely additive.
- Do NOT write under `.superpowers/` or `docs/superpowers/` — breaks the build pre-flight.
- Test-first: write a failing test, confirm it fails, implement minimal code, confirm it passes, commit.
- Tests use `tmp_path` + inline Python bytes for synthetic `.eml` content — no real emails committed.
- The `tests/_out/` directory is git-ignored (local-only). All nine `*.py` scripts in it still reference the old installer path `/Users/mattrosenberg/MailWarden-installer` — Task 3 fixes them.

---

### Task 1: Corpus builder module + unit tests

**Files:**
- Create: `tools/eval_corpus.py`
- Create: `tests/test_eval_corpus.py`
- Modify: `.gitignore` (add one line)

**Interfaces — what Task 2 relies on:**
- `build_corpus(benchmark_dir: Path) -> list[dict]`
  - Each dict: `{filename: str, label: str, source: str, from_email: str, subject: str, raw: bytes, path: Path}`
  - `label` is `"spam"` or `"legit"`
  - `source` is `"inbox"` or `"provider"` (spam only; always `"inbox"` for legit)
- `score_results(labeled: list[dict], verdicts: list[str]) -> dict`
  - Returns `{recall, recall_inbox, recall_provider, precision, false_positives, total_spam, total_legit, total_inbox_spam, total_provider_spam, tp, fp, fn, tp_inbox, tp_provider, misclassified}`
  - `misclassified` is a list of `{kind, filename, from_email, subject, source}` (no `raw` key)
  - `verdicts` elements are `"JUNK"`, `"PASS"`, or `"UNKNOWN"`; `"UNKNOWN"` counts as not-junked

---

- [ ] **Step 1.1: Write the failing tests**

Create `tests/test_eval_corpus.py` with this content:

```python
import sys
from pathlib import Path
import pytest

# Allow importing from tools/ without installation
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))


# ─── build_corpus tests ────────────────────────────────────────────────────────

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


def make_benchmark(tmp_path, files_by_folder: dict) -> Path:
    """Helper: create a benchmark dir structure with given {folder_name: [(name, content), ...]}."""
    for folder, files in files_by_folder.items():
        d = tmp_path / folder
        d.mkdir(parents=True, exist_ok=True)
        for name, content in files:
            (d / name).write_bytes(content)
    return tmp_path


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
    """Legit emails never carry a 'provider' source marker."""
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
    """If a labeled folder does not exist, build_corpus silently skips it."""
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("bad.eml", SPAM_EML)],
        # 2-Legit and 3-Personal intentionally absent
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
    assert m["precision"] == 0.0   # 0 TP, 1 FP → 0/(0+1)
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
    verdicts = ["PASS", "JUNK", "PASS"]   # missed inbox, caught provider
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["recall_inbox"] == 0.0
    assert m["recall_provider"] == 1.0
    assert m["false_positives"] == 0
    assert m["tp_inbox"] == 0
    assert m["tp_provider"] == 1


def test_score_all_zero_spam():
    """Edge: no spam emails → recall defined as 0.0, not division error."""
    labeled = [_item("legit"), _item("legit")]
    verdicts = ["PASS", "PASS"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["recall"] == 0.0
    assert m["total_spam"] == 0


def test_score_no_legit_all_spam():
    """Edge: no legit emails → FP is 0, precision fully meaningful."""
    labeled = [_item("spam"), _item("spam")]
    verdicts = ["JUNK", "JUNK"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    assert m["false_positives"] == 0
    assert m["precision"] == 1.0


def test_score_misclassified_excludes_raw():
    """Misclassified dicts must not carry the `raw` bytes key (too large for reporting)."""
    labeled = [dict(_item("spam"), raw=b"big bytes")]
    verdicts = ["PASS"]
    from eval_corpus import score_results
    m = score_results(labeled, verdicts)
    for entry in m["misclassified"]:
        assert "raw" not in entry
```

- [ ] **Step 1.2: Confirm tests fail**

```bash
tests/.venv/bin/python -m pytest tests/test_eval_corpus.py -v 2>&1 | head -30
```

Expected: `ModuleNotFoundError: No module named 'eval_corpus'` (or similar import failure). If tests pass at this point, something is wrong — stop and investigate.

- [ ] **Step 1.3: Add `.gitignore` entry**

In `.gitignore`, after the `tests/_out/` line, add:

```
tools/__pycache__/
```

- [ ] **Step 1.4: Implement `tools/eval_corpus.py`**

Create `tools/eval_corpus.py`:

```python
import email as _email_stdlib
import re
from pathlib import Path

_FOLDER_LABELS = {
    "1-Spam": "spam",
    "2-Legitimate-Newsletters-and-Marketing": "legit",
    "3-Legitimate-Personal": "legit",
}

_PROVIDER_HEADERS = re.compile(r"x-spam-(status|flag)", re.IGNORECASE)
_PROVIDER_YES = re.compile(r"\byes\b", re.IGNORECASE)


def build_corpus(benchmark_dir) -> list:
    """Read ~/Desktop/MailWarden-Benchmark and return a labeled list of emails.

    Each item: {filename, label, source, from_email, subject, raw, path}
      label  — "spam" or "legit"
      source — "inbox" or "provider" (legit always "inbox";
                spam is "provider" when X-Spam-Status/X-Spam-Flag: Yes present)
    """
    items = []
    for folder_name, label in _FOLDER_LABELS.items():
        folder = Path(benchmark_dir) / folder_name
        if not folder.is_dir():
            continue
        for f in sorted(folder.iterdir()):
            if f.is_dir():        # skip subdirectories (including _excluded)
                continue
            if f.name == ".DS_Store":
                continue
            if f.suffix.lower() != ".eml":
                continue
            raw = f.read_bytes()
            msg = _email_stdlib.message_from_bytes(raw)
            from_email = msg.get("From", "")
            subject = msg.get("Subject", "")
            source = "inbox"
            if label == "spam":
                for hdr_name in msg.keys():
                    if _PROVIDER_HEADERS.match(hdr_name):
                        if _PROVIDER_YES.search(msg.get(hdr_name, "")):
                            source = "provider"
                            break
            items.append({
                "filename": f.name,
                "label": label,
                "source": source,
                "from_email": from_email,
                "subject": subject,
                "raw": raw,
                "path": f,
            })
    return items


def score_results(labeled: list, verdicts: list) -> dict:
    """Score classified verdicts against labeled ground truth.

    labeled  — list of dicts as returned by build_corpus
    verdicts — parallel list of "JUNK" | "PASS" | "UNKNOWN"
               UNKNOWN is treated as not-junked (same as PASS)

    Returns a dict with:
      recall, recall_inbox, recall_provider  — float 0.0–1.0
      precision                              — float 0.0–1.0
      false_positives                        — int
      total_spam, total_legit                — int
      total_inbox_spam, total_provider_spam  — int
      tp, fp, fn, tp_inbox, tp_provider      — int
      misclassified                          — list of dicts (no raw key)
    """
    assert len(labeled) == len(verdicts), "labeled and verdicts must be the same length"

    tp = fp = fn = 0
    tp_inbox = tp_provider = 0
    total_inbox_spam = total_provider_spam = 0
    misclassified = []

    SAFE_KEYS = {"filename", "label", "source", "from_email", "subject"}

    for item, verdict in zip(labeled, verdicts):
        junked = verdict == "JUNK"
        if item["label"] == "spam":
            if item.get("source") == "provider":
                total_provider_spam += 1
                if junked:
                    tp_provider += 1
            else:
                total_inbox_spam += 1
                if junked:
                    tp_inbox += 1
            if junked:
                tp += 1
            else:
                fn += 1
                misclassified.append(
                    {"kind": "missed_spam", **{k: item[k] for k in SAFE_KEYS if k in item}}
                )
        else:
            if junked:
                fp += 1
                misclassified.append(
                    {"kind": "false_positive", **{k: item[k] for k in SAFE_KEYS if k in item}}
                )

    total_spam = tp + fn
    total_legit = len(labeled) - total_spam
    recall = tp / total_spam if total_spam > 0 else 0.0
    recall_inbox = tp_inbox / total_inbox_spam if total_inbox_spam > 0 else 0.0
    recall_provider = tp_provider / total_provider_spam if total_provider_spam > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    return {
        "recall": recall,
        "recall_inbox": recall_inbox,
        "recall_provider": recall_provider,
        "precision": precision,
        "false_positives": fp,
        "total_spam": total_spam,
        "total_legit": total_legit,
        "total_inbox_spam": total_inbox_spam,
        "total_provider_spam": total_provider_spam,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tp_inbox": tp_inbox,
        "tp_provider": tp_provider,
        "misclassified": misclassified,
    }
```

- [ ] **Step 1.5: Confirm tests pass**

```bash
tests/.venv/bin/python -m pytest tests/test_eval_corpus.py -v
```

Expected: all 19 tests pass. If any fail, fix `eval_corpus.py` before proceeding.

- [ ] **Step 1.6: Confirm full suite still passes**

```bash
tests/.venv/bin/python -m pytest tests/ -v --ignore=tests/_out 2>&1 | tail -5
```

Expected: same count as before + 19 new, all green.

- [ ] **Step 1.7: Commit**

```bash
git add tools/eval_corpus.py tests/test_eval_corpus.py .gitignore
git commit -m "feat(S14): corpus builder + scoring logic with unit tests"
```

---

### Task 2: Scoring harness CLI (`tools/eval_run.py`)

**Files:**
- Create: `tools/eval_run.py`

**Interfaces:**
- Consumes: `build_corpus`, `score_results` from `tools/eval_corpus.py`
- Consumes: `spam_filter.classify_eml_offline` from `payload/MailWarden/src/spam_filter.py`
- Produces: terminal output + optional `--out` file; exit 0

No new unit tests are needed for `eval_run.py` itself — the underlying logic is fully covered by Task 1 tests. What we DO need is a smoke test that the CLI is importable and its `--help` doesn't crash, and that `_run_with_mock` (a testable inner path) wires correctly. Add these tests to the existing `tests/test_eval_corpus.py`.

---

- [ ] **Step 2.1: Add CLI smoke tests**

Append to `tests/test_eval_corpus.py`:

```python
# ─── eval_run.py smoke tests ────────────────────────────────────────────────────

def test_eval_run_importable():
    """eval_run.py must be importable without raising (argparse setup, imports)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "eval_run", REPO / "tools" / "eval_run.py"
    )
    mod = importlib.util.load_module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert hasattr(mod, "main")


def test_eval_run_end_to_end_mock(tmp_path, monkeypatch):
    """Full pipeline with mocked classify_eml_offline: no API calls."""
    # Build a tiny benchmark
    benchmark = make_benchmark(tmp_path, {
        "1-Spam": [("sp.eml", SPAM_EML)],
        "2-Legitimate-Newsletters-and-Marketing": [("lg.eml", LEGIT_EML)],
    })

    # Patch classify_eml_offline to return a fixed verdict
    import sys
    import types

    fake_sf = types.ModuleType("spam_filter")
    def fake_classify(raw, signals, **kw):
        # Junk the spam, pass the legit — perfect harness
        from email import message_from_bytes
        msg = message_from_bytes(raw)
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
    mod = importlib.util.load_module_from_spec(spec)
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
```

- [ ] **Step 2.2: Confirm the new tests fail**

```bash
tests/.venv/bin/python -m pytest tests/test_eval_corpus.py::test_eval_run_importable tests/test_eval_corpus.py::test_eval_run_end_to_end_mock -v
```

Expected: both fail with `FileNotFoundError` or `ModuleNotFoundError` (eval_run.py doesn't exist yet).

- [ ] **Step 2.3: Implement `tools/eval_run.py`**

Create `tools/eval_run.py`:

```python
#!/usr/bin/env python3
"""
MailWarden eval harness — score the real filter against a hand-labeled corpus.

Usage:
  tests/.venv/bin/python tools/eval_run.py
  tests/.venv/bin/python tools/eval_run.py --offline         # free smoke: pre-classifier only
  tests/.venv/bin/python tools/eval_run.py --out /tmp/run.txt  # save full report
  tests/.venv/bin/python tools/eval_run.py --yes             # skip cost confirmation

Reads corpus from ~/Desktop/MailWarden-Benchmark/ (three labeled folders).
Reads shipped signals from resources/defaults/signals.json.
Reads API key + model from ~/MailWarden/config/config.json or $ANTHROPIC_API_KEY.
"""
import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "payload" / "MailWarden" / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(REPO / "tools"))

DEFAULT_BENCHMARK = Path.home() / "Desktop" / "MailWarden-Benchmark"
DEFAULT_SIGNALS = REPO / "resources" / "defaults" / "signals.json"
CONFIG = Path.home() / "MailWarden" / "config" / "config.json"
COST_PER_EMAIL = 0.0043   # ~Haiku 4.5; ballpark only


def run_eval(benchmark_dir, signals, api_key, model, threshold,
             offline=False, verbose=False):
    """Core eval logic. Returns {lines: [str, ...], metrics: dict}.

    Separated from main() so the mock test can call it directly.
    """
    import spam_filter
    from eval_corpus import build_corpus, score_results

    lines = []

    def w(line=""):
        print(line)
        lines.append(line)

    items = build_corpus(Path(benchmark_dir))
    if not items:
        w(f"No .eml files found in {benchmark_dir}")
        return {"lines": lines, "metrics": {}}

    spam_count = sum(1 for i in items if i["label"] == "spam")
    legit_count = len(items) - spam_count
    inbox_spam = sum(1 for i in items if i["label"] == "spam" and i["source"] == "inbox")
    provider_spam = spam_count - inbox_spam

    w(f"Corpus: {len(items)} emails — {spam_count} spam "
      f"({inbox_spam} inbox, {provider_spam} provider-caught), {legit_count} legit")
    w(f"Model:  {model}   threshold: {threshold}   offline: {offline}")
    w("=" * 80)

    verdicts = []
    for item in items:
        try:
            res = spam_filter.classify_eml_offline(
                item["raw"], signals,
                api_key=(api_key if not offline else ""),
                model=model,
                threshold=threshold,
                run_dnsbl=False,
            )
            verdict = res.get("final_decision", "UNKNOWN")
        except Exception as e:
            verdict = "UNKNOWN"
            w(f"  ERROR on {item['filename']}: {e}")
        verdicts.append(verdict)

        is_spam = item["label"] == "spam"
        correct = (verdict == "JUNK") == is_spam
        if verbose or not correct:
            tag = "  " if correct else "XX"
            label_tag = "SPAM " if is_spam else "LEGIT"
            w(f"{tag} [{label_tag}] {item['filename'][:55]:57} -> {verdict}")

    w("=" * 80)
    metrics = score_results(items, verdicts)

    w(f"\nRecall  (spam caught):      {metrics['recall']:.1%}  "
      f"({metrics['tp']}/{metrics['total_spam']})")
    w(f"  Inbox spam:               {metrics['recall_inbox']:.1%}  "
      f"({metrics['tp_inbox']}/{metrics['total_inbox_spam']})")
    w(f"  Provider-caught spam:     {metrics['recall_provider']:.1%}  "
      f"({metrics['tp_provider']}/{metrics['total_provider_spam']})")
    w(f"Precision (of junked mail): {metrics['precision']:.1%}  "
      f"({metrics['tp']}/{metrics['tp'] + metrics['fp']}  junked total)")
    w(f"False positives:            {metrics['false_positives']}")

    if metrics["misclassified"]:
        w(f"\nMisclassified ({len(metrics['misclassified'])}):")
        for m in metrics["misclassified"]:
            if m["kind"] == "missed_spam":
                src_tag = f"  [{m.get('source', '?')}]"
                w(f"  MISSED SPAM{src_tag}: {m['filename']}")
            else:
                w(f"  FALSE POSITIVE: {m['filename']}")
            w(f"    From:    {m['from_email']}")
            w(f"    Subject: {m['subject']}")
    else:
        w("\nNo misclassifications.")

    return {"lines": lines, "metrics": metrics}


def main():
    ap = argparse.ArgumentParser(
        description="Score the MailWarden filter against a hand-labeled corpus."
    )
    ap.add_argument("--benchmark-dir", default=str(DEFAULT_BENCHMARK),
                    help="path to MailWarden-Benchmark folder (default: ~/Desktop/MailWarden-Benchmark)")
    ap.add_argument("--signals", default=str(DEFAULT_SIGNALS),
                    help="path to signals.json (default: resources/defaults/signals.json)")
    ap.add_argument("--offline", action="store_true",
                    help="pre-classifier only; no API calls")
    ap.add_argument("--out", default=None,
                    help="write full report to this file")
    ap.add_argument("--yes", action="store_true",
                    help="skip cost-confirmation prompt")
    ap.add_argument("--verbose", action="store_true",
                    help="print every email (not just misclassified)")
    args = ap.parse_args()

    signals = {}
    try:
        signals = json.loads(Path(args.signals).read_text())
    except Exception as e:
        print(f"Warning: could not load signals from {args.signals}: {e}", file=sys.stderr)

    cfg = {}
    try:
        cfg = json.loads(CONFIG.read_text())
    except Exception:
        pass

    anthro = cfg.get("anthropic", {}) if isinstance(cfg, dict) else {}
    api_key = (os.environ.get("ANTHROPIC_API_KEY") or anthro.get("api_key", "") or "")
    model = anthro.get("model") or "claude-haiku-4-5-20251001"
    threshold = (cfg.get("filter", {}).get("confidence_threshold", 0.85)
                 if isinstance(cfg, dict) else 0.85)

    # Cost confirmation
    if not args.offline and not args.yes:
        from eval_corpus import build_corpus
        items = build_corpus(Path(args.benchmark_dir))
        est = len(items) * COST_PER_EMAIL
        print(f"Estimated cost: ~${est:.2f} for {len(items)} emails at ~${COST_PER_EMAIL}/email (Haiku 4.5 ballpark).")
        answer = input("Proceed? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            return 0

    result = run_eval(
        benchmark_dir=args.benchmark_dir,
        signals=signals,
        api_key=api_key,
        model=model,
        threshold=threshold,
        offline=args.offline,
        verbose=args.verbose,
    )

    if args.out:
        try:
            Path(args.out).write_text("\n".join(result["lines"]) + "\n", encoding="utf-8")
            print(f"\n(Report saved to {args.out})")
        except Exception as e:
            print(f"Warning: could not write --out {args.out}: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2.4: Confirm CLI tests pass**

```bash
tests/.venv/bin/python -m pytest tests/test_eval_corpus.py -v 2>&1 | tail -10
```

Expected: all 21 tests pass (the 19 from Task 1 + the 2 new ones).

- [ ] **Step 2.5: Smoke test the CLI manually (offline mode, free)**

```bash
tests/.venv/bin/python tools/eval_run.py --offline --verbose
```

Expected: prints corpus count, "offline: True", lists each email with its pre-classifier verdict, then prints recall/precision/FP summary. No API key required. No money spent.

- [ ] **Step 2.6: Confirm full suite still passes**

```bash
tests/.venv/bin/python -m pytest tests/ -v --ignore=tests/_out 2>&1 | tail -5
```

Expected: all green with 21 total in the eval tests.

- [ ] **Step 2.7: Commit**

```bash
git add tools/eval_run.py tests/test_eval_corpus.py
git commit -m "feat(S14): eval harness CLI — corpus runner with recall/precision reporting"
```

---

### Task 3: Regenerate stale `tests/_out` baselines

All nine `tests/_out/*.py` scripts contain a hardcoded `REPO` path pointing to the old installer directory (`/Users/mattrosenberg/MailWarden-installer`). They need updating to the current repo. Since `tests/_out/` is git-ignored, these edits are local-only — not committed. The resulting `.txt` files are also local-only.

**Files to edit locally (not committed):**
- `tests/_out/run_baseline.py`
- `tests/_out/run_offline.py`
- `tests/_out/spam_gate.py`
- `tests/_out/spam_gate_hard.py`
- `tests/_out/verify_build_wiring.py`
- `tests/_out/verify_learn.py`
- `tests/_out/verify_p1.py`
- `tests/_out/verify_scope.py`
- `tests/_out/_smoke_entry.py`

---

- [ ] **Step 3.1: Verify the stale path appears in all nine scripts**

```bash
grep -l "MailWarden-installer" tests/_out/*.py
```

Expected: lists all 9 files. If any file is missing or has a different pattern, note it before proceeding.

- [ ] **Step 3.2: Replace the stale REPO path in all nine files**

Run this command (single invocation, safe to re-run):

```bash
sed -i '' 's|/Users/mattrosenberg/MailWarden-installer|/Users/mattrosenberg/Documents/Claude-Projects/MailWarden-app|g' tests/_out/*.py
```

- [ ] **Step 3.3: Verify the replacement took**

```bash
grep -l "MailWarden-installer" tests/_out/*.py
```

Expected: no output (zero matches). If any files still match, the sed didn't catch them — inspect and fix manually.

- [ ] **Step 3.4: Confirm `corpus_runner.py` works offline (cheapest possible check)**

```bash
tests/.venv/bin/python tests/_out/run_offline.py
```

Expected: prints 8/8 all-green result (no API calls) and writes `tests/_out/corpus_offline.txt`. If it errors, diagnose before running the online steps.

- [ ] **Step 3.5: Regenerate the online baselines**

This makes real API calls (~$0.035). Run only when the offline check passes:

```bash
tests/.venv/bin/python tests/_out/run_baseline.py
```

Expected: prints results for both Haiku and Sonnet, 8/8 all-green each, and writes:
- `tests/_out/baseline_haiku.txt`
- `tests/_out/baseline_sonnet.txt`

- [ ] **Step 3.6: Verify the new baseline files reference the correct repo path**

```bash
grep "signals" tests/_out/baseline_haiku.txt | head -1
```

Expected: shows `signals : /Users/mattrosenberg/Documents/Claude-Projects/MailWarden-app/resources/defaults/signals.json` (not the installer path).

- [ ] **Step 3.7: Run the spam gate (online)**

```bash
tests/.venv/bin/python tests/_out/spam_gate.py
```

Expected: `*** ALL GREEN ***` and writes `tests/_out/spam_gate.txt`.

- [ ] **Step 3.8: Final full suite check**

```bash
tests/.venv/bin/python -m pytest tests/ --ignore=tests/_out -v 2>&1 | tail -5
```

Expected: all green. `tests/_out/` is excluded from pytest (gitignored, no conftest).

> **Note:** No git commit for Task 3 — these are all local-only (gitignored) files. The "done" signal is all the `.txt` output files being fresh and referencing the correct repo path.

---

## Self-review

**Spec coverage:**
- ✅ Corpus builder reads three Desktop folders with correct labels — Task 1
- ✅ Skips `_excluded/`, `.DS_Store`, non-`.eml` — Task 1 (`test_build_corpus_skips_*`)
- ✅ Corpus builder detects inbox vs provider-caught spam — Task 1 (`test_build_corpus_provider_*`)
- ✅ Scoring harness reports email count + estimated cost before spending — Task 2 (`main()` cost gate)
- ✅ Runs every email through `classify_eml_offline` at shipped defaults — Task 2 (`run_eval`)
- ✅ Reports recall, precision, FP, and misclassified list in plain English — Task 2 (`run_eval`)
- ✅ Keeps inbox spam readable separately from provider-caught spam in recall — Task 2 (`run_eval` output + `score_results`)
- ✅ Optional `--out` file dump — Task 2 (`main()`)
- ✅ No run-history, no auto-compare, no dashboard surface, no tracking — confirmed absent from both files
- ✅ Built corpus and result files go in gitignored location — `.gitignore` already covers `tools/__pycache__/`; result files go wherever `--out` user specifies
- ✅ Never under `payload/`, never in installer allowlist — `tools/` is outside `payload/`
- ✅ Test-first with synthetic `.eml` fixtures via `tmp_path` — confirmed; no real emails committed
- ✅ Stale `tests/_out` baselines regenerated — Task 3
- ✅ Does NOT use superpowers SDD skill or write under `.superpowers/` — confirmed

**Placeholder scan:** None found. Every step has exact commands and exact code.

**Type consistency:**
- `build_corpus` → returns `list[dict]` with `label`, `source`, `from_email`, `subject`, `raw`, `filename`, `path` keys → consumed identically by `score_results` (reads `label`, `source`) and `run_eval` (reads `raw`, `filename`, `from_email`, `subject`, `label`, `source`)
- `score_results` → returns dict with `recall_inbox`, `recall_provider`, `tp_inbox`, `tp_provider`, `total_inbox_spam`, `total_provider_spam` — all used in `run_eval` output and in tests
- `run_eval` → returns `{"lines": list[str], "metrics": dict}` — used in `test_eval_run_end_to_end_mock` as `result["metrics"]["recall"]`

**One gap found and resolved:** The `test_eval_run_end_to_end_mock` test patches `spam_filter` in `sys.modules`. Because `run_eval` does `import spam_filter` at call time (not at module load), the monkeypatch will work correctly as long as `eval_run.py` does not import spam_filter at module level. Confirmed: the implementation imports inside `run_eval()`, not at the top of the file.

---

## Running the harness for real (reference, not part of the plan tasks)

After implementation is approved and all tasks complete, to run the actual 79-email corpus:

```bash
# Offline (free — pre-classifier only; AI-path emails show UNKNOWN):
tests/.venv/bin/python tools/eval_run.py --offline --verbose

# Full run with AI (~$0.34 estimated):
tests/.venv/bin/python tools/eval_run.py --yes

# Save results for before/after comparison:
tests/.venv/bin/python tools/eval_run.py --yes --out ~/MailWarden/eval/baseline-$(date +%Y-%m-%d).txt
```
