#!/usr/bin/env python3
"""
MailWarden eval harness — score the real filter against a hand-labeled corpus.

Measures what a NEW user gets (shipped defaults), not your personal tuned setup.
Model, threshold, and signals are fixed at shipping values; only the API key
is read from your local config.

Usage:
  tests/.venv/bin/python tools/eval_run.py
  tests/.venv/bin/python tools/eval_run.py --offline        # free: pre-classifier only
  tests/.venv/bin/python tools/eval_run.py --out /tmp/r.txt # save full report
  tests/.venv/bin/python tools/eval_run.py --yes            # skip cost prompt

Reads corpus from ~/Desktop/MailWarden-Benchmark/ (three labeled folders).
API key is read from $ANTHROPIC_API_KEY or ~/MailWarden/config/config.json.
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

# Shipped defaults — hardcoded so this harness measures the out-of-box experience,
# not your personal tuned config.
SHIPPED_MODEL = "claude-haiku-4-5-20251001"
SHIPPED_THRESHOLD = 0.85
COST_PER_EMAIL = 0.0043   # ~Haiku 4.5 ballpark; actual varies


def run_eval(benchmark_dir, signals, api_key, model, threshold,
             offline=False, verbose=False):
    """Core eval logic. Returns {lines: [str, ...], metrics: dict}.

    Separated from main() so tests can call it directly with a mock spam_filter.
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
    inbox_spam = sum(
        1 for i in items if i["label"] == "spam" and i["source"] == "inbox"
    )
    provider_spam = spam_count - inbox_spam

    w(f"Corpus: {len(items)} emails  —  "
      f"{spam_count} spam ({inbox_spam} inbox, {provider_spam} provider-flagged), "
      f"{legit_count} legit")
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
    w(f"  Provider-flagged spam:    {metrics['recall_provider']:.1%}  "
      f"({metrics['tp_provider']}/{metrics['total_provider_spam']})  "
      f"[best-effort: SpamAssassin marker only; most providers don't stamp this, "
      f"so this split under-counts]")
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
    ap.add_argument(
        "--benchmark-dir", default=str(DEFAULT_BENCHMARK),
        help="path to MailWarden-Benchmark folder (default: ~/Desktop/MailWarden-Benchmark)"
    )
    ap.add_argument(
        "--offline", action="store_true",
        help="pre-classifier only; no API calls (free)"
    )
    ap.add_argument(
        "--out", default=None,
        help="write full report to this file"
    )
    ap.add_argument(
        "--yes", action="store_true",
        help="skip cost-confirmation prompt"
    )
    ap.add_argument(
        "--verbose", action="store_true",
        help="print every email, not just misclassified ones"
    )
    args = ap.parse_args()

    # Shipped defaults — do not read model/threshold/signals from user config.
    model = SHIPPED_MODEL
    threshold = SHIPPED_THRESHOLD
    signals = {}
    try:
        signals = json.loads(DEFAULT_SIGNALS.read_text())
    except Exception as e:
        print(f"Warning: could not load shipped signals from {DEFAULT_SIGNALS}: {e}",
              file=sys.stderr)

    # API key only — the one thing that IS personal.
    api_key = os.environ.get("ANTHROPIC_API_KEY") or ""
    if not api_key:
        try:
            cfg = json.loads(CONFIG.read_text())
            api_key = (cfg.get("anthropic", {}) or {}).get("api_key", "") or ""
        except Exception:
            pass

    # Cost confirmation
    if not args.offline and not args.yes:
        from eval_corpus import build_corpus
        items = build_corpus(Path(args.benchmark_dir))
        est = len(items) * COST_PER_EMAIL
        print(f"Corpus: {len(items)} emails.")
        print(f"Estimated cost: ~${est:.2f} "
              f"(~${COST_PER_EMAIL}/email on {model}, ballpark only).")
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
            Path(args.out).write_text(
                "\n".join(result["lines"]) + "\n", encoding="utf-8"
            )
            print(f"\n(Report saved to {args.out})")
        except Exception as e:
            print(f"Warning: could not write --out {args.out}: {e}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
