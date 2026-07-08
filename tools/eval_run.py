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
  tests/.venv/bin/python tools/eval_run.py --model claude-sonnet-4-6  # override shipped model
  tests/.venv/bin/python tools/eval_run.py --full            # add per-email verdict listing
  tests/.venv/bin/python tools/eval_run.py --cascade         # two-model cascade (screen=--model/shipped, confirm=--confirm-model)

Reads corpus from ~/Desktop/MailWarden-Benchmark/ (three labeled folders,
plus the optional 4-Graymail folder, which is scored separately and excluded
from recall/precision/FP).
API key is read from $ANTHROPIC_API_KEY or ~/MailWarden/config/config.json.

Offline regression gate (Keychain migration and any dark-shipped work):
  tests/.venv/bin/python tools/eval_run.py --offline
The `--offline` output must be BYTE-IDENTICAL to the same command run against a
clean baseline worktree (e.g. `git worktree add <dir> <baseline-sha>` + run there
with this same venv). The pre-classifier is deterministic and no prompt text may
change, so any diff is a regression. Run `--offline` on both trees and `cmp` them.
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
# not your personal tuned config. --model overrides SHIPPED_MODEL for A/B runs.
SHIPPED_MODEL = "claude-haiku-4-5-20251001"
SHIPPED_CONFIRM_MODEL = "claude-sonnet-4-6"
SHIPPED_THRESHOLD = 0.85

# Cost-estimate assumption for --cascade runs: the share of corpus emails the
# screen model junks (each one costs a second, confirm-model call). Ballpark
# only — a labeled benchmark corpus is spam-heavy, so assume half.
ASSUMED_CONFIRM_FRACTION = 0.5

# Ballpark per-email token estimate, derived from this install's real
# lifetime average (~/MailWarden/memory/token_usage.json). Used only to
# size the pre-run cost confirmation; actual usage varies per email.
AVG_INPUT_TOKENS_PER_EMAIL = 1950
AVG_OUTPUT_TOKENS_PER_EMAIL = 225

# $ per million tokens (input, output). Dev-tool estimate only — not the
# source of truth for billing; do not import this elsewhere.
PRICING_PER_MTOK = {
    "claude-haiku-4-5": (1.0, 5.0),    # matches any claude-haiku-4-5* id
    "claude-sonnet-4-6": (3.0, 15.0),  # exact match only
}


def _pricing_for_model(model):
    """Return (input_$/MTok, output_$/MTok) for a model id, or None if unknown."""
    if model.startswith("claude-haiku-4-5"):
        return PRICING_PER_MTOK["claude-haiku-4-5"]
    if model == "claude-sonnet-4-6":
        return PRICING_PER_MTOK["claude-sonnet-4-6"]
    return None


def estimate_cost(n_emails, model, cascade=False, confirm_model=None):
    """Return (cost_usd_or_None, human_description) for a run of n_emails.

    cost_usd is None when the model has no entry in PRICING_PER_MTOK — the
    description still reports the token estimate in that case, tagged
    "unknown pricing".

    When ``cascade`` is True, a second-call term is added: the confirm model
    is assumed to run on ASSUMED_CONFIRM_FRACTION of the corpus (the confirm
    call fires only on screen-junk verdicts). Non-cascade output is
    byte-identical to before the cascade existed.
    """
    est_input = n_emails * AVG_INPUT_TOKENS_PER_EMAIL
    est_output = n_emails * AVG_OUTPUT_TOKENS_PER_EMAIL
    pricing = _pricing_for_model(model)
    if pricing is None:
        desc = (f"~{est_input:,} input / ~{est_output:,} output tokens "
                f"on {model} (unknown pricing, ballpark tokens only)")
        return None, desc
    in_price, out_price = pricing
    cost = (est_input / 1_000_000) * in_price + (est_output / 1_000_000) * out_price
    if cascade and confirm_model:
        c_pricing = _pricing_for_model(confirm_model)
        n_confirm = n_emails * ASSUMED_CONFIRM_FRACTION
        c_input = n_confirm * AVG_INPUT_TOKENS_PER_EMAIL
        c_output = n_confirm * AVG_OUTPUT_TOKENS_PER_EMAIL
        if c_pricing is None:
            desc = (f"~${cost:.2f} screen on {model} + unknown-priced confirm "
                    f"({confirm_model}) on ~{int(n_confirm)} emails "
                    f"(assumed {ASSUMED_CONFIRM_FRACTION:.0%} junk rate)")
            return None, desc
        c_in_price, c_out_price = c_pricing
        c_cost = ((c_input / 1_000_000) * c_in_price
                  + (c_output / 1_000_000) * c_out_price)
        total = cost + c_cost
        desc = (f"~${total:.2f}  (screen {model} on all {n_emails} ~${cost:.2f} "
                f"+ confirm {confirm_model} on ~{int(n_confirm)} "
                f"(assumed {ASSUMED_CONFIRM_FRACTION:.0%} junk rate) "
                f"~${c_cost:.2f}, ballpark only)")
        return total, desc
    desc = (f"~${cost:.2f}  (~{est_input:,} input / ~{est_output:,} output tokens "
            f"on {model} @ ${in_price}/${out_price} per MTok, ballpark only)")
    return cost, desc


def run_eval(benchmark_dir, signals, api_key, model, threshold,
             offline=False, verbose=False, full=False,
             cascade=False, confirm_model=SHIPPED_CONFIRM_MODEL):
    """Core eval logic. Returns {lines: [str, ...], metrics: dict}.

    Separated from main() so tests can call it directly with a mock spam_filter.

    ``full=False`` (default) preserves the exact report format from before
    the --full flag existed — byte-identical --out files depend on this.
    ``full=True`` appends a final section listing every corpus email.

    ``cascade=True`` runs the two-model cascade through the REAL
    classify_eml_offline cascade path (``model`` screens, ``confirm_model``
    re-judges screen-junk verdicts). Non-cascade runs pass exactly the same
    kwargs as before the flag existed — byte-identical reports.
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
    graymail_count = sum(1 for i in items if i["label"] == "graymail")
    legit_count = len(items) - spam_count - graymail_count
    inbox_spam = sum(
        1 for i in items if i["label"] == "spam" and i["source"] == "inbox"
    )
    provider_spam = spam_count - inbox_spam

    # Graymail suffix appears ONLY when 4-Graymail is non-empty, so a
    # graymail-free corpus still produces byte-identical reports.
    graymail_suffix = f", {graymail_count} graymail" if graymail_count else ""
    w(f"Corpus: {len(items)} emails  —  "
      f"{spam_count} spam ({inbox_spam} inbox, {provider_spam} provider-flagged), "
      f"{legit_count} legit{graymail_suffix}")
    if cascade:
        w(f"Model:  {model} -> confirm {confirm_model} (cascade)   "
          f"threshold: {threshold}   offline: {offline}")
    else:
        w(f"Model:  {model}   threshold: {threshold}   offline: {offline}")
    w("=" * 80)

    verdicts = []
    for item in items:
        try:
            kw = dict(
                api_key=(api_key if not offline else ""),
                model=model,
                threshold=threshold,
                run_dnsbl=False,
            )
            if cascade:
                kw["classify_mode"] = "cascade"
                kw["confirm_model"] = confirm_model
            res = spam_filter.classify_eml_offline(
                item["raw"], signals, **kw,
            )
            verdict = res.get("final_decision", "UNKNOWN")
        except Exception as e:
            verdict = "UNKNOWN"
            w(f"  ERROR on {item['filename']}: {e}")
        verdicts.append(verdict)

        if item["label"] == "graymail":
            # Graymail has no wrong answer — never flagged XX, shown only
            # in verbose mode.
            if verbose:
                w(f"   [GRAY ] {item['filename'][:55]:57} -> {verdict}")
        else:
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
    if metrics.get("graymail_total", 0) > 0:
        w(f"Graymail (scored separately): {metrics['graymail_junked']}"
          f"/{metrics['graymail_total']} junked  "
          f"[excluded from recall/precision/FP]")

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

    if full:
        w(f"\nFull verdict listing ({len(items)}):")
        rows = sorted(zip(items, verdicts), key=lambda pair: pair[0]["filename"])
        for item, verdict in rows:
            if item["label"] == "spam":
                label_tag = "SPAM "
            elif item["label"] == "graymail":
                label_tag = "GRAY "
            else:
                label_tag = "LEGIT"
            w(f"  {label_tag}  {verdict:7}  {item['filename']}")

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
    ap.add_argument(
        "--model", default=None,
        help=f"override the model used for classification (default: shipped "
             f"model, {SHIPPED_MODEL})"
    )
    ap.add_argument(
        "--full", action="store_true",
        help="append a per-email verdict listing to the report"
    )
    ap.add_argument(
        "--cascade", action="store_true",
        help="two-model cascade: --model (or shipped model) screens every "
             "email; --confirm-model re-judges screen-junk verdicts; junked "
             "only when both agree"
    )
    ap.add_argument(
        "--confirm-model", default=SHIPPED_CONFIRM_MODEL,
        help=f"confirm model for --cascade (default: {SHIPPED_CONFIRM_MODEL})"
    )
    args = ap.parse_args()

    # Shipped defaults — do not read threshold/signals from user config.
    # --model may override the shipped model for A/B comparisons.
    model = args.model or SHIPPED_MODEL
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
        _, cost_desc = estimate_cost(len(items), model,
                                     cascade=args.cascade,
                                     confirm_model=args.confirm_model)
        print(f"Corpus: {len(items)} emails.")
        print(f"Estimated cost: {cost_desc}.")
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
        full=args.full,
        cascade=args.cascade,
        confirm_model=args.confirm_model,
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
