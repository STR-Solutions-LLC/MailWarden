#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
MailWarden corpus runner — the acceptance gate for the calibration build.

Runs the 7-email test corpus through the REAL offline classify path
(spam_filter.classify_eml_offline) and asserts each email's expected outcome:

  01_instagram    PASS   (legit; was AI false-positived)
  02_linkedin     PASS   (legit; was AI false-positived)
  03_nbcuni       PASS   (legit personal mail; was AI false-positived)
  04_dashlane     PASS   (legit; was pre-classifier 3-soft junked, no AI)
  05_womensmarch  PASS   (legit advocacy; was AI false-positived)
  06_jeffries     PASS   (legit fundraising; was AI false-positived)
  07_mcafee_phish JUNK   (real phishing — must STAY junked)

Exit 0 iff all 7 match expectation. NO IMAP, NO moves, NO writes (except the
optional --out report file).

Signals default to the shipped resources/defaults/signals.json so the result is
reproducible and contains no user data. API key + model are read from
~/MailWarden/config/config.json (the same source the app uses) or $ANTHROPIC_API_KEY.

Usage (run with the test venv python):
  tests/.venv/bin/python tests/corpus_runner.py [--signals PATH] [--account NAME]
                                                [--offline] [--verbose] [--out PATH]

  --offline   pre-classifier only; no API calls (free smoke test of parsing +
              header checks). AI-path emails report UNDECIDED, so the gate will
              not pass in this mode — it is for mechanical validation only.
  --out PATH  write the full report to PATH (Python writes it directly, so it
              survives shells that drop redirected stdout).
"""
import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "payload" / "MailWarden" / "src"
FIXTURES = REPO / "tests" / "fixtures"
DEFAULT_SIGNALS = REPO / "resources" / "defaults" / "signals.json"
CONFIG = Path.home() / "MailWarden" / "config" / "config.json"

sys.path.insert(0, str(SRC))
import spam_filter  # noqa: E402

# (filename, expected final decision, human description)
CORPUS = [
    ("01_instagram.eml",    "PASS", "Instagram security alert"),
    ("02_linkedin.eml",     "PASS", "LinkedIn device verification"),
    ("03_nbcuni.eml",       "PASS", "NBCUni personal (Disclosure Day)"),
    ("04_dashlane.eml",     "PASS", "Dashlane pricing notice"),
    ("05_womensmarch.eml",  "PASS", "Women's March advocacy"),
    ("06_jeffries.eml",     "PASS", "Hakeem Jeffries fundraising"),
    ("07_mcafee_phish.eml", "JUNK", "McAfee phish (eponanfc.com)"),
    ("08_support_token_legit.eml", "PASS",
     "Legit support email carrying planted SUPPORT/GOOD_MAIL tokens (6b)"),
]


def load_json(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--signals", default=str(DEFAULT_SIGNALS))
    ap.add_argument("--account", default=None)
    ap.add_argument("--offline", action="store_true",
                    help="pre-classifier only; no API calls")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--model", default=None, help="override model (else config/default)")
    ap.add_argument("--out", default=None, help="write full report to this path")
    args = ap.parse_args()

    report = []

    def w(line=""):
        print(line)
        report.append(line)

    signals = load_json(args.signals)
    cfg = load_json(CONFIG)
    anthro = cfg.get("anthropic", {}) if isinstance(cfg, dict) else {}
    api_key = "" if args.offline else (
        os.environ.get("ANTHROPIC_API_KEY") or anthro.get("api_key", "") or "")
    model = args.model or anthro.get("model") or "claude-haiku-4-5-20251001"
    threshold = (cfg.get("filter", {}).get("confidence_threshold", 0.85)
                 if isinstance(cfg, dict) else 0.85)

    w(f"signals : {args.signals}")
    w(f"model   : {model}    threshold: {threshold}    offline: {args.offline}")
    w(f"api key : {'present' if api_key else 'ABSENT'}")
    w("=" * 92)

    rows = []
    tin = tout = 0
    for fname, expected, desc in CORPUS:
        fp = FIXTURES / fname
        if not fp.is_file():
            w(f"XX  {fname:22} expect={expected:4}  got=MISSING  (fixture not found)")
            rows.append((fname, expected, "MISSING", "", None, False))
            continue
        raw = fp.read_bytes()
        try:
            res = spam_filter.classify_eml_offline(
                raw, signals, api_key=api_key, model=model,
                threshold=threshold, account_name=args.account, run_dnsbl=False,
            )
        except Exception as e:
            import traceback
            w(f"XX  {fname:22} expect={expected:4}  got=ERROR  {type(e).__name__}: {e}")
            w(traceback.format_exc())
            rows.append((fname, expected, "ERROR", "", None, False))
            continue
        final = res.get("final_decision")
        by = res.get("decided_by")
        ai = res.get("ai") or {}
        pre = res.get("pre_classifier", {})
        match = (final == expected)
        rows.append((fname, expected, final, by, res, match))

        u = res.get("usage")
        if u:
            tin += u["input_tokens"]
            tout += u["output_tokens"]

        detail = ""
        if by == "pre-classifier":
            fired = pre.get("hard_signals", []) + pre.get("soft_signals", [])
            detail = "pre:" + "+".join(fired)
        elif by == "ai" and ai.get("decision"):
            detail = f"ai={ai['decision']}@{ai['confidence']:.2f} {ai.get('signals_hit')}"
        elif ai.get("error"):
            detail = f"ai_error={ai['error']}"
        flag = "OK " if match else "XX "
        w(f"{flag} {fname:22} expect={expected:4}  got={str(final):9} "
          f"by={str(by):14} {detail}")

    w("=" * 92)
    npass = sum(1 for r in rows if r[5])
    w(f"RESULT: {npass}/{len(CORPUS)} match expected"
      + ("   *** ALL GREEN ***" if npass == len(CORPUS) else ""))
    if tin or tout:
        approx = tin / 1e6 * 1.0 + tout / 1e6 * 5.0  # ~Haiku 4.5 rates; ballpark only
        w(f"tokens : in={tin} out={tout}   (~${approx:.4f}, approx)")

    if args.verbose:
        w("\n----- detail -----")
        for fname, expected, final, by, res, match in rows:
            if not isinstance(res, dict):
                continue
            pre = res.get("pre_classifier", {})
            ai = res.get("ai")
            w(f"\n{fname}  expect={expected} got={final} "
              f"({'MATCH' if match else 'MISMATCH'})")
            w(f"  pre hard={pre.get('hard_signals')} soft={pre.get('soft_signals')}")
            sd = pre.get("signal_details") or {}
            for k, v in sd.items():
                w(f"    - {k}: {v}")
            if isinstance(ai, dict) and ai.get("decision"):
                w(f"  ai decision={ai['decision']} conf={ai['confidence']} "
                  f"signals={ai.get('signals_hit')}")
                w(f"  ai reasoning: {ai.get('reasoning')}")
            elif isinstance(ai, dict) and ai.get("error"):
                w(f"  ai error={ai['error']}")

    if args.out:
        try:
            Path(args.out).write_text("\n".join(report) + "\n", encoding="utf-8")
        except Exception as e:
            print(f"(could not write --out {args.out}: {e})", file=sys.stderr)

    return 0 if npass == len(CORPUS) else 1


if __name__ == "__main__":
    sys.exit(main())
