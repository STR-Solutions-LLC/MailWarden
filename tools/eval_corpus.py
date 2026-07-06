import email as _email_stdlib
import re
from pathlib import Path

_FOLDER_LABELS = {
    "1-Spam": "spam",
    "2-Legitimate-Newsletters-and-Marketing": "legit",
    "3-Legitimate-Personal": "legit",
}

# Graymail — mail the owner dislikes but that is not hard spam (e.g. AAA,
# Kanary, USI). Scored SEPARATELY: junking graymail is never a false
# positive, missing it is never a recall miss. Kept OUT of _FOLDER_LABELS so
# the headline recall/precision/FP denominators can never silently absorb it.
# Bluehost/ (raw DKIM test set) and _harvest/ (raw junk exports) are
# deliberately enumerated NOWHERE — the corpus is folder-name allowlisted.
_GRAYMAIL_FOLDER = "4-Graymail"

_PROVIDER_HEADERS = re.compile(r"x-spam-(status|flag)", re.IGNORECASE)
_PROVIDER_YES = re.compile(r"\byes\b", re.IGNORECASE)


def _read_labeled_folder(folder: Path, label: str) -> list:
    """Read one benchmark folder's .eml files as labeled corpus items."""
    items = []
    if not folder.is_dir():
        return items
    for f in sorted(folder.iterdir()):
        if f.is_dir():
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


def build_corpus(benchmark_dir) -> list:
    """Read ~/Desktop/MailWarden-Benchmark and return a labeled list of emails.

    Each item: {filename, label, source, from_email, subject, raw, path}
      label  — "spam", "legit", or "graymail" (4-Graymail folder; scored
               separately, excluded from recall/precision/FP)
      source — "inbox" or "provider" (legit/graymail always "inbox";
                spam is "provider" when X-Spam-Status/X-Spam-Flag: Yes is present)
    """
    items = []
    for folder_name, label in _FOLDER_LABELS.items():
        items.extend(_read_labeled_folder(Path(benchmark_dir) / folder_name, label))
    items.extend(
        _read_labeled_folder(Path(benchmark_dir) / _GRAYMAIL_FOLDER, "graymail"))
    return items


def score_results(labeled: list, verdicts: list) -> dict:
    """Score classified verdicts against labeled ground truth.

    labeled  — list of dicts as returned by build_corpus
    verdicts — parallel list of "JUNK" | "PASS" | "UNKNOWN"
               UNKNOWN is treated as not-junked (same as PASS)

    Graymail items (label == "graymail") are scored SEPARATELY: they are
    excluded from recall, precision, FP, and the misclassified list — a
    junked graymail is not a false positive and a passed one is not a miss.

    Returns a dict with:
      recall, recall_inbox, recall_provider  — float 0.0–1.0
      precision                              — float 0.0–1.0
      false_positives                        — int
      total_spam, total_legit                — int
      total_inbox_spam, total_provider_spam  — int
      tp, fp, fn, tp_inbox, tp_provider      — int
      graymail_total, graymail_junked        — int (separate track)
      misclassified                          — list of dicts (no raw/path keys)
    """
    assert len(labeled) == len(verdicts), "labeled and verdicts must be the same length"

    tp = fp = fn = 0
    tp_inbox = tp_provider = 0
    total_inbox_spam = total_provider_spam = 0
    graymail_total = graymail_junked = 0
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
                    {"kind": "missed_spam",
                     **{k: item[k] for k in SAFE_KEYS if k in item}}
                )
        elif item["label"] == "graymail":
            graymail_total += 1
            if junked:
                graymail_junked += 1
        else:
            if junked:
                fp += 1
                misclassified.append(
                    {"kind": "false_positive",
                     **{k: item[k] for k in SAFE_KEYS if k in item}}
                )

    total_spam = tp + fn
    # Explicit count — graymail must never inflate the legit denominator.
    total_legit = sum(1 for i in labeled if i["label"] == "legit")
    recall = tp / total_spam if total_spam > 0 else 0.0
    recall_inbox = tp_inbox / total_inbox_spam if total_inbox_spam > 0 else 0.0
    recall_provider = (
        tp_provider / total_provider_spam if total_provider_spam > 0 else 0.0
    )
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
        "graymail_total": graymail_total,
        "graymail_junked": graymail_junked,
        "misclassified": misclassified,
    }
