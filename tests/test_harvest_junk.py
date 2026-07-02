#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Tests for tools/harvest_junk.py — pure logic + a fake IMAP connection.
NO network, NO real mail, NO Anthropic. Guards the read-only invariant.
"""
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "payload" / "MailWarden" / "src"))
sys.path.insert(0, str(REPO / "tools"))


def _load():
    spec = importlib.util.spec_from_file_location(
        "harvest_junk", REPO / "tools" / "harvest_junk.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _eml(from_addr, msgid, extra_headers=""):
    return (
        f"From: {from_addr}\r\n"
        f"To: me@example.com\r\n"
        f"Subject: test\r\n"
        f"{extra_headers}"
        f"Message-ID: {msgid}\r\n"
        f"\r\nbody\r\n"
    ).encode("utf-8")


SA_EML = _eml("s@junk.net", "<sa1@junk.net>", "X-Spam-Status: Yes, score=9\r\n")
MW_EML = _eml("mw@sender.com", "<mw1@sender.com>")
PROV_EML = _eml("p@other.com", "<pr1@other.com>")


class FakeIMAP:
    """Minimal read-only IMAP double. Records every command so a test can
    assert no mutating verb was issued."""
    def __init__(self, uids_to_raw):
        self._uids = list(uids_to_raw.keys())
        self._map = uids_to_raw
        self.commands = []
        self.selected = None

    def select(self, mailbox, readonly=False):
        self.commands.append(("select", mailbox, readonly))
        # Only the quoted plain name selects OK in these tests.
        if mailbox == '"Junk"':
            self.selected = mailbox
            return ("OK", [b"3"])
        return ("NO", [b"missing"])

    def uid(self, command, *args):
        self.commands.append(("uid", command) + tuple(args))
        if command == "SEARCH":
            return ("OK", [b" ".join(self._uids)])
        if command == "FETCH":
            uid = args[0]
            raw = self._map.get(uid)
            if raw is None:
                return ("NO", [None])
            return ("OK", [(b"1 (BODY[] {%d}" % len(raw), raw)])
        raise AssertionError(f"unexpected uid command {command}")

    def logout(self):
        self.commands.append(("logout",))


# ─── provenance ────────────────────────────────────────────────────────────────

def test_classify_provenance_spamassassin():
    mod = _load()
    assert mod.classify_provenance(SA_EML, set()) == "spamassassin"


def test_classify_provenance_mailwarden_via_moved_ids():
    mod = _load()
    assert mod.classify_provenance(MW_EML, {"<mw1@sender.com>"}) == "mailwarden"


def test_classify_provenance_provider_default():
    mod = _load()
    assert mod.classify_provenance(PROV_EML, set()) == "provider"


def test_classify_provenance_spamassassin_beats_mailwarden():
    # intrinsic SA header wins even if the id is also in the moved set
    mod = _load()
    assert mod.classify_provenance(SA_EML, {"<sa1@junk.net>"}) == "spamassassin"


# ─── decisions.log parser ───────────────────────────────────────────────────────

_LOG = (
    "[2026-06-01 10:00:00] ACCOUNT: AOL\n"
    "  MESSAGE-ID: <mw1@sender.com>\n"
    "  FROM: X <mw@sender.com>\n"
    "  SUBJECT: test\n"
    "  DECISION: SPAM (confidence: 0.99)\n"
    "  SIGNALS HIT: foo\n"
    "  ACTION: [MOVED to Junk]\n"
    "  ---\n"
    "[2026-06-01 10:05:00] ACCOUNT: AOL\n"
    "  MESSAGE-ID: <passed@sender.com>\n"
    "  ACTION: [PASS - left in inbox]\n"
    "  ---\n"
    "[2026-06-01 10:06:00] ACCOUNT: AOL\n"
    "  MESSAGE-ID: <dry@sender.com>\n"
    "  ACTION: [DRY RUN - would move to Junk]\n"
    "  ---\n"
    "[2026-06-01 10:07:00] ACCOUNT: AOL\n"
    "  MESSAGE-ID: <failed@sender.com>\n"
    "  ACTION: [MOVE FAILED to Junk]\n"
    "  ---\n"
)


def test_parse_mailwarden_moved_ids_only_real_moves():
    mod = _load()
    moved = mod.parse_mailwarden_moved_ids(_LOG)
    assert moved == {"<mw1@sender.com>"}
    assert "<passed@sender.com>" not in moved
    assert "<dry@sender.com>" not in moved       # DRY RUN excluded
    assert "<failed@sender.com>" not in moved     # MOVE FAILED excluded


# ─── harvest_account (fake IMAP) ────────────────────────────────────────────────

def test_harvest_account_writes_and_tags(tmp_path):
    mod = _load()
    conn = FakeIMAP({b"1": SA_EML, b"2": MW_EML, b"3": PROV_EML})
    account = {"name": "AOL", "junk_folder": "Junk"}
    summary = mod.harvest_account(
        conn, account, tmp_path, moved_ids={"<mw1@sender.com>"},
        max_per_account=500)
    assert summary["found"] == 3
    assert summary["written"] == 3
    assert summary["provenance"] == {
        "spamassassin": 1, "mailwarden": 1, "provider": 1}
    acct_dir = tmp_path / "AOL"
    assert len(list(acct_dir.glob("*.eml"))) == 3
    prov = (acct_dir / "_provenance.tsv").read_text()
    assert "spamassassin" in prov and "mailwarden" in prov and "provider" in prov


def test_harvest_account_dry_run_writes_nothing(tmp_path):
    mod = _load()
    conn = FakeIMAP({b"1": SA_EML})
    summary = mod.harvest_account(
        conn, {"name": "AOL", "junk_folder": "Junk"}, tmp_path,
        moved_ids=set(), max_per_account=500, dry_run=True)
    assert summary["found"] == 1
    assert summary["written"] == 0
    assert not (tmp_path / "AOL").exists()


def test_harvest_account_caps_at_max(tmp_path):
    mod = _load()
    conn = FakeIMAP({str(i).encode(): PROV_EML for i in range(1, 21)})
    summary = mod.harvest_account(
        conn, {"name": "AOL", "junk_folder": "Junk"}, tmp_path,
        moved_ids=set(), max_per_account=5)
    assert summary["written"] == 5


def test_harvest_account_is_read_only(tmp_path):
    """No mutating IMAP verb may ever be issued."""
    mod = _load()
    conn = FakeIMAP({b"1": SA_EML, b"2": PROV_EML})
    mod.harvest_account(
        conn, {"name": "AOL", "junk_folder": "Junk"}, tmp_path,
        moved_ids=set(), max_per_account=500)
    # every select is readonly=True
    selects = [c for c in conn.commands if c[0] == "select"]
    assert selects and all(c[2] is True for c in selects)
    # no STORE / COPY / MOVE / EXPUNGE anywhere
    flat = " ".join(str(part) for c in conn.commands for part in c).upper()
    for verb in ("STORE", "COPY", "MOVE", "EXPUNGE", "\\SEEN", "DELETE"):
        assert verb not in flat, f"mutating verb {verb} was issued"


def test_module_source_has_no_mutating_verbs():
    """Static guard against a future edit adding a write path. Checks for
    CALL-shaped tokens (not prose), so the safety docstring can still name the
    verbs it forbids."""
    src = (REPO / "tools" / "harvest_junk.py").read_text()
    forbidden = [
        '"STORE"', "'STORE'", '"EXPUNGE"', "'EXPUNGE'",
        '"COPY"', "'COPY'", '"MOVE"', "'MOVE'",
        "+FLAGS", "\\\\Seen", ".expunge(", ".store(", ".copy(",
    ]
    for tok in forbidden:
        assert tok not in src, f"call-shaped token {tok!r} appears in harvest_junk.py"


def test_missing_junk_folder_returns_empty(tmp_path):
    mod = _load()
    # FakeIMAP only selects '"Junk"'; a different name yields NO on both tries.
    conn = FakeIMAP({b"1": SA_EML})
    summary = mod.harvest_account(
        conn, {"name": "AOL", "junk_folder": "Spam"}, tmp_path,
        moved_ids=set(), max_per_account=500)
    assert summary["selected"] is None
    assert summary["written"] == 0
