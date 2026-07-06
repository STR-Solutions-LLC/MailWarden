#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Tests for tools/fetch_untroubled.py — pure logic only. NO network, NO 7z,
NO downloads. Listing HTML and message files are synthetic fixtures.
"""
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))


def _load():
    spec = importlib.util.spec_from_file_location(
        "fetch_untroubled", REPO / "tools" / "fetch_untroubled.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_LISTING_HTML = """
<html><body><pre>
<a href="1998-01.7z">1998-01.7z</a>   01-Feb-1998 00:00  120k
<a href="2026-04.7z">2026-04.7z</a>   06-May-2026 00:00  6.3M
<a href="2026-05.7z">2026-05.7z</a>   01-Jun-2026 00:00  5.9M
<a href="2026-06.7z">2026-06.7z</a>   01-Jul-2026 00:00  7.5M
<a href="2026-07.7z">2026-07.7z</a>   02-Jul-2026 00:00  371k
</pre></body></html>
"""

VALID_EML = (
    b"From: spammer@junk.example\r\n"
    b"To: victim@example.com\r\n"
    b"Subject: cheap stuff\r\n"
    b"\r\n"
    b"buy now buy now buy now\r\n"
)


def test_parse_months_sorted_unique():
    mod = _load()
    months = mod.parse_months(_LISTING_HTML)
    assert months == ["1998-01", "2026-04", "2026-05", "2026-06", "2026-07"]


def test_latest_full_month_excludes_current_partial():
    mod = _load()
    months = mod.parse_months(_LISTING_HTML)
    # current month is 2026-07 (partial) -> newest FULL month is 2026-06
    assert mod.latest_full_month(months, "2026-07") == "2026-06"


def test_latest_full_month_falls_back_when_all_current():
    mod = _load()
    assert mod.latest_full_month(["2026-07"], "2026-07") == "2026-07"


def test_pick_valid_messages_skips_junk(tmp_path):
    mod = _load()
    (tmp_path / "0001").write_bytes(VALID_EML)
    (tmp_path / "0002").write_bytes(b"")             # empty -> skip
    (tmp_path / "0003").write_bytes(b"tiny")         # too short -> skip
    (tmp_path / "0004").write_bytes(VALID_EML)
    (tmp_path / "0005").write_bytes(
        b"Subject: no from header\r\n\r\nbody")       # no From -> skip
    picked = mod._valid_messages(tmp_path, count=10)
    assert len(picked) == 2


def test_pick_valid_messages_caps_at_count(tmp_path):
    mod = _load()
    for i in range(20):
        (tmp_path / f"{i:04d}").write_bytes(VALID_EML)
    picked = mod._valid_messages(tmp_path, count=15)
    assert len(picked) == 15


def test_pick_valid_messages_is_deterministic(tmp_path):
    mod = _load()
    for i in range(10):
        (tmp_path / f"{i:04d}").write_bytes(VALID_EML)
    a = mod._valid_messages(tmp_path, count=5)
    b = mod._valid_messages(tmp_path, count=5)
    assert [p.name for p in a] == [p.name for p in b]


def test_require_7z_errors_clearly_when_missing(monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    try:
        mod.require_7z()
        assert False, "expected SystemExit"
    except SystemExit as e:
        assert e.code == 2


def test_require_7z_returns_path_when_present(monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod.shutil, "which",
                        lambda name: "/usr/bin/7z" if name == "7z" else None)
    assert mod.require_7z() == "/usr/bin/7z"


def test_place_into_corpus_normalizes_names(tmp_path):
    mod = _load()
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    srcs = []
    for i in range(3):
        p = src_dir / f"raw{i}"
        p.write_bytes(VALID_EML)
        srcs.append(p)
    out = tmp_path / "1-Spam"
    names = mod.place_into_corpus(srcs, "2026-06", out)
    assert names == ["untroubled-2026-06-001.eml",
                     "untroubled-2026-06-002.eml",
                     "untroubled-2026-06-003.eml"]
    assert all((out / n).read_bytes() == VALID_EML for n in names)
