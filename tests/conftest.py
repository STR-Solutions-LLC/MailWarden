#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Shared test fixtures.

F4(c) added _capture_parse_failure, which writes debug artifacts under
spam_filter.PARSE_FAILURES_DIR (PROJECT_ROOT/memory/classify_parse_failures).
In this repo PROJECT_ROOT is the tracked payload/MailWarden tree, so any test
that exercises an unparseable classification response (several cascade tests
do) would otherwise dirty the working tree. Redirect captures to a per-test
tmp dir for EVERY test.
"""
import os
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_parse_failure_captures(tmp_path, monkeypatch):
    monkeypatch.setattr(spam_filter, "PARSE_FAILURES_DIR",
                        tmp_path / "classify_parse_failures")
