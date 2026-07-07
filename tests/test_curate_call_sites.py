#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""N4 — regression guard for the _account_has_active_ai_curate scope bug.

Rule scope matches on the account USERNAME (email); a02d7ea fixed a bug where
the account DISPLAY NAME (account.get("name")) was passed instead, so
inbox-scoped curate rules silently never fired. This source-scan asserts every
call site passes the username (account.get("username", ...)) or the offline
``account_name`` kwarg, and that NONE passes account.get("name"), so the bug
cannot silently return.
"""
import ast
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
SPAM_FILTER = os.path.abspath(os.path.join(SRC, "spam_filter.py"))
sys.path.insert(0, os.path.abspath(SRC))


def _is_account_get(node, key):
    """True if `node` is exactly ``account.get("<key>", ...)``."""
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "account"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == key)


def _curate_calls():
    tree = ast.parse(open(SPAM_FILTER).read())
    calls = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_account_has_active_ai_curate"):
            calls.append(node)
    return calls


def test_all_call_sites_present():
    # Def line + call sites; guards against the scan silently matching nothing.
    assert len(_curate_calls()) >= 4


def test_no_call_site_passes_account_display_name():
    for call in _curate_calls():
        for arg in call.args:
            assert not _is_account_get(arg, "name"), (
                "_account_has_active_ai_curate must never be passed "
                "account.get('name') — scope matches on the username")


def test_every_call_site_passes_username_or_offline_kwarg():
    for call in _curate_calls():
        # The account identifier is the 2nd positional arg.
        assert len(call.args) >= 2, "call must pass the account identifier"
        ident = call.args[1]
        ok = _is_account_get(ident, "username") or isinstance(ident, ast.Name)
        assert ok, ("account identifier must be account.get('username', ...) "
                    "or the offline account_name variable")
