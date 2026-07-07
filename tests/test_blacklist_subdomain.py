#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""C6 — blacklist domain matching is subdomain-aware, symmetric with the
whitelist's F4 suffix match (plain suffix, no shared-ESP guard).

A parent blacklist entry now blocks its subdomains ("em.retailer.com" when
"retailer.com" is listed), while look-alikes ("evilretailer.com") and
right-anchored tricks ("retailer.com.evil.com") do NOT match. Per-entry scope
is honored identically to exact matches.
"""
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))

import spam_filter  # noqa: E402


def _bl(data):
    return spam_filter._ensure_list_sets(data)


def test_parent_entry_blocks_subdomain_sender():
    bl = _bl({"domains": ["retailer.com"]})
    mt, mv = spam_filter.check_blacklist("Ann <ann@em.retailer.com>", bl)
    assert mt == "domain"


def test_exact_domain_still_blocks():
    bl = _bl({"domains": ["retailer.com"]})
    assert spam_filter.check_blacklist("x <x@retailer.com>", bl)[0] == "domain"


def test_lookalike_prefix_does_not_match():
    bl = _bl({"domains": ["retailer.com"]})
    assert spam_filter.check_blacklist(
        "x <x@evilretailer.com>", bl) == (None, None)


def test_right_anchored_trick_does_not_match():
    bl = _bl({"domains": ["retailer.com"]})
    assert spam_filter.check_blacklist(
        "x <x@retailer.com.evil.com>", bl) == (None, None)


def test_subdomain_match_respects_scope():
    bl = _bl({"domains": [{"value": "retailer.com",
                           "scope": ["matt@example.com"]}]})
    # In-scope account: the subdomain sender is blocked by the parent entry.
    assert spam_filter.check_blacklist(
        "x <x@em.retailer.com>", bl, account_name="matt@example.com")[0] == "domain"
    # Different account: the scoped parent entry must NOT block its subdomain.
    assert spam_filter.check_blacklist(
        "x <x@em.retailer.com>", bl, account_name="dad@example.com") == (None, None)


def test_sibling_subdomains_case_documented():
    # INTENTIONALLY NOT COVERED as a match: blocking "em1.retailer.com" does
    # NOT block a SIBLING "em2.retailer.com" — only the exact host and its own
    # subdomains match. Blocking all siblings requires listing the parent
    # "retailer.com" (see test_parent_entry_blocks_subdomain_sender). This test
    # documents that deliberate boundary.
    bl = _bl({"domains": ["em1.retailer.com"]})
    assert spam_filter.check_blacklist(
        "x <x@em2.retailer.com>", bl) == (None, None)
