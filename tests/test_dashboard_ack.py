#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Finding #8 — the Dashboard's retired-refinement ack.

When an owner approves a pending refinement from the Dashboard whose rule was
already dropped, the Dashboard cannot reactivate it (there is no GUI restore
control) and must not claim it is "now active". Instead it points the owner at
the existing email RESTORE reply. This locks that copy in place.
"""
import os
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "payload", "MailWarden", "src")
sys.path.insert(0, os.path.abspath(SRC))
APP = os.path.join(os.path.dirname(__file__), "..", "app")
sys.path.insert(0, os.path.abspath(APP))

from mailwarden_app import dashboard  # noqa: E402


def test_pending_retired_message_points_to_email_restore():
    msg = dashboard.pending_retired_message()
    assert "RESTORE" in msg
    assert "now active" not in msg.lower()


def test_pending_retired_message_says_dashboard_cannot_restore():
    msg = dashboard.pending_retired_message()
    assert "Dashboard can't restore" in msg
