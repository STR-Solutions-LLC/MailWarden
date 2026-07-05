#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""Finding #8 — the Dashboard's retired-refinement ack.

When an owner APPROVES a pending refinement from the Dashboard whose rule was
already dropped, approving does not un-drop it and the ack must not claim it is
"now active". Feature 2 added a real Dashboard restore control (Signal History →
Dropped rules), so the ack now points the owner there — and notes the email
RESTORE reply still works — instead of saying the Dashboard can't restore. This
locks that copy in place.
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


def test_pending_retired_message_points_to_dropped_rules_panel():
    # Feature 2: the ack now directs the owner to the real restore control
    # instead of the retired "Dashboard can't restore a dropped rule" claim.
    msg = dashboard.pending_retired_message()
    assert "Dropped rules" in msg
    assert "can't restore" not in msg
