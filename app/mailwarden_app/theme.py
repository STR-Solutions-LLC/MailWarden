# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Centralized ttk theme + color constants for MailWarden's tkinter UI.

apply_theme() is called once at the top of Setup Assistant and Dashboard.
It configures ttk styles so every Label, Button, LabelFrame, Treeview,
Notebook, Entry, Checkbutton, Scale, and Combobox picks up consistent
modern colors without each widget hard-coding them.

Colors are drawn from the MailWarden icon: deep navy for primary accents,
cream for warm surfaces, subtle gray backgrounds for cards, and a single
orange call-to-action color used sparingly.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk


# ---------------------------------------------------------------------------
# Palette — single source of truth
# ---------------------------------------------------------------------------
NAVY = "#1C3052"          # primary accent (icon background, headings)
NAVY_DARK = "#12203A"     # deeper navy for pressed states
CREAM = "#F8E7B4"         # warm highlight (from icon envelope)
ACCENT = "#D97706"        # call-to-action orange (warn border, primary button)
ACCENT_HOVER = "#B05B04"  # orange pressed

BG = "#F6F7FA"            # window background — very light neutral
SURFACE = "#FFFFFF"        # card / input background
SURFACE_ALT = "#EEF1F6"    # zebra / subtle contrast
BORDER = "#D8DCE3"         # hairline borders
BORDER_STRONG = "#B3B9C4"  # focus / emphasized borders

TEXT = "#1F2530"           # primary text
TEXT_MUTED = "#5B6474"     # secondary text
TEXT_INVERSE = "#FFFFFF"   # text on navy/accent buttons

GREEN = "#1F8A3B"          # healthy status
YELLOW = "#C18A1D"         # warning / stale
RED = "#C0392B"            # error / blocked

HEADING_FONT = ("Helvetica Neue", 20, "bold")
SUBHEADING_FONT = ("Helvetica Neue", 14, "bold")
BODY_FONT = ("Helvetica Neue", 12)
SMALL_FONT = ("Helvetica Neue", 11)
MONO_FONT = ("Menlo", 11)


def bring_to_front(root: tk.Tk) -> None:
    """Force a tkinter root to come forward and take focus. Required on
    macOS when launched via LaunchServices — otherwise the window is
    created but never appears on screen."""
    # LOUD on-device evidence that focus-taking actually fired — accessory
    # apps (no Dock tile) can struggle to take focus, so we log every call.
    try:
        from . import startup_log
        startup_log.step("theme: bring_to_front ran")
    except Exception:
        pass
    try:
        root.update_idletasks()
        root.deiconify()
        root.lift()
        root.focus_force()
        # Flash topmost to make it the active window, then release.
        root.attributes("-topmost", True)
        root.after(200, lambda: root.attributes("-topmost", False))
    except tk.TclError:
        pass
    # Also tell NSApp to activate. py2app bundles sometimes don't get focus
    # from the Dock/Finder launch without this.
    try:
        from AppKit import NSApp  # type: ignore
        NSApp().activateIgnoringOtherApps_(True)
    except Exception:
        pass


def apply_theme(root: tk.Misc) -> None:
    """Configure ttk.Style for the whole app. Call once per root window."""
    style = ttk.Style(root)

    # Start from a known-good built-in theme; override colors on top.
    # "aqua" is native macOS but ignores most color overrides; "clam" is a
    # cross-platform theme that respects background= / foreground= fully.
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    try:
        root.configure(bg=BG)
    except tk.TclError:
        pass

    # --- base ----
    style.configure(".", background=BG, foreground=TEXT,
                    font=BODY_FONT, borderwidth=0)

    # --- frames / cards ----
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=SURFACE, relief=tk.FLAT)
    style.configure("TLabelframe", background=BG, foreground=TEXT,
                    borderwidth=1, relief=tk.SOLID)
    style.configure("TLabelframe.Label", background=BG, foreground=NAVY,
                    font=SUBHEADING_FONT)

    # --- labels ----
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Heading.TLabel", background=BG, foreground=NAVY,
                    font=HEADING_FONT)
    style.configure("Subheading.TLabel", background=BG, foreground=NAVY,
                    font=SUBHEADING_FONT)
    style.configure("Muted.TLabel", background=BG, foreground=TEXT_MUTED,
                    font=SMALL_FONT)
    style.configure("Status.TLabel", background=BG, foreground=TEXT_MUTED,
                    font=SMALL_FONT)
    style.configure("Green.TLabel", background=BG, foreground=GREEN,
                    font=SUBHEADING_FONT)
    style.configure("Yellow.TLabel", background=BG, foreground=YELLOW,
                    font=SUBHEADING_FONT)
    style.configure("Red.TLabel", background=BG, foreground=RED,
                    font=SUBHEADING_FONT)
    style.configure("Warn.TLabel", background="#FFF4E5", foreground="#9A4A06",
                    font=BODY_FONT, padding=(10, 8))

    # --- buttons ----
    # Primary (orange) — used for Install, Save, Validate actions.
    style.configure("Primary.TButton",
                    background=ACCENT, foreground=TEXT_INVERSE,
                    font=("Helvetica Neue", 12, "bold"),
                    padding=(14, 7), borderwidth=0)
    style.map("Primary.TButton",
              background=[("active", ACCENT_HOVER), ("pressed", ACCENT_HOVER),
                          ("disabled", "#EACBA2")],
              foreground=[("disabled", "#8A8A8A")])

    # Danger (red) — destructive actions like Uninstall.
    style.configure("Danger.TButton",
                    background=RED, foreground=TEXT_INVERSE,
                    font=("Helvetica Neue", 12, "bold"),
                    padding=(14, 7), borderwidth=0)
    style.map("Danger.TButton",
              background=[("active", "#B0241B"), ("pressed", "#B0241B"),
                          ("disabled", "#E8B0AC")],
              foreground=[("disabled", "#8A8A8A")])

    # Secondary (navy on light) — used for Next/Back/Cancel.
    style.configure("TButton",
                    background=SURFACE, foreground=NAVY,
                    font=("Helvetica Neue", 12),
                    padding=(12, 6), borderwidth=1, relief=tk.SOLID,
                    bordercolor=BORDER)
    style.map("TButton",
              background=[("active", SURFACE_ALT), ("pressed", SURFACE_ALT),
                          ("disabled", SURFACE_ALT)],
              foreground=[("disabled", TEXT_MUTED)],
              bordercolor=[("focus", NAVY)])

    # Compact secondary — same as TButton but with reduced horizontal padding;
    # used in button rows that must fit many buttons (e.g. blacklist row).
    style.configure("Compact.TButton",
                    background=SURFACE, foreground=NAVY,
                    font=("Helvetica Neue", 12),
                    padding=(7, 6), borderwidth=1, relief=tk.SOLID,
                    bordercolor=BORDER)
    style.map("Compact.TButton",
              background=[("active", SURFACE_ALT), ("pressed", SURFACE_ALT),
                          ("disabled", SURFACE_ALT)],
              foreground=[("disabled", TEXT_MUTED)],
              bordercolor=[("focus", NAVY)])

    # --- entries / combos ----
    style.configure("TEntry", fieldbackground=SURFACE, foreground=TEXT,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                    padding=4)
    style.map("TEntry",
              bordercolor=[("focus", NAVY)],
              lightcolor=[("focus", NAVY)],
              darkcolor=[("focus", NAVY)])
    style.configure("TCombobox", fieldbackground=SURFACE, foreground=TEXT,
                    bordercolor=BORDER, padding=4, arrowsize=14)
    style.map("TCombobox",
              bordercolor=[("focus", NAVY)],
              fieldbackground=[("readonly", SURFACE)])

    # --- checkbuttons / radiobuttons ----
    style.configure("TCheckbutton", background=BG, foreground=TEXT)
    style.map("TCheckbutton",
              background=[("active", BG)],
              indicatorcolor=[("selected", NAVY), ("!selected", SURFACE)])
    style.configure("TRadiobutton", background=BG, foreground=TEXT)
    style.map("TRadiobutton",
              background=[("active", BG)],
              indicatorcolor=[("selected", NAVY), ("!selected", SURFACE)])

    # --- notebook tabs ----
    style.configure("TNotebook", background=BG, borderwidth=0, padding=0)
    style.configure("TNotebook.Tab",
                    background=BG, foreground=TEXT_MUTED,
                    padding=(16, 8), borderwidth=0,
                    font=("Helvetica Neue", 12))
    style.map("TNotebook.Tab",
              background=[("selected", SURFACE)],
              foreground=[("selected", NAVY)],
              font=[("selected", ("Helvetica Neue", 12, "bold"))])

    # --- treeview (tables) ----
    style.configure("Treeview",
                    background=SURFACE, foreground=TEXT,
                    fieldbackground=SURFACE, bordercolor=BORDER,
                    rowheight=24)
    style.configure("Treeview.Heading",
                    background=SURFACE_ALT, foreground=NAVY,
                    font=("Helvetica Neue", 11, "bold"),
                    padding=(8, 6), relief=tk.FLAT)
    style.map("Treeview",
              background=[("selected", NAVY)],
              foreground=[("selected", TEXT_INVERSE)])
    style.map("Treeview.Heading",
              background=[("active", SURFACE_ALT)])

    # --- scale (confidence slider) ----
    style.configure("TScale", background=BG, troughcolor=BORDER,
                    slidercolor=NAVY)

    # --- scrollbar ----
    style.configure("Vertical.TScrollbar", background=BG,
                    troughcolor=BG, bordercolor=BG, arrowcolor=TEXT_MUTED)

    # --- spinbox ----
    style.configure("TSpinbox", fieldbackground=SURFACE, foreground=TEXT,
                    bordercolor=BORDER, padding=4)
