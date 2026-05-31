# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Setup Assistant — six-step tkinter wizard for first-time configuration.

Runs automatically when MailWarden.app launches and no valid config.json is
present. Also reachable from Dashboard → Accounts → Add Account (reuses the
account form) and from Upgrade Confirmation → Edit Settings (pre-populates
fields from backup).
"""
from __future__ import annotations

import copy
import shutil
import subprocess
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any, Callable

from . import app_entrypoint
from . import config_io
from . import help_content
from . import paths
from . import smappservice_install
from . import theme
from . import validators

STEPS = [
    "Welcome",
    "Anthropic API key",
    "Email accounts",
    "Daily report",
    "Menu bar",
    "Review & install",
]


class SetupAssistant(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MailWarden Setup")
        self.geometry("760x640")
        self.minsize(720, 600)
        theme.apply_theme(self)

        self.current_step = 0
        self.config_draft: dict = copy.deepcopy(config_io.DEFAULT_CONFIG)
        self.api_key_validated = False
        self.install_succeeded = False

        # Step state
        # EULA is accepted during .pkg install (mandatory macOS Installer click-
        # through); no duplicate agreement here. Step 1 is a welcome-only screen.
        self._eula_agreed = tk.BooleanVar(value=True)
        self._api_key_var = tk.StringVar()
        self._api_key_status = tk.StringVar(value="")
        self._menu_bar_var = tk.BooleanVar(value=True)
        self._summary_time_var = tk.StringVar(value="08:00")
        self._summary_recipient_var = tk.StringVar(value="")
        self._accounts: list[dict] = []

        self._build_chrome()
        self._render_current_step()

    # ------------------------------------------------------------------ chrome
    def _build_chrome(self):
        self.banner = ttk.Frame(self, padding=(20, 14))
        self.banner.pack(side=tk.TOP, fill=tk.X)
        self.step_label = ttk.Label(self.banner, style="Subheading.TLabel")
        self.step_label.pack(side=tk.LEFT)
        self.step_indicator = ttk.Label(self.banner, style="Muted.TLabel")
        self.step_indicator.pack(side=tk.RIGHT)

        self.content = ttk.Frame(self, padding=(20, 8))
        self.content.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        button_row = ttk.Frame(self, padding=(20, 14))
        button_row.pack(side=tk.BOTTOM, fill=tk.X)
        self.back_btn = ttk.Button(button_row, text="Back", command=self._on_back)
        self.back_btn.pack(side=tk.LEFT)
        self.cancel_btn = ttk.Button(button_row, text="Cancel", command=self._on_cancel)
        self.cancel_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.next_btn = ttk.Button(button_row, text="Next", style="Primary.TButton",
                                    command=self._on_next)
        self.next_btn.pack(side=tk.RIGHT)

    def _render_current_step(self):
        for child in self.content.winfo_children():
            child.destroy()

        self.step_label.config(text=STEPS[self.current_step])
        self.step_indicator.config(text=f"Step {self.current_step + 1} of {len(STEPS)}")

        self.back_btn.config(state=(tk.NORMAL if self.current_step > 0 else tk.DISABLED))
        self.next_btn.config(text=("Install and Start" if self.current_step == len(STEPS) - 1 else "Next"))

        renderers = [
            self._build_step_1_welcome,
            self._build_step_2_api_key,
            self._build_step_3_accounts,
            self._build_step_4_summary,
            self._build_step_5_menu_bar,
            self._build_step_6_review,
        ]
        renderers[self.current_step]()
        self._update_next_state()

    def _update_next_state(self):
        can_advance = self._current_step_is_valid()
        self.next_btn.config(state=(tk.NORMAL if can_advance else tk.DISABLED))

    def _current_step_is_valid(self) -> bool:
        step = self.current_step
        if step == 0:
            return bool(self._eula_agreed.get())
        if step == 1:
            return self.api_key_validated and bool(self._api_key_var.get().strip())
        if step == 2:
            return len(self._accounts) >= 1
        if step == 3:
            return bool(self._summary_recipient_var.get().strip())
        if step == 4:
            return True
        if step == 5:
            return True
        return False

    def _on_next(self):
        if not self._current_step_is_valid():
            return
        if self.current_step < len(STEPS) - 1:
            self.current_step += 1
            self._render_current_step()
        else:
            self._install_and_start()

    def _on_back(self):
        if self.current_step > 0:
            self.current_step -= 1
            self._render_current_step()

    def _on_cancel(self):
        if messagebox.askyesno("Cancel setup",
                               "Quit MailWarden setup? Nothing will be installed."):
            self.destroy()

    # ------------------------------------------------------------------ step 1
    def _build_step_1_welcome(self):
        ttk.Label(self.content, text="Welcome to MailWarden",
                  style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 10))
        ttk.Label(self.content, text=help_content.WELCOME_PARAGRAPH,
                  wraplength=700, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 14))

        usage_box = ttk.LabelFrame(self.content,
                                    text="Where to install MailWarden",
                                    padding=(12, 10))
        usage_box.pack(fill=tk.X, pady=(0, 14))
        ttk.Label(usage_box, text=help_content.USAGE_MODEL_LONG,
                  wraplength=680, justify=tk.LEFT,
                  style="Warn.TLabel").pack(anchor=tk.W, fill=tk.X)

        ttk.Label(self.content, text="Next up: your Anthropic API key.",
                  style="Muted.TLabel").pack(anchor=tk.W, pady=(0, 4))
        ttk.Label(self.content,
                  text="You accepted the license agreement during installation, "
                       "so there is nothing else to agree to here. "
                       "Click Next to enter your API key and email credentials.",
                  wraplength=700, justify=tk.LEFT,
                  style="Muted.TLabel").pack(anchor=tk.W)

    # ------------------------------------------------------------------ step 2
    def _build_step_2_api_key(self):
        ttk.Label(self.content, text="Anthropic API key",
                  style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 8))
        ttk.Label(self.content, text=(
            "MailWarden uses your own Anthropic account to classify emails. "
            "API charges are billed directly to you. Typical usage is pennies "
            "per day.\n\n"
            "Your key begins with sk-ant-. Get one at console.anthropic.com."),
            wraplength=700, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 12))

        row = ttk.Frame(self.content)
        row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(row, text="API key:", width=12).pack(side=tk.LEFT)
        self._api_key_entry = ttk.Entry(row, textvariable=self._api_key_var,
                                         show="•", width=60)
        self._api_key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Show", variable=self._show_var,
                        command=self._toggle_api_key_visibility).pack(side=tk.LEFT, padx=(8, 0))

        btn_row = ttk.Frame(self.content)
        btn_row.pack(fill=tk.X, pady=(0, 8))
        self._validate_btn = ttk.Button(btn_row, text="Validate Key",
                                          command=self._on_validate_api_key)
        self._validate_btn.pack(side=tk.LEFT)
        ttk.Label(btn_row, textvariable=self._api_key_status,
                  foreground="#555").pack(side=tk.LEFT, padx=(12, 0))

        self._api_key_var.trace_add("write", lambda *_: self._on_api_key_changed())

    def _toggle_api_key_visibility(self):
        self._api_key_entry.config(show=("" if self._show_var.get() else "•"))

    def _on_api_key_changed(self):
        self.api_key_validated = False
        self._api_key_status.set("Not validated.")
        self._update_next_state()

    def _on_validate_api_key(self):
        key = self._api_key_var.get().strip()
        self._api_key_status.set("Validating…")
        self._validate_btn.config(state=tk.DISABLED)
        self.update_idletasks()

        def worker():
            ok, msg = validators.validate_api_key(key)

            def on_done():
                self.api_key_validated = ok
                self._api_key_status.set(msg)
                self._validate_btn.config(state=tk.NORMAL)
                self._update_next_state()

            self.after(0, on_done)

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------ step 3
    def _build_step_3_accounts(self):
        ttk.Label(self.content, text="Email accounts",
                  style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 4))
        ttk.Label(self.content, text=(
            "Add at least one email account for MailWarden to monitor. "
            "Each account is tested live before it's saved."),
            wraplength=700, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 12))

        # Account list
        list_frame = ttk.LabelFrame(self.content, text="Configured accounts",
                                     padding=(6, 6))
        list_frame.pack(fill=tk.X, pady=(0, 8))
        self._account_list = tk.Listbox(list_frame, height=5)
        self._account_list.pack(side=tk.LEFT, fill=tk.X, expand=True)
        for i, a in enumerate(self._accounts):
            self._account_list.insert(tk.END,
                f"{a.get('name','')} ({a.get('username','')})")

        list_buttons = ttk.Frame(list_frame)
        list_buttons.pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(list_buttons, text="Add…",
                   command=self._on_add_account).pack(fill=tk.X, pady=(0, 4))
        ttk.Button(list_buttons, text="Edit…",
                   command=self._on_edit_account).pack(fill=tk.X, pady=(0, 4))
        ttk.Button(list_buttons, text="Remove",
                   command=self._on_remove_account).pack(fill=tk.X)

        ttk.Label(self.content, text=(
            "Tip: Gmail and AOL require an App Password, not your regular password. "
            "The account form links to the exact page where you generate one."),
            wraplength=700, foreground="#666").pack(anchor=tk.W, pady=(8, 0))

    def _on_add_account(self):
        dlg = AccountFormDialog(self)
        self.wait_window(dlg)
        if dlg.saved_account is not None:
            self._accounts.append(dlg.saved_account)
            self._account_list.insert(tk.END,
                f"{dlg.saved_account.get('name','')} ({dlg.saved_account.get('username','')})")
            if not self._summary_recipient_var.get():
                self._summary_recipient_var.set(dlg.saved_account.get("username", ""))
        self._update_next_state()

    def _on_edit_account(self):
        sel = self._account_list.curselection()
        if not sel:
            messagebox.showinfo("Select an account", "Select an account to edit first.")
            return
        idx = sel[0]
        dlg = AccountFormDialog(self, existing=self._accounts[idx])
        self.wait_window(dlg)
        if dlg.saved_account is not None:
            self._accounts[idx] = dlg.saved_account
            self._account_list.delete(idx)
            self._account_list.insert(idx,
                f"{dlg.saved_account.get('name','')} ({dlg.saved_account.get('username','')})")
        self._update_next_state()

    def _on_remove_account(self):
        sel = self._account_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if messagebox.askyesno("Remove account",
                                f"Remove '{self._accounts[idx]['name']}' from setup?"):
            del self._accounts[idx]
            self._account_list.delete(idx)
        self._update_next_state()

    # ------------------------------------------------------------------ step 4
    def _build_step_4_summary(self):
        ttk.Label(self.content, text="Daily report",
                  style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 4))
        ttk.Label(self.content, text=(
            "MailWarden sends a daily summary email showing what was filtered "
            "and your current API usage. Choose where to send it and at what "
            "time."),
            wraplength=700, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 12))

        frm = ttk.Frame(self.content)
        frm.pack(fill=tk.X)

        ttk.Label(frm, text="Send to:", width=12).grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(frm, textvariable=self._summary_recipient_var,
                  width=40).grid(row=0, column=1, sticky=tk.W + tk.E, pady=4)

        ttk.Label(frm, text="Time:", width=12).grid(row=1, column=0, sticky=tk.W)
        time_entry = ttk.Entry(frm, textvariable=self._summary_time_var, width=10)
        time_entry.grid(row=1, column=1, sticky=tk.W, pady=4)
        ttk.Label(frm, text="(24-hour, HH:MM — local time)",
                  foreground="#666").grid(row=1, column=2, sticky=tk.W, padx=(8, 0))

        frm.columnconfigure(1, weight=1)

        self._summary_recipient_var.trace_add(
            "write", lambda *_: self._update_next_state())

    # ------------------------------------------------------------------ step 5
    def _build_step_5_menu_bar(self):
        ttk.Label(self.content, text="Menu bar icon",
                  style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 4))
        ttk.Label(self.content, text=(
            "MailWarden can live in your macOS menu bar as a small status "
            "indicator. The icon changes color when the filter is running "
            "normally, is stale, or has errored. You can enable or disable "
            "this later from Dashboard → Settings."),
            wraplength=700, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 12))

        ttk.Checkbutton(self.content,
                        text="Show MailWarden in the menu bar (recommended)",
                        variable=self._menu_bar_var).pack(anchor=tk.W)

    # ------------------------------------------------------------------ step 6
    def _build_step_6_review(self):
        ttk.Label(self.content, text="Review and install",
                  style="Heading.TLabel").pack(anchor=tk.W, pady=(0, 12))

        txt = tk.Text(self.content, wrap=tk.WORD, height=18)
        txt.pack(fill=tk.BOTH, expand=True)

        summary = ["License agreement:  accepted",
                   f"Anthropic API key:  {'validated' if self.api_key_validated else 'NOT validated'}",
                   "",
                   f"Accounts ({len(self._accounts)}):"]
        for a in self._accounts:
            summary.append(f"  • {a.get('name','')} — {a.get('username','')}  "
                           f"(junk folder: {a.get('junk_folder','—')})")
        summary += [
            "",
            f"Daily report:       {self._summary_recipient_var.get()} "
            f"at {self._summary_time_var.get()}",
            f"Menu bar icon:      {'enabled' if self._menu_bar_var.get() else 'disabled'}",
            "",
            "When you click Install and Start, MailWarden will:",
            "  1. Save your configuration to ~/MailWarden/config/config.json",
            "  2. Write the bundled defaults (empty whitelists, learned signals,",
            "     skip-names list) into ~/MailWarden/memory/",
            "  3. Register background agents via macOS Login Items (SMAppService).",
            "     A system dialog may appear — toggle MailWarden ON to approve.",
            "  4. Send a welcome email to your primary account with the",
            "     email-command cheat sheet",
            "",
            "IMPORTANT — MailWarden starts in DRY RUN mode. It will classify",
            "emails but will NOT move any mail to your junk folder until you",
            "turn off dry run from Dashboard → Home. This lets you review its",
            "first few decisions safely before giving it permission to act.",
        ]
        txt.insert("1.0", "\n".join(summary))
        txt.config(state=tk.DISABLED)

    # ----------------------------------------------------------- install
    def _install_and_start(self):
        self.next_btn.config(state=tk.DISABLED)
        self.back_btn.config(state=tk.DISABLED)

        try:
            self._finalize_config()
            self._install_defaults()
            self._register_smappservice()
            self._send_welcome_email()
        except Exception as e:
            messagebox.showerror("Setup failed",
                                  f"Setup could not complete:\n\n{e}")
            self.next_btn.config(state=tk.NORMAL)
            self.back_btn.config(state=tk.NORMAL)
            return

        messagebox.showinfo(
            "MailWarden is ready",
            "Setup complete. The Dashboard will open next.\n\n"
            "MailWarden starts in DRY RUN mode — it will classify emails "
            "but will not move anything until you turn off dry run from "
            "Dashboard → Home.",
        )
        self.install_succeeded = True
        self.destroy()  # run() returns to app_entrypoint, which launches Dashboard

    def _finalize_config(self):
        cfg = self.config_draft
        cfg["anthropic"]["api_key"] = self._api_key_var.get().strip()

        # Pull the SMTP seed off the first account into the global smtp block,
        # then strip the sentinel key from every account before saving.
        if self._accounts:
            seed = self._accounts[0].get("_smtp_seed")
            if seed:
                cfg["smtp"] = dict(seed)
        for a in self._accounts:
            a.pop("_smtp_seed", None)
        cfg["accounts"] = self._accounts

        recipient = self._summary_recipient_var.get().strip()
        cfg["summary"]["recipient"] = recipient

        time_str = self._summary_time_var.get().strip() or "08:00"
        hour, _, minute = time_str.partition(":")
        try:
            cfg["summary"]["hour"] = int(hour)
            cfg["summary"]["minute"] = int(minute) if minute else 0
        except ValueError:
            cfg["summary"]["hour"] = 8
            cfg["summary"]["minute"] = 0

        cfg["ui"]["menu_bar_enabled"] = bool(self._menu_bar_var.get())
        cfg["filter"]["dry_run"] = True  # §0.11: dry run ON by default

        if self._accounts and not cfg.get("smtp", {}).get("from_address"):
            cfg.setdefault("smtp", {})["from_address"] = self._accounts[0].get("username", "")

        config_io.save_config(cfg)

        state = config_io.load_installer_state()
        if not state.get("installed_at"):
            state["installed_at"] = datetime.now().isoformat()
        state["last_upgrade_at"] = datetime.now().isoformat()
        state["installer_version"] = help_content.VERSION
        config_io.save_installer_state(state)

    def _install_defaults(self):
        defaults_src = app_entrypoint.get_bundled_defaults_dir()

        # memory/ JSONs — only write if missing (first-run install)
        memory_defaults = [
            ("signals.json", paths.SIGNALS_PATH),
            ("whitelist.json", paths.WHITELIST_PATH),
            ("blacklist.json", paths.BLACKLIST_PATH),
            ("processed_ids.json", paths.PROCESSED_IDS_PATH),
            ("token_usage.json", paths.TOKEN_USAGE_PATH),
            ("pending_signals.json", paths.PENDING_SIGNALS_PATH),
        ]
        paths.MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        for src_name, dst_path in memory_defaults:
            if dst_path.exists():
                continue
            src = defaults_src / src_name
            if src.exists():
                shutil.copy2(src, dst_path)

        # skip_names.txt goes in the static blacklist/ dir
        paths.BLACKLIST_DIR.mkdir(parents=True, exist_ok=True)
        skip = defaults_src / "skip_names.txt"
        skip_dst = paths.BLACKLIST_DIR / "skip_names.txt"
        if skip.exists() and not skip_dst.exists():
            shutil.copy2(skip, skip_dst)

        # Ensure supporting dirs exist
        paths.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        paths.SPAM_EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    def _register_smappservice(self):
        """Register MailWarden's background agents via SMAppService.

        v1.6.0: replaces _install_launchd. Shows a consent dialog, calls
        register_all(), then polls for the requiresApproval state and opens
        the Login Items settings deep-link if the user needs to approve.

        If the user closes or ignores the approval dialog, a warning flag
        is stored in config.json so the Dashboard Diagnostics tab can show
        a persistent banner.
        """
        install_menubar = bool(self._menu_bar_var.get())

        # Show consent dialog before registration.
        proceed = messagebox.askyesno(
            "Background services",
            "MailWarden needs permission to run in the background so it can "
            "filter your email automatically.\n\n"
            "After you click Yes, a System Settings window may appear — "
            "please toggle MailWarden ON in that window.\n\n"
            "Continue?",
            default="yes",
        )
        if not proceed:
            # User declined — mark as unapproved so Dashboard shows a banner.
            cfg = self.config_draft
            cfg.setdefault("ui", {})["smappservice_approved"] = False
            config_io.save_config(cfg)
            return

        smappservice_install.register_all(install_menubar=install_menubar)

        # Poll for requiresApproval state — open Login Items settings if needed.
        import time as _time
        import subprocess as _sp
        deadline = _time.monotonic() + 30.0
        opened_settings = False

        while _time.monotonic() < deadline:
            if smappservice_install.any_requires_approval():
                if not opened_settings:
                    # Open the Login Items deep-link automatically.
                    try:
                        _sp.Popen(
                            ["open",
                             "x-apple.systempreferences:"
                             "com.apple.LoginItems-Settings.extension"],
                            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
                    except OSError:
                        pass
                    opened_settings = True
                    messagebox.showinfo(
                        "Approval needed",
                        "System Settings has opened. Toggle MailWarden ON in "
                        "Login Items and Extensions, then click OK here to "
                        "continue setup.",
                    )
            if smappservice_install.all_enabled():
                break
            _time.sleep(1.0)

        if not smappservice_install.all_enabled():
            # Still not approved — save flag for Dashboard warning banner.
            cfg = self.config_draft
            cfg.setdefault("ui", {})["smappservice_approved"] = False
            config_io.save_config(cfg)
        else:
            cfg = self.config_draft
            cfg.setdefault("ui", {})["smappservice_approved"] = True
            config_io.save_config(cfg)

    def _send_welcome_email(self):
        """Non-fatal — if sending fails, log it but don't block install."""
        try:
            if not self._accounts:
                return
            primary = self._accounts[0]
            smtp = self.config_draft.get("smtp", {}) or primary.get("_smtp_seed", {})
            from_addr = primary.get("username", "")
            to_addr = self._summary_recipient_var.get().strip() or from_addr
            if not smtp.get("host") or not from_addr:
                return

            from email.message import EmailMessage

            msg = EmailMessage()
            msg["Subject"] = help_content.welcome_email_subject()
            msg["From"] = from_addr
            msg["To"] = to_addr
            msg.set_content(help_content.welcome_email_body(to_addr))

            # Route through validators.safe_smtp_connect so the welcome email
            # follows the same port-465 / STARTTLS / refuse-plaintext rules as
            # every other SMTP send in the app.
            server = validators.safe_smtp_connect(
                smtp["host"], int(smtp["port"]),
                smtp["username"], smtp["password"],
                use_starttls=smtp.get("use_starttls", True),
            )
            try:
                server.send_message(msg)
            finally:
                try:
                    server.quit()
                except Exception:
                    pass
        except Exception as e:
            # Record but don't fail install
            (paths.LOGS_DIR / "setup.log").write_text(
                f"[{datetime.now().isoformat()}] welcome email failed: {e}\n",
                encoding="utf-8",
            )  # already uses utf-8 — keep

    # (Dashboard hand-off is now in-process; see run() at module bottom.)


# ---------------------------------------------------------------------- dialog
class AccountFormDialog(tk.Toplevel):
    """Modal dialog for adding or editing one account."""

    def __init__(self, parent: tk.Tk, existing: dict | None = None):
        super().__init__(parent)
        self.title("Account" if existing else "Add account")
        self.transient(parent)
        self.grab_set()
        self.resizable(True, True)
        self.geometry("640x620")

        self.saved_account: dict | None = None
        self._folders: list[str] = []
        self._separator: str = "."

        existing = existing or {}
        self._name = tk.StringVar(value=existing.get("name", ""))
        self._imap_host = tk.StringVar(value=existing.get("imap_host", ""))
        self._imap_port = tk.StringVar(value=str(existing.get("imap_port", 993)))
        self._imap_user = tk.StringVar(value=existing.get("username", ""))
        self._imap_pass = tk.StringVar(value=existing.get("password", ""))
        # SMTP is global (one per config), but we surface the fields in the
        # account form so the first account's values seed the global smtp block.
        # Priority: (1) transient _smtp_seed on a brand-new account being
        # re-edited in the same Setup session; (2) the saved config.smtp
        # block (what the Dashboard shows when editing an existing account —
        # the old code skipped this and always showed blank fields).
        existing_smtp = existing.get("_smtp_seed") or {}
        if not existing_smtp:
            try:
                saved = config_io.load_config().get("smtp") or {}
                if saved:
                    existing_smtp = {
                        "host": saved.get("host", ""),
                        "port": saved.get("port", 587),
                        "username": saved.get("username", ""),
                        "password": saved.get("password", ""),
                    }
            except Exception:
                existing_smtp = {}
        self._smtp_host = tk.StringVar(value=existing_smtp.get("host", ""))
        self._smtp_port = tk.StringVar(value=str(existing_smtp.get("port", 587)))
        self._smtp_user = tk.StringVar(value=existing_smtp.get("username", ""))
        self._smtp_pass = tk.StringVar(value=existing_smtp.get("password", ""))
        self._junk_folder = tk.StringVar(value=existing.get("junk_folder", ""))
        self._imap_connection_ok = bool(existing)
        self._folders = [existing.get("junk_folder", "")] if existing.get("junk_folder") else []
        self._separator = "."
        self._status = tk.StringVar(value="")
        self._spam_action = tk.StringVar(
            value=existing.get("spam_action", "junk")
        )

        self._build()

    def _build(self):
        pad = {"padx": 8, "pady": 4}
        frm = ttk.Frame(self, padding=(14, 14))
        frm.pack(fill=tk.BOTH, expand=True)

        row = 0
        ttk.Label(frm, text="Account label:").grid(row=row, column=0, sticky=tk.W, **pad)
        ttk.Entry(frm, textvariable=self._name).grid(row=row, column=1, columnspan=3,
                                                     sticky=tk.W + tk.E, **pad)

        row += 1
        ttk.Label(frm, text="Provider:").grid(row=row, column=0, sticky=tk.W, **pad)
        self._preset = ttk.Combobox(
            frm, values=[p["label"] for p in validators.PROVIDER_PRESETS],
            state="readonly")
        self._preset.grid(row=row, column=1, columnspan=3, sticky=tk.W + tk.E, **pad)
        self._preset.bind("<<ComboboxSelected>>", self._on_preset)

        row += 1
        ttk.Separator(frm).grid(row=row, column=0, columnspan=4, sticky=tk.E + tk.W, pady=8)

        # --- IMAP row: host + port side by side ---
        row += 1
        ttk.Label(frm, text="IMAP host:").grid(row=row, column=0, sticky=tk.W, **pad)
        ttk.Entry(frm, textvariable=self._imap_host).grid(row=row, column=1,
                                                          sticky=tk.W + tk.E, **pad)
        ttk.Label(frm, text="Port:").grid(row=row, column=2, sticky=tk.E, **pad)
        ttk.Entry(frm, textvariable=self._imap_port, width=8).grid(row=row, column=3,
                                                                    sticky=tk.W, **pad)

        row += 1
        ttk.Label(frm, text="Email address:").grid(row=row, column=0, sticky=tk.W, **pad)
        ttk.Entry(frm, textvariable=self._imap_user).grid(row=row, column=1, columnspan=3,
                                                          sticky=tk.W + tk.E, **pad)

        row += 1
        ttk.Label(frm, text="Password:").grid(row=row, column=0, sticky=tk.W, **pad)
        self._imap_pass_entry = ttk.Entry(frm, textvariable=self._imap_pass, show="•")
        self._imap_pass_entry.grid(row=row, column=1, columnspan=2,
                                    sticky=tk.W + tk.E, **pad)
        show = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Show", variable=show,
                        command=lambda: self._imap_pass_entry.config(
                            show=("" if show.get() else "•"))).grid(row=row, column=3,
                                                                     sticky=tk.W, **pad)

        # Explanatory label above Test IMAP Connection (backlog #3).
        row += 1
        ttk.Label(frm,
                  text="Click Test Connection to verify credentials and "
                       "auto-pick your junk folder below:",
                  style="Muted.TLabel",
                  wraplength=520).grid(row=row, column=0, columnspan=4,
                                        sticky=tk.W, padx=8, pady=(8, 0))

        row += 1
        ttk.Button(frm, text="Test IMAP Connection", style="Primary.TButton",
                   command=self._on_test_imap).grid(row=row, column=0, columnspan=4,
                                                    sticky=tk.W, **pad)

        row += 1
        ttk.Label(frm, text="Junk folder:").grid(row=row, column=0, sticky=tk.W, **pad)
        self._junk_combo = ttk.Combobox(frm, textvariable=self._junk_folder,
                                         values=self._folders, width=40)
        self._junk_combo.grid(row=row, column=1, columnspan=3,
                               sticky=tk.W + tk.E, **pad)

        row += 1
        ttk.Label(frm, text="Spam handling:").grid(row=row, column=0, sticky=tk.W, **pad)
        _SPAM_ACTION_LABELS = [
            "Move to Junk folder (default)",
            "Move to Trash (30-day buffer)",
            "Delete permanently (no recovery)",
        ]
        _SPAM_ACTION_VALUES = ["junk", "trash", "delete"]
        # Map stored value → display label for initial selection
        _initial_idx = _SPAM_ACTION_VALUES.index(
            self._spam_action.get()
        ) if self._spam_action.get() in _SPAM_ACTION_VALUES else 0
        self._spam_action_combo = ttk.Combobox(
            frm,
            values=_SPAM_ACTION_LABELS,
            state="readonly",
            width=40,
        )
        self._spam_action_combo.current(_initial_idx)
        self._spam_action_combo.grid(row=row, column=1, columnspan=3,
                                      sticky=tk.W + tk.E, **pad)
        self._spam_action_combo.bind(
            "<<ComboboxSelected>>", self._on_spam_action_changed
        )

        row += 1
        ttk.Separator(frm).grid(row=row, column=0, columnspan=4, sticky=tk.E + tk.W, pady=8)

        # --- SMTP: hidden by default, revealed by "Advanced" checkbox ---
        row += 1
        self._use_custom_smtp = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frm,
            text="Advanced: use a different SMTP server than IMAP",
            variable=self._use_custom_smtp,
            command=self._toggle_smtp_section,
        ).grid(row=row, column=0, columnspan=4, sticky=tk.W, **pad)

        # Container holding all SMTP fields; show/hide based on checkbox.
        row += 1
        self._smtp_frame = ttk.Frame(frm)
        self._smtp_frame.grid(row=row, column=0, columnspan=4,
                              sticky=tk.W + tk.E, pady=(4, 0))

        sp = {"padx": 8, "pady": 4}
        ttk.Label(self._smtp_frame, text="SMTP host:").grid(row=0, column=0,
                                                             sticky=tk.W, **sp)
        ttk.Entry(self._smtp_frame, textvariable=self._smtp_host).grid(
            row=0, column=1, sticky=tk.W + tk.E, **sp)
        ttk.Label(self._smtp_frame, text="Port:").grid(row=0, column=2,
                                                       sticky=tk.E, **sp)
        ttk.Entry(self._smtp_frame, textvariable=self._smtp_port, width=8).grid(
            row=0, column=3, sticky=tk.W, **sp)

        ttk.Label(self._smtp_frame, text="SMTP user:").grid(row=1, column=0,
                                                             sticky=tk.W, **sp)
        ttk.Entry(self._smtp_frame, textvariable=self._smtp_user).grid(
            row=1, column=1, columnspan=3, sticky=tk.W + tk.E, **sp)

        ttk.Label(self._smtp_frame, text="SMTP password:").grid(row=2, column=0,
                                                                 sticky=tk.W, **sp)
        self._smtp_pass_entry = ttk.Entry(self._smtp_frame,
                                           textvariable=self._smtp_pass, show="•")
        self._smtp_pass_entry.grid(row=2, column=1, columnspan=3,
                                    sticky=tk.W + tk.E, **sp)

        self._smtp_frame.columnconfigure(1, weight=1)
        self._smtp_frame.grid_remove()  # hidden by default

        row += 1
        self._test_smtp_row = ttk.Frame(frm)
        self._test_smtp_row.grid(row=row, column=0, columnspan=4, sticky=tk.W, **pad)
        ttk.Button(self._test_smtp_row, text="Test SMTP & send a test email",
                   command=self._on_send_test_email).pack(side=tk.LEFT)

        row += 1
        ttk.Label(frm, textvariable=self._status, wraplength=560,
                  style="Status.TLabel").grid(row=row, column=0, columnspan=4,
                                               sticky=tk.W, **pad)

        row += 1
        ttk.Separator(frm).grid(row=row, column=0, columnspan=4, sticky=tk.E + tk.W, pady=6)

        row += 1
        button_row = ttk.Frame(frm)
        button_row.grid(row=row, column=0, columnspan=4, sticky=tk.E + tk.W)
        ttk.Button(button_row, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(button_row, text="Save Account", style="Primary.TButton",
                   command=self._on_save).pack(side=tk.RIGHT)

        frm.columnconfigure(1, weight=1)

    _SPAM_ACTION_VALUES = ["junk", "trash", "delete"]

    def _on_spam_action_changed(self, _evt=None):
        """Store the selected spam action value; confirm if switching to delete."""
        idx = self._spam_action_combo.current()
        selected = self._SPAM_ACTION_VALUES[idx] if idx >= 0 else "junk"
        if selected == "delete":
            confirmed = messagebox.askyesno(
                "Confirm permanent deletion",
                "If MailWarden flags an important email as spam (a 'false positive'), "
                "and this account is set to 'Delete permanently', that email will be "
                "gone for good — there is no Junk folder to recover it from. "
                "Forward-back-as-False-Positive recovery only works if the email still "
                "exists somewhere. Are you sure you want this account to delete spam "
                "instead of move it?",
                icon="warning",
                default="no",
                parent=self,
            )
            if not confirmed:
                # Revert to junk
                self._spam_action_combo.current(0)
                self._spam_action.set("junk")
                return
        self._spam_action.set(selected)

    def _toggle_smtp_section(self):
        if self._use_custom_smtp.get():
            self._smtp_frame.grid()
        else:
            self._smtp_frame.grid_remove()

    def _on_preset(self, _evt=None):
        idx = self._preset.current()
        if idx < 0:
            return
        preset = validators.PROVIDER_PRESETS[idx]
        if preset.get("imap_host") and not self._imap_host.get():
            self._imap_host.set(preset["imap_host"])
        self._imap_port.set(str(preset.get("imap_port", 993)))
        if "smtp_host" in preset and preset["smtp_host"]:
            self._smtp_host.set(preset["smtp_host"])
        self._smtp_port.set(str(preset.get("smtp_port", 587)))
        if preset.get("note"):
            self._status.set(preset["note"])

    def _on_test_imap(self):
        host = self._imap_host.get().strip()
        port_raw = self._imap_port.get().strip() or "993"
        try:
            port = int(port_raw)
        except ValueError:
            self._status.set(
                f"✗ Port must be a number (got {port_raw!r}). "
                f"Common values: 993 for IMAPS, 143 for IMAP.")
            return
        if port < 1 or port > 65535:
            self._status.set(
                f"✗ Port {port} is out of range. Use 1–65535 "
                f"(typically 993 for IMAPS).")
            return
        user = self._imap_user.get().strip()
        pw = self._imap_pass.get()

        self._status.set("Testing IMAP — this may take up to 15 seconds…")
        self.update_idletasks()

        def worker():
            result = validators.test_imap(host, port, user, pw)

            def done():
                if result["ok"]:
                    self._imap_connection_ok = True
                    self._folders = result["folders"]
                    self._separator = result["separator"]
                    self._junk_combo.config(values=self._folders)
                    # Auto-pick the junk folder (backlog #3). Always overwrite
                    # so the user never sees an empty dropdown.
                    guess = _guess_junk_folder(self._folders)
                    if guess:
                        self._junk_folder.set(guess)
                        msg = (f"✓ IMAP OK. Auto-selected junk folder: {guess}. "
                               f"(Change above if wrong — {len(self._folders)} folders available.)")
                    else:
                        msg = (f"✓ IMAP OK, but no folder looks like junk. "
                               f"Pick one from the dropdown above — "
                               f"{len(self._folders)} folders available.")
                    self._status.set(msg)
                else:
                    self._imap_connection_ok = False
                    err = result["error"]
                    self._status.set("✗ " + err)
                    # Messagebox so the failure is impossible to miss
                    # (status label alone was too subtle in earlier test).
                    messagebox.showerror("IMAP connection failed", err,
                                          parent=self)

            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def _on_test_smtp(self):
        self._status.set("Testing SMTP…")
        self.update_idletasks()

        def worker():
            ok, msg = validators.test_smtp(
                self._smtp_host.get().strip() or self._imap_host.get().strip(),
                int(self._smtp_port.get() or "587"),
                self._smtp_user.get().strip() or self._imap_user.get().strip(),
                self._smtp_pass.get() or self._imap_pass.get(),
            )

            def done():
                self._status.set(msg)

            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def _on_send_test_email(self):
        self._status.set("Sending test email…")
        self.update_idletasks()

        def worker():
            user = self._imap_user.get().strip()
            ok, msg = validators.send_test_email(
                self._smtp_host.get().strip() or self._imap_host.get().strip(),
                int(self._smtp_port.get() or "587"),
                self._smtp_user.get().strip() or user,
                self._smtp_pass.get() or self._imap_pass.get(),
                from_addr=user,
                to_addr=user,
            )

            def done():
                self._status.set(msg)

            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def _on_save(self):
        if not self._name.get().strip():
            messagebox.showwarning("Missing label", "Give this account a label.")
            return
        if not self._imap_host.get().strip() or not self._imap_user.get().strip():
            messagebox.showwarning("Missing IMAP fields",
                                    "IMAP host and email address are required.")
            return
        if not self._junk_folder.get().strip():
            messagebox.showwarning("Junk folder required",
                                    "Run Test IMAP Connection and pick your junk folder.")
            return

        account = config_io.new_account_entry(
            name=self._name.get().strip(),
            imap_host=self._imap_host.get().strip(),
            imap_port=int(self._imap_port.get() or "993"),
            imap_username=self._imap_user.get().strip(),
            imap_password=self._imap_pass.get(),
            junk_folder=self._junk_folder.get().strip(),
            folders_to_scan=["INBOX"],
            spam_action=self._spam_action.get() or "junk",
        )
        # SMTP is a GLOBAL config field in the filter's schema, not per-account.
        # Seed it under a sentinel key so SetupAssistant can pull it out on save.
        account["_smtp_seed"] = {
            "host": self._smtp_host.get().strip() or self._imap_host.get().strip(),
            "port": int(self._smtp_port.get() or "587"),
            "username": self._smtp_user.get().strip() or self._imap_user.get().strip(),
            "password": self._smtp_pass.get() or self._imap_pass.get(),
            "from_address": self._imap_user.get().strip(),
            "use_starttls": True,
        }
        self.saved_account = account

        # Attempt to create the Train MailWarden IMAP folder now, while we
        # have the credentials. Opens a short-lived connection on a background
        # thread (same pattern as _on_test_imap) so the Tk main thread is not
        # blocked. On completion the status label is updated; the dialog closes
        # regardless of whether the create succeeded.
        host = self._imap_host.get().strip()
        port = int(self._imap_port.get() or "993")
        user = self._imap_user.get().strip()
        pw = self._imap_pass.get()
        self._status.set("Saving — creating Train MailWarden folder…")
        self.update_idletasks()

        def _create_folder_then_close():
            import imaplib
            ok = False
            msg = ""
            try:
                conn = imaplib.IMAP4_SSL(host, port, timeout=10)
                try:
                    conn.login(user, pw)
                    ok, msg = _ensure_train_folder(conn)
                finally:
                    try:
                        conn.logout()
                    except Exception:
                        pass
            except Exception as e:
                ok, msg = False, str(e)

            def _finish():
                if ok:
                    self._status.set(
                        f"✓ Account saved. Train MailWarden folder ready ({msg}).")
                else:
                    self._status.set(
                        "Account saved. Couldn't create Train folder automatically"
                        " — you can create it via Dashboard later.")
                # Small delay so the user can read the status before the dialog
                # closes (mirrors the brief pause after a successful IMAP test).
                self.after(900, self.destroy)

            self.after(0, _finish)

        threading.Thread(target=_create_folder_then_close, daemon=True).start()


_TRAIN_FOLDER_NAME = "Train MailWarden"


def _ensure_train_folder(conn) -> tuple[bool, str]:
    """Thin wrapper around the ensure_train_folder logic for use in the
    Setup Assistant context, where spam_filter.py is not on sys.path.

    Mirrors ensure_train_folder() in spam_filter.py exactly — keep in sync.
    """
    target = _TRAIN_FOLDER_NAME.lower()
    try:
        rc_list, items = conn.list('""', '"*"')
    except Exception:
        rc_list, items = "NO", []

    if rc_list == "OK" and items:
        for raw in items:
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace") if isinstance(
                raw, (bytes, bytearray)) else str(raw)
            if '"' in line:
                parts = line.rsplit('"', 2)
                if len(parts) >= 2:
                    name = parts[-2]
                    if target in name.lower():
                        return (True, f"{name} already exists")
            else:
                tail = line.rsplit(None, 1)[-1] if line.split() else ""
                if target in tail.lower():
                    return (True, f"{tail} already exists")

    def _decode(data) -> str:
        return b" ".join(
            x for x in (data or []) if x
        ).decode("utf-8", errors="replace")

    first_err = ""
    try:
        rc, data = conn.create(f'"{_TRAIN_FOLDER_NAME}"')
        if rc == "OK":
            return (True, _TRAIN_FOLDER_NAME)
        detail = _decode(data).lower()
        if "alreadyexists" in detail or "already exists" in detail:
            return (True, _TRAIN_FOLDER_NAME)
        first_err = detail
    except Exception as e:
        first_err = str(e)

    inbox_name = f"INBOX.{_TRAIN_FOLDER_NAME}"
    try:
        rc2, data2 = conn.create(f'"{inbox_name}"')
        if rc2 == "OK":
            return (True, inbox_name)
        detail2 = _decode(data2).lower()
        if "alreadyexists" in detail2 or "already exists" in detail2:
            return (True, inbox_name)
    except Exception as e:
        detail2 = str(e)

    return (False, f"top-level: {first_err!r}; INBOX. fallback: {detail2!r}")


def _guess_junk_folder(folders: list[str]) -> str | None:
    lower = {f.lower(): f for f in folders}
    for candidate in [
        "inbox.spam", "[gmail]/spam", "spam", "junk", "junk e-mail",
        "inbox.junk", "inbox.spam (beta)",
    ]:
        if candidate in lower:
            return lower[candidate]
    for f in folders:
        if "spam" in f.lower() or "junk" in f.lower():
            return f
    return None


def run() -> int:
    from . import startup_log
    startup_log.step("SetupAssistant.run() entered")
    try:
        app = SetupAssistant()
        startup_log.step("SetupAssistant constructed; bringing to front")
        theme.bring_to_front(app)
        startup_log.step("SetupAssistant entering mainloop")
        app.mainloop()
        startup_log.step(f"SetupAssistant mainloop exited; install_succeeded={app.install_succeeded}")
    except BaseException as e:
        startup_log.fatal(e)
        raise
    if app.install_succeeded:
        from . import dashboard
        return dashboard.run()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run())
