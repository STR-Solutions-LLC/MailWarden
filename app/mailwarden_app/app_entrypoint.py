# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Main entry point for MailWarden.app.

Dispatch rules:
  - If argv contains --menu-bar, run the menu bar rumps agent.
  - Else if ~/MailWarden/config/config.json is missing or invalid, run Setup Assistant.
  - Else, open the Dashboard.

This module also discovers the bundled defaults directory inside the .app,
so other modules can copy skip_names.txt, signals.json, EULAs, etc. without
hardcoding macOS bundle paths.
"""
import os
import sys
from pathlib import Path

from . import paths


def get_bundled_defaults_dir() -> Path:
    """
    Return the path to the defaults/ directory bundled inside MailWarden.app.

    When running from the built .app, __file__ is inside
    .../MailWarden.app/Contents/Resources/mailwarden_app/app_entrypoint.py
    and defaults sit at .../MailWarden.app/Contents/Resources/defaults/.

    When running from source during development, we walk up from this file's
    location looking for a `defaults/` sibling.
    """
    here = Path(__file__).resolve()
    for ancestor in [here.parent] + list(here.parents):
        candidate = ancestor / "defaults"
        if candidate.is_dir():
            return candidate
    # Fallback: installer source tree
    return Path.home() / "MailWarden-installer" / "resources" / "defaults"


def _cli_status() -> int:
    """Print the filter's current configuration state. Works even when the
    GUI Dashboard is unavailable, so the user is never trapped."""
    from . import config_io
    import json
    cfg = config_io.load_config()
    accounts = cfg.get("accounts", [])
    filt = cfg.get("filter", {})
    print(f"MailWarden status")
    print(f"  dry_run:            {filt.get('dry_run', True)}")
    print(f"  max_emails_per_run: {filt.get('max_emails_per_run', 100)}")
    print(f"  model:              {cfg.get('anthropic', {}).get('model', '(unset)')}")
    print(f"  threshold:          {cfg.get('anthropic', {}).get('confidence_threshold', 0.85)}")
    print(f"  accounts ({len(accounts)}):")
    for a in accounts:
        print(f"    - name={a.get('name','?')} user={a.get('username','?')} "
              f"junk={a.get('junk_folder','?')} enabled={a.get('enabled', False)}")
    print(f"  config at: {paths.CONFIG_PATH}")
    return 0


def _cli_set_dry_run(value: str) -> int:
    """Toggle dry_run from the command line. Value is 'true'/'false'/'on'/'off'."""
    from . import config_io
    truthy = value.strip().lower() in ("true", "1", "on", "yes", "y")
    cfg = config_io.load_config()
    cfg.setdefault("filter", {})["dry_run"] = truthy
    config_io.save_config(cfg)
    print(f"dry_run is now {truthy}")
    return 0


def _run_test_validate() -> int:
    """Live HTTPS test: hit api.anthropic.com with an obviously-invalid key
    and verify the call returns in under 15 seconds with an auth-rejection
    message. Fails if the call hangs — catches the SSL-sabotage bug and
    any future network-path regression."""
    import time
    from . import validators
    t0 = time.monotonic()
    ok, msg = validators.validate_api_key(
        "sk-ant-BUILD-GATE-INTENTIONALLY-INVALID-KEY-" + "x" * 60)
    elapsed = time.monotonic() - t0
    print(f"validate_api_key() returned after {elapsed:.2f}s")
    print(f"  ok:  {ok}")
    print(f"  msg: {msg}")
    if elapsed > 20:
        print("FAIL: validate took too long; HTTPS is hanging")
        return 1
    if ok:
        print("FAIL: a bogus key was accepted — this should be impossible")
        return 1
    expected = ("rejected", "authentication", "401", "403", "invalid")
    low = msg.lower()
    if not any(w in low for w in expected):
        print(f"FAIL: unexpected message; expected auth-rejection, got: {msg}")
        return 1
    print("OK: HTTPS path reached Anthropic and was correctly rejected")
    return 0


def _run_diagnose() -> int:
    """Print runtime diagnostics and attempt every critical import. Exit 0
    only if every import succeeds — used by build_installer.sh as a gate."""
    import sys
    print("=== MailWarden runtime diagnose ===")
    print(f"executable: {sys.executable}")
    print(f"prefix:     {sys.prefix}")
    print(f"version:    {sys.version.splitlines()[0]}")
    print("sys.path:")
    for p in sys.path:
        print(f"  {p}")
    print()
    mods = [
        # third-party
        "anthropic", "rumps", "openpyxl", "tkinter",
        "AppKit", "Foundation", "PyObjCTools.AppHelper",
        # SMAppService is the v1.6.0 service-registration path. If this
        # import fails, NO background services register and the install
        # is silently dead. The bare module import below is necessary but
        # not sufficient — see the SMAppService symbol check after the loop.
        "ServiceManagement",
        "pydantic", "httpx", "httpcore", "h11", "anyio",
        "certifi", "distro", "idna", "jiter", "sniffio",
        "typing_extensions", "docstring_parser",
        "et_xmlfile", "annotated_types",
        # stdlib the filter scripts import — py2app modulegraph
        # can drop these if the main app code does not use them.
        "email", "email.mime", "email.mime.text", "email.mime.multipart",
        "email.header", "email.policy", "email.parser", "email.utils",
        "imaplib", "smtplib", "argparse", "hashlib", "ssl",
        "logging.handlers",
    ]
    failed: list[tuple[str, str]] = []
    for m in mods:
        try:
            __import__(m)
            print(f"  OK   {m}")
        except Exception as e:
            print(f"  FAIL {m}: {type(e).__name__}: {e}")
            failed.append((m, str(e)))

    # Filter-script imports: bundled payload copy of spam_filter / daily_report /
    # learn_signals / utils. Loads them as modules (not __main__), so we run
    # every top-level import without actually executing filter logic. Catches
    # missing stdlib submodules like email.mime that py2app would drop.
    bundled_src = None
    here = Path(__file__).resolve()
    for ancestor in list(here.parents):
        candidate = ancestor / "payload" / "MailWarden" / "src"
        if candidate.is_dir():
            bundled_src = candidate
            break
    if bundled_src:
        import importlib
        sys.path.insert(0, str(bundled_src))
        # utils first since the others import from it
        for name in ("utils", "spam_filter", "daily_report", "learn_signals"):
            try:
                importlib.import_module(name)
                print(f"  OK   {name}  (filter script top-level imports)")
            except Exception as e:
                print(f"  FAIL {name}: {type(e).__name__}: {e}")
                failed.append((name, str(e)))
    else:
        print("  (no bundled filter src found — skipping filter-import gate)")

    # Verify the exact symbol smappservice_install.py:68 imports. A bare
    # `import ServiceManagement` succeeds against a stub namespace package
    # in some pyobjc edge cases — only the from-import proves the framework
    # wrapper is actually bundled and the class is accessible.
    try:
        from ServiceManagement import SMAppService  # noqa: F401
        print("  OK   ServiceManagement.SMAppService  (SMAppService registration path)")
    except Exception as e:
        print(f"  FAIL ServiceManagement.SMAppService: {type(e).__name__}: {e}")
        failed.append(("ServiceManagement.SMAppService", str(e)))

    print()
    if failed:
        print(f"=== {len(failed)} import failures ===")
        return 1
    print("=== all imports OK ===")
    return 0


_FILTER_LOCK_MAX_AGE_SEC = 600  # 10 minutes


def _acquire_filter_lock() -> bool:
    """Return True if we obtained the filter lock, False if another process
    is already inside the 10-minute window. Prevents launchd's 15-minute
    tick and a Dashboard Run Now click from running the filter twice in
    parallel (which otherwise doubles every log line and races on
    decisions.log writes)."""
    import time as _time
    lock = paths.FILTER_LOCK
    try:
        lock.parent.mkdir(parents=True, exist_ok=True)
        if lock.exists():
            age = _time.time() - lock.stat().st_mtime
            if age < _FILTER_LOCK_MAX_AGE_SEC:
                return False
            # Stale lock — claim it.
            try:
                lock.unlink()
            except OSError:
                pass
        lock.write_text(str(os.getpid()))
    except OSError:
        # If we can't write the lock file, proceed anyway rather than
        # block the filter on a filesystem glitch.
        return True
    return True


def _release_filter_lock() -> None:
    try:
        paths.FILTER_LOCK.unlink()
    except (FileNotFoundError, OSError):
        pass


def _run_user_script(script_name: str) -> int:
    """Execute one of the filter scripts at ~/MailWarden/src/<script_name>.py
    inside this bundled Python process, so anthropic and other deps import
    from the .app's bundled Resources/lib/python3.12/. Must be called before
    the GUI dispatch because these scripts are headless.

    The scripts use `from utils import ...`, expecting the sibling utils.py
    to be importable. runpy.run_path does NOT add the script's directory to
    sys.path, so we do it explicitly. Also switch CWD to MailWarden root so
    the filter's relative-path operations match the launchd WorkingDirectory.
    """
    import os
    import runpy
    script = paths.SRC_DIR / script_name
    if not script.exists():
        sys.stderr.write(f"MailWarden: script missing at {script}\n")
        return 2
    script_dir = str(paths.SRC_DIR)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    try:
        os.chdir(str(paths.MAILWARDEN_ROOT))
    except OSError:
        pass

    # Force UTF-8 text I/O. py2app's embedded Python ignores PYTHONUTF8
    # in the real environment (locale.getpreferredencoding stays 'US-ASCII'
    # even when the env var is set), so we patch builtins.open to default
    # every text-mode read/write to UTF-8. This is the only reliable way
    # to stop UnicodeDecodeError in the bundled filter scripts, which have
    # ~60 bare open() calls that the Matt/main repo cannot easily update
    # in one pass.
    import builtins
    _real_open = builtins.open
    def _utf8_open(*args, **kwargs):  # noqa: E306
        mode = ""
        if len(args) >= 2 and isinstance(args[1], str):
            mode = args[1]
        else:
            mode = kwargs.get("mode", "r")
        # Only touch text-mode opens; binary opens must stay as-is.
        if "b" not in mode and "encoding" not in kwargs:
            kwargs["encoding"] = "utf-8"
            if "errors" not in kwargs:
                kwargs["errors"] = "replace"
        return _real_open(*args, **kwargs)
    builtins.open = _utf8_open

    # Clean argv before handing off: the filter scripts have their own
    # argparse and do not know about our --run-filter / --run-report /
    # --run-learner dispatch flags. Leaving them in argv trips their
    # argparse with "unrecognized arguments" and aborts.
    our_flags = {"--run-filter", "--run-report", "--run-learner",
                 "--diagnose", "--test-validate", "--status", "--dashboard"}
    sys.argv = [str(script)] + [a for a in sys.argv[1:]
                                 if a not in our_flags and not a.startswith("--set-dry-run=")]

    # Filter + report share the same IMAP account list and decisions.log, so
    # gate them behind a single lock. Scheduled runs and manual Run Now
    # clicks that fire within 10 minutes of each other would otherwise
    # both execute, doubling log lines and racing on processed_ids.
    if script_name in ("spam_filter.py", "daily_report.py"):
        if not _acquire_filter_lock():
            sys.stderr.write(
                "MailWarden: another filter/report run is already in "
                "progress; skipping this invocation.\n")
            return 0
        try:
            runpy.run_path(str(script), run_name="__main__")
        finally:
            _release_filter_lock()
    else:
        runpy.run_path(str(script), run_name="__main__")
    return 0


def _run_classify_eml() -> int:
    """Offline classification harness: classify a raw .eml from disk through the
    REAL pre-classifier + AI path, with NO IMAP, NO processed-ids, NO folder
    moves, and NO writes to the live decisions log or token usage. The primary
    local regression tool (build machine) and on-device confidence check (M1).

    Usage:
      MailWarden --classify-eml "<path.eml>" [--account NAME] [--signals PATH]
                 [--model NAME] [--threshold 0.85] [--dnsbl]

    API key resolution (read-only): $ANTHROPIC_API_KEY, else the anthropic.api_key
    in ~/MailWarden/config/config.json (the same key the app uses). Never printed.
    """
    import json as _json
    import logging as _logging

    argv = sys.argv

    def _opt(name, default=None):
        if name in argv:
            i = argv.index(name)
            if i + 1 < len(argv):
                return argv[i + 1]
        return default

    idx = argv.index("--classify-eml")
    eml_path = None
    for a in argv[idx + 1:]:
        if not a.startswith("--"):
            eml_path = a
            break
    if not eml_path:
        sys.stderr.write(
            'Usage: MailWarden --classify-eml "<path to .eml>" '
            '[--account NAME] [--signals PATH] [--model NAME] '
            '[--threshold N] [--dnsbl]\n')
        return 2

    account = _opt("--account")
    signals_override = _opt("--signals")
    model_override = _opt("--model")
    threshold_override = _opt("--threshold")
    run_dnsbl = "--dnsbl" in argv

    p = Path(eml_path).expanduser()
    if not p.is_file():
        sys.stderr.write(f"MailWarden: no such .eml file: {p}\n")
        return 2

    # Locate the filter src and import it. Prefer the installed runtime copy
    # (~/MailWarden/src); fall back to the build tree's payload/MailWarden/src.
    bundled_src = None
    if (paths.SRC_DIR / "spam_filter.py").exists():
        bundled_src = paths.SRC_DIR
    else:
        here = Path(__file__).resolve()
        for ancestor in list(here.parents):
            cand = ancestor / "payload" / "MailWarden" / "src"
            if cand.is_dir():
                bundled_src = cand
                break
    if bundled_src is None:
        sys.stderr.write("MailWarden: could not locate filter src (spam_filter.py)\n")
        return 2
    if str(bundled_src) not in sys.path:
        sys.path.insert(0, str(bundled_src))

    import spam_filter  # noqa: E402

    # Resolve signals (read-only): --signals override, else runtime user signals,
    # else shipped defaults. Offline classify NEVER writes signals.
    signals = {"signals": {}}
    signals_src = "(empty)"
    candidates = []
    if signals_override:
        candidates.append(Path(signals_override).expanduser())
    candidates.append(paths.SIGNALS_PATH)
    candidates.append(get_bundled_defaults_dir() / "signals.json")
    for c in candidates:
        try:
            if c and c.is_file():
                with c.open(encoding="utf-8") as f:
                    signals = _json.load(f)
                signals_src = str(c)
                break
        except Exception as e:
            sys.stderr.write(f"MailWarden: could not read signals {c}: {e}\n")

    # Resolve api key + model + threshold (read-only) from env or runtime config.
    cfg = {}
    try:
        if paths.CONFIG_PATH.is_file():
            with paths.CONFIG_PATH.open(encoding="utf-8") as f:
                cfg = _json.load(f)
    except Exception:
        cfg = {}
    anthro = cfg.get("anthropic", {}) if isinstance(cfg, dict) else {}
    api_key = os.environ.get("ANTHROPIC_API_KEY", "") or anthro.get("api_key", "") or ""
    model = model_override or anthro.get("model") or "claude-haiku-4-5-20251001"
    threshold = 0.85
    if threshold_override is not None:
        try:
            threshold = float(threshold_override)
        except ValueError:
            pass
    elif isinstance(cfg, dict):
        threshold = cfg.get("filter", {}).get("confidence_threshold", 0.85)

    raw = p.read_bytes()

    # Stderr logger only — never touch the live filter log.
    log = _logging.getLogger("classify_eml")
    log.setLevel(_logging.INFO)
    if not log.handlers:
        h = _logging.StreamHandler(sys.stderr)
        h.setFormatter(_logging.Formatter("    [%(levelname)s] %(message)s"))
        log.addHandler(h)

    res = spam_filter.classify_eml_offline(
        raw, signals,
        api_key=api_key, model=model, max_tokens=500,
        threshold=threshold, account_name=account,
        run_dnsbl=run_dnsbl, logger=log,
    )

    pre = res.get("pre_classifier", {})
    ai = res.get("ai")
    usage = res.get("usage")
    print("=" * 64)
    print("MailWarden --classify-eml")
    print(f"  file:     {p}")
    print(f"  from:     {res.get('from_email', '')}")
    print(f"  subject:  {res.get('subject', '')}")
    print(f"  signals:  {signals_src}")
    if account:
        print(f"  account:  {account}")
    print("-" * 64)
    print("PRE-CLASSIFIER (header checks — free, no AI):")
    print(f"  hard signals: {pre.get('hard_signals') or '(none)'}")
    print(f"  soft signals: {pre.get('soft_signals') or '(none)'}")
    if pre.get("verdict") == "SPAM":
        print(f"  -> BLOCKED HERE at {pre.get('confidence'):.2f} — no Claude call made ($0)")
    else:
        print("  -> not blocked here; routed to Claude")
    print("-" * 64)
    if ai is None:
        print("AI: (not called — pre-classifier already decided)")
    elif ai.get("error"):
        print(f"AI: ERROR — {ai['error']}")
    else:
        print("AI CLASSIFIER (Claude):")
        print(f"  decision:   {ai.get('decision')}")
        print(f"  confidence: {ai.get('confidence')}")
        print(f"  signals:    {ai.get('signals_hit')}")
        print(f"  reasoning:  {ai.get('reasoning')}")
    if usage:
        print(f"  tokens:     in={usage['input_tokens']} out={usage['output_tokens']} "
              f"model={usage['model']}")
    print("-" * 64)
    final = res.get("final_decision")
    label = {"JUNK": "WOULD JUNK", "PASS": "WOULD PASS",
             "UNKNOWN": "UNDECIDED"}.get(final, str(final))
    print(f"FINAL: {label}   (decided by {res.get('decided_by')})")
    print("=" * 64)
    return 0


def main() -> int:
    """Dispatch to a filter run, menu bar, Setup Assistant, or Dashboard."""
    # Build-time gates. Neither should touch the user's ~/MailWarden/.
    if "--diagnose" in sys.argv:
        return _run_diagnose()
    if "--test-validate" in sys.argv:
        return _run_test_validate()
    if "--classify-eml" in sys.argv:
        return _run_classify_eml()

    from . import startup_log
    startup_log.session_start()

    try:
        return _main_inner(startup_log)
    except BaseException as e:
        startup_log.fatal(e)
        raise


def _main_inner(startup_log) -> int:
    # Developer-only CLI escape hatches (never surfaced to users).
    if "--status" in sys.argv:
        return _cli_status()
    for arg in sys.argv:
        if arg.startswith("--set-dry-run="):
            return _cli_set_dry_run(arg.split("=", 1)[1])

    # Self-install / upgrade ~/MailWarden/ from bundled Resources. Only the
    # Dashboard process runs bootstrap — headless launchd-spawned agents
    # (filter, report, menubar) must NEVER call bootstrap. Two reasons:
    #   1. Bootstrap's launchd reinstall path races with itself when all
    #      three agents enter it concurrently during a version-bump
    #      upgrade — that's the 2026-04-20 self-bootout cascade.
    #   2. A launchd agent that bootouts its own label mid-call gets
    #      SIGTERMed by launchd and dies.
    # The Dashboard is launched by the user (not launchd) and runs
    # bootstrap at install time via the postinstall `open` command, so
    # ~/MailWarden/ is always fresh by the time the agents fire.
    _agent_flags = {"--run-filter", "--run-report", "--run-learner", "--menu-bar"}
    _headless_flag = next((a for a in sys.argv if a in _agent_flags), None)
    if _headless_flag is not None:
        startup_log.step(f"bootstrap skipped (headless agent: {_headless_flag})")
    else:
        startup_log.step("bootstrap start")
        try:
            from . import bootstrap
            result = bootstrap.bootstrap_runtime()
            startup_log.step(f"bootstrap done action={result.get('action')}")
        except Exception as e:
            startup_log.step(f"bootstrap FAILED (non-fatal): {type(e).__name__}: {e}")
            # Never block UI launch on a bootstrap hiccup.

        # v1.6.0: after bootstrap, ensure SMAppService agents are registered.
        # This is Dashboard-only (headless agents are already gated above).
        #
        # Auto-restart durability: when a user upgrades from an older beta,
        # macOS keeps the OLD registration (which pointed at a now-corrected
        # plist) because register_all_if_needed() SKIPS any agent already
        # showing status == 1. The fix below detects a version change and
        # forces a clean unregister_all() + register_all() so the corrected
        # plists take effect without the user manually clicking "Restart all
        # background services" in the Dashboard.
        #
        #   - stamp == current bundle version  → cheap register_all_if_needed()
        #     (no-op if all three are already enabled; only registers agents
        #     that are notRegistered/notFound; requiresApproval (2) left alone).
        #   - stamp missing or != current      → force unregister_all() +
        #     register_all() ONCE, then write the stamp. This covers first run
        #     after this feature ships and every subsequent upgrade.
        #
        # The stamp file (~/MailWarden/memory/registered_version.json) makes
        # this once-per-version: only the first launch after a version change
        # pays the unregister/register cost; same-version relaunches don't.
        try:
            from . import bootstrap, config_io, smappservice_install
            current_version = bootstrap.BUNDLED_FILTER_VERSION
            stamp = config_io.load_json(paths.REGISTERED_VERSION_PATH, {})
            last_version = stamp.get("version") if isinstance(stamp, dict) else None

            if last_version == current_version:
                reg = smappservice_install.register_all_if_needed()
                startup_log.step(
                    f"smappservice register_all_if_needed (version unchanged "
                    f"{current_version}): registered={reg.get('registered')} "
                    f"failed={reg.get('failed')} skipped={reg.get('skipped')}"
                )
            else:
                startup_log.step(
                    f"smappservice version change "
                    f"({last_version} -> {current_version}): forcing clean "
                    f"unregister_all() + register_all()"
                )
                smappservice_install.unregister_all()
                reg = smappservice_install.register_all()
                startup_log.step(
                    f"smappservice register_all after refresh: "
                    f"registered={reg.get('registered')} "
                    f"failed={reg.get('failed')} skipped={reg.get('skipped')}"
                )
                config_io.save_json_atomic(
                    paths.REGISTERED_VERSION_PATH,
                    {"version": current_version, "stamped_at": config_io.now_iso()},
                )
                startup_log.step(
                    f"smappservice registered_version stamped to {current_version}"
                )
        except Exception as e:
            startup_log.step(
                f"smappservice registration refresh FAILED (non-fatal): "
                f"{type(e).__name__}: {e}"
            )

    # Headless filter entry points — invoked by launchd agents.
    if "--run-filter" in sys.argv:
        startup_log.step("dispatch: --run-filter")
        return _run_user_script("spam_filter.py")
    if "--run-report" in sys.argv:
        startup_log.step("dispatch: --run-report")
        return _run_user_script("daily_report.py")
    if "--run-learner" in sys.argv:
        startup_log.step("dispatch: --run-learner")
        return _run_user_script("learn_signals.py")

    if "--menu-bar" in sys.argv:
        startup_log.step("dispatch: --menu-bar")
        # The Dock-hiding (setActivationPolicy_) now happens INSIDE menu_bar
        # via a rumps @before_start handler, which is the first moment
        # NSApp() actually exists. Calling it here (before rumps creates
        # NSApplication.sharedApplication()) was a silent no-op — that was
        # the menu-bar-Dock-icon bug.
        from . import menu_bar
        return menu_bar.main()

    # Dashboard launch (explicit --dashboard, or the implicit no-flag default).
    # Single-instance guard: if a live Dashboard already owns the pidfile,
    # raise it (un-minimize + activate) and exit instead of opening a second
    # Dock-bearing process. This is what stops the Dock-icon pileup AND makes
    # double-clicking the app in Applications restore a minimized Dashboard.
    if paths.mailwarden_installed():
        from . import dashboard_instance
        existing = dashboard_instance.live_dashboard_pid()
        if existing is not None and existing != os.getpid():
            # Prefer the cross-process RAISE socket (un-minimizes too); fall
            # back to AppKit activate (raises visible windows only).
            if dashboard_instance.raise_existing(existing):
                startup_log.step(
                    f"dispatch: Dashboard already running (pid={existing}); "
                    f"RAISE delivered and exiting")
                return 0
            if dashboard_instance.activate_pid(existing):
                startup_log.step(
                    f"dispatch: Dashboard already running (pid={existing}); "
                    f"activated existing window and exiting")
                return 0
            # Pidfile named a live pid we could not raise/activate (stale +
            # recycled, or AppKit unavailable). Treat as not running and open
            # a fresh one.
            startup_log.step(
                f"dispatch: stale/unactivatable Dashboard pid={existing}; "
                f"opening a new Dashboard")
        startup_log.step("dispatch: Dashboard (config present)")
        dashboard_instance.write_pidfile()
        try:
            from . import dashboard
            return dashboard.run()
        finally:
            dashboard_instance.remove_pidfile()
            # Mirror remove_pidfile(): tear down the RAISE channel's port file
            # so no stale dashboard.port outlives this process.
            try:
                from . import dashboard_ipc  # noqa: F401
                paths.DASHBOARD_PORT.unlink()
            except (FileNotFoundError, OSError, ImportError):
                pass

    startup_log.step("dispatch: Setup Assistant (no config)")
    from . import setup_assistant
    return setup_assistant.run()


if __name__ == "__main__":
    sys.exit(main())
