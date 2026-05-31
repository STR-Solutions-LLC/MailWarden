# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
py2app build config for MailWarden.app.

Usage:
    cd ~/MailWarden-installer/app
    python3 -m venv build-venv
    source build-venv/bin/activate
    pip install -U pip setuptools py2app rumps anthropic openpyxl
    python setup_app.py py2app

build_installer.sh wraps all of that.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup

HERE = Path(__file__).parent.resolve()
APP_NAME = "MailWarden"
VERSION = "1.6.0-beta.12"

# ----------------------------------------------------------------------------
# Copy the shared bundled defaults and runtime payload into app/resources/
# at build time so py2app picks them up via DATA_FILES.
# ----------------------------------------------------------------------------
SHARED_DEFAULTS = HERE.parent / "resources" / "defaults"
SHARED_PAYLOAD = HERE.parent / "payload" / "MailWarden"

LOCAL_DEFAULTS = HERE / "resources" / "defaults"
LOCAL_PAYLOAD = HERE / "resources" / "payload" / "MailWarden"

if LOCAL_DEFAULTS.exists():
    shutil.rmtree(LOCAL_DEFAULTS)
shutil.copytree(SHARED_DEFAULTS, LOCAL_DEFAULTS)

if LOCAL_PAYLOAD.exists():
    shutil.rmtree(LOCAL_PAYLOAD)
shutil.copytree(SHARED_PAYLOAD, LOCAL_PAYLOAD)


def _tree_to_data_files(root: Path, bundle_prefix: str) -> list[tuple[str, list[str]]]:
    """Walk a tree and emit a list of (bundle_dir, [abs_files]) tuples for py2app."""
    groups: dict[str, list[str]] = {}
    for f in root.rglob("*"):
        # Never bundle Python bytecode. .pyc/.pyo and __pycache__ dirs are
        # generated artifacts (Python regenerates them at runtime from the
        # .py sources that DO ship); bundling them leaks stale, host-specific
        # compiled files into the .pkg.
        if "__pycache__" in f.parts or f.suffix in (".pyc", ".pyo"):
            continue
        if f.is_file():
            rel_dir = f.parent.relative_to(root).as_posix()
            bundle_dir = (bundle_prefix if rel_dir == "." else f"{bundle_prefix}/{rel_dir}")
            groups.setdefault(bundle_dir, []).append(str(f))
    return sorted(groups.items())


DATA_FILES: list[tuple[str, list[str]]] = []
DATA_FILES += _tree_to_data_files(LOCAL_DEFAULTS, "defaults")
DATA_FILES += _tree_to_data_files(LOCAL_PAYLOAD, "payload/MailWarden")


# ----------------------------------------------------------------------------
# App bundle config
# ----------------------------------------------------------------------------
ICON_PATH = HERE / "resources" / "app_icon.icns"

APP = ["launcher.py"]

PLIST = {
    "CFBundleName": APP_NAME,
    "CFBundleDisplayName": APP_NAME,
    "CFBundleExecutable": APP_NAME,
    "CFBundleIdentifier": "com.strsolutions.mailwarden",
    "CFBundleShortVersionString": VERSION,
    "CFBundleVersion": VERSION,
    "NSHighResolutionCapable": True,
    "LSUIElement": False,
    "NSHumanReadableCopyright": "(c) 2026 STR Solutions, LLC. All rights reserved.",
    # LaunchServices starts apps under the C locale by default. Setting
    # these here forces the interpreter into UTF-8 mode BEFORE Python
    # starts, so every `open()` in the bundled filter scripts defaults
    # to UTF-8 text reads. Without this, any non-ASCII byte in EULA.md,
    # decisions.log, or any config triggers UnicodeDecodeError deep in
    # the filter and aborts with a LaunchServices "Launch error" dialog.
    "LSEnvironment": {
        "PYTHONUTF8": "1",
        "LC_ALL": "en_US.UTF-8",
        "LANG": "en_US.UTF-8",
    },
}

OPTIONS = {
    "argv_emulation": False,
    "arch": "universal2",
    # site_packages=True copies the entire build-venv site-packages into the
    # bundle. This is heavier than curating a packages= list, but it is the
    # only reliable way to ship single-module packages (typing_extensions)
    # and namespace packages (PyObjCTools) that py2app's modulegraph misses.
    "site_packages": True,
    # py2app's modulegraph can miss dynamic imports used by anthropic's async
    # runtime and its httpx/pydantic stack. Listing each dependency explicitly
    # guarantees every .py (and native shared lib) ships in the bundle.
    "packages": [
        "mailwarden_app",
        # anthropic + its transitive runtime
        "anthropic",
        "pydantic",
        "pydantic_core",
        "annotated_types",
        "typing_inspection",
        "httpx",
        "httpcore",
        "h11",
        "anyio",
        "sniffio",
        "certifi",
        "distro",
        "idna",
        "jiter",
        "docstring_parser",
        # spreadsheet import/export (Dashboard Whitelist/Blacklist tab)
        "openpyxl",
        "et_xmlfile",
        # menu bar agent + its PyObjC native bindings
        "rumps",
        "AppKit",
        "Foundation",
        "CoreFoundation",
        "Cocoa",
        "objc",
        # SMAppService bindings (smappservice_install.py). PyObjC framework
        # wrappers are exactly the kind of package py2app's modulegraph
        # silently drops — see typing_extensions / PyObjCTools precedent.
        # Without this, ModuleNotFoundError at runtime and NO services
        # register with macOS.
        "ServiceManagement",
    ],
    "includes": ["tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox",
                 "tkinter.simpledialog",
                 # email / MIME — spam_filter and daily_report both use these;
                 # py2app modulegraph was dropping email.mime.text because the
                 # Dashboard code doesn't reference it.
                 "email", "email.message", "email.policy", "email.parser",
                 "email.mime", "email.mime.text", "email.mime.multipart",
                 "email.mime.base", "email.header", "email.utils",
                 # stdlib used by spam_filter / daily_report / learn_signals
                 "json", "csv", "imaplib", "smtplib", "urllib.request", "urllib.error",
                 "urllib.parse", "webbrowser", "threading", "subprocess", "shutil",
                 "tempfile", "datetime", "pathlib", "argparse", "hashlib", "ssl",
                 "logging", "logging.handlers", "runpy",
                 "typing_extensions",
                 "PyObjCTools", "PyObjCTools.AppHelper"],
    "plist": PLIST,
}

# Bundle the Tcl/Tk runtime alongside the .app. py2app does not do this
# automatically for python.org's universal2 Python — without these, tkinter
# raises "Can't find a usable init.tcl" on the target Mac. See the python.org
# Python 3.12 framework for the source paths.
TK_FRAMEWORK = Path("/Library/Frameworks/Python.framework/Versions/3.12/lib")
for sub in ("tcl8.6", "tk8.6", "tcl8"):
    src = TK_FRAMEWORK / sub
    if src.is_dir():
        # py2app data_files: (target_subdir, [file_paths])
        for f in src.rglob("*"):
            if f.is_file():
                rel_dir = f.parent.relative_to(TK_FRAMEWORK).as_posix()
                DATA_FILES.append((rel_dir, [str(f)]))
if ICON_PATH.exists():
    OPTIONS["iconfile"] = str(ICON_PATH)

# Bundle the small menu bar PNG template icon into Resources so the menu bar
# agent can prefer it over the large multi-rep .icns file at runtime.
MENUBAR_PNG_PATH = HERE / "resources" / "menubar_icon.png"
if MENUBAR_PNG_PATH.exists():
    DATA_FILES.append(("", [str(MENUBAR_PNG_PATH)]))


setup(
    name=APP_NAME,
    app=APP,
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
