# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
py2app entry script. Runs BEFORE mailwarden_app.* imports, so it has to
patch three things that py2app mishandles for a universal2 bundle:

  1. sys.path — py2app's __boot__.py calls _site_packages() with the BUILD
     MACHINE's absolute paths. Those paths do not exist on the end user's
     Mac, so site.addsitedir() silently adds nothing, and every bundled
     package in Contents/Resources/lib/python3.12/ fails to import. We
     prepend that directory to sys.path manually.

  2. UTF-8 locale — LaunchServices (Finder double-click) launches apps
     under the C locale, so Python defaults to ASCII for file reads. Any
     non-ASCII byte inside a tkinter callback aborts the interpreter. We
     set PYTHONUTF8=1 + LC_ALL=en_US.UTF-8 up front.

  3. Tcl/Tk script paths — py2app ships libtcl8.6/libtk8.6 dylibs but not
     their init.tcl trees for python.org's universal2 Python. We point
     TCL_LIBRARY / TK_LIBRARY at the copies we bundle in Resources/tcl8.6
     and Resources/tk8.6.
"""
import os
import sys
from pathlib import Path

# --- 1. sys.path: prepend the bundle's real package directory ---------------
_bundle_resources = Path(__file__).resolve().parent
_bundle_pkg_dir = _bundle_resources / "lib" / "python3.12"
if _bundle_pkg_dir.is_dir() and str(_bundle_pkg_dir) not in sys.path:
    sys.path.insert(0, str(_bundle_pkg_dir))

# --- 2. UTF-8 default locale ------------------------------------------------
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("LC_ALL", "en_US.UTF-8")
os.environ.setdefault("LANG", "en_US.UTF-8")

# --- 3. Tcl/Tk bundled script locations -------------------------------------
for tcl_dir_name in ("tcl8.6",):
    candidate = _bundle_resources / tcl_dir_name
    if candidate.is_dir():
        os.environ.setdefault("TCL_LIBRARY", str(candidate))
        break
for tk_dir_name in ("tk8.6",):
    candidate = _bundle_resources / tk_dir_name
    if candidate.is_dir():
        os.environ.setdefault("TK_LIBRARY", str(candidate))
        break

# --- 4. SSL CA bundle ------------------------------------------------------
# py2app's __boot__.py forcibly sets SSL_CERT_FILE and SSL_CERT_DIR to
# "<bundle>/openssl.ca/no-such-file", which is a placeholder path that does
# not exist. Every HTTPS request (anthropic, httpx, urllib) then hangs or
# fails cert verification. We override with certifi's bundled CA file
# (certifi is already in the bundle as a dep of anthropic).
try:
    import certifi  # noqa: E402

    _ca = certifi.where()
    if _ca and Path(_ca).exists():
        os.environ["SSL_CERT_FILE"] = _ca
        os.environ["SSL_CERT_DIR"] = str(Path(_ca).parent)
        os.environ["REQUESTS_CA_BUNDLE"] = _ca
        os.environ["CURL_CA_BUNDLE"] = _ca
except Exception:
    pass

from mailwarden_app import app_entrypoint  # noqa: E402


if __name__ == "__main__":
    sys.exit(app_entrypoint.main())
