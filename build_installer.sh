#!/bin/bash
# (c) 2026 STR Solutions, LLC. All rights reserved.
#
# Build MailWarden.pkg.
#
# Pipeline:
#   1. Run the §0 pre-build audit. Halt on any finding.
#   2. (removed 2026-07-03 — resources/defaults/signals.json ships as tracked)
#   3. Regenerate eula.html from EULA.md.
#   4. Build MailWarden.app via py2app in a clean venv.
#   5. Re-run the audit against the built .app.
#   6. pkgbuild the component, productbuild the distribution .pkg.
#   7. Leave dist/MailWarden.pkg ready for signing (see codesign/sign_and_notarize.sh).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER_ROOT="$SCRIPT_DIR"
APP_DIR="$INSTALLER_ROOT/app"
BUILD_VENV="$APP_DIR/build-venv"
DIST_DIR="$INSTALLER_ROOT/dist"
COMPONENT_PKG="$INSTALLER_ROOT/build/MailWarden-component.pkg"
FINAL_PKG="$DIST_DIR/MailWarden.pkg"
APP_BUNDLE_ID="com.strsolutions.mailwarden"
APP_VERSION="1.6.0-beta.17.1"

mkdir -p "$DIST_DIR" "$(dirname "$COMPONENT_PKG")"

log() { printf "\033[1;34m[build]\033[0m %s\n" "$*"; }
die() { printf "\033[1;31m[build]\033[0m %s\n" "$*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# Step 0 — REMOVED 2026-07-03. It refreshed resources/defaults/signals.json
# from the build machine's live ~/MailWarden install. The tracked file is now
# the curated source of truth (the a-1 signal cleanup was made there and
# measured against the eval corpus); the live-install sync silently
# resurrected the very signals a-1 removed. Ship exactly what the repo
# reviews. To import learned signals from a runtime again, do it as a
# reviewed commit, not a build step. (scripts/scrub_signals.py kept for
# manual use.)
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# Step 0.5 — clean dev-runtime junk from the source payload tree before audit.
# The audit scans payload/MailWarden/ for .lock sidecars, .claude-mpm dirs,
# __pycache__/*.pyc, non-empty logs/, and false_positives/. These regenerate on
# every local engine/test run; remove them so the audit validates a clean source.
# Scope: ONLY these artifact categories — never src/*.py, blacklist/, EULA.md,
# LICENSE, requirements.txt, or ~/MailWarden.
# ----------------------------------------------------------------------------
log "Cleaning dev-runtime artifacts from source payload tree..."
PAYLOAD_SRC="$INSTALLER_ROOT/payload/MailWarden"
find "$PAYLOAD_SRC" -name "*.lock" -delete 2>/dev/null || true
find "$PAYLOAD_SRC" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$PAYLOAD_SRC" -name ".claude-mpm" -type d -exec rm -rf {} + 2>/dev/null || true
if [ -d "$PAYLOAD_SRC/logs" ]; then
    for f in "$PAYLOAD_SRC/logs"/*; do
        [ -f "$f" ] && : > "$f"
    done
fi
if [ -d "$PAYLOAD_SRC/false_positives" ]; then
    find "$PAYLOAD_SRC/false_positives" -maxdepth 1 -type f -delete
fi

# ----------------------------------------------------------------------------
# Step 1 — pre-build audit. Hard gate. Audits the tracked signals.json as-is.
# ----------------------------------------------------------------------------
log "Running §1 pre-build audit..."
if ! "$INSTALLER_ROOT/scripts/audit_payload.sh"; then
    die "Audit failed. Fix findings before continuing."
fi

# ----------------------------------------------------------------------------
# Step 2 — regenerate eula.html from EULA.md.
# ----------------------------------------------------------------------------
log "Rendering eula.html from EULA.md..."
python3 "$INSTALLER_ROOT/scripts/md_to_eula_html.py"

# macOS 26's Installer.app doesn't render mime-type="text/html" screens — it
# shows raw source. textutil-converted RTF renders correctly and matches
# the look users expect from signed installers.
log "Converting installer screens to RTF..."
for base in welcome readme eula; do
    src="$INSTALLER_ROOT/resources/${base}.html"
    dst="$INSTALLER_ROOT/resources/${base}.rtf"
    if [ -f "$src" ]; then
        /usr/bin/textutil -convert rtf "$src" -output "$dst"
    fi
done

# ----------------------------------------------------------------------------
# Step 3 — build MailWarden.app via py2app in a fresh venv.
# ----------------------------------------------------------------------------
log "Preparing build venv..."
rm -rf "$APP_DIR/build" "$APP_DIR/dist" "$BUILD_VENV"
# Use a Python that ships with tkinter. /usr/bin/python3 is the stable default
# on macOS; Homebrew Python on Apple Silicon often omits _tkinter.
BUILD_PY="${BUILD_PY:-/usr/bin/python3}"
if ! "$BUILD_PY" -c "import tkinter" 2>/dev/null; then
    die "Build Python lacks tkinter. Set BUILD_PY=/path/to/python3 and retry."
fi
# Require a universal2 Python so the resulting bundle actually loads on both
# Intel and Apple Silicon. A single-arch build_py still passes the dual-arch
# runtime gate IF every native wheel happened to fuse correctly, but we want
# to fail fast and obvious if the interpreter itself is wrong.
BUILD_PY_REAL="$(readlink -f "$BUILD_PY" 2>/dev/null || echo "$BUILD_PY")"
BUILD_PY_ARCHS="$(/usr/bin/file "$BUILD_PY_REAL" | grep -oE 'arm64|x86_64' \
                    | sort -u | tr '\n' ' ')"
case "$BUILD_PY_ARCHS" in
    "arm64 x86_64 "|"x86_64 arm64 ")
        log "BUILD_PY is universal2 ($BUILD_PY_REAL)"
        ;;
    *)
        die "BUILD_PY=$BUILD_PY is not universal2 (archs: '$BUILD_PY_ARCHS'). "\
"Use python.org's universal2 Python 3.12 at "\
"/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
        ;;
esac
"$BUILD_PY" -m venv "$BUILD_VENV"
# shellcheck disable=SC1091
source "$BUILD_VENV/bin/activate"
# setuptools pinned <81: py2app's build imports pkg_resources, which
# setuptools removed in 81+ (hit 2026-07-03 when unpinned upgrade pulled it).
pip install --quiet --upgrade pip "setuptools<81" wheel
# dnspython + dkimpy are runtime deps of the filter (local DKIM verification,
# audit a-2). Both pure-Python (no native wheels → no universal2 fusion). They
# are NOT transitive deps of anything above, so name them explicitly or the
# bundle ships without them and local DKIM verification / DNSBL silently no-op.
pip install --quiet py2app rumps anthropic openpyxl dnspython dkimpy
# pyobjc-framework-ServiceManagement is REQUIRED at runtime by
# smappservice_install.py (v1.6.0 SMAppService migration). It is NOT a
# transitive dep of rumps or any other package above, so it must be named
# explicitly. The framework wrapper must match the installed pyobjc-core
# ABI, so derive the pin from whatever major rumps actually resolved —
# a hardcoded major breaks when PyPI moves (2026-07-03: pyobjc 12.0 was
# yanked and 12.1+ requires Python >=3.10, while this build's universal2
# /usr/bin/python3 is 3.9 and resolves pyobjc-core 11.x).
PYOBJC_CORE_MAJOR=$(pip show pyobjc-core | awk '/^Version:/{split($2,v,"."); print v[1]}')
[ -n "$PYOBJC_CORE_MAJOR" ] || die "pyobjc-core not installed — rumps install failed?"
pip install --quiet "pyobjc-framework-ServiceManagement>=${PYOBJC_CORE_MAJOR}.0,<$((PYOBJC_CORE_MAJOR+1))"

log "Building MailWarden.app with py2app..."
cd "$APP_DIR"
python setup_app.py py2app --no-strip --quiet
deactivate
cd "$INSTALLER_ROOT"

BUILT_APP="$APP_DIR/dist/MailWarden.app"
if [ ! -d "$BUILT_APP" ]; then
    die "py2app did not produce $BUILT_APP"
fi

# ----------------------------------------------------------------------------
# Step 3.5 — manually copy packages that py2app's modulegraph misses.
# typing_extensions is a single-file module; PyObjCTools is a namespace
# package. Both are required at runtime (anthropic uses typing_extensions,
# rumps uses PyObjCTools.AppHelper) but py2app ships neither, even with
# site_packages=True.
# ----------------------------------------------------------------------------
log "Copying missing packages into the bundle..."
BUNDLE_SITE="$BUILT_APP/Contents/Resources/lib/python3.12"
VENV_SITE="$BUILD_VENV/lib/python3.12/site-packages"
for item in typing_extensions.py PyObjCTools docstring_parser; do
    src="$VENV_SITE/$item"
    if [ -e "$src" ]; then
        cp -R "$src" "$BUNDLE_SITE/"
        log "  copied $item"
    else
        log "  (WARN: $item not found in build venv)"
    fi
done

# ----------------------------------------------------------------------------
# Universal2 fat-binary fusion. pip installs native wheels matching the
# BUILD machine's architecture only (arm64 wheels on Apple Silicon). Without
# this step the .app loads on the build arch but crashes on the other.
# ----------------------------------------------------------------------------
log "Fusing single-arch .so files to universal2..."
"$BUILD_VENV/bin/pip" install --quiet delocate 2>/dev/null || true
# shellcheck disable=SC1091
source "$BUILD_VENV/bin/activate"
bash "$INSTALLER_ROOT/scripts/make_universal_sos.sh" "$BUILT_APP"
deactivate

# ----------------------------------------------------------------------------
# Step 3.75 — runtime import gate. Invoke the REAL app binary with --diagnose
# under BOTH architectures. Single-arch wheels that slip through pip land
# here; we do not ship a bundle that works on one arch but crashes on the
# other.
# ----------------------------------------------------------------------------
log "Runtime import gate (--diagnose) — native arch..."
if ! "$BUILT_APP/Contents/MacOS/MailWarden" --diagnose >/dev/null; then
    "$BUILT_APP/Contents/MacOS/MailWarden" --diagnose || true
    die "Runtime import gate failed on native arch. The bundle is missing a dependency — do not ship."
fi
log "  native arch: all imports OK"

log "Runtime import gate (--diagnose) — x86_64 via Rosetta..."
if ! /usr/bin/arch -x86_64 "$BUILT_APP/Contents/MacOS/MailWarden" --diagnose >/dev/null; then
    /usr/bin/arch -x86_64 "$BUILT_APP/Contents/MacOS/MailWarden" --diagnose || true
    die "Runtime import gate failed on x86_64. Intel Macs will not run this bundle — do not ship."
fi
log "  x86_64: all imports OK"

log "Runtime import gate (--diagnose) — arm64 explicit..."
if ! /usr/bin/arch -arm64 "$BUILT_APP/Contents/MacOS/MailWarden" --diagnose >/dev/null 2>&1; then
    log "  (arm64 explicit skipped — not available on this host)"
else
    log "  arm64: all imports OK"
fi

# Live HTTPS test. Guarantees SSL_CERT_FILE/SSL_CERT_DIR resolution works
# end-to-end and that validate_api_key does not hang. Uses an intentionally
# invalid key so the only sensitive network traffic is one rejected auth.
log "Runtime HTTPS gate (--test-validate) — native arch..."
if ! "$BUILT_APP/Contents/MacOS/MailWarden" --test-validate; then
    die "HTTPS gate failed on native arch. The app will hang or error on Validate."
fi
log "Runtime HTTPS gate (--test-validate) — x86_64 via Rosetta..."
if ! /usr/bin/arch -x86_64 "$BUILT_APP/Contents/MacOS/MailWarden" --test-validate; then
    die "HTTPS gate failed on x86_64. Intel Macs would hang on Validate."
fi

# ----------------------------------------------------------------------------
# Step 4 — post-build audit against the built .app (private data check).
# ----------------------------------------------------------------------------
log "Auditing built .app for leaks..."
# Find candidate Anthropic-key-shaped matches, then exempt files whose
# ONLY matches are the BUILD-GATE-INTENTIONALLY-INVALID-KEY sentinel
# (an intentional placeholder at app_entrypoint.py:90-91 used to verify
# validate_api_key rejects malformed sk-ant keys at build time; Python's
# peephole optimizer folds the concatenation into one long literal in
# the compiled .pyc, which this exemption accounts for).
CANDIDATES=$(grep -rlE 'sk-ant-[A-Za-z0-9_-]{40,}' "$BUILT_APP" 2>/dev/null || true)
LEAKS=""
for f in $CANDIDATES; do
    if grep -aE 'sk-ant-[A-Za-z0-9_-]{40,}' "$f" 2>/dev/null \
            | grep -qv 'BUILD-GATE-INTENTIONALLY-INVALID-KEY'; then
        LEAKS="$LEAKS $f"
    fi
done
if [ -n "$LEAKS" ]; then
    echo "$LEAKS" | tr ' ' '\n' | grep -v '^$'
    die "A real Anthropic API key was found inside the built .app. Aborting."
fi
if grep -rlE '(matt@nthmonkey\.com|@nthmonkey\.com|dumbmachine@|@firstchairmarketing\.com)' \
        "$BUILT_APP" 2>/dev/null; then
    die "Developer email address found inside the built .app. Aborting."
fi

# ----------------------------------------------------------------------------
# Step 4.25 — copy bundled LaunchAgent plists into the .app bundle.
# v1.6.0: SMAppService expects plists at Contents/Library/LaunchAgents/.
# These are the STATIC plists shipped inside the bundle; no per-user
# rendering happens at install time (unlike the old ~/Library/LaunchAgents/
# approach). $HOME in StandardOutPath/WorkingDirectory is expanded by launchd
# at runtime when running in the user's GUI domain.
# ----------------------------------------------------------------------------
log "Copying bundled LaunchAgent plists into the .app..."
BUNDLE_LAUNCHAGENTS="$BUILT_APP/Contents/Library/LaunchAgents"
mkdir -p "$BUNDLE_LAUNCHAGENTS"
SOURCE_PLISTS="$INSTALLER_ROOT/app/resources/Library/LaunchAgents"
if [ -d "$SOURCE_PLISTS" ]; then
    cp "$SOURCE_PLISTS/com.mailwarden.filter.plist" "$BUNDLE_LAUNCHAGENTS/"
    cp "$SOURCE_PLISTS/com.mailwarden.report.plist" "$BUNDLE_LAUNCHAGENTS/"
    cp "$SOURCE_PLISTS/com.mailwarden.menubar.plist" "$BUNDLE_LAUNCHAGENTS/"
    log "  copied 3 plist files to $BUNDLE_LAUNCHAGENTS"
else
    die "Bundled LaunchAgents source not found at $SOURCE_PLISTS"
fi

# ----------------------------------------------------------------------------
# Step 4.4 — stage the built .app OUTSIDE the repo tree before signing.
# The repo lives in an iCloud-synced folder (~/Documents): FileProvider
# re-stamps com.apple.FinderInfo/fpfs xattrs on bundle items continuously,
# racing the (minutes-long) signing pass. Any such attr at seal time =
# codesign "detritus not allowed" = an ad-hoc app = notary rejection
# (lost this race twice on 2026-07-03 despite pre-sign xattr strips).
# /private/tmp is never synced; ditto --noextattr --noqtn strips every
# attribute in transit. All signing + packaging below uses the staged copy.
# ----------------------------------------------------------------------------
SIGN_STAGE="$(mktemp -d /private/tmp/mailwarden-sign-XXXXXX)"
log "Staging .app outside the synced tree for signing ($SIGN_STAGE)..."
/usr/bin/ditto --noextattr --noqtn "$BUILT_APP" "$SIGN_STAGE/MailWarden.app" \
    || die "ditto staging failed"
BUILT_APP="$SIGN_STAGE/MailWarden.app"

# ----------------------------------------------------------------------------
# Step 4.5 — codesign the .app.
# If a Developer ID Application cert is available in the keychain, sign with
# it now (required for SMAppService registration). Fall back to ad-hoc if not.
# The codesign/sign_and_notarize.sh script handles .pkg signing + notarytool
# after this step produces the .pkg; no change needed there.
# ----------------------------------------------------------------------------
DEVID_CERT="Developer ID Application: STR Solutions, LLC (6BXSAHWH29)"
if /usr/bin/security find-identity -v -p codesigning \
        | grep -qF "$DEVID_CERT"; then
    log "Developer ID cert found — signing .app with Developer ID Application..."
    # Strip Finder info / resource forks / provenance xattrs BEFORE signing.
    # Detritus on any bundle file breaks the code seal and the notary
    # service rejects the whole .pkg (hit 2026-07-03: freshly-downloaded
    # wheels carried provenance attrs; verification failed but was only a
    # warning, so an effectively ad-hoc app shipped to notarization).
    log "  Stripping extended attributes from the bundle..."
    /usr/bin/xattr -cr "$BUILT_APP" 2>/dev/null || true
    # Apple's notary service requires every Mach-O binary inside the bundle
    # to be signed with --options runtime AND --timestamp. --deep alone does
    # not add timestamps to nested signatures, so we walk the bundle and sign
    # each binary explicitly (innermost first), then sign the outer .app.
    log "  Signing inner Mach-O binaries (.so/.dylib) with hardened runtime + timestamp..."
    find "$BUILT_APP" -type f \( -name "*.so" -o -name "*.dylib" \) -print0 \
        | while IFS= read -r -d '' bin; do
            /usr/bin/codesign --force \
                --options runtime \
                --timestamp \
                --sign "$DEVID_CERT" \
                "$bin" >/dev/null 2>&1 || log "    WARNING: failed to sign $bin"
          done
    # Sign the embedded Python binary explicitly
    if [ -f "$BUILT_APP/Contents/MacOS/python" ]; then
        /usr/bin/codesign --force \
            --options runtime \
            --timestamp \
            --sign "$DEVID_CERT" \
            "$BUILT_APP/Contents/MacOS/python" 2>&1 | grep -v "replacing existing signature" || true
    fi
    # Sign the Python framework's main dylib. This binary has no extension
    # (just named "Python") and no executable bit set, so the .so/.dylib
    # find loop above misses it entirely. Apple's notary REQUIRES every
    # Mach-O inside the bundle to carry Developer ID + timestamp; leaving
    # this one ad-hoc-signed (py2app's default) causes notary to reject
    # the entire .pkg with "binary is not signed with a valid Developer ID
    # certificate" — see notary log for fa0aff53-64de-4336-a5ce-b7fea6047a19.
    FRAMEWORK_PY="$BUILT_APP/Contents/Frameworks/Python.framework/Versions/3.12/Python"
    if [ -f "$FRAMEWORK_PY" ]; then
        /usr/bin/codesign --force \
            --options runtime \
            --timestamp \
            --sign "$DEVID_CERT" \
            "$FRAMEWORK_PY" 2>&1 | grep -v "replacing existing signature" || true
    fi
    # Sign the main wrapper executable
    if [ -f "$BUILT_APP/Contents/MacOS/MailWarden" ]; then
        /usr/bin/codesign --force \
            --options runtime \
            --timestamp \
            --sign "$DEVID_CERT" \
            "$BUILT_APP/Contents/MacOS/MailWarden" 2>&1 | grep -v "replacing existing signature" || true
    fi
    # Finally, sign the .app bundle itself with entitlements
    # Second strip IMMEDIATELY before the outer seal: this repo lives in an
    # iCloud-synced folder (~/Documents), and FileProvider re-stamps
    # com.apple.FinderInfo / com.apple.fileprovider.fpfs on bundle items
    # WHILE the (minutes-long) inner signing loop runs. Any such attr at
    # seal time = "detritus not allowed" = ad-hoc app = notary rejection.
    # -d targets the two offenders explicitly (-c alone has been observed
    # to leave them); provenance attrs are SIP-managed, unremovable, and
    # tolerated by codesign.
    log "  Stripping extended attributes again (iCloud FileProvider re-tags mid-build)..."
    /usr/bin/xattr -rd com.apple.FinderInfo "$BUILT_APP" 2>/dev/null || true
    /usr/bin/xattr -rd com.apple.fileprovider.fpfs "$BUILT_APP" 2>/dev/null || true
    /usr/bin/xattr -cr "$BUILT_APP" 2>/dev/null || true
    log "  Signing outer .app bundle with entitlements + hardened runtime + timestamp..."
    /usr/bin/codesign --force \
        --options runtime \
        --timestamp \
        --entitlements "$INSTALLER_ROOT/app/MailWarden.entitlements" \
        --sign "$DEVID_CERT" \
        "$BUILT_APP" 2>&1 | grep -v "replacing existing signature" || true
    # Verification is a HARD GATE on the Developer ID path: a broken seal
    # here is exactly what the notary rejects, so failing loudly now saves
    # a wasted 10-minute notarization round-trip (and can never ship an
    # ad-hoc-signed app as if it were signed).
    if ! /usr/bin/codesign --verify --deep --strict "$BUILT_APP"; then
        die "codesign verification FAILED — notarization would reject this bundle. Do not ship."
    fi
    log "  Developer ID codesign complete"
else
    log "Developer ID cert NOT found — falling back to ad-hoc sign."
    log "  SMAppService will not work without a Developer ID signature."
    log "  To sign properly: add 'Developer ID Application: STR Solutions, LLC (6BXSAHWH29)' to keychain."
    /usr/bin/codesign --force --deep --sign - "$BUILT_APP" 2>&1 \
        | grep -v "replacing existing signature" || true
    /usr/bin/codesign --verify --deep --strict "$BUILT_APP" 2>&1 \
        | head -5 || log "  (verification warning; build continues)"
fi

# ----------------------------------------------------------------------------
# Step 5 — stage the .app into a component .pkg.
# ----------------------------------------------------------------------------
log "Staging component .pkg..."
# pkg-root also lives OUTSIDE the synced tree (same FileProvider re-tagging
# hazard as Step 4.4 — detritus stamped between cp and pkgbuild would embed
# broken-seal files in the payload). ditto preserves the signed app exactly.
STAGE="$SIGN_STAGE/pkg-root"
rm -rf "$STAGE"
mkdir -p "$STAGE/Applications"
/usr/bin/ditto "$BUILT_APP" "$STAGE/Applications/MailWarden.app"

pkgbuild \
    --root "$STAGE" \
    --identifier "$APP_BUNDLE_ID.app" \
    --version "$APP_VERSION" \
    --install-location "/" \
    --scripts "$INSTALLER_ROOT/scripts" \
    "$COMPONENT_PKG" >/dev/null

# ----------------------------------------------------------------------------
# Step 6 — wrap with productbuild for the EULA/welcome/readme screens.
# ----------------------------------------------------------------------------
log "Running productbuild..."
productbuild \
    --distribution "$INSTALLER_ROOT/distribution.xml" \
    --package-path "$(dirname "$COMPONENT_PKG")" \
    --resources "$INSTALLER_ROOT/resources" \
    "$FINAL_PKG" >/dev/null

# ----------------------------------------------------------------------------
# Step 7 — attach the MailWarden icon to the .pkg file itself so it shows up
# with custom artwork in Finder (productbuild leaves the default brown box).
# PyObjC lives in Python 3.12+; fall back silently if it isn't available.
# ----------------------------------------------------------------------------
ICON_ICNS="$APP_DIR/resources/app_icon.icns"
if [ -f "$ICON_ICNS" ]; then
    log "Attaching Finder icon to .pkg..."
    ICON_PY="${BUILD_PY}"
    # Prefer the build venv's Python so PyObjC is guaranteed present.
    if [ -x "$BUILD_VENV/bin/python3" ]; then
        ICON_PY="$BUILD_VENV/bin/python3"
    fi
    "$ICON_PY" "$INSTALLER_ROOT/scripts/set_pkg_icon.py" \
        "$FINAL_PKG" "$ICON_ICNS" || \
        log "  (icon attach failed; .pkg will use default Finder icon)"
fi

ls -lh "$FINAL_PKG"
log "Done. Unsigned .pkg at: $FINAL_PKG"
log "To sign and notarize: ./codesign/sign_and_notarize.sh \"$FINAL_PKG\""
