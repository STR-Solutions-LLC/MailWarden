#!/bin/bash
# (c) 2026 STR Solutions, LLC. All rights reserved.
#
# Sign + notarize a MailWarden.pkg for Gatekeeper-clean distribution.
#
# Prerequisites:
#   1. A "Developer ID Installer" certificate installed in Keychain.
#      Verify: security find-identity -v -p codesigning
#   2. codesign/team_id.txt            — 10-char team ID (gitignored)
#   3. codesign/apple_id.txt           — your Apple ID email (gitignored)
#   4. codesign/apple_id_password.txt  — an app-specific password created at
#                                        https://appleid.apple.com/account/manage
#                                        Sign in → App-Specific Passwords (gitignored)
#
# Usage:
#   ./codesign/sign_and_notarize.sh /path/to/MailWarden.pkg
#
# On success, writes the signed + notarized + stapled .pkg next to the input
# with `-signed` appended to the filename, and exits 0.

set -euo pipefail

die() { printf "\033[1;31m[sign]\033[0m %s\n" "$*" >&2; exit 1; }
log() { printf "\033[1;34m[sign]\033[0m %s\n" "$*"; }

INPUT="${1:-}"
[ -n "$INPUT" ] || die "Usage: sign_and_notarize.sh <path to MailWarden.pkg>"
[ -f "$INPUT" ] || die "Input .pkg not found: $INPUT"

CODESIGN_DIR="$(cd "$(dirname "$0")" && pwd)"

# Notarization auth. PREFERRED: an App Store Connect API key
# (codesign/AuthKey_*.p8 + api_key_id.txt + api_issuer_id.txt) — Apple's current
# method. FALLBACK: the legacy Apple-ID + app-specific-password trio. Apple has
# been disabling password ("primary") auth for notarization, so the API key
# wins when present. All of these files are gitignored (never committed).
API_KEY_FILE="$(ls "$CODESIGN_DIR"/AuthKey_*.p8 2>/dev/null | head -1 || true)"
API_KEY_ID_FILE="$CODESIGN_DIR/api_key_id.txt"
API_ISSUER_FILE="$CODESIGN_DIR/api_issuer_id.txt"

TEAM_ID_FILE="$CODESIGN_DIR/team_id.txt"
APPLE_ID_FILE="$CODESIGN_DIR/apple_id.txt"
APPLE_PASS_FILE="$CODESIGN_DIR/apple_id_password.txt"

# Pre-set so `set -u` never trips on the auth path we don't use.
API_KEY_ID=""; API_ISSUER=""; TEAM_ID=""; APPLE_ID=""; APPLE_PASS=""
USE_API_KEY=0

if [ -n "$API_KEY_FILE" ] && [ -f "$API_KEY_ID_FILE" ] && [ -f "$API_ISSUER_FILE" ]; then
    USE_API_KEY=1
    API_KEY_ID="$(tr -d '[:space:]' < "$API_KEY_ID_FILE")"
    API_ISSUER="$(tr -d '[:space:]' < "$API_ISSUER_FILE")"
else
    for f in "$TEAM_ID_FILE" "$APPLE_ID_FILE" "$APPLE_PASS_FILE"; do
        [ -f "$f" ] || die "Missing credential: $f — see header comment, or add an App Store Connect API key (AuthKey_*.p8 + api_key_id.txt + api_issuer_id.txt)."
    done
    TEAM_ID="$(tr -d '[:space:]' < "$TEAM_ID_FILE")"
    APPLE_ID="$(tr -d '[:space:]' < "$APPLE_ID_FILE")"
    APPLE_PASS="$(tr -d '[:space:]' < "$APPLE_PASS_FILE")"
fi

# Find the "Developer ID Installer" identity that matches our team.
# NOTE: use -p basic, not -p codesigning. The "Developer ID Installer"
# cert is used by productsign, not codesign, so macOS does not list it
# under the codesigning policy. -p basic returns all valid identities.
IDENTITY="$(security find-identity -v -p basic \
    | awk -F'"' '/Developer ID Installer/ {print $2; exit}')"
[ -n "$IDENTITY" ] || die "No 'Developer ID Installer' identity found in Keychain."

log "Using signing identity: $IDENTITY"

SIGNED="${INPUT%.pkg}-signed.pkg"
log "Signing into: $SIGNED"
productsign --sign "$IDENTITY" "$INPUT" "$SIGNED"

log "Verifying signature..."
pkgutil --check-signature "$SIGNED" | head -5

# Capture the full notarytool output so we have the submission ID for
# later `notarytool log <id>` diagnosis if anything goes sideways.
NOTARY_LOG="$(mktemp -t mailwarden-notary-XXXXXX.log)"
if [ "$USE_API_KEY" -eq 1 ]; then
    log "Submitting via App Store Connect API key (may take 1–10 min)..."
    NOTARY_ARGS=(--key "$API_KEY_FILE" --key-id "$API_KEY_ID" --issuer "$API_ISSUER")
else
    log "Submitting via Apple ID + app-specific password (may take 1–10 min)..."
    NOTARY_ARGS=(--apple-id "$APPLE_ID" --team-id "$TEAM_ID" --password "$APPLE_PASS")
fi
if ! xcrun notarytool submit "$SIGNED" "${NOTARY_ARGS[@]}" --wait | tee "$NOTARY_LOG"; then
    SUBMISSION_ID="$(grep -oE '[0-9a-f-]{36}' "$NOTARY_LOG" | head -1 || true)"
    die "Notarization failed. Submission ID: ${SUBMISSION_ID:-unknown}. See the notary output above; for detail run: xcrun notarytool log ${SUBMISSION_ID:-<ID>} (with the same auth you submitted with)."
fi
rm -f "$NOTARY_LOG"

log "Stapling notarization ticket..."
xcrun stapler staple "$SIGNED"

log "Validating stapled .pkg..."
xcrun stapler validate "$SIGNED"

# Re-attach the Finder icon. Apple's stapler strips resource-fork
# icons on some macOS versions (handoff §7.5), so we reattach after
# staple to guarantee the .pkg shows with branding in Finder.
ICON_ICNS="$(cd "$CODESIGN_DIR/.." && pwd)/app/resources/app_icon.icns"
SET_ICON="$(cd "$CODESIGN_DIR/.." && pwd)/scripts/set_pkg_icon.py"
if [ -f "$ICON_ICNS" ] && [ -f "$SET_ICON" ]; then
    log "Re-attaching Finder icon (stapler can strip it)..."
    # set_pkg_icon.py needs PyObjC. /usr/bin/python3 on most macOS systems
    # does NOT ship with PyObjC, but the build-venv that built the .app
    # does. Prefer the build-venv if present, fall back to /usr/bin/python3.
    ICON_PY="/usr/bin/python3"
    BUILD_VENV_PY="$(cd "$CODESIGN_DIR/.." && pwd)/app/build-venv/bin/python3"
    if [ -x "$BUILD_VENV_PY" ] && "$BUILD_VENV_PY" -c "import Cocoa" >/dev/null 2>&1; then
        ICON_PY="$BUILD_VENV_PY"
    fi
    "$ICON_PY" "$SET_ICON" "$SIGNED" "$ICON_ICNS" \
        || log "  (icon attach failed; .pkg will use default Finder icon)"
fi

log "Done. Signed + notarized + stapled: $SIGNED"

# ----------------------------------------------------------------------------
# Permanent project convention: every installer is also delivered as
# "MailWarden-<version>.pkg" (version read from app/setup_app.py — the single
# source of truth, never hardcoded here) next to the signed output, plus a
# convenience copy on the Desktop. Purely additive: the "-signed.pkg" file
# above is left in place untouched. Safe to re-run — existing files at either
# destination are overwritten.
REPO_ROOT="$(cd "$CODESIGN_DIR/.." && pwd)"
SETUP_APP_PY="$REPO_ROOT/app/setup_app.py"
APP_VERSION=""
if [ -f "$SETUP_APP_PY" ]; then
    # `|| true` so a no-match (grep exits 1) degrades to an empty string and
    # reaches the warning path below, instead of tripping `set -euo pipefail`
    # and aborting an already-successful sign+notarize+staple.
    APP_VERSION="$(grep -m1 -E '^VERSION[[:space:]]*=[[:space:]]*"' "$SETUP_APP_PY" \
        | sed -E 's/^VERSION[[:space:]]*=[[:space:]]*"([^"]*)".*$/\1/' || true)"
fi

if [ -z "$APP_VERSION" ]; then
    log "WARNING: could not read VERSION from $SETUP_APP_PY — skipping versioned/Desktop copies. The notarized .pkg is still valid at $SIGNED"
else
    VERSIONED_PKG="$(dirname "$SIGNED")/MailWarden-${APP_VERSION}.pkg"
    if cp -f "$SIGNED" "$VERSIONED_PKG"; then
        log "Versioned copy: $VERSIONED_PKG"
    else
        log "WARNING: failed to create versioned copy at $VERSIONED_PKG"
    fi

    DESKTOP_PKG="$HOME/Desktop/MailWarden-${APP_VERSION}.pkg"
    if cp -f "$SIGNED" "$DESKTOP_PKG" 2>/dev/null; then
        log "Desktop copy: $DESKTOP_PKG"
    else
        log "WARNING: could not copy to Desktop ($DESKTOP_PKG) — permissions or disk full? The notarized .pkg is still valid at $SIGNED"
    fi
fi
