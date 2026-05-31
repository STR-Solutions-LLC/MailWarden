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

TEAM_ID_FILE="$CODESIGN_DIR/team_id.txt"
APPLE_ID_FILE="$CODESIGN_DIR/apple_id.txt"
APPLE_PASS_FILE="$CODESIGN_DIR/apple_id_password.txt"

for f in "$TEAM_ID_FILE" "$APPLE_ID_FILE" "$APPLE_PASS_FILE"; do
    [ -f "$f" ] || die "Missing credential: $f — see header comment."
done

TEAM_ID="$(tr -d '[:space:]' < "$TEAM_ID_FILE")"
APPLE_ID="$(tr -d '[:space:]' < "$APPLE_ID_FILE")"
APPLE_PASS="$(tr -d '[:space:]' < "$APPLE_PASS_FILE")"

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

log "Submitting to Apple notary service (may take 1–10 min)..."
# Capture the full notarytool output so we have the submission ID for
# later `notarytool log <id>` diagnosis if anything goes sideways. The
# old form `notarytool submit ... --wait` without capture meant a
# transient network blip would leave the user with nothing to poll on.
NOTARY_LOG="$(mktemp -t mailwarden-notary-XXXXXX.log)"
if ! xcrun notarytool submit "$SIGNED" \
        --apple-id "$APPLE_ID" \
        --team-id "$TEAM_ID" \
        --password "$APPLE_PASS" \
        --wait | tee "$NOTARY_LOG"; then
    SUBMISSION_ID="$(grep -oE '[0-9a-f-]{36}' "$NOTARY_LOG" | head -1 || true)"
    die "Notarization failed. Submission ID: ${SUBMISSION_ID:-unknown}. "\
"Diagnose with: xcrun notarytool log ${SUBMISSION_ID:-<ID>} "\
"--apple-id $APPLE_ID --team-id $TEAM_ID --password @keychain"
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
