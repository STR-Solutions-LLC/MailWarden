#!/bin/bash
# (c) 2026 STR Solutions, LLC. All rights reserved.
#
# §0 pre-build audit. Run before every pkgbuild. Halts the build if any
# developer data has leaked into the installer source or payload.
#
# Usage: scripts/audit_payload.sh
# Exits 0 on clean, 1 on any finding.

# -e halts on any unexpected command failure; -u catches typo'd variable
# references; pipefail ensures a grep|head pipeline's exit status reflects
# the grep, not the head. Without these, a silent error mid-audit could
# leave FAIL=0 and pass a bad build. The per-check logic below uses
# `if ! grep ...` explicitly so no-match (grep's expected exit 1) doesn't
# kill the script under -e.
set -euo pipefail

AUDIT_ROOT="${AUDIT_ROOT:-$HOME/MailWarden-installer}"
FAIL=0

fail() { echo "FAIL: $*" >&2; FAIL=1; }
pass() { echo "  OK: $*"; }

echo "Running §0 pre-build audit on: $AUDIT_ROOT"
echo

# --- 1. Real Anthropic API keys (40+ chars after sk-ant-) ---
if grep -rnE 'sk-ant-[A-Za-z0-9_-]{40,}' \
        --exclude-dir=.git --exclude-dir=build --exclude-dir=dist \
        --exclude-dir=build-venv --exclude-dir=.eggs \
        --exclude-dir=MailWarden.app --exclude='*.pyc' \
        --exclude-dir=scripts --exclude-dir=.githooks \
        --exclude-dir=.claude --exclude-dir=.claude-mpm \
        "$AUDIT_ROOT" 2>/dev/null; then
    fail "Real Anthropic API key found"
else
    pass "No real API keys in source or payload"
fi

# --- 2. Developer email addresses ---
# Meta-scanners (build_installer.sh runs its own grep on the built .app) are
# exempted; they never ship with the .pkg.
if grep -rnE '(matt@nthmonkey\.com|@nthmonkey\.com|dumbmachine@|@First-Chairbook|@firstchairmarketing\.com|info@firstchairmarketing\.com)' \
        --exclude-dir=.git --exclude-dir=build --exclude-dir=dist \
        --exclude-dir=build-venv --exclude-dir=.eggs \
        --exclude-dir=MailWarden.app --exclude='*.pyc' \
        --exclude-dir=scripts --exclude-dir=.githooks \
        --exclude-dir=.claude --exclude-dir=.claude-mpm \
        --exclude='build_installer.sh' \
        "$AUDIT_ROOT" 2>/dev/null; then
    fail "Developer email address found"
else
    pass "No developer email addresses"
fi

# --- 3. Developer hostnames, usernames, paths ---
if grep -rnE '(box5275\.bluehost\.com|First-Chairbook|/Users/mattrosenberg|/Users/dumbmachine)' \
        --exclude-dir=.git --exclude-dir=build --exclude-dir=dist \
        --exclude-dir=build-venv --exclude-dir=.eggs \
        --exclude-dir=MailWarden.app --exclude='*.pyc' \
        --exclude-dir=scripts --exclude-dir=.githooks \
        --exclude-dir=.claude --exclude-dir=.claude-mpm \
        "$AUDIT_ROOT" 2>/dev/null; then
    fail "Developer hostname or user path found"
else
    pass "No developer hostnames or paths"
fi

# --- 4. Private files that must never ship in the payload ---
PAYLOAD="$AUDIT_ROOT/payload/MailWarden"

if [ -f "$PAYLOAD/config/config.json" ]; then
    fail "config/config.json in payload (contains real credentials)"
else
    pass "No config.json in payload"
fi

if ls "$PAYLOAD/spam_examples"/*.eml >/dev/null 2>&1; then
    fail "Raw .eml files in payload/spam_examples/ (real email content)"
else
    pass "No .eml files in payload"
fi

if [ -f "$PAYLOAD/memory/decisions.log" ]; then
    fail "memory/decisions.log in payload (dev classification log)"
else
    pass "No decisions.log in payload"
fi

if [ -f "$PAYLOAD/memory/processed_ids.json" ] && [ -s "$PAYLOAD/memory/processed_ids.json" ]; then
    content="$(cat "$PAYLOAD/memory/processed_ids.json")"
    case "$content" in
        *\"ids\":\ *{\}*|*\"ids\":{}*)
            pass "processed_ids.json in payload is empty default"
            ;;
        *)
            fail "processed_ids.json in payload is non-empty (dev's Message-IDs)"
            ;;
    esac
else
    pass "No non-empty processed_ids.json in payload"
fi

# --- 5. Scrubbed signals.json must not contain dev-specific domains ---
SIGNALS="$AUDIT_ROOT/resources/defaults/signals.json"
if [ -f "$SIGNALS" ]; then
    if grep -E '@(nthmonkey|bluehost|gmail|aol|firstchairmarketing)\.com' "$SIGNALS" >/dev/null 2>&1; then
        fail "resources/defaults/signals.json contains specific domains — rerun scrub"
    else
        pass "resources/defaults/signals.json has no specific dev domains"
    fi
else
    fail "resources/defaults/signals.json missing (build step skipped)"
fi

# --- 5b. All files under resources/defaults/ must be world-readable (not 600) ---
# When .pkg installs, defaults/ ends up at /Applications/MailWarden.app/Contents/
# Resources/defaults/ owned by root:wheel. Any file with mode 600 there is
# unreadable by the runtime user → bootstrap fails with EACCES → app dies
# silently on first launch (Dock bounce + crash, no menu, no error dialog).
# See v1.6.0-beta.2 signals.json regression for the original case. The fix
# is in scrub_signals.py (chmod 644 after atomic write), but this guard
# catches the class of bug if it ever recurs from a different writer.
DEFAULTS_DIR="$AUDIT_ROOT/resources/defaults"
if [ -d "$DEFAULTS_DIR" ]; then
    unreadable="$(find "$DEFAULTS_DIR" -type f ! -perm -004 2>/dev/null)"
    if [ -n "$unreadable" ]; then
        echo "$unreadable" | while read -r f; do
            fail "defaults file not world-readable (mode 6xx/7xx): $f — chmod 644 it before ship"
        done
    else
        pass "All resources/defaults/ files are world-readable"
    fi
fi

# --- 6. pip-quoting stray files ---
stray="$(find "$AUDIT_ROOT" -type f \( -name '=*' -o -name '>=*' -o -name '<=*' \) 2>/dev/null)"
if [ -n "$stray" ]; then
    echo "$stray" | while read -r f; do
        fail "pip-quoting stray file: $f"
    done
else
    pass "No pip-quoting stray files"
fi

# --- 7. macOS/Python noise in payload ---
noise="$(find "$PAYLOAD" -type f \( -name '.DS_Store' -o -name '*.pyc' -o -name '*.pyo' \) 2>/dev/null)"
if [ -n "$noise" ]; then
    # Here-string (no pipe) so fail() sets FAIL in THIS shell, not a
    # subshell. The [ -n "$f" ] guard skips the empty trailing line a
    # here-string yields. (A `... | while` pipe runs the loop in a
    # subshell, so FAIL=1 would be lost and the build would falsely PASS.)
    while IFS= read -r f; do
        [ -n "$f" ] && fail "noise file in payload: $f"
    done <<< "$noise"
else
    pass "No .DS_Store / .pyc noise in payload"
fi

# --- 8. Forbidden learner plist (legacy, removed in v1.5) ---
# This rule checks that no PLIST or DISTRIBUTION file shipped in the .pkg
# invokes the removed com.mailwarden.learn agent. Python modules that
# reference the label only to UNLOAD stale v1.4 files (see bootstrap.py,
# launchd_install.py) are intentional cleanup code and are exempted.
if find "$AUDIT_ROOT" \
        \( -name '*.plist' -o -name '*.plist.example' \
           -o -name 'distribution.xml' \) \
        -not -path '*/build/*' -not -path '*/dist/*' \
        -not -path '*/MailWarden.app/*' -not -path '*/.git/*' \
        -exec grep -l 'com\.mailwarden\.learn' {} \; 2>/dev/null | grep -q .; then
    fail "Reference to removed com.mailwarden.learn found in a plist/distribution file"
else
    pass "No com.mailwarden.learn references in plist/distribution files"
fi

echo
if [ $FAIL -ne 0 ]; then
    echo "====================================="
    echo "AUDIT FAILED — do not ship this build"
    echo "====================================="
    exit 1
fi
echo "====================="
echo "AUDIT PASSED"
echo "====================="
exit 0
