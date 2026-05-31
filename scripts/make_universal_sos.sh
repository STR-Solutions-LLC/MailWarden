#!/bin/bash
# (c) 2026 STR Solutions, LLC. All rights reserved.
#
# For every .so inside the built .app that is NOT already universal2,
# download the wheel for the missing architecture, extract its .so, and
# lipo-fuse with the one in the bundle. Result: every native extension
# becomes a true universal2 fat binary.
#
# Without this step, pip installs wheels matching the BUILD machine's
# architecture only. On an Apple Silicon build machine, pydantic_core
# and jiter (anthropic's Rust deps) ship as arm64-only .so files. The
# resulting .app loads fine on Apple Silicon but crashes with an
# import error on Intel.
#
# Idempotent — re-running only touches .so files that still need fusing.

set -u

APP="$1"
if [ -z "$APP" ] || [ ! -d "$APP" ]; then
    echo "usage: $0 <path to MailWarden.app>" >&2
    exit 2
fi

LIB="$APP/Contents/Resources/lib/python3.12"
WORK="$(mktemp -d -t mailwarden-lipo-XXXXXX)"
trap "rm -rf '$WORK'" EXIT

log() { printf "\033[1;36m[lipo]\033[0m %s\n" "$*"; }

# Build: (so_relpath, pkg_spec) list of extensions that pip-install as single-arch.
# Expand this list whenever a new arch-specific .so shows up in the audit.
NEED_FUSE=(
    "pydantic_core/_pydantic_core.cpython-312-darwin.so::pydantic-core"
    "jiter/jiter.cpython-312-darwin.so::jiter"
)

# Find every .so that lacks x86_64 or arm64. Catches anything we missed.
log "Scanning bundle for non-universal .so files..."
MISSING=""
while IFS= read -r f; do
    archs="$(/usr/bin/file "$f" | grep -oE 'arm64|x86_64' | sort -u | tr '\n' ' ')"
    if [ "$archs" != "arm64 x86_64 " ] && [ "$archs" != "x86_64 arm64 " ]; then
        rel="${f#$LIB/}"
        echo "  ! $rel ($archs)"
        MISSING="$MISSING$rel\n"
    fi
done < <(find "$LIB" -name "*.so")

if [ -z "$MISSING" ]; then
    log "All .so files already universal2."
    exit 0
fi

# Determine our current arch. We want wheels for the OPPOSITE arch.
CUR_ARCH="$(uname -m)"
case "$CUR_ARCH" in
    arm64)  NEED_PLATFORM="macosx_11_0_x86_64" ;;
    x86_64) NEED_PLATFORM="macosx_11_0_arm64" ;;
    *)      echo "unknown arch: $CUR_ARCH" >&2; exit 1 ;;
esac
log "Build arch: $CUR_ARCH; fetching wheels for: $NEED_PLATFORM"

# Resolve the build venv's pip so we can pin downloads to the EXACT version
# already installed for arm64. Without pinning, `pip download` grabs the
# latest PyPI release — so if pydantic-core (or any NEED_FUSE pkg) ships a
# new version between venv-refresh and build, we fuse mismatched archs and
# the x86_64 runtime gate fails with "incompatible version" errors.
VENV_PIP="$(cd "$(dirname "$0")/.." && pwd)/app/build-venv/bin/pip"
if [ ! -x "$VENV_PIP" ]; then
    echo "ERROR: build venv pip not found at $VENV_PIP" >&2
    exit 1
fi

# Look up the installed version of $1 in the build venv. Echoes "X.Y.Z".
venv_version() {
    "$VENV_PIP" show "$1" 2>/dev/null | awk '/^Version:/ {print $2}'
}

cd "$WORK"
for entry in "${NEED_FUSE[@]}"; do
    rel_so="${entry%%::*}"
    pkg="${entry##*::}"
    target="$LIB/$rel_so"
    if [ ! -f "$target" ]; then
        log "  (skip $pkg — $rel_so not present)"
        continue
    fi
    pinned_version="$(venv_version "$pkg")"
    if [ -z "$pinned_version" ]; then
        echo "ERROR: $pkg not installed in build venv; cannot pin x86_64 wheel version" >&2
        exit 1
    fi
    log "Fusing $pkg==$pinned_version ($rel_so)..."

    # pip download only_binary for the OPPOSITE platform, pinned to the
    # version already installed in the arm64 venv.
    rm -rf "$WORK/wheel-$pkg"
    mkdir -p "$WORK/wheel-$pkg"
    if ! pip download \
            --only-binary=:all: \
            --no-deps \
            --platform "$NEED_PLATFORM" \
            --python-version 3.12 \
            --dest "$WORK/wheel-$pkg" \
            --quiet \
            "$pkg==$pinned_version" 2>&1 | tail -3; then
        echo "ERROR: pip download failed for $pkg==$pinned_version ($NEED_PLATFORM)" >&2
        exit 1
    fi
    wheel_file="$(ls "$WORK/wheel-$pkg"/*.whl | head -1)"
    if [ -z "$wheel_file" ]; then
        echo "ERROR: no wheel produced for $pkg" >&2
        exit 1
    fi

    # Extract the .so for the opposite arch from the wheel.
    rm -rf "$WORK/extract-$pkg"
    mkdir -p "$WORK/extract-$pkg"
    unzip -q "$wheel_file" -d "$WORK/extract-$pkg"
    other_so="$WORK/extract-$pkg/$rel_so"
    if [ ! -f "$other_so" ]; then
        # Some wheels flatten the path — search.
        other_so="$(find "$WORK/extract-$pkg" -name "$(basename "$rel_so")" | head -1)"
    fi
    if [ ! -f "$other_so" ]; then
        echo "ERROR: opposite-arch .so not found in $wheel_file" >&2
        exit 1
    fi

    # lipo-fuse. Output to a tmp then replace atomically.
    fused="$WORK/$(basename "$rel_so").fused"
    if ! /usr/bin/lipo -create "$target" "$other_so" -output "$fused"; then
        echo "ERROR: lipo -create failed for $target" >&2
        exit 1
    fi
    mv "$fused" "$target"

    # Verify the result really is universal2. Without this check, a silent
    # lipo failure or a wheel that unexpectedly shipped a single-arch .so
    # leaves us shipping a broken bundle — we'd only discover it ~20
    # minutes later when the x86_64 runtime gate fails.
    archs_now="$(/usr/bin/file "$target" | grep -oE 'arm64|x86_64' | sort -u | tr '\n' ' ')"
    if [ "$archs_now" != "arm64 x86_64 " ] && [ "$archs_now" != "x86_64 arm64 " ]; then
        echo "ERROR: post-lipo $rel_so is not universal2 (archs: '$archs_now')" >&2
        exit 1
    fi
    log "  -> $rel_so: $archs_now"
done

# Final sweep: any remaining single-arch .so in the bundle is a failure we
# must catch NOW, not at the runtime gate. NEED_FUSE only covers known
# Rust extensions; a new dep could ship single-arch and slip through.
log "Post-fuse sweep: verifying every .so is universal2..."
REMAINING=""
while IFS= read -r f; do
    archs="$(/usr/bin/file "$f" | grep -oE 'arm64|x86_64' | sort -u | tr '\n' ' ')"
    if [ "$archs" != "arm64 x86_64 " ] && [ "$archs" != "x86_64 arm64 " ]; then
        rel="${f#$LIB/}"
        echo "  STILL SINGLE-ARCH: $rel ($archs)" >&2
        REMAINING="$REMAINING$rel\n"
    fi
done < <(find "$LIB" -name "*.so")
if [ -n "$REMAINING" ]; then
    echo "ERROR: one or more .so files are still single-arch after fusion." >&2
    echo "Add them to NEED_FUSE in scripts/make_universal_sos.sh." >&2
    exit 1
fi

log "Done fusing. Every .so is universal2."
