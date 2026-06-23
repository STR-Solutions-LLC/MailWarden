#!/usr/bin/env python3
# (c) 2026 STR Solutions, LLC. All rights reserved.
"""
Failing-first tests for the 4 new hard-fail checks in scripts/audit_payload.sh (§7b).

Run with:
  cd <repo-root>
  python -m pytest tests/test_audit_new_checks.py -v

Each test:
  1. Plants a bad artifact in payload/MailWarden/
  2. Runs the audit script (AUDIT_ROOT=repo root)
  3. Asserts the expected FAIL line appears in output and exit code is nonzero
  4. Cleans up the artifact
"""
import os
import subprocess
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.resolve()
AUDIT_SCRIPT = REPO_ROOT / "scripts" / "audit_payload.sh"
PAYLOAD = REPO_ROOT / "payload" / "MailWarden"


def run_audit():
    result = subprocess.run(
        ["bash", str(AUDIT_SCRIPT)],
        capture_output=True, text=True,
        env={**os.environ, "AUDIT_ROOT": str(REPO_ROOT)},
    )
    return result.returncode, result.stdout, result.stderr


def test_lock_file_detected():
    """Plant a .lock file → audit must FAIL with .lock sidecar message."""
    lock_file = PAYLOAD / "memory" / "_test_audit.lock"
    try:
        lock_file.parent.mkdir(parents=True, exist_ok=True)
        lock_file.write_text("")
        rc, out, err = run_audit()
        assert rc != 0, "audit should have failed with .lock file present"
        combined = out + err
        assert ".lock sidecar" in combined, f"Expected '.lock sidecar' in output; got:\n{combined}"
    finally:
        lock_file.unlink(missing_ok=True)


def test_claude_mpm_dir_detected():
    """Plant a .claude-mpm dir → audit must FAIL with .claude-mpm message."""
    mpm_dir = PAYLOAD / "memory" / ".claude-mpm"
    try:
        mpm_dir.mkdir(parents=True, exist_ok=True)
        rc, out, err = run_audit()
        assert rc != 0, "audit should have failed with .claude-mpm dir present"
        combined = out + err
        assert ".claude-mpm/" in combined, f"Expected '.claude-mpm/' FAIL in output; got:\n{combined}"
    finally:
        if mpm_dir.is_dir():
            shutil.rmtree(str(mpm_dir))


def test_nonempty_log_detected():
    """Plant a non-empty log file → audit must FAIL with non-empty log message."""
    log_file = PAYLOAD / "logs" / "_test_audit.log"
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("test log line\n")
        rc, out, err = run_audit()
        assert rc != 0, "audit should have failed with non-empty log file present"
        combined = out + err
        assert "non-empty log file" in combined, f"Expected 'non-empty log file' in output; got:\n{combined}"
    finally:
        log_file.unlink(missing_ok=True)


def test_false_positives_detected():
    """Plant a file in false_positives/ → audit must FAIL with false_positives message."""
    fp_dir = PAYLOAD / "false_positives"
    fp_file = fp_dir / "_test_audit.eml"
    try:
        fp_dir.mkdir(parents=True, exist_ok=True)
        fp_file.write_text("test")
        rc, out, err = run_audit()
        assert rc != 0, "audit should have failed with false_positives file present"
        combined = out + err
        assert "false_positives" in combined, f"Expected 'false_positives' FAIL in output; got:\n{combined}"
    finally:
        fp_file.unlink(missing_ok=True)
        if fp_dir.is_dir() and not any(fp_dir.iterdir()):
            fp_dir.rmdir()
