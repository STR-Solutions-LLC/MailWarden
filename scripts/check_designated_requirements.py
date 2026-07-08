#!/usr/bin/env python3
"""Designated-requirement gate for the Keychain migration (design plan §4.2).

Keychain ACL trust for MailWarden's two shipped executables is anchored on each
one's code-signing *designated requirement* (DR) — specifically its identifier
plus the STR Solutions team OU (6BXSAHWH29) — and NOT on a cdhash. A Developer-ID
re-sign by the same team produces the same DR, so keychain items created by one
release stay readable by the next without a prompt (this is how the design
resolves risk #2, "re-sign survival"). That guarantee holds ONLY while both
identifiers never change once the first keychain release ships.

This gate freezes them. ``build_installer.sh`` runs it after Developer-ID
signing and the build DIES if either executable's DR drifts from the frozen
expectation (an identifier rename, a wrong team, or an ad-hoc signature that
never carries the anchor at all).

Design decision (recorded in the batch report): this is a Python helper rather
than inline shell so the parser is unit-testable headless with no bundle — the
pure functions ``evaluate_requirement`` / ``check_targets`` take codesign output
as text, and only ``main`` shells out to ``codesign -d -r-`` for real artifacts.
It joins the existing ``scripts/*.py`` build-helper precedent (set_pkg_icon.py).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

TEAM_OU = "6BXSAHWH29"

# Frozen identifiers — see design plan §4.2 and decision §12.4. Changing either
# of these after the first keychain release ships strands every keychain item
# created by earlier releases (their stored DRs stop matching). If a change is
# ever genuinely required it must be a deliberate, reviewed edit here paired
# with the item-re-creation migration the design describes — never an accident.
#
# NOTE (batch-4 ground-truth correction): the bundled interpreter's real,
# Developer-ID-signed identifier is the bare "python", NOT "org.python.python".
# The nested-signing loop runs `codesign --force --sign <DevID>` with no `-i`,
# so codesign derives the identifier from the basename ("python"). Every past
# notarized beta shipped it this way; the design doc's "org.python.python" was
# taken from python.org's framework binary / a pre-signing copy, not the final
# signed MacOS/python. Freezing on the real value honours §12.4's intent (keep
# what every past beta already carries) — see the plan's batch-4 correction note.
FROZEN = {
    "app": "com.strsolutions.mailwarden",
    "python": "python",
}


def evaluate_requirement(dr_text: str, expected_identifier: str,
                         expected_team: str = TEAM_OU) -> list:
    """Return a list of human-readable problems with this DR; an empty list
    means it satisfies the frozen expectation.

    A DR satisfies the expectation only when the requirement text pins BOTH the
    exact identifier and the team OU. An ad-hoc DR (``cdhash H"…"``) pins
    neither, so it fails — which is the entire point: an ad-hoc dev build must
    never be mistaken for a shippable, keychain-trusted build.
    """
    problems: list = []
    # codesign renders a "simple" identifier (bare word, e.g. `python`) UNQUOTED
    # and a dotted/special identifier (e.g. `com.strsolutions.mailwarden`) QUOTED.
    # Accept either form, anchored on the `identifier ` keyword and a trailing
    # boundary so `python` does not spuriously match `python3`.
    id_pattern = r'identifier\s+"?' + re.escape(expected_identifier) + r'"?(?=\s|$)'
    if re.search(id_pattern, dr_text) is None:
        problems.append('missing identifier %s' % expected_identifier)
    # codesign renders the team clause as `certificate leaf[subject.OU] = "…"`.
    # Accept that exact rendering or a bare quoted team OU, so a future codesign
    # formatting tweak cannot cause a false build failure while the team string
    # must still be present.
    ou_needle = 'subject.OU] = "%s"' % expected_team
    quoted_team = '"%s"' % expected_team
    if ou_needle not in dr_text and quoted_team not in dr_text:
        problems.append('missing team OU "%s"' % expected_team)
    return problems


def check_targets(dr_by_target: dict, expected_by_target: dict,
                  expected_team: str = TEAM_OU) -> dict:
    """Evaluate several targets at once. Returns ``{target: problems}``; a
    target with an empty problem list passed. The overall gate passes iff every
    target passed. A target with no DR output at all is a failure (a missing or
    unsigned binary must not slip through as "no problems")."""
    result: dict = {}
    for target, expected_identifier in expected_by_target.items():
        dr_text = dr_by_target.get(target, "")
        if not dr_text.strip():
            result[target] = [
                "no designated-requirement output (missing or unsigned binary?)"]
            continue
        result[target] = evaluate_requirement(
            dr_text, expected_identifier, expected_team)
    return result


def read_designated_requirement(path: str) -> str:
    """Run ``codesign -d -r- <path>`` and return its combined output. The
    designated requirement prints as a ``# designated => …`` line; other ``-d``
    detail is noise the parser ignores. stdout and stderr are joined because
    codesign has historically split this information across both streams."""
    proc = subprocess.run(
        ["/usr/bin/codesign", "-d", "-r-", path],
        capture_output=True, text=True)
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Freeze the Keychain trust-anchor designated requirements "
                    "(design plan §4.2).")
    parser.add_argument("app", help="path to the signed MailWarden.app bundle")
    parser.add_argument("--expect-app-identifier", default=FROZEN["app"],
                        help="frozen identifier for Contents/MacOS/MailWarden")
    parser.add_argument("--expect-python-identifier", default=FROZEN["python"],
                        help="frozen identifier for Contents/MacOS/python")
    parser.add_argument("--expect-team", default=TEAM_OU,
                        help="frozen Developer ID team OU")
    args = parser.parse_args(argv)

    app_path = Path(args.app)
    targets = {
        "app": str(app_path),
        "python": str(app_path / "Contents" / "MacOS" / "python"),
    }
    expected = {
        "app": args.expect_app_identifier,
        "python": args.expect_python_identifier,
    }

    dr_by_target = {
        name: read_designated_requirement(p) for name, p in targets.items()
    }
    results = check_targets(dr_by_target, expected, args.expect_team)

    ok = True
    for name in ("app", "python"):
        problems = results.get(name, ["<not evaluated>"])
        if problems:
            ok = False
            print("FAIL  %s (%s):" % (name, targets[name]))
            for p in problems:
                print("        - %s" % p)
        else:
            print("OK    %s (%s): DR pins identifier %r + team %s"
                  % (name, targets[name], expected[name], args.expect_team))

    if not ok:
        print("Designated-requirement gate FAILED — keychain trust anchor "
              "drifted. Do not ship.")
        return 1
    print("Designated-requirement gate PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
