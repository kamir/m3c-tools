#!/usr/bin/env python3
"""windows-trust-parity.py — drift guard for the opt-out Windows trust surface.

Compares two `go test -json` event streams (a Linux run and a Windows run of the
SAME package set: ./pkg/skillctl/... ./cmd/skillctl/... ./evaluation/...) and
fails if the Windows run executed materially FEWER tests than the Linux run.

Why this exists
---------------
The windows-gate workflow runs the whole trust surface WHOLE-PACKAGE on Windows
(no -run allow-list). That alone guarantees new trust tests are picked up. This
script is the second belt: it catches a silent regression where tests stop
*executing* on Windows (e.g. a package fails to build there, or a sweeping
build-tag hides a chunk of tests) even though the workflow text still looks
opt-out.

What counts as "executed"
-------------------------
Every top-level test that reaches a terminal action — pass, fail, OR skip — is
counted as executed. A platform-gated test that calls t.Skip("…windows…") STILL
COUNTS: it ran, made its decision, and skipped. So legitimate platform self-skips
do NOT widen the gap; only a test that never ran at all (missing/!build) does.

Self-skip allowance
-------------------
The trust surface today has NO live-external-service tests (every server is an
in-process httptest fake), so the Linux and Windows executed-counts should match
almost exactly. We allow a small slack (ALLOWANCE) for the handful of tests that
are present on one OS's run but legitimately absent on the other (e.g. a future
Unix-only helper test guarded by a build tag). If Windows trails Linux by more
than ALLOWANCE executed tests, that's drift → fail.

Usage:  windows-trust-parity.py <linux.json> <windows.json>
"""

import json
import sys

# Max number of tests Windows may execute fewer-of than Linux before we treat
# the gap as drift. Kept small on purpose: the trust surface is self-contained,
# so the honest gap is ~0. Bump this ONLY with a comment explaining the new
# legitimately-OS-specific tests.
ALLOWANCE = 5


def executed_tests(path):
    """Return the set of executed top-level tests as 'pkg::Test' keys.

    A test is 'executed' if it emitted a terminal pass/fail/skip action. We key
    on (package, top-level test name) and ignore subtests so that a differing
    number of table-driven subtests between OSes never trips the guard.
    """
    executed = set()
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    # `go test -json` can interleave non-JSON build output.
                    continue
                action = ev.get("Action")
                test = ev.get("Test")
                pkg = ev.get("Package", "")
                if test is None:
                    continue  # package-level event, not a test
                if action not in ("pass", "fail", "skip"):
                    continue
                top = test.split("/", 1)[0]  # collapse subtests
                executed.add(f"{pkg}::{top}")
    except FileNotFoundError:
        print(f"ERROR: report not found: {path}", file=sys.stderr)
        sys.exit(2)
    return executed


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    linux = executed_tests(argv[1])
    windows = executed_tests(argv[2])

    n_lin, n_win = len(linux), len(windows)
    missing_on_windows = sorted(linux - windows)
    gap = n_lin - n_win

    print(f"Linux executed tests:   {n_lin}")
    print(f"Windows executed tests: {n_win}")
    print(f"Gap (Linux - Windows):  {gap}  (allowance: {ALLOWANCE})")

    if missing_on_windows:
        print(f"\nTests executed on Linux but NOT on Windows ({len(missing_on_windows)}):")
        for t in missing_on_windows[:50]:
            print(f"  - {t}")
        if len(missing_on_windows) > 50:
            print(f"  … and {len(missing_on_windows) - 50} more")

    # Drift = Windows executed materially fewer tests than Linux.
    if gap > ALLOWANCE:
        print(
            f"\n::error::Windows trust surface executed {gap} fewer tests than "
            f"Linux (allowance {ALLOWANCE}). Tests are silently not running on "
            f"Windows — investigate a build break or an over-broad build tag.",
            file=sys.stderr,
        )
        return 1

    print("\nOK: Windows trust-surface parity within allowance.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
