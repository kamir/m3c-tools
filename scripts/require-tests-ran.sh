#!/usr/bin/env bash
# require-tests-ran.sh -- run named Go tests and FAIL if they did not run.
#
# Why this exists: `go test -run <pattern>` exits 0 when the pattern matches
# nothing. It prints "[no tests to run]" and the job goes green. A gate built on
# a bare `-run` is therefore one rename away from certifying nothing, and the
# rename need not be malicious: a refactor is enough.
#
# WORKING-RULES B6 and B9: the number of evaluated gates comes from the RUN, not
# from the declaration, and "green" is a statement about the gates that ran.
#
# Usage: require-tests-ran.sh <package> <TestName> [TestName...]
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <package> <TestName> [TestName...]" >&2
  exit 2
fi

pkg="$1"; shift
names=("$@")

pattern="^($(IFS='|'; echo "${*}"))$"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

# -json so the check reads structured events instead of guessing from prose.
set +e
go test -count=1 -json -run "$pattern" "$pkg" >"$out" 2>&1
status=$?
set -e

# Echo the human-readable form so a failing test is still readable in the log.
python3 - "$out" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        print(line)
        continue
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        print(line)
        continue
    if e.get("Action") == "output":
        sys.stdout.write(e.get("Output", ""))
PY

missing=()
for n in "${names[@]}"; do
  if ! python3 - "$out" "$n" <<'PY'
import json, sys
path, want = sys.argv[1], sys.argv[2]
for line in open(path, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        continue
    # Only a run/pass/fail event for the exact test name counts. "no tests to
    # run" produces none of these, which is the whole point.
    if e.get("Test") == want and e.get("Action") in ("run", "pass", "fail"):
        sys.exit(0)
sys.exit(1)
PY
  then
    missing+=("$n")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  echo "" >&2
  echo "GATE REFUSED: ${#missing[@]} of ${#names[@]} required tests never ran in $pkg:" >&2
  for n in "${missing[@]}"; do echo "  $n" >&2; done
  echo "" >&2
  echo "A test that does not run cannot have passed. Either the name changed" >&2
  echo "and this list is stale, or the test is gone. Both are findings." >&2
  exit 1
fi

echo "ausgewertet ${#names[@]} von ${#names[@]} geforderten Tests in $pkg, go test exit ${status}"
exit "$status"
