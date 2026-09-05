#!/usr/bin/env bash
#
# trust-coverage.sh measures STATEMENT coverage of the trust decision path.
#
# It exists because a first attempt at this number was wrong in the direction
# that would have embarrassed us. Measuring `go test ./pkg/skillctl/registry/...`
# reported PullBundlesFromBackend, the function containing the whole gate
# composition, at 0.0 percent, and the obvious conclusion, that the decision
# function is untested, was false. It is exercised by end-to-end tests in
# cmd/skillctl, and per-package coverage cannot see across that boundary.
#
# So the measurement uses -coverpkg deliberately, and it names both numbers,
# because the difference between them is itself worth knowing: a decision
# function with no unit test and good e2e coverage is a different risk from one
# with neither.
#
# WHAT THIS IS NOT: it is not MC/DC. Statement coverage says a line ran. MC/DC
# asks whether each condition inside a decision was shown to independently change
# the outcome, and cmd/structural reports how large that obligation is. The two
# numbers are reported apart on purpose; neither substitutes for the other.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

SCOPE_REGEX='backend_pull\.go|install_trust_mode\.go|attest_quorum\.go|backend/git/git\.go'
OUT=$(mktemp -t trustcov)
trap 'rm -f "$OUT"' EXIT

echo "trust path statement coverage"
echo

echo "  measured across package boundaries (-coverpkg), which is the honest number:"
if ! go test ./cmd/skillctl/... ./pkg/skillctl/registry/... ./pkg/skillctl/backend/git/... \
  -count=1 -coverpkg=./pkg/skillctl/registry/...,./pkg/skillctl/backend/git/... \
  -coverprofile="$OUT" >/dev/null 2>&1; then
  echo "  FAILED: the test run did not complete; no coverage number is produced." >&2
  exit 1
fi

go tool cover -func="$OUT" 2>/dev/null | grep -E "$SCOPE_REGEX" | \
  awk -F'\t+' '{gsub("%","",$NF); s+=$NF; n++} END {
    if (n) printf "    %d functions in scope, mean %.1f%%\n", n, s/n
    else   print  "    no functions matched the scope: check SCOPE_REGEX"
  }'

echo
echo "  functions in scope with zero coverage:"
z=$(go tool cover -func="$OUT" 2>/dev/null | grep -E "$SCOPE_REGEX" | grep -c "	0.0%")
if [ "$z" -eq 0 ]; then
  echo "    none"
else
  go tool cover -func="$OUT" 2>/dev/null | grep -E "$SCOPE_REGEX" | grep "	0.0%" | \
    sed 's|.*/pkg/skillctl/|    |'
fi

echo
echo "  the decision function itself:"
go tool cover -func="$OUT" 2>/dev/null | grep "PullBundlesFromBackend" | \
  sed 's|.*/pkg/skillctl/|    |'

echo
echo "  Statement coverage says a line ran. It does not say a condition was shown"
echo "  to matter. Run cmd/structural for the MC/DC obligation, and report the two"
echo "  numbers separately: neither one substitutes for the other."
