#!/usr/bin/env bash
# check-no-emdash.sh: fail if U+2014 EM DASH appears anywhere in the tracked tree.
#
# Why a mechanical gate and not a review habit: the em dash is the single
# strongest stylistic fingerprint of machine-written text, and a repository that
# sells provenance should not read like it was generated. A human reviewer finds
# maybe half of them; git grep finds all of them.
#
# Usage:
#   ./scripts/check-no-emdash.sh            # the gate (exit 1 on any hit)
#   ./scripts/check-no-emdash.sh --staged   # only files staged for commit
#   ./scripts/check-no-emdash.sh --all      # also report the exempt paths
#
# The rule and the replacement table live in CODESTYLE.md.
set -euo pipefail

EM=$(printf '\xe2\x80\x94')   # U+2014 EM DASH
EN=$(printf '\xe2\x80\x93')   # U+2013 EN DASH

# Exempt paths, each for a reason that is about bytes, not about prose:
#   pkg/skillctl/bodyscan/testdata/  scanner corpus; the fixtures ARE the input
#                                    under test, and .expected.json pins offsets
#   demo/kup-training/artifacts/     checked-in generated demo output, including
#                                    signed bundles and digests that would break
EXEMPT='^(pkg/skillctl/bodyscan/testdata/|demo/kup-training/artifacts/)'

MODE="${1:-}"
case "$MODE" in
  --staged) FILES=$(git diff --cached --name-only --diff-filter=ACM) ;;
  --all)    FILES=$(git ls-files --cached --others --exclude-standard) ;;
  "")       FILES=$(git ls-files --cached --others --exclude-standard) ;;
  *) echo "usage: $0 [--staged|--all]" >&2; exit 2 ;;
esac

[ "$MODE" = "--all" ] || FILES=$(printf '%s\n' "$FILES" | grep -Ev "$EXEMPT" || true)
[ -n "$FILES" ] || { echo "PASS: nothing to check."; exit 0; }

# plain grep rather than `git grep`, so a new file that is not staged yet is
# checked too. -I skips binaries, -F is a literal match, -n gives the line.
scan() {
  printf '%s\n' "$FILES" | tr '\n' '\0' \
    | xargs -0 grep -I -n -F -H -e "$1" -- 2>/dev/null || true
}
HITS=$(scan "$EM")
NOTE=$(scan "$EN")

if [ -n "$NOTE" ]; then
  N=$(printf '%s\n' "$NOTE" | wc -l | tr -d ' ')
  echo "NOTE: $N line(s) contain an en dash (U+2013). Not a failure: it is legal"
  echo "      in a numeric or date range (10-19), never as sentence punctuation."
  [ "$MODE" = "--all" ] && printf '%s\n' "$NOTE"
  echo ""
fi

if [ -n "$HITS" ]; then
  COUNT=$(printf '%s\n' "$HITS" | wc -l | tr -d ' ')
  echo "ERROR: em dash (U+2014) is not allowed. $COUNT line(s):"
  echo ""
  printf '%s\n' "$HITS"
  echo ""
  echo "Replace it by what the sentence is actually doing (CODESTYLE.md):"
  echo "  label, then its expansion       'A - YouTube'        -> 'A: YouTube'"
  echo "  two independent statements      'X works - Y does'   -> 'X works. Y does.'"
  echo "  an aside inside one sentence    'X - and Y - is Z'   -> 'X, and Y, is Z'"
  echo "  a continuation or afterthought  'X - not Y'          -> 'X, not Y'"
  echo "  an empty table cell             '| - |'              -> '| n/a |'"
  echo "Never a blind swap to a hyphen: pick the punctuation the clause needs."
  exit 1
fi

echo "PASS: no em dash (U+2014) in the tracked tree."
