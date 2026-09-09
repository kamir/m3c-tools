#!/usr/bin/env bash
# check-no-real-names.sh: fail if a real person's name appears in the tracked tree.
#
# The rule: examples, fixtures, tutorials and test identities use the standard
# cast (Alice, Bob, Charlie, Diana, Eddy, Freddy, Gustav, Hans), never the name
# of an actual colleague, customer or contact.
#
# Why a mechanical gate and not a review habit, the same argument as the em dash
# next door: a name reaches the public tree through a hundred small additions,
# each of which looks harmless on its own. A reviewer catches the ones in prose
# and misses the ones in a test fixture, a file name, or a shell variable. This
# repository is public and mirrored into a customer's GitLab; a persona that is
# also a real person turns example output into a statement about that person.
#
# Usage:
#   ./scripts/check-no-real-names.sh            # the gate (exit 1 on any hit)
#   ./scripts/check-no-real-names.sh --staged   # only files staged for commit
#   ./scripts/check-no-real-names.sh --all      # also report the exempt lines
#
# ---------------------------------------------------------------------------
# WHAT THIS GATE DOES NOT DO, deliberately.
#
# It does not touch AUTHORSHIP. A git commit author, a copyright line and the
# publisher field of a signed installer name a real legal person because that is
# their job. Replacing those with a persona would not anonymise anything, it
# would falsify provenance, and in a repository whose subject is provenance that
# is the worse failure. The exemptions below are that distinction written down.
#
# It also does not catch a name nobody added to this list. The list is the
# gate's whole knowledge, so extending it is part of onboarding a new contact,
# not an afterthought.
# ---------------------------------------------------------------------------
set -euo pipefail

# The names to refuse. One per line, matched case-insensitively on word
# boundaries, so "generic" does not trip on "eric".
NAMES='Mirko|Eric|Kaempf|Kämpf|Frank'

# Exempt LINES, not paths, because three of these four files also carry ordinary
# example text that the gate must keep checking. Each pattern is anchored to
# what makes the line legitimate, not merely to the name in it:
#
#   PRODUCT_PUBLISHER      the publisher of a signed Windows installer. This is
#                          a legal attribution and it must match the signing
#                          certificate; a persona here would be a false claim.
#   GCP_ACCOUNT / GCP Account
#                          a functional account id in the certificate-renewal
#                          runbook. Not a persona: the procedure fails without
#                          the real value, and it is needed under time pressure.
#   KAMIR_EMAIL            the contact address the publisher runbook fills in.
#   plaudDeferForTranscript
#                          a transcript fixture. The string is INPUT to the
#                          function under test, and it is a real sentence a real
#                          person said, which is what makes it a good fixture.
#
# Every one of these is a candidate for removal rather than exemption, and the
# first three carry a live address. They are listed here so the gate can go
# green today without that decision being made silently.
EXEMPT_LINES='(PRODUCT_PUBLISHER|GCP_ACCOUNT|GCP Account|KAMIR_EMAIL|plaudDeferForTranscript)'

# Exempt paths: this file names every forbidden name, by construction.
EXEMPT_PATHS='^(scripts/check-no-real-names\.sh)$'

MODE="${1:-}"
case "$MODE" in
  --staged) FILES=$(git diff --cached --name-only --diff-filter=ACM) ;;
  --all)    FILES=$(git ls-files --cached --others --exclude-standard) ;;
  "")       FILES=$(git ls-files --cached --others --exclude-standard) ;;
  *) echo "usage: $0 [--staged|--all]" >&2; exit 2 ;;
esac

FILES=$(printf '%s\n' "$FILES" | grep -Ev "$EXEMPT_PATHS" || true)
[ -n "$FILES" ] || { echo "PASS: nothing to check."; exit 0; }

# plain grep rather than `git grep`, for two reasons. A file that is new and not
# staged yet is checked too. And `git grep -E` does NOT understand \b: it
# matches nothing and reports success, which is the most dangerous answer a gate
# can give. -w asks for the word boundary in a way both tools agree on.
HITS=$(printf '%s\n' "$FILES" | tr '\n' '\0' \
  | xargs -0 grep -I -n -w -E -H -i -e "$NAMES" -- 2>/dev/null || true)

[ "$MODE" = "--all" ] || HITS=$(printf '%s\n' "$HITS" | grep -Ev "$EXEMPT_LINES" || true)

# File NAMES carry personas too, and no content grep would ever see them.
PATHHITS=$(printf '%s\n' "$FILES" | grep -iE "(^|/|-|_)($NAMES)(-|_|\.|/|$)" || true)

COUNT=$(printf '%s\n' "$HITS"     | grep -c . || true)
PCOUNT=$(printf '%s\n' "$PATHHITS" | grep -c . || true)

if [ "$COUNT" -eq 0 ] && [ "$PCOUNT" -eq 0 ]; then
  echo "PASS: no real names in the tracked tree."
  exit 0
fi

echo "ERROR: a real person's name is not allowed in this public repository."
echo ""
[ "$COUNT" -gt 0 ] && { echo "$COUNT line(s):"; printf '%s\n' "$HITS" | sed 's/^/  /'; echo ""; }
[ "$PCOUNT" -gt 0 ] && { echo "$PCOUNT file name(s):"; printf '%s\n' "$PATHHITS" | sed 's/^/  /'; echo ""; }
cat <<'GUIDE'
Use the standard cast instead, and keep the roles stable across the tree:

  Bob      the author: packs, signs, publishes
  Alice    the recipient: pins trust, verifies, installs
  Charlie  a reviewer or attester
  Diana    a registry or governance operator
  Eddy, Freddy, Gustav, Hans   further parties as needed

An identity id follows the same rule: id:bob@example, id:alice@example.

If the name belongs to AUTHORSHIP rather than to an example (a commit author, a
copyright holder, the publisher of a signed installer), it does not belong to a
persona either. Add the line to EXEMPT_LINES in this script with the reason,
rather than replacing a true attribution with a false one.
GUIDE
exit 1
