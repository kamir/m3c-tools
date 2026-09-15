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

# The German genitive is the SAME name, and `-w` alone does not think so:
# "Mirkos Skill" has a word character after the name, so the word-anchored pass
# reports nothing. That is not a hypothetical. The first rename pass left 18
# such lines standing (6 in the acceptance matrix, 11 in the tutorials, and one
# doc anchor left dangling by a heading that WAS renamed), and the gate called
# the tree clean.
# The trailing `s` stays INSIDE the -w match, so both ends are still anchored
# and "generics" is still not a hit.
NAMES_WORD="($NAMES)s?"

# A name also hides inside an identifier, where there is no word boundary at
# all: `fromMirko`, `$MirkoHome`. Those two forms need their own pass, and that
# pass is deliberately case-SENSITIVE. Case-insensitively, `[a-z]eric` would
# match "generic" and "numeric" on every line of prose in the tree; anchored to
# the capital that a camelCase name must carry, the same pattern matched
# exactly 12 lines here (10 Go, 2 PowerShell) and nothing innocent.
#
# The name must also END the identifier part, or "getFrankfurtData" becomes a
# hit: a lowercase letter directly after the name means the name was never
# there. Measured, not assumed: without that guard the pattern flagged it.
CAMEL="[a-z0-9_]($NAMES)([^a-z]|$)|($NAMES)[A-Z]"

# Exempt LINES, not paths, because both files also carry ordinary example text
# that the gate must keep checking. Each pattern is anchored to what makes the
# line legitimate, not merely to the name in it:
#
#   PRODUCT_PUBLISHER      the publisher of a signed Windows installer. This is
#                          a legal attribution and it must match the signing
#                          certificate; a persona here would be a false claim.
#   plaudDeferForTranscript
#                          a transcript fixture. The string is INPUT to the
#                          function under test, and it is a real sentence a real
#                          person said, which is what makes it a good fixture.
#   mirkos-braindump       the NAME of the repository the distiller reads, and
#                          a name is how a pointer finds its target. Renaming it
#                          would not anonymise anything, it would break the
#                          pointer: the same argument that keeps the `kamir`
#                          namespace out of NAMES below.
#
# Two entries that stood here earlier are GONE, not exempted: the GCP account in
# the certificate runbook now comes from ${GCP_ACCOUNT:?...} and the publisher
# runbook's recipient is a form field. An exemption postpones a decision; those
# two are decided.
EXEMPT_LINES='(PRODUCT_PUBLISHER|plaudDeferForTranscript|mirkos-braindump)'

# Two more classes that a name list alone would never catch, both found by
# reading the tree rather than by trusting the first grep.
#
# IDENTITIES: a persona also hides in an identity id. `kamir` cannot go in the
# NAMES list above, because it is also the GitHub namespace, and the namespace
# is load-bearing: 774 occurrences across 358 Go files, 891 across 417 files of
# every kind, measured 2026-09-15 on this branch head with
#
#     git grep -c 'github.com/kamir/' | awk -F: '{s+=$NF} END {print s, NR}'
#
# The command is here because the number will drift with the tree and a bare
# figure rots silently; the earlier comment carried 876 from a run nobody could
# repeat. What does NOT drift is the argument: a module path is how the compiler
# finds code, so renaming it breaks the build rather than anonymising anyone.
# Anchoring on `id:<name>@` keeps the import path untouched and still refuses
# the persona.
BAD_IDS='id:(kamir|mirko|eric|frank)@'

# ADDRESSES: a private mail address is a different class from a first name. It
# is harvestable, it is not fixable by renaming, and this tree is public AND
# mirrored into a customer GitLab. Nothing here should carry a personal inbox.
BAD_MAIL='[A-Za-z0-9._%+-]+\.(kaempf|kämpf)@|(mirko|eric|frank)[._][A-Za-z]+@'

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
  | xargs -0 grep -I -n -w -E -H -i -e "$NAMES_WORD" -- 2>/dev/null || true)

# No -i here, on purpose: the capital IS the signal that distinguishes the
# persona in `fromMirko` from the "eric" inside "generic". See CAMEL above.
CAMELHITS=$(printf '%s\n' "$FILES" | tr '\n' '\0' \
  | xargs -0 grep -I -n -E -H -e "$CAMEL" -- 2>/dev/null || true)

# The identity and address checks are NOT word-anchored: `id:kamir@m3c` and an
# address are already their own delimiters, and -w would refuse to match them.
IDHITS=$(printf '%s\n' "$FILES" | tr '\n' '\0' \
  | xargs -0 grep -I -n -E -H -i -e "$BAD_IDS" -- 2>/dev/null || true)
MAILHITS=$(printf '%s\n' "$FILES" | tr '\n' '\0' \
  | xargs -0 grep -I -n -E -H -i -e "$BAD_MAIL" -- 2>/dev/null || true)
HITS=$(printf '%s\n%s\n%s\n%s\n' "$HITS" "$CAMELHITS" "$IDHITS" "$MAILHITS" \
  | grep -v '^$' | sort -u -t: -k1,1 -k2,2n || true)

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

A personal mail address is not a naming problem at all: remove it. Where a real
account is genuinely needed to run something, read it from the environment with
${VAR:?why it is needed} so the procedure STOPS instead of continuing with an
empty value.

If the name belongs to AUTHORSHIP rather than to an example (a commit author, a
copyright holder, the publisher of a signed installer), it does not belong to a
persona either. Add the line to EXEMPT_LINES in this script with the reason,
rather than replacing a true attribution with a false one.
GUIDE
exit 1
