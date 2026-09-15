#!/usr/bin/env bash
# Refuse NEWLY ADDED em dashes (U+2014).
#
# Scoped to the diff ON PURPOSE. main carries 2870 of them across 469 of 624 Go
# files (measured 2026-09-15); a tree-wide check would be red from its first
# run, and a gate that is red on arrival gets switched off, after which nothing
# is checked at all. Same calibration as spec-funnel-check.py: block what
# changed, pay the backlog down deliberately.
#
# Why the rule at all: the em dash is the clearest stylistic tell of machine
# written text, and it is a placeholder for a decision not yet made. A colon, a
# full stop or a comma forces the sentence to say which relation it means.
# Canon: CLAUDE.md, "Schreibstil (bindend): keine Geviertstriche".
#
# A space-hyphen or a double hyphen in the same place is the same habit in a
# different glyph and is NOT a way around this. That half stays with the human;
# this script catches only the glyph a machine can see.
#
# Usage:
#   check-no-emdash.sh [base]     default base: $PROSE_BASE, else origin/main
#   check-no-emdash.sh --selftest prove the pattern still bites, then exit
set -euo pipefail

# The pattern is the raw UTF-8 of U+2014, written as bytes rather than as
# $'—': \u is a bash 4.2 feature, and on a 3.2 shell the pattern would
# silently become the text "u2014" and match nothing forever.
DASH=$'\xe2\x80\x94'

# selftest: a gate is only worth its exit code once someone has watched it go
# red. While this script was being written it twice reported a cheerful "no new
# em dashes" over text that carried one: first because \+ is a repetition
# operator in BRE (so the pipeline errored and `|| true` swallowed it), then
# because an edit silently failed to apply. Neither was visible from the
# output. Hence: probe the pattern against a known violation and a known clean
# line before trusting any verdict.
selftest() {
    local rc=0
    printf 'a %s b\n' "$DASH" | grep -q -- "$DASH" || {
        echo "check-no-emdash: SELFTEST FAILED, the pattern misses a real em dash." >&2
        rc=2
    }
    if printf 'a - b\n' | grep -q -- "$DASH"; then
        echo "check-no-emdash: SELFTEST FAILED, the pattern matches a plain hyphen." >&2
        rc=2
    fi
    if printf 'a -- b\n' | grep -q -- "$DASH"; then
        echo "check-no-emdash: SELFTEST FAILED, the pattern matches a double hyphen." >&2
        rc=2
    fi
    return $rc
}

if [ "${1:-}" = "--selftest" ]; then
    selftest
    echo "check-no-emdash: selftest ok (matches U+2014, ignores - and --)."
    exit 0
fi

# Never judge with a pattern that was never proven to match.
selftest

BASE="${1:-${PROSE_BASE:-origin/main}}"
if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
    echo "check-no-emdash: base '$BASE' not found; fetch it or pass one explicitly." >&2
    exit 2
fi

# Added lines only: a file may legitimately still carry old ones. Plain BRE and
# a literal '+', because in BRE a backslash-plus is the repetition operator and
# '^\+\+\+' errors out instead of matching a diff header.
added="$(git diff --unified=0 "$BASE"...HEAD | grep '^+' | grep -v '^+++' || true)"
hits="$(printf '%s\n' "$added" | grep -n -- "$DASH" || true)"

if [ -z "$hits" ]; then
    echo "check-no-emdash: no new em dashes against $BASE."
    exit 0
fi

echo "check-no-emdash: added lines carry an em dash (U+2014)." >&2
echo >&2
printf '%s\n' "$hits" >&2
echo >&2
echo "Pick the punctuation that names the relation of the two halves:" >&2
echo "  label and its resolution       :" >&2
echo "  two independent statements     ." >&2
echo "  two clauses too close to part  ;" >&2
echo "  an aside inside one sentence   , ,   or   ( )" >&2
echo "  a continuation or an addendum  ," >&2
echo "  an empty table cell            n/a" >&2
echo >&2
echo "If none of them fit, the sentence is doing two things at once. Split it." >&2
exit 1
