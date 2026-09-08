#!/usr/bin/env bash
# check-index.sh: the two documentation indexes against the directories they claim.
#
# docs/program-index.md claims to list every buildable entry point and
# docs/component-index.md claims to list the library packages, with a count. All
# three claims rotted silently: five cmd/ binaries were absent from the program
# index and twelve pkg/skillctl packages from the component index, while the
# component index still documented a `skillimport` package that exists nowhere.
#
# A prose claim about a directory can be checked against the directory, so it is,
# in BOTH directions and for the counts as well:
#
#   1. every buildable cmd/<name> is named in the program index
#   2. every cmd/ path the program index names still exists
#   3. every Go package under pkg/ is named in the component index
#   4. every Go package under internal/ is named in the component index
#   5. every package token the component index names is a package in this tree
#   6. the two package COUNTS in the component index equal the directory counts
#
# The reverse direction (2, 5) is what catches a phantom row. The count check (6)
# exists because a list check alone leaves the number free to rot: adding a 41st
# package WITH its row would satisfy the list and quietly falsify "40
# subpackages". Both count sentences are required to be present exactly once, so
# rewording one out of the file turns this red rather than switching the check
# off. This is why the file may state a number at all.
#
# Deliberately mechanical: it checks PRESENCE and ARITHMETIC, never prose. A new
# package still needs a human-written responsibility line, and the red gate is
# what makes the author notice that one is owed.
#
# Blocking, and it runs where the other docs gates run: section 7 of
# scripts/check-docs.sh, and the docs-gate job of ci.yml, release.yml and
# skillctl-release.yml.
#
# Usage:
#   ./scripts/check-index.sh    # exit 0 clean, 1 on any drift, 2 on a usage error
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PROG_INDEX="docs/program-index.md"
COMP_INDEX="docs/component-index.md"

FAILURES=0
fail() { echo "  x $1"; FAILURES=$((FAILURES + 1)); }

if [ ! -f "$PROG_INDEX" ] || [ ! -f "$COMP_INDEX" ]; then
    echo "check-index: an index file is missing ($PROG_INDEX / $COMP_INDEX)" >&2
    exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The cmd/ paths the program index names, and the package tokens the component
# index names (a first table cell in backticks). Extracted with sed rather than
# a quoted backtick, so the shell never has to escape one.
grep -oE 'cmd/[a-z0-9-]+/' "$PROG_INDEX" | sed 's|^cmd/||; s|/$||' | sort -u > "$TMP/prog"
grep -oE '^\| `[a-z0-9/]+`' "$COMP_INDEX" | sed -E 's/^\| .(.*).$/\1/' | sort -u > "$TMP/comp"

# 1. cmd/<name> that has Go sources must be in the program index.
for d in cmd/*/; do
    name="${d#cmd/}"; name="${name%/}"
    ls "cmd/$name"/*.go >/dev/null 2>&1 || continue
    grep -qx "$name" "$TMP/prog" || fail "cmd/$name builds but is not listed in $PROG_INDEX"
done

# 2. Nothing the program index points at may have been deleted.
while read -r name; do
    [ -d "cmd/$name" ] || fail "$PROG_INDEX lists cmd/$name, which no longer exists"
done < "$TMP/prog"

# 3. Every Go package under pkg/ must be in the component index.
for pkg in $(find pkg -name '*.go' ! -name '*_test.go' -exec dirname {} \; | sort -u | sed 's|^pkg/||'); do
    grep -qx "$pkg" "$TMP/comp" || fail "pkg/$pkg is a package but is not listed in $COMP_INDEX"
done

# 4. Every Go package under internal/ likewise. The index writes these either
# relative to internal/ (`thinking/api`) or as a full path (`internal/dbdriver`),
# so both spellings count.
for pkg in $(find internal -name '*.go' ! -name '*_test.go' -exec dirname {} \; | sort -u | sed 's|^internal/||'); do
    grep -qx "$pkg" "$TMP/comp" || grep -qx "internal/$pkg" "$TMP/comp" ||
        fail "internal/$pkg is a package but is not listed in $COMP_INDEX"
done

# 5. Every package the component index names must exist. Tokens are written
# relative to pkg/ or to internal/, or as a full path.
while read -r tok; do
    if [ ! -d "pkg/$tok" ] && [ ! -d "internal/$tok" ] && [ ! -d "$tok" ]; then
        fail "$COMP_INDEX documents \`$tok\`, which is not a package in this tree"
    fi
done < "$TMP/comp"

# 6. The counts. Each sentence must appear EXACTLY once: zero matches means the
# claim was reworded past the gate, several means the gate would be checking an
# arbitrary one of them.
check_count() {
    local label="$1" pattern="$2" measured="$3" hits declared
    hits="$(grep -cE "$pattern" "$COMP_INDEX" || true)"
    if [ "$hits" -ne 1 ]; then
        fail "$COMP_INDEX: the $label count sentence matches $hits times, want exactly 1 (pattern: $pattern)"
        return
    fi
    declared="$(grep -oE "$pattern" "$COMP_INDEX" | grep -oE '[0-9]+' | head -1)"
    if [ "$declared" != "$measured" ]; then
        fail "$COMP_INDEX says $declared $label, the tree has $measured"
    fi
}

SUBPKGS="$(find pkg/skillctl -name '*.go' ! -name '*_test.go' -exec dirname {} \; | sort -u | wc -l | tr -d ' ')"
THINKING="$(find internal/thinking -name '*.go' ! -name '*_test.go' -exec dirname {} \; | sort -u | wc -l | tr -d ' ')"
check_count "pkg/skillctl subpackage" '[0-9]+ subpackages under .pkg/skillctl/.' "$SUBPKGS"
check_count "internal Thinking Engine package" 'The [0-9]+ internal packages' "$THINKING"

if [ "$FAILURES" -gt 0 ]; then
    echo "check-index: $FAILURES drift(s) between the tree and the indexes" >&2
    exit 1
fi
echo "  ok: $(wc -l < "$TMP/prog" | tr -d ' ') cmd/ entries and $(wc -l < "$TMP/comp" | tr -d ' ') packages indexed, both directions clean; counts $SUBPKGS + $THINKING match the tree"
