#!/usr/bin/env bash
# check-docs.sh: Validate documentation consistency with implementation.
#
# Checks that key references in docs/ match the current codebase, and runs the
# BLOCKING gates: the CLI/manual + CLI/--help gate (cmd/docaudit, section 4),
# the verb register (cmd/verbaudit, section 5), the tutorial chain (section 6)
# and the index directory-diff (section 7).
#
# Exit: 0 = ok (warnings allowed) - 1 = a blocking issue, the release stops.
# Usage: ./scripts/check-docs.sh
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

WARNINGS=0
FAILURES=0
fail() { echo -e "  ${RED}x${NC} $1"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "  ${YELLOW}!${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
pass() { echo -e "  ${GREEN}✓${NC} $1"; }

echo "=== Documentation Consistency Check ==="
echo ""

# ─── 1. Check docs directory exists ───
echo "1. Docs presence"
if [ -d "docs" ]; then
    DOC_COUNT=$(find docs -name '*.md' | wc -l | tr -d ' ')
    pass "docs/ directory exists ($DOC_COUNT markdown files)"
else
    warn "No docs/ directory found"
fi

# ─── 2. Check .env.example keys are documented ───
echo "2. Environment variables"
if [ -f ".env.example" ]; then
    MISSING_DOCS=0
    while IFS= read -r line; do
        key=$(echo "$line" | grep -oE '^[A-Z_]+' || true)
        if [ -n "$key" ] && [ -d "docs" ]; then
            if ! grep -rq "$key" docs/ 2>/dev/null; then
                warn "$key not mentioned in docs/"
                MISSING_DOCS=$((MISSING_DOCS + 1))
            fi
        fi
    done < .env.example
    if [ "$MISSING_DOCS" -eq 0 ]; then
        pass "All .env.example keys referenced in docs"
    fi
else
    pass "No .env.example to check"
fi

# ─── 3. Check Make targets in docs ───
echo "3. Make targets"
if [ -d "docs" ]; then
    for target in build install menubar test-unit; do
        if ! grep -rq "$target" docs/ 2>/dev/null; then
            warn "make $target not mentioned in docs"
        fi
    done
    pass "Key make targets checked"
else
    pass "No docs to check targets against"
fi

# ─── 4. CLI ↔ manual ↔ --help consistency (BLOCKING) ───
#
# Sections 1-3 above are heuristics and only warn. This one is the release
# gate: docaudit compares each CLI's REAL flag surface (AST-extracted) against
# its manual, in both directions, and exits 1 on any drift. It blocks, because
# a manual that disagrees with the binary is how a user ends up trusting a flag
# that does not exist, or missing one that does.
#
# It also reconciles the dispatch switch against the binary's own printUsage, a
# separate failure: a verb absent from the manual is a documentation gap, a verb
# absent from `--help` is invisible to everyone who never opens the manual.
echo "4. CLI/manual and CLI/--help consistency (docaudit)"
if ! command -v go >/dev/null 2>&1; then
    fail "go toolchain not found - cannot run the CLI/manual gate"
elif go run ./cmd/docaudit -cli all; then
    pass "flags agree with the manuals, and --help names every dispatched verb"
else
    fail "CLI surface, manual and --help disagree (see the report above)"
    echo "    Draft the missing entries with:"
    echo "      go run ./cmd/docaudit -cli <m3c-tools|skillctl> -scaffold"
fi

# ─── 5. skillctl verb register (BLOCKING) ───
#
# FR-0113 / SPEC-0404 §7-K3: verbaudit AST-reads the `switch os.Args[1]` dispatch
# in cmd/skillctl/main.go and reconciles it against docs/CLI-VERBS.md. A
# dispatched verb with no register row turns this red (REQ-7.10), and a
# main-table row must carry an exit-code space (REQ-7.9). It blocks for the same
# reason the flag gate does: verb allocation must be a WRITE, so two collisions
# in two days cannot recur.
echo "5. skillctl verb register (verbaudit)"
if ! command -v go >/dev/null 2>&1; then
    fail "go toolchain not found - cannot run the verb-register gate"
elif go run ./cmd/verbaudit; then
    pass "every dispatched verb is registered in docs/CLI-VERBS.md"
else
    fail "a dispatched verb is not registered (see the report above)"
    echo "    Register the verb first (add a row to docs/CLI-VERBS.md), then implement its case."
fi

# ─── 6. Tutorial chain (BLOCKING) ───
#
# gate: scripts/tutorial-smoke.sh runs the chain the German scenario tutorials
# describe (docs/tutorial-szenario-0*.de.md) against a bare local:// registry in
# a throwaway HOME, and asserts every documented exit code, INCLUDING the two
# refusals. docaudit gates the flag surface of the two manuals; nothing gated the
# tutorials, so a renamed flag or a changed message could make them wrong without
# turning anything red. FR-0118, SPEC-0407 AC-11.
echo ""
echo "6. Tutorial chain (tutorial-smoke)"
if ! command -v go >/dev/null 2>&1; then
    warn "go toolchain not found - skipping the tutorial chain"
elif [ ! -f "scripts/tutorial-smoke.sh" ]; then
    warn "scripts/tutorial-smoke.sh not found - skipping"
else
    SMOKE_BIN="$(mktemp -d)/skillctl"
    if ! go build -o "$SMOKE_BIN" ./cmd/skillctl >/dev/null 2>&1; then
        fail "cannot build skillctl for the tutorial chain"
    elif ./scripts/tutorial-smoke.sh --skillctl "$SMOKE_BIN" >/tmp/tutorial-smoke.$$.log 2>&1; then
        pass "the tutorial chain still behaves as documented"
    else
        fail "the tutorial chain drifted from the tutorials (see below)"
        grep -E "DRIFT|FAIL:" /tmp/tutorial-smoke.$$.log | head -12 | sed 's/^/      /'
        echo "      full run: ./scripts/tutorial-smoke.sh --keep"
    fi
    rm -f "/tmp/tutorial-smoke.$$.log"
    rm -rf "$(dirname "$SMOKE_BIN")"
fi

# ─── 7. Index freshness: cmd/ and pkg/ vs the two indexes (BLOCKING) ───
#
# docs/program-index.md claims to list "every buildable entry point" and
# docs/component-index.md claims to list the library packages. Both claims rotted
# silently: five cmd/ binaries were absent from the program index and twelve
# pkg/skillctl packages from the component index, while the component index still
# documented a `skillimport` package that exists nowhere in the tree.
#
# A prose claim about a directory can be checked against the directory, so it is,
# in BOTH directions: every buildable cmd/<name> must be named in the program
# index and every cmd/ path the index names must exist; every Go package under
# pkg/ must appear in the component index and every package the index names must
# exist. The reverse direction is what catches the phantom row.
#
# Deliberately mechanical: it checks PRESENCE, never prose. A new package still
# needs a human-written responsibility line, and this is what makes the writer
# notice.
echo ""
echo "7. Index freshness (cmd/ and pkg/ vs the indexes)"
PROG_INDEX="docs/program-index.md"
COMP_INDEX="docs/component-index.md"
if [ ! -f "$PROG_INDEX" ] || [ ! -f "$COMP_INDEX" ]; then
    fail "an index file is missing ($PROG_INDEX / $COMP_INDEX)"
else
    INDEX_DRIFT=0
    IDX_TMP="$(mktemp -d)"
    # The cmd/ paths the program index names, and the package tokens the
    # component index names (a first table cell in backticks). Extracted with
    # sed rather than a quoted backtick, so the shell never has to escape one.
    grep -oE 'cmd/[a-z0-9-]+/' "$PROG_INDEX" | sed 's|^cmd/||; s|/$||' | sort -u > "$IDX_TMP/prog"
    grep -oE '^\| `[a-z0-9/]+`' "$COMP_INDEX" | sed -E 's/^\| .(.*).$/\1/' | sort -u > "$IDX_TMP/comp"

    # cmd/<name> that has Go sources must be in the program index.
    for d in cmd/*/; do
        name="${d#cmd/}"; name="${name%/}"
        ls "cmd/$name"/*.go >/dev/null 2>&1 || continue
        if ! grep -qx "$name" "$IDX_TMP/prog"; then
            fail "cmd/$name builds but is not listed in $PROG_INDEX"
            INDEX_DRIFT=1
        fi
    done
    # ... and nothing the program index points at may have been deleted.
    for name in $(cat "$IDX_TMP/prog"); do
        if [ ! -d "cmd/$name" ]; then
            fail "$PROG_INDEX lists cmd/$name, which no longer exists"
            INDEX_DRIFT=1
        fi
    done
    # Every Go package under pkg/ must be in the component index.
    for pkg in $(find pkg -name '*.go' ! -name '*_test.go' -exec dirname {} \; | sort -u | sed 's|^pkg/||'); do
        if ! grep -qx "$pkg" "$IDX_TMP/comp"; then
            fail "pkg/$pkg is a package but is not listed in $COMP_INDEX"
            INDEX_DRIFT=1
        fi
    done
    # ... and every package the component index names must exist. Tokens are
    # written relative to pkg/ or to internal/, or as a full path.
    for tok in $(cat "$IDX_TMP/comp"); do
        if [ ! -d "pkg/$tok" ] && [ ! -d "internal/$tok" ] && [ ! -d "$tok" ]; then
            fail "$COMP_INDEX documents \`$tok\`, which is not a package in this tree"
            INDEX_DRIFT=1
        fi
    done
    rm -rf "$IDX_TMP"
    if [ "$INDEX_DRIFT" -eq 0 ]; then
        pass "every cmd/ binary and pkg/ package is indexed, and every indexed one exists"
    fi
fi

# ─── Summary ───
echo ""
echo "─────────────────────────────"
if [ "$FAILURES" -gt 0 ]; then
    echo -e "${RED}FAIL${NC}: $FAILURES blocking issue(s), $WARNINGS warning(s)"
    echo "Release is BLOCKED until the docs match the code."
    exit 1
elif [ "$WARNINGS" -gt 0 ]; then
    echo -e "${YELLOW}PASS with warnings${NC}: $WARNINGS warning(s)"
    echo "Docs may need updating. Release is allowed."
    exit 0
else
    echo -e "${GREEN}PASS${NC}: Documentation is consistent."
    exit 0
fi
