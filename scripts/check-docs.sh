#!/usr/bin/env bash
# check-docs.sh — Validate documentation consistency with implementation.
#
# Checks that key references in docs/ match the current codebase, and runs the
# BLOCKING CLI/manual gate (cmd/docaudit) as section 4.
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

# ─── 4. CLI ↔ manual consistency (BLOCKING) ───
#
# Sections 1-3 above are heuristics and only warn. This one is the release
# gate: docaudit compares each CLI's REAL flag surface (AST-extracted) against
# its manual, in both directions, and exits 1 on any drift. It blocks, because
# a manual that disagrees with the binary is how a user ends up trusting a flag
# that does not exist -- or missing one that does.
echo "4. CLI/manual consistency (docaudit)"
if ! command -v go >/dev/null 2>&1; then
    fail "go toolchain not found - cannot run the CLI/manual gate"
elif go run ./cmd/docaudit -cli all; then
    pass "every real flag is documented and every documented flag is real"
else
    fail "CLI surface and manual disagree (see the report above)"
    echo "    Draft the missing entries with:"
    echo "      go run ./cmd/docaudit -cli <m3c-tools|skillctl> -scaffold"
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
