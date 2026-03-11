#!/usr/bin/env bash
# check-docs.sh — Validate documentation consistency with implementation.
#
# Checks that key references in docs/ match the current codebase.
# Usage: ./scripts/check-docs.sh
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

WARNINGS=0
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

# ─── Summary ───
echo ""
echo "─────────────────────────────"
if [ "$WARNINGS" -gt 0 ]; then
    echo -e "${YELLOW}PASS with warnings${NC}: $WARNINGS warning(s)"
    echo "Docs may need updating. Release is allowed."
    exit 0
else
    echo -e "${GREEN}PASS${NC}: Documentation is consistent."
    exit 0
fi
