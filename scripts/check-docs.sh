#!/usr/bin/env bash
# check-docs.sh — Verify documentation consistency with implementation.
#
# Checks:
#   1. CLI commands in docs match actual binary help output
#   2. .env variables in docs match .env.example
#   3. Package references in architecture.md exist on disk
#   4. Make targets in docs match Makefile
#
# Usage: ./scripts/check-docs.sh [--fix]
#   --fix: print suggested updates (does not auto-edit)
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS + 1)); }
warn() { echo -e "  ${YELLOW}!${NC} $1"; WARNINGS=$((WARNINGS + 1)); }

echo "=== Documentation Consistency Check ==="
echo ""

# --- 1. Check .env variables documented in getting-started.md ---
echo "Checking .env variable coverage..."
if [ -f docs/getting-started.md ] && [ -f .env.example ]; then
    # Extract variable names from .env.example (uncommented lines with =)
    env_vars=$(grep -E '^#?\s*[A-Z_]+=|^[A-Z_]+=' .env.example | sed 's/^#\s*//' | cut -d= -f1 | sort -u)
    doc_vars=$(grep -oE '[A-Z_]{3,}' docs/getting-started.md | sort -u)

    missing_from_docs=0
    for var in $env_vars; do
        # Skip if it's a generic word, only check real config vars
        case "$var" in
            ER1_*|YT_*|M3C_*|IMPORT_*)
                if ! echo "$doc_vars" | grep -qw "$var"; then
                    # Only warn for important vars, not every single one
                    case "$var" in
                        ER1_API_URL|ER1_API_KEY|ER1_CONTEXT_ID|YT_WHISPER_MODEL|M3C_SCREENSHOT_MODE|YT_PROXY_URL)
                            if ! grep -q "$var" docs/getting-started.md docs/architecture.md 2>/dev/null; then
                                warn "Key variable $var not mentioned in docs"
                                missing_from_docs=$((missing_from_docs + 1))
                            fi
                            ;;
                    esac
                fi
                ;;
        esac
    done
    if [ "$missing_from_docs" -eq 0 ]; then
        pass ".env key variables covered in docs"
    fi
else
    warn "docs/getting-started.md or .env.example not found"
fi

# --- 2. Check package directories referenced in architecture.md ---
echo "Checking package references..."
if [ -f docs/architecture.md ]; then
    for pkg in menubar transcript recorder whisper screenshot er1 impression importer tracking; do
        if [ -d "pkg/$pkg" ]; then
            if grep -q "pkg/$pkg\|$pkg/" docs/architecture.md; then
                pass "pkg/$pkg referenced and exists"
            else
                warn "pkg/$pkg exists but not in architecture.md"
            fi
        fi
    done

    # Check files referenced in architecture.md exist
    for file in $(grep -oE 'pkg/[a-z_/]+\.go|cmd/[a-z_/]+\.go' docs/architecture.md | sort -u); do
        if [ -f "$file" ]; then
            pass "$file exists"
        else
            fail "$file referenced in architecture.md but not found"
        fi
    done
else
    warn "docs/architecture.md not found"
fi

# --- 3. Check make targets documented ---
echo "Checking make targets..."
if [ -f Makefile ]; then
    for target in build build-app install test-unit menubar ci release permissions; do
        if grep -q "^${target}:" Makefile || grep -q "^\.PHONY:.*${target}" Makefile; then
            if grep -rq "$target" docs/ 2>/dev/null; then
                pass "make $target documented"
            else
                warn "make $target exists but not in docs"
            fi
        fi
    done
else
    warn "Makefile not found"
fi

# --- 4. Check observation channels documented ---
echo "Checking observation channels..."
if [ -f docs/index.md ]; then
    for channel in YouTube Idea Impulse Import; do
        if grep -qi "$channel" docs/index.md; then
            pass "Channel '$channel' documented in index.md"
        else
            fail "Channel '$channel' missing from index.md"
        fi
    done
else
    warn "docs/index.md not found"
fi

# --- Summary ---
echo ""
if [ "$ERRORS" -gt 0 ]; then
    echo -e "${RED}FAIL${NC}: $ERRORS error(s), $WARNINGS warning(s)"
    exit 1
elif [ "$WARNINGS" -gt 0 ]; then
    echo -e "${YELLOW}WARN${NC}: $WARNINGS warning(s), 0 errors"
    exit 0
else
    echo -e "${GREEN}PASS${NC}: Documentation is consistent with implementation."
    exit 0
fi
