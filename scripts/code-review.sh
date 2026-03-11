#!/usr/bin/env bash
# code-review.sh — Pre-release code review checks.
#
# Validates code quality, consistency, and release readiness.
# Blocks release if critical issues are found.
#
# Usage: ./scripts/code-review.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

pass()  { echo -e "  ${GREEN}✓${NC} $1"; }
fail()  { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS + 1)); }
warn()  { echo -e "  ${YELLOW}!${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
info()  { echo -e "  ${CYAN}→${NC} $1"; }

echo "=== Pre-Release Code Review ==="
echo ""

# ─── 1. Build check ───
echo "1. Build"
if go build -o /dev/null ./cmd/m3c-tools/ 2>/dev/null; then
    pass "go build succeeds"
else
    fail "go build FAILED"
fi

# ─── 2. Vet ───
echo "2. Vet"
VET_OUTPUT=$(go vet ./... 2>&1) || true
if [ -z "$VET_OUTPUT" ]; then
    pass "go vet clean"
else
    fail "go vet found issues:"
    echo "$VET_OUTPUT" | head -10 | sed 's/^/      /'
fi

# ─── 3. Unit tests ───
echo "3. Tests"
if go test -count=1 ./pkg/... 2>/dev/null | grep -q "^ok"; then
    pass "pkg/ tests pass"
else
    # Some packages may have no tests — check if any failures
    TEST_OUT=$(go test -count=1 ./pkg/... 2>&1) || true
    if echo "$TEST_OUT" | grep -q "^FAIL"; then
        fail "pkg/ tests have failures"
        echo "$TEST_OUT" | grep "^FAIL" | sed 's/^/      /'
    else
        pass "pkg/ tests pass (some packages have no tests)"
    fi
fi

# ─── 4. Sensitive data scan ───
echo "4. Sensitive data"
SENSITIVE_PATTERNS='API_KEY\s*=\s*[A-Za-z0-9]|password\s*=\s*"[^"]|secret\s*=\s*"[^"]|token\s*=\s*"[^"]'
# Only scan Go source files, skip tests
SENSITIVE_HITS=$(grep -rlEi "$SENSITIVE_PATTERNS" --include='*.go' --exclude='*_test.go' --exclude='*testhelper*' . 2>/dev/null || true)
if [ -z "$SENSITIVE_HITS" ]; then
    pass "No hardcoded secrets in Go source"
else
    warn "Possible hardcoded secrets in:"
    echo "$SENSITIVE_HITS" | sed 's/^/      /'
fi

# Check .env is not staged
if git diff --cached --name-only 2>/dev/null | grep -q "^\.env$"; then
    fail ".env is staged for commit — DO NOT commit secrets"
else
    pass ".env not staged"
fi

# ─── 5. TODO/FIXME/HACK audit ───
echo "5. Code markers"
TODO_HITS=$(grep -rnE '(TODO|FIXME|HACK|XXX):' --include='*.go' . 2>/dev/null || true)
if [ -n "$TODO_HITS" ]; then
    TODO_COUNT=$(echo "$TODO_HITS" | wc -l | tr -d ' ')
else
    TODO_COUNT=0
fi
if [ "$TODO_COUNT" -gt 0 ]; then
    warn "$TODO_COUNT TODO/FIXME/HACK markers in Go source"
    echo "$TODO_HITS" | head -10 | sed 's/^/      /'
    if [ "$TODO_COUNT" -gt 10 ]; then
        echo "      ... and $((TODO_COUNT - 10)) more"
    fi
else
    pass "No TODO/FIXME/HACK markers"
fi

# ─── 6. Dead code / unused imports ───
echo "6. Dead code"
# Check for unused imports (quick heuristic via build)
UNUSED_IMPORTS=$(go build ./... 2>&1 | grep "imported and not used" || true)
if [ -z "$UNUSED_IMPORTS" ]; then
    pass "No unused imports"
else
    fail "Unused imports:"
    echo "$UNUSED_IMPORTS" | head -5 | sed 's/^/      /'
fi

# ─── 7. Large files check ───
echo "7. File sizes"
LARGE_GO_FILES=$(find . -name '*.go' -not -path './vendor/*' -exec wc -l {} + 2>/dev/null | awk '$1 > 2000 && !/total$/ {print $2 " (" $1 " lines)"}' || true)
if [ -z "$LARGE_GO_FILES" ]; then
    pass "No Go files over 2000 lines"
else
    warn "Large Go files (consider splitting):"
    echo "$LARGE_GO_FILES" | sed 's/^/      /'
fi

# ─── 8. Error handling patterns ───
echo "8. Error handling"
# Check for silently ignored errors (= vs :=) in non-test files
IGNORED_ERRS=$(grep -rn 'err\s*=' --include='*.go' --exclude='*_test.go' . 2>/dev/null | grep -v ':=' | grep -v '_ =' | grep -v 'var err' | grep -v '// ' | grep -v 'if err' | head -5 || true)
if [ -z "$IGNORED_ERRS" ]; then
    pass "No obviously ignored errors"
else
    warn "Possibly overwritten errors (review manually):"
    echo "$IGNORED_ERRS" | sed 's/^/      /'
fi

# ─── 9. Version consistency ───
echo "9. Version"
MAKEFILE_VER=$(grep 'APP_VERSION' Makefile 2>/dev/null | head -1 | awk '{print $NF}')
LATEST_TAG=$(git tag --list 'v*' --sort=-v:refname | head -1)
if [ -n "$MAKEFILE_VER" ]; then
    info "Makefile APP_VERSION: $MAKEFILE_VER"
fi
if [ -n "$LATEST_TAG" ]; then
    info "Latest git tag: $LATEST_TAG"
fi
pass "Version info collected"

# ─── 10. Dependencies ───
echo "10. Dependencies"
if go mod verify 2>/dev/null; then
    pass "go.mod verified"
else
    fail "go mod verify failed"
fi

VULN_CHECK=""
if command -v govulncheck >/dev/null 2>&1; then
    VULN_CHECK=$(govulncheck ./... 2>&1 | grep "^Vulnerability" || true)
    if [ -z "$VULN_CHECK" ]; then
        pass "No known vulnerabilities (govulncheck)"
    else
        warn "Known vulnerabilities found:"
        echo "$VULN_CHECK" | head -5 | sed 's/^/      /'
    fi
else
    info "govulncheck not installed (skipping — install: go install golang.org/x/vuln/cmd/govulncheck@latest)"
fi

# ─── Summary ───
echo ""
echo "─────────────────────────────"
if [ "$ERRORS" -gt 0 ]; then
    echo -e "${RED}BLOCKED${NC}: $ERRORS error(s), $WARNINGS warning(s) — fix before releasing"
    exit 1
elif [ "$WARNINGS" -gt 0 ]; then
    echo -e "${YELLOW}PASS with warnings${NC}: $WARNINGS warning(s), 0 errors"
    echo "Review warnings above. Release is allowed but consider fixing them."
    exit 0
else
    echo -e "${GREEN}PASS${NC}: Code review passed. Ready to release."
    exit 0
fi
