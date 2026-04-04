#!/usr/bin/env bash
# test-gate-windows.sh — Local Windows dev test gate for m3c-tools
#
# Validates that the Windows build is clean without needing a Windows machine.
# Runs four phases: vet → cross-compile → Windows-safe unit tests → smoke.
#
# Usage:
#   ./scripts/test-gate-windows.sh           # all phases
#   ./scripts/test-gate-windows.sh --quick   # skip slow test phase
#
# SPEC-0128: Windows Dev Test Cycle
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

QUICK="${1:-}"
PASS=0; FAIL=0

_pass() { echo "  ✓ $1"; ((PASS++)) || true; }
_fail() { echo "  ✗ $1"; ((FAIL++)) || true; }
_section() { echo ""; echo "=== $1 ==="; }

# Windows-compatible test patterns (excludes CGO/darwin/network/hardware tests)
WINDOWS_TESTS=(
  "TestComposite"
  "TestBuild$"
  "TestParseTagLine"
  "TestER1Config"
  "TestER1Queue"
  "TestER1EnqueueFailure"
  "TestUploadFailure"
  "TestExportsDB"
  "TestFilesDB"
  "TestHashFile"
  "TestFormatterLoader"
  "TestPrettyPrint"
  "TestFormatTranscript"
  "TestFormatSnippet"
  "TestFormatKeyValue"
  "TestFormatTable"
  "TestFormatSection"
  "TestFormatStatusLine"
  "TestBuildApp"
  "TestTranslateFlagParsing"
  "TestTranslateNotTranslatable"
  "TestTranslateTranslatable"
  "TestRetryQueue"
  "TestRetryBackoff"
  "TestRetryProcessing"
  "TestRetryPartialFailure"
  "TestRetryMaxRetries"
  "TestRetryDropCallback"
  "TestRetryRespects"
  "TestRetryProcessesAfter"
  "TestRetryGraceful"
  "TestRetryRunStops"
  "TestRetryRunProcesses"
  "TestRetryEmptyQueue"
  "TestRetryOnRetry"
  "TestTranscriptFilter"
  "TestProxyBuildURL"
  "TestProxyGetTransport"
  "TestProxyNewWithProxy"
  "TestProxyHTTP"
  "TestProxyWebshare"
  "TestProxySocks5"
  "TestRetryRunner"
  "TestBackgroundRetry"
  "TestTranscriptImport"
  "TestTranscriptList"
  "TestTranscriptSearch"
  "TestTranscriptExport"
  "TestScheduleCommand"
  "TestStatusCommand"
  "TestCancelCommand"
  "TestScheduleStatusCancel"
  "TestCLIHelp"
  "TestCLIUnknownCommand"
  "TestCLINoArgs"
  "TestRepoRoot"
  "TestWriteFixture"
  "TestFixtureDir"
  "TestTempDataDir"
  "TestWithEnv"
  "TestRunCLIWithEnv"
  "TestImporter"
  "TestFieldnote"
  "TestPlaudConfig"
  "TestPlaudToken"
  "TestPlaudFormatDuration"
  "TestScreenshotMode"
  "TestScreenshotCLI"
)

# Join with | for -run flag
RUN_PATTERN="$(IFS="|"; echo "${WINDOWS_TESTS[*]}")"

echo "╔══════════════════════════════════════════════╗"
echo "║  m3c-tools Windows Test Gate (SPEC-0128)    ║"
echo "╚══════════════════════════════════════════════╝"

# ── Phase 1: Go vet ──────────────────────────────────────────────────────────
_section "Phase 1: go vet"
if go vet ./...; then
  _pass "go vet ./..."
else
  _fail "go vet ./... — fix errors before proceeding"
  exit 1
fi

# ── Phase 2: Windows cross-compile ───────────────────────────────────────────
_section "Phase 2: Windows cross-compile (amd64, CGO_ENABLED=0)"

BUILD_OUT="$(mktemp -d)"
trap 'rm -rf "$BUILD_OUT"' EXIT

echo "  Building m3c-tools.exe..."
if GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o "$BUILD_OUT/m3c-tools.exe" ./cmd/m3c-tools 2>&1; then
  SIZE=$(wc -c < "$BUILD_OUT/m3c-tools.exe" | tr -d ' ')
  _pass "m3c-tools.exe (${SIZE} bytes)"
else
  _fail "m3c-tools.exe build failed"
  exit 1
fi

echo "  Building skillctl.exe..."
if GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o "$BUILD_OUT/skillctl.exe" ./cmd/skillctl 2>&1; then
  _pass "skillctl.exe"
else
  _fail "skillctl.exe build failed"
  exit 1
fi

echo "  Verifying tray package compiles for Windows..."
if GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build ./pkg/tray/... 2>&1; then
  _pass "pkg/tray (Windows build tag)"
else
  _fail "pkg/tray Windows compile failed"
  exit 1
fi

echo "  Verifying config package..."
if GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build ./pkg/config/... 2>&1; then
  _pass "pkg/config"
else
  _fail "pkg/config Windows compile failed"
fi

# ── Phase 3: Unit tests (Windows-safe subset) ────────────────────────────────
if [[ "$QUICK" == "--quick" ]]; then
  echo ""
  echo "=== Phase 3: Unit tests (skipped — --quick) ==="
  echo "  (run without --quick to include)"
else
  _section "Phase 3: Windows-safe unit tests"
  echo "  (excludes recorder, whisper, menubar, network, ER1-server tests)"
  echo ""
  if go test -count=1 -timeout=120s ./e2e/ -run "$RUN_PATTERN" 2>&1; then
    _pass "unit tests passed"
  else
    _fail "unit tests failed"
  fi
fi

# ── Phase 4: CLI smoke (native, sanity check) ─────────────────────────────────
_section "Phase 4: CLI smoke (native binary)"

echo "  Building native test binary..."
NATIVE_BIN="$BUILD_OUT/m3c-tools-native"
if go build -o "$NATIVE_BIN" ./cmd/m3c-tools 2>&1; then
  _pass "native build"
else
  _fail "native build failed"
  exit 1
fi

echo "  Checking 'help' output..."
HELP_OUT=$("$NATIVE_BIN" help 2>&1 || true)
if echo "$HELP_OUT" | grep -q "m3c-tools"; then
  _pass "'help' contains 'm3c-tools'"
else
  _fail "'help' output missing expected content"
fi

echo "  Checking Windows-specific config keys in source..."
if grep -r "USERPROFILE\|AppData\|windows" pkg/config/ --include="*.go" -q 2>/dev/null || \
   grep -r "runtime.GOOS" pkg/ --include="*.go" -q 2>/dev/null; then
  _pass "Windows config paths present in source"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "────────────────────────────────────────────────"
echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "  GATE PASSED — safe to push"
  echo ""
  echo "  Next: push to trigger GitHub Actions windows-latest runner"
  echo "         (.github/workflows/windows-gate.yml)"
  exit 0
else
  echo "  GATE FAILED — fix errors before pushing"
  exit 1
fi
