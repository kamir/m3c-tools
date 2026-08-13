#!/usr/bin/env bash
# qa-target-device.sh — Runnable QA acceptance track for a FRESH m3c-tools install
# ON THE TARGET DEVICE (macOS or Linux). Ships WITH the tool; safe to re-run.
#
# Companion doc:   docs/QA-target-device-setup.md
# Windows twin:    scripts/qa-target-device.ps1
#
# Design rules:
#   * read-only, idempotent, safe to re-run
#   * NEVER prints ER1_API_KEY or any secret (key presence is checked with grep -q)
#   * OFFLINE by default; network stages gated behind --online or QA_ONLINE=1
#   * exits non-zero if ANY required check FAILs
#   * a transient network failure on an online check => clear FAIL + remediation, not a crash
#
# Usage:
#   scripts/qa-target-device.sh [--online] [-h|--help]
# Env:
#   M3C=/path/to/m3c-tools    override binary location (takes precedence)
#   M3C_ENV=/path/to/.env     extra config source to inspect first
#   QA_ONLINE=1               same as --online
#   M3C_EXPECT_VERSION=2.10.0 expected release version (default 2.10.0)
#
set -u

EXPECT_VERSION="${M3C_EXPECT_VERSION:-2.10.0}"
ONLINE=0
[ "${QA_ONLINE:-0}" = "1" ] && ONLINE=1

# ---- CLI -------------------------------------------------------------------
usage() {
  cat <<'EOF'
qa-target-device.sh — QA acceptance track for a fresh m3c-tools install (macOS/Linux)

  --online        also run the network stages (check-er1, transcript smoke, plaud dev)
  -h, --help      show this help

Environment:
  M3C=<path>            override the m3c-tools binary location (wins over PATH/build/)
  M3C_ENV=<path>        additional config file to inspect first
  QA_ONLINE=1           same as --online
  M3C_EXPECT_VERSION=X  expected release version string (default 2.10.0)

Exit code: 0 = all REQUIRED checks passed; non-zero = at least one required FAIL.
Offline by default. Never prints secrets. Read-only; safe to re-run.
EOF
}
for arg in "$@"; do
  case "$arg" in
    --online) ONLINE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

# ---- pretty print ----------------------------------------------------------
if [ -t 1 ]; then C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_B=$'\033[36m'; C_0=$'\033[0m'
else C_G=; C_R=; C_Y=; C_B=; C_0=; fi

REQ_FAIL=0; REQ_PASS=0; SOFT_WARN=0; SOFT_PASS=0; SKIPPED=0
pass()  { printf '  %s[PASS]%s %s\n' "$C_G" "$C_0" "$1"; REQ_PASS=$((REQ_PASS+1)); }
fail()  { printf '  %s[FAIL]%s %s\n' "$C_R" "$C_0" "$1"; REQ_FAIL=$((REQ_FAIL+1));
          [ -n "${2:-}" ] && printf '         %s↳ %s%s\n' "$C_Y" "$2" "$C_0"; }
warn()  { printf '  %s[WARN]%s %s\n' "$C_Y" "$C_0" "$1"; SOFT_WARN=$((SOFT_WARN+1));
          [ -n "${2:-}" ] && printf '         ↳ %s\n' "$2"; }
soft()  { printf '  %s[ ok ]%s %s\n' "$C_B" "$C_0" "$1"; SOFT_PASS=$((SOFT_PASS+1)); }
skip()  { printf '  %s[SKIP]%s %s\n' "$C_B" "$C_0" "$1"; SKIPPED=$((SKIPPED+1)); }
stage() { printf '\n%s== %s ==%s\n' "$C_B" "$1" "$C_0"; }

# ---- run-with-timeout (mac has no coreutils `timeout` by default) -----------
TO_BIN=""
if command -v timeout  >/dev/null 2>&1; then TO_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TO_BIN="gtimeout"; fi
run_to() { # run_to <secs> <cmd...>
  local secs="$1"; shift
  if [ -n "$TO_BIN" ]; then "$TO_BIN" "$secs" "$@"; else "$@"; fi
}

TMP="$(mktemp -d "${TMPDIR:-/tmp}/qa-m3c.XXXXXX")" || { echo "cannot mktemp" >&2; exit 2; }
cleanup() { rm -rf "$TMP" 2>/dev/null || true; }
trap cleanup EXIT

OS="$(uname -s 2>/dev/null || echo unknown)"
SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"

printf '%sm3c-tools — QA target-device acceptance track%s\n' "$C_B" "$C_0"
printf 'platform=%s  mode=%s  expect-version=%s\n' \
       "$OS" "$( [ "$ONLINE" = "1" ] && echo ONLINE || echo offline )" "$EXPECT_VERSION"

# ===========================================================================
# Stage A — Binary integrity & runs
# ===========================================================================
stage "Stage A — Binary integrity & runs"

# A1: locate binary. An explicit $M3C override is authoritative (no fallback to a
# different binary); otherwise PATH, then ./build, then repo build/.
BIN=""
if [ -n "${M3C:-}" ]; then
  if [ -x "$M3C" ]; then
    BIN="$M3C"
  else
    fail "A1 binary: \$M3C=$M3C is not an executable file" "point M3C at the real m3c-tools binary (or unset it to auto-discover)"
  fi
else
  if command -v m3c-tools >/dev/null 2>&1; then BIN="$(command -v m3c-tools)"
  elif [ -x "./build/m3c-tools" ]; then BIN="$(cd build && pwd)/m3c-tools"
  elif [ -x "$SCRIPT_DIR/../build/m3c-tools" ]; then BIN="$(cd "$SCRIPT_DIR/.." && pwd)/build/m3c-tools"
  else
    fail "A1 binary located" "not on PATH, not at ./build/m3c-tools — install v2.10.0 or set M3C=<path>"
  fi
fi
if [ -z "$BIN" ]; then
  # Cannot proceed without a binary — print the summary and bail cleanly.
  printf '\n%s== SUMMARY ==%s\n' "$C_B" "$C_0"
  printf '  required: %d passed / %s%d FAILED%s   soft: %d ok / %d warn   skipped: %d\n' \
         "$REQ_PASS" "$C_R" "$REQ_FAIL" "$C_0" "$SOFT_PASS" "$SOFT_WARN" "$SKIPPED"
  printf '  %sRESULT: FAIL%s (m3c-tools binary not found — nothing else could run)\n' "$C_R" "$C_0"
  exit 1
fi
pass "A1 binary located: $BIN"

# A2: version prints a real version (stdout is clean; stderr carries [config]/[auth] noise)
if run_to 20 "$BIN" version >"$TMP/ver.out" 2>"$TMP/ver.err"; then
  VER_LINE="$(grep -m1 '^m3c-tools ' "$TMP/ver.out" 2>/dev/null || true)"
  if [ -n "$VER_LINE" ]; then
    VER_TOK="$(printf '%s' "$VER_LINE" | awk '{print $2}')"
    if [ "$VER_TOK" = "$EXPECT_VERSION" ]; then
      pass "A2 version = $EXPECT_VERSION"
    elif [ "$VER_TOK" = "dev" ]; then
      warn "A2 version prints 'dev' (unreleased/local build)" "install the official v$EXPECT_VERSION artifact for real acceptance"
    else
      warn "A2 version = $VER_TOK (expected $EXPECT_VERSION)" "confirm this is the intended release"
    fi
  else
    fail "A2 version output not recognized" "expected a line like 'm3c-tools $EXPECT_VERSION (commit=…, built=…)'"
  fi
else
  fail "A2 version command failed (exit $?)" "binary may be the wrong platform/arch — re-check A1 / re-download"
fi

# ===========================================================================
# Stage B — Config present & valid  (never echoes values)
# ===========================================================================
stage "Stage B — Config present & valid"

# Build candidate config-source list (existing files only), in resolution order.
# Canonicalize paths and skip duplicates so the same file is not listed twice.
CFG_FILES=""
add_cfg() {
  [ -n "$1" ] && [ -f "$1" ] || return 0
  local d b canon
  d="$(cd "$(dirname "$1")" >/dev/null 2>&1 && pwd)" || return 0
  b="$(basename "$1")"; canon="$d/$b"
  case "
$CFG_FILES" in *"
$canon"*) return 0 ;; esac
  CFG_FILES="$CFG_FILES
$canon"
}
add_cfg "${M3C_ENV:-}"
add_cfg "./.env"
add_cfg "$SCRIPT_DIR/../.env"
add_cfg "$HOME/.m3c-tools.env"
if [ -f "$HOME/.m3c-tools/active-profile" ]; then
  AP="$(head -n1 "$HOME/.m3c-tools/active-profile" 2>/dev/null | tr -d ' \r\n')"
  [ -n "$AP" ] && add_cfg "$HOME/.m3c-tools/profiles/$AP.env"
fi

if [ -n "$CFG_FILES" ]; then
  # show which sources exist (paths are not secret; values are never printed)
  FOUND="$(printf '%s' "$CFG_FILES" | sed '/^$/d' | paste -sd',' - 2>/dev/null)"
  pass "B1 config source exists: ${FOUND:-<found>}"
else
  fail "B1 config source exists" "copy .env.example -> .env, or run 'm3c-tools login', or 'm3c-tools config create'"
fi

# key_present KEY — true if KEY has a NON-empty, non-comment value in ANY existing source.
# Uses grep -q: never prints the matched line (no secret leakage).
key_present() {
  local key="$1" f
  printf '%s' "$CFG_FILES" | sed '/^$/d' | while IFS= read -r f; do
    [ -f "$f" ] || continue
    if grep -Eq "^[[:space:]]*${key}=[^[:space:]#]" "$f"; then echo yes; return 0; fi
  done | grep -q yes
}

if key_present ER1_API_URL; then pass "B2 ER1_API_URL set"
else fail "B2 ER1_API_URL set" "add ER1_API_URL=https://onboarding.guide/upload_2 (or your local URL)"; fi

if key_present ER1_CONTEXT_ID; then pass "B3 ER1_CONTEXT_ID set"
else fail "B3 ER1_CONTEXT_ID set" "add ER1_CONTEXT_ID=<your-context-id>; 'm3c-tools login' fills this in"; fi

if key_present ER1_API_KEY; then
  soft "B4 ER1_API_KEY set"
else
  warn "B4 ER1_API_KEY not in config (OK if device-token auth is active)" \
       "run 'm3c-tools login' for a device token, or set ER1_API_KEY=… — see doctor Authentication"
fi

# ===========================================================================
# Stage C — Offline self-check (doctor)
# ===========================================================================
stage "Stage C — Offline self-check (doctor)"
# doctor exits non-zero when the Connectivity section fails (expected offline),
# so offline we grade on "did it produce the diagnostics report".
DOC_RC=0
run_to 40 "$BIN" doctor >"$TMP/doc.out" 2>"$TMP/doc.err" || DOC_RC=$?
if grep -q "Config Consistency" "$TMP/doc.out"; then
  pass "C1 doctor produced a diagnostics report"
else
  fail "C1 doctor did not produce a report" "profile likely broken — 'm3c-tools config list' / 'config switch <name>'"
fi
if [ "$ONLINE" = "1" ]; then
  if [ "$DOC_RC" = "0" ] && grep -q "ALL CHECKS PASSED" "$TMP/doc.out"; then
    pass "C2 doctor full pass (ALL CHECKS PASSED)"
  else
    FIRSTBAD="$(grep -E '✗|✘|!  |: FAIL' "$TMP/doc.out" 2>/dev/null | head -n1 | sed 's/^[[:space:]]*//')"
    fail "C2 doctor full pass (exit $DOC_RC)" "first issue: ${FIRSTBAD:-see doctor output}; fix the named subsystem then re-run"
  fi
else
  skip "C2 doctor full pass — ONLINE only (re-run with --online)"
fi

# ===========================================================================
# Stage D — Online ER1 connectivity  (ONLINE only)
# ===========================================================================
stage "Stage D — Online ER1 connectivity"
if [ "$ONLINE" = "1" ]; then
  DRC=0
  run_to 45 "$BIN" check-er1 >"$TMP/er1.out" 2>"$TMP/er1.err" || DRC=$?
  if [ "$DRC" = "0" ] && grep -q "REACHABLE" "$TMP/er1.out" && grep -q "Auth check: OK" "$TMP/er1.out"; then
    pass "D1 check-er1 REACHABLE + auth OK"
  elif grep -q "UNREACHABLE" "$TMP/er1.out" 2>/dev/null; then
    fail "D1 check-er1 UNREACHABLE" "check network/VPN + ER1_API_URL; 'm3c-tools doctor' localizes DNS/TLS/health"
  elif grep -q "Auth check: FAILED" "$TMP/er1.out" 2>/dev/null; then
    fail "D1 check-er1 auth FAILED" "token/API-key invalid or expired — run 'm3c-tools login' or fix ER1_API_KEY"
  else
    fail "D1 check-er1 failed (exit $DRC)" "possible transient network error — re-run; if it persists check connectivity"
  fi
else
  skip "D1 check-er1 — ONLINE only (re-run with --online)"
fi

# ===========================================================================
# Stage E — Core capture smoke test
# ===========================================================================
stage "Stage E — Core capture smoke test"
# E1: transcript smoke (ONLINE)
if [ "$ONLINE" = "1" ]; then
  ERC=0
  run_to 45 "$BIN" transcript dQw4w9WgXcQ --list >"$TMP/tr.out" 2>"$TMP/tr.err" || ERC=$?
  if [ "$ERC" = "0" ] && [ -s "$TMP/tr.out" ]; then
    pass "E1 transcript --list smoke ($(wc -l <"$TMP/tr.out" | tr -d ' ') track(s))"
  else
    fail "E1 transcript --list smoke (exit $ERC)" "YouTube 429/network? tool degrades gracefully — retry later or set YT_PROXY_URL"
  fi
else
  skip "E1 transcript smoke — ONLINE only (re-run with --online)"
fi
# E2: whisper presence (OFFLINE, soft). setup --check exits 1 when venv absent even if
# a system whisper exists, so grade on the 'Whisper:' line, not the exit code.
run_to 20 "$BIN" setup --check >"$TMP/setup.out" 2>"$TMP/setup.err" || true
if grep -E '^[[:space:]]*Whisper:' "$TMP/setup.out" 2>/dev/null | grep -vq '(not installed)'; then
  soft "E2 whisper present"
else
  warn "E2 whisper not installed (optional — only for local audio transcription)" \
       "run 'm3c-tools setup' or put a 'whisper' binary on PATH"
fi

# ===========================================================================
# Stage F — Platform-specific
# ===========================================================================
stage "Stage F — Platform-specific"
if [ "$OS" = "Darwin" ]; then
  # F-mac-1: audio input devices (soft — needs PortAudio + a device)
  FRC=0
  run_to 20 "$BIN" devices >"$TMP/dev.out" 2>"$TMP/dev.err" || FRC=$?
  if [ "$FRC" = "0" ] && grep -q "Audio input devices" "$TMP/dev.out"; then
    soft "F-mac-1 devices lists audio inputs"
  else
    warn "F-mac-1 devices did not list inputs (exit $FRC)" "grant mic permission; check System Settings > Sound"
  fi
  # F-mac-2 / F-mac-3: recording + menubar are interactive — manual per the doc
  skip "F-mac-2 record (live audio) — manual step, see docs/QA-target-device-setup.md"
  skip "F-mac-3 menubar launch — manual step, see docs/QA-target-device-setup.md"
  # F-mac-4: plaud dev status (ONLINE, soft)
  if [ "$ONLINE" = "1" ]; then
    PRC=0
    run_to 30 "$BIN" plaud dev status >"$TMP/pd.out" 2>"$TMP/pd.err" || PRC=$?
    if [ "$PRC" = "0" ] && grep -qi "transcription queue" "$TMP/pd.out"; then
      soft "F-mac-4 plaud dev status reachable"
    else
      warn "F-mac-4 plaud dev status not reachable (exit $PRC)" \
           "run 'm3c-tools plaud auth mcp'; Plaud API can return transient HTTP 400 — re-run"
    fi
  else
    skip "F-mac-4 plaud dev status — ONLINE only (re-run with --online)"
  fi
else
  # Linux (and any non-Darwin): mac-only capture is not built in; legacy plaud only.
  skip "F-mac-* checks — not applicable on $OS (record/devices/screenshot are macOS-only)"
  if run_to 20 "$BIN" help >"$TMP/help.out" 2>/dev/null; then
    if grep -q "plaud auth" "$TMP/help.out" && grep -q "plaud list" "$TMP/help.out"; then
      soft "F-lin legacy plaud surface present (auth/list/check/sync/fix-times)"
    else
      warn "F-lin legacy plaud surface not found in help" "wrong/old binary — reinstall v$EXPECT_VERSION"
    fi
  fi
fi

# ===========================================================================
# Summary
# ===========================================================================
printf '\n%s== SUMMARY ==%s\n' "$C_B" "$C_0"
printf '  required: %d passed / %s%d FAILED%s   soft: %d ok / %d warn   skipped: %d\n' \
       "$REQ_PASS" "$( [ "$REQ_FAIL" -gt 0 ] && printf '%s' "$C_R" )" "$REQ_FAIL" "$C_0" \
       "$SOFT_PASS" "$SOFT_WARN" "$SKIPPED"
if [ "$ONLINE" != "1" ]; then
  printf '  %snote:%s offline mode — online stages (C2/D1/E1%s) were skipped; re-run with --online\n' \
         "$C_Y" "$C_0" "$( [ "$OS" = "Darwin" ] && echo /F-mac-4 )"
fi
if [ "$REQ_FAIL" -gt 0 ]; then
  printf '  %sRESULT: FAIL%s — %d required check(s) failed\n' "$C_R" "$C_0" "$REQ_FAIL"
  exit 1
fi
printf '  %sRESULT: PASS%s — all required checks passed%s\n' "$C_G" "$C_0" \
       "$( [ "$SOFT_WARN" -gt 0 ] && echo " (with $SOFT_WARN warning(s))" )"
exit 0
