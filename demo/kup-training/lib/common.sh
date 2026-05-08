#!/usr/bin/env bash
# Shared helpers for the KuP Skill-Manager training demo.
# Source this from any demo step:  source "$(dirname "$0")/lib/common.sh"

set -uo pipefail

# Colours (skip when not a TTY)
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'
else
  C_RESET=''; C_BOLD=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''
fi

# Workspace layout (the demo writes only under here).
DEMO_DIR="${DEMO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$DEMO_DIR/artifacts}"
KEYS_DIR="$ARTIFACTS_DIR/keys"
BUNDLES_DIR="$ARTIFACTS_DIR/bundles"
TRUST_DIR="$ARTIFACTS_DIR/trust-roots"
INSTALL_HOME="$ARTIFACTS_DIR/eric-home"          # used as $HOME for `skillctl install`
LOG_DIR="$ARTIFACTS_DIR/logs"

mkdir -p "$KEYS_DIR" "$BUNDLES_DIR" "$TRUST_DIR" "$INSTALL_HOME/.claude" "$LOG_DIR"

# Identities for the demo
MIRKO_ID="${MIRKO_ID:-id:mirko@m3c}"
ERIC_ID="${ERIC_ID:-id:eric@kup}"
REVIEWER_ID="${REVIEWER_ID:-id:reviewer@m3c}"

# Skill under test
SKILL_NAME="${SKILL_NAME:-kup-hello}"
SKILL_VERSION="${SKILL_VERSION:-0.1.0}"

# Registry endpoint (online stretch goal); skip online path if unset or unreachable.
REGISTRY_URL="${REGISTRY_URL:-${M3C_REGISTRY_URL:-https://127.0.0.1:8081}}"

# Built skillctl binary (preflight populates this).
SKILLCTL="${SKILLCTL:-$ARTIFACTS_DIR/bin/skillctl}"

log()    { printf "${C_CYAN}[demo]${C_RESET} %s\n" "$*" >&2; }
note()   { printf "${C_BLUE}      %s${C_RESET}\n" "$*" >&2; }
ok()     { printf "${C_GREEN}  ✓ %s${C_RESET}\n" "$*" >&2; }
warn()   { printf "${C_YELLOW}  ! %s${C_RESET}\n" "$*" >&2; }
fail()   { printf "${C_RED}  ✗ %s${C_RESET}\n" "$*" >&2; }
header() {
  printf "\n${C_BOLD}${C_CYAN}==> %s${C_RESET}\n" "$*" >&2
  printf "${C_CYAN}    %s${C_RESET}\n" "$(printf '─%.0s' $(seq 1 60))" >&2
}

# Execute a command, capture exit, assert it matches expected.
# Usage:  assert_exit <expected> -- <command...>
assert_exit() {
  local expected="$1"; shift
  [[ "$1" == "--" ]] && shift
  local cmd_str
  cmd_str="$*"
  set +e
  "$@" >>"$LOG_DIR/full.log" 2>&1
  local actual=$?
  set -e
  if [[ "$actual" == "$expected" ]]; then
    ok "exit $actual (expected $expected)  —  $cmd_str"
    return 0
  else
    fail "exit $actual (expected $expected)  —  $cmd_str"
    fail "tail of full.log:"
    tail -n 5 "$LOG_DIR/full.log" | sed 's/^/      /' >&2
    return 1
  fi
}

# Run a command; require exit 0; print last stdout line as a result.
# Uses an explicit subshell + temp file to dodge the bash `local rc=$?`
# corner case (where `local` masks the prior exit status under some
# shopt configurations).
run_ok() {
  local cmd_str="$*"
  local tmp_out
  tmp_out=$(mktemp)
  local rc=0
  if "$@" >"$tmp_out" 2>>"$LOG_DIR/full.log"; then
    rc=0
  else
    rc=$?
  fi
  if [[ "$rc" -ne 0 ]]; then
    fail "exit $rc — $cmd_str"
    rm -f "$tmp_out"
    return 1
  fi
  ok "$cmd_str"
  if [[ -s "$tmp_out" ]]; then
    head -3 "$tmp_out" | sed 's/^/      /' >&2
  fi
  cat "$tmp_out"
  rm -f "$tmp_out"
}

require_skillctl() {
  if [[ ! -x "$SKILLCTL" ]]; then
    fail "skillctl binary not found at $SKILLCTL"
    fail "run ./00-preflight.sh first"
    exit 2
  fi
}

# Resolve ER1_API_KEY from macOS keychain if it's not already in env.
# Same convention used by register-identity.sh and push-to-er1.sh:
#   service = aims-core-er1 ,  account = $USER
# Returns 0 whether or not the key was resolved (caller checks $ER1_API_KEY).
ensure_er1_api_key_from_keychain() {
  if [[ -n "${ER1_API_KEY:-}" ]]; then return 0; fi
  if ! command -v security >/dev/null 2>&1; then return 0; fi
  local _kc_key
  _kc_key=$(security find-generic-password -s aims-core-er1 -a "$USER" -w 2>/dev/null || true)
  if [[ -n "$_kc_key" ]]; then
    export ER1_API_KEY="$_kc_key"
  fi
}

# Online-mode probe: returns 0 if registry is reachable AND creds are set.
# Auto-resolves ER1_API_KEY from the macOS keychain on first call so users
# don't have to remember to export it before running each step script.
online_mode_available() {
  ensure_er1_api_key_from_keychain
  [[ -n "${ER1_API_KEY:-}" ]] || return 1
  curl -sk -m 3 -o /dev/null -w "%{http_code}" "$REGISTRY_URL/api/skills/health" 2>/dev/null \
    | grep -q "^200$" || return 1
  return 0
}

# Auth headers for the online registry (uses ER1_API_KEY + X-User-ID).
# Usage:  auth_curl <user-id> -- <curl args...>
auth_curl() {
  local user="$1"; shift
  [[ "$1" == "--" ]] && shift
  curl -sk \
    -H "X-API-KEY: ${ER1_API_KEY:-}" \
    -H "X-User-ID: $user" \
    -H "Content-Type: application/json" \
    "$@"
}
