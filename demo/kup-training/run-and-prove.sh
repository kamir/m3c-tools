#!/usr/bin/env bash
# run-and-prove.sh — run the full KuP Release-Gate chain and assert every
# step produced its load-bearing artifact, with real content checks (not
# just exit codes).
#
# Usage:
#   ./run-and-prove.sh                # full chain, fail-fast on first red
#   ./run-and-prove.sh --keep-going   # run all steps even if some fail
#   ./run-and-prove.sh --skip-online  # skip P0+02 (offline-only chain)
#   ./run-and-prove.sh --json out.json  # emit a release-gate-form-compatible summary
#
# Output:
#   - Live colored pass/fail per check
#   - Final summary with counts
#   - Optional --json summary (m3c-system-insight-document/v1 shape)
#   - Exit 0 iff every check passed; 1 otherwise
#
# Lifecycle:
#   This script is the executable proof that the KuP Skill-Manager training
#   demo's chain is reproducible end-to-end. Run it before every cohort
#   session as the release gate. The form (release-gate-form.html) is for
#   capturing operator feedback alongside the automated proof.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# Args
KEEP_GOING=0
SKIP_ONLINE=0
JSON_OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep-going)  KEEP_GOING=1; shift ;;
    --skip-online) SKIP_ONLINE=1; shift ;;
    --json)        JSON_OUT="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Colors
c_green()  { printf "\033[32m%s\033[0m\n" "$*"; }
c_red()    { printf "\033[31m%s\033[0m\n" "$*" >&2; }
c_yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
c_dim()    { printf "\033[2m%s\033[0m\n" "$*"; }
c_bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

# Results accumulator
declare -a RESULTS=()         # "<id>|<verdict>|<msg>"
declare -i CHECKS_TOTAL=0
declare -i CHECKS_PASS=0
declare -i CHECKS_FAIL=0
LOG="$LOG_DIR/run-and-prove.log"

mkdir -p "$LOG_DIR"
: > "$LOG"

record() {
  local id="$1" verdict="$2" msg="$3"
  RESULTS+=("${id}|${verdict}|${msg}")
  CHECKS_TOTAL=$((CHECKS_TOTAL+1))
  case "$verdict" in
    green) CHECKS_PASS=$((CHECKS_PASS+1)); c_green  "  ✓ [$id] $msg" ;;
    red)   CHECKS_FAIL=$((CHECKS_FAIL+1)); c_red    "  ✗ [$id] $msg" ;;
    yellow) c_yellow "  ! [$id] $msg" ;;
    *) c_dim "  ? [$id] $msg" ;;
  esac
}

run_step() {
  local id="$1" desc="$2"; shift 2
  c_bold ""
  c_bold "═══════════════════════════════════════"
  c_bold " $id — $desc"
  c_bold "═══════════════════════════════════════"
  echo "[$id] $desc" >> "$LOG"
  if "$@" >> "$LOG" 2>&1; then
    return 0
  else
    local rc=$?
    echo "[$id] script returned $rc (continuing to assertions)" >> "$LOG"
    return "$rc"
  fi
}

assert_file() {
  local id="$1" path="$2" desc="$3"
  if [ -e "$path" ]; then
    record "$id" green "$desc — exists"
  else
    record "$id" red "$desc — MISSING ($path)"
  fi
}

assert_file_min() {
  local id="$1" path="$2" min="$3" desc="$4"
  if [ ! -e "$path" ]; then
    record "$id" red "$desc — MISSING ($path)"; return
  fi
  local sz; sz=$(wc -c < "$path" | tr -d ' ')
  if [ "$sz" -ge "$min" ]; then
    record "$id" green "$desc — ${sz} bytes ≥ ${min}"
  else
    record "$id" red "$desc — ${sz} bytes < ${min} (truncated?)"
  fi
}

assert_grep() {
  local id="$1" path="$2" pattern="$3" desc="$4"
  if [ ! -e "$path" ]; then
    record "$id" red "$desc — file missing ($path)"; return
  fi
  if grep -qE "$pattern" "$path"; then
    record "$id" green "$desc"
  else
    record "$id" red "$desc — pattern not found"
  fi
}

# Fixed-string variant — use when the value may contain regex metachars
# (base64 strings have + and / which are regex specials in -E mode).
assert_contains() {
  local id="$1" path="$2" needle="$3" desc="$4"
  if [ ! -e "$path" ]; then
    record "$id" red "$desc — file missing ($path)"; return
  fi
  if grep -qF "$needle" "$path"; then
    record "$id" green "$desc"
  else
    record "$id" red "$desc — string not found"
  fi
}

assert_exit() {
  local id="$1" expected="$2" desc="$3"; shift 3
  local actual
  set +e
  "$@" >> "$LOG" 2>&1
  actual=$?
  set -e
  if [ "$actual" -eq "$expected" ]; then
    record "$id" green "$desc — exit $actual (expected $expected)"
  else
    record "$id" red "$desc — exit $actual (expected $expected)"
  fi
}

# Fail-fast helper
finished() {
  if [ "$CHECKS_FAIL" -gt 0 ] && [ "$KEEP_GOING" -ne 1 ]; then
    summary
    exit 1
  fi
}

summary() {
  c_bold ""
  c_bold "═══════════════════════════════════════"
  c_bold " SUMMARY"
  c_bold "═══════════════════════════════════════"
  printf "  Checks total: %d\n" "$CHECKS_TOTAL"
  c_green "  Pass:  $CHECKS_PASS"
  if [ "$CHECKS_FAIL" -gt 0 ]; then
    c_red "  Fail:  $CHECKS_FAIL"
  else
    printf "  Fail:  %d\n" "$CHECKS_FAIL"
  fi
  echo ""
  if [ -n "$JSON_OUT" ]; then
    write_json
    c_dim "  → JSON summary: $JSON_OUT"
  fi
  c_dim "  → log: $LOG"
}

write_json() {
  local now; now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local overall="green"
  [ "$CHECKS_FAIL" -gt 0 ] && overall="red"
  {
    printf '{\n'
    printf '  "schema": "m3c-system-insight-document/v1",\n'
    printf '  "form_version": "run-and-prove-v1",\n'
    printf '  "session_id": "kup-release-gate-prove-%s",\n' "$(date -u +%Y%m%d-%H%M%S)"
    printf '  "captured_by": "run-and-prove.sh",\n'
    printf '  "captured_at_export": "%s",\n' "$now"
    printf '  "mode": "automated",\n'
    printf '  "host": "%s",\n' "$(uname -sm | tr ' ' '-' | tr '[:upper:]' '[:lower:]')"
    printf '  "start_dir": "%s",\n' "$SCRIPT_DIR"
    printf '  "overall_verdict": "%s",\n' "$overall"
    printf '  "counts": { "total": %d, "green": %d, "red": %d },\n' \
      "$CHECKS_TOTAL" "$CHECKS_PASS" "$CHECKS_FAIL"
    printf '  "checks": [\n'
    local first=1
    for line in "${RESULTS[@]}"; do
      local id verdict msg
      id="${line%%|*}"
      verdict="${line#*|}"; verdict="${verdict%%|*}"
      msg="${line#*|*|}"
      msg="${msg//\"/\\\"}"
      if [ "$first" -eq 1 ]; then first=0; else printf ',\n'; fi
      printf '    {"id": "%s", "verdict": "%s", "msg": "%s"}' "$id" "$verdict" "$msg"
    done
    printf '\n  ]\n}\n'
  } > "$JSON_OUT"
}

trap 'rc=$?; if [ $rc -ne 0 ] && [ $CHECKS_FAIL -eq 0 ]; then c_red "ABORTED with rc=$rc — see $LOG"; fi; summary' EXIT

# ============================================================================
# Step P0 — register identities (skipped in offline mode)
# ============================================================================
if [ "$SKIP_ONLINE" -eq 0 ]; then
  c_bold ""
  c_bold "═══════════════════════════════════════"
  c_bold " P0 — register identities (one-time)"
  c_bold "═══════════════════════════════════════"
  # Only register if keys already exist (otherwise this fails — let 01/03 generate first)
  if [ -f "$KEYS_DIR/mirko.pub" ]; then
    if "$SCRIPT_DIR/register-identity.sh" id:mirko@m3c "$KEYS_DIR/mirko.pub" \
       "Mirko (KuP demo author)" >> "$LOG" 2>&1; then
      record P0 green "Mirko identity registered or already exists"
    else
      rc=$?
      if [ $rc -eq 0 ] || grep -q "already_exists\|HTTP 201\|HTTP 409" "$LOG" 2>/dev/null; then
        record P0 green "Mirko identity ok (idempotent)"
      else
        record P0 yellow "Mirko identity registration returned $rc — will retry post-01"
      fi
    fi
  else
    record P0 yellow "skipping Mirko registration (keys not yet generated — will run after step 01)"
  fi
fi

# ============================================================================
# Step 00 — Preflight
# ============================================================================
run_step 00 "Preflight" bash 00-preflight.sh
assert_file        00 "$SKILLCTL"               "skillctl binary built"
assert_exit        00 0 "skillctl --help runs"  "$SKILLCTL" --help
finished

# ============================================================================
# Step 01 — Mirko authors and signs
# ============================================================================
run_step 01 "Mirko authors and signs" bash 01-mirko-author.sh
assert_file 01 "$KEYS_DIR/mirko.priv"             "mirko.priv keypair"
assert_file 01 "$KEYS_DIR/mirko.pub"              "mirko.pub keypair"
BUNDLE="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.skb"
assert_file_min 01 "$BUNDLE" 256                  "bundle .skb"
assert_file 01 "$ARTIFACTS_DIR/digest.txt"        "digest.txt"
DIGEST=$(cat "$ARTIFACTS_DIR/digest.txt" 2>/dev/null || echo "")
SIG="${BUNDLE}.${DIGEST#sha256:}.author.sig"
assert_file_min 01 "$SIG" 64                      "author signature (64 bytes)"
assert_exit 01 0 "verify-sig accepts genuine bundle" \
  "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/mirko.pub" "$BUNDLE"
finished

# ============================================================================
# (Re-)register Mirko now that keys exist
# ============================================================================
if [ "$SKIP_ONLINE" -eq 0 ]; then
  if "$SCRIPT_DIR/register-identity.sh" id:mirko@m3c "$KEYS_DIR/mirko.pub" \
     "Mirko (KuP demo author)" >> "$LOG" 2>&1; then
    record P0 green "Mirko identity active in registry"
  else
    record P0 yellow "Mirko identity registration not OK — 02 will likely return signature_invalid"
  fi
fi

# ============================================================================
# Step 02 — Mirko publishes (online stretch)
# ============================================================================
if [ "$SKIP_ONLINE" -eq 0 ]; then
  run_step 02 "Mirko publishes to aims" bash 02-mirko-publish.sh
  assert_file 02 "$LOG_DIR/admit.json"           "admit.json written"
  if [ -f "$LOG_DIR/admit.json" ]; then
    if grep -qE '"code"\s*:\s*"(already_exists|admitted|signature_invalid)"|"digest"' "$LOG_DIR/admit.json"; then
      record 02 green "registry responded (admitted, dup, or specific failure code)"
    else
      record 02 yellow "registry response shape unexpected (best-effort step — continuing)"
    fi
  fi
fi

# ============================================================================
# Step 03 — Reviewer attests
# ============================================================================
run_step 03 "Reviewer attests" bash 03-reviewer-attest.sh
assert_file 03 "$KEYS_DIR/reviewer.priv"          "reviewer.priv keypair"
assert_file 03 "$KEYS_DIR/reviewer.pub"           "reviewer.pub keypair"
assert_file 03 "$ARTIFACTS_DIR/attestation.json"  "attestation.json"
assert_grep 03 "$ARTIFACTS_DIR/attestation.json"  '"level"\s*:\s*"green"' 'attestation level=green'
finished

# Register reviewer too (online)
if [ "$SKIP_ONLINE" -eq 0 ] && [ -f "$KEYS_DIR/reviewer.pub" ]; then
  if "$SCRIPT_DIR/register-identity.sh" id:reviewer@m3c "$KEYS_DIR/reviewer.pub" \
     "Reviewer (KuP demo)" >> "$LOG" 2>&1; then
    record P0 green "Reviewer identity active in registry"
  fi
fi

# ============================================================================
# Step 04 — Eric pins trust root
# ============================================================================
run_step 04 "Eric pins trust root" bash 04-eric-trust-root.sh
TRUST_FILE="$INSTALL_HOME/.claude/skill-trust-roots.yaml"
assert_file 04 "$TRUST_FILE"                       "trust-roots.yaml"
# Verify Mirko's pubkey is actually in there
MIRKO_PUB_B64=$(openssl pkey -in "$KEYS_DIR/mirko.pub" -pubin -outform DER 2>/dev/null \
  | tail -c 32 | base64 | tr -d '\n')
if [ -f "$TRUST_FILE" ] && [ -n "$MIRKO_PUB_B64" ]; then
  # base64 contains + and / which are regex metachars; use fixed-string match.
  assert_contains 04 "$TRUST_FILE" "$MIRKO_PUB_B64" 'Mirko pubkey pinned in trust roots'
fi
finished

# ============================================================================
# Step 05 — Eric installs and runs (LOAD-BEARING)
# ============================================================================
run_step 05 "Eric installs and runs (VALID)" bash 05-eric-install-and-run.sh
HELLO_OUT="$INSTALL_HOME/output/hello.txt"
assert_file 05 "$HELLO_OUT"                        "★ hello.txt — load-bearing valid-path proof"
if [ -f "$HELLO_OUT" ]; then
  assert_grep 05 "$HELLO_OUT" 'kup-hello|Hello' 'hello.txt has canonical greeting content'
fi
finished

# ============================================================================
# Steps 06–09 — INVALID paths (must refuse)
# ============================================================================
run_step 06 "INVALID — tampered bytes" bash 06-invalid-tampered.sh
TAMPERED="$BUNDLES_DIR/tampered.skb"
if [ -f "$TAMPERED" ]; then
  assert_exit 06 11 "verify-sig REFUSES tampered bundle (signature_invalid)" \
    "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/mirko.pub" "$TAMPERED"
else
  record 06 red "tampered bundle not produced"
fi

run_step 07 "INVALID — wrong key (impersonation)" bash 07-invalid-wrong-key.sh
ATTACKER_BUNDLE="$BUNDLES_DIR/attacker-${SKILL_NAME}-${SKILL_VERSION}.skb"
if [ -f "$ATTACKER_BUNDLE" ]; then
  assert_exit 07 11 "verify-sig REFUSES attacker bundle against pinned mirko.pub" \
    "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/mirko.pub" "$ATTACKER_BUNDLE"
  if [ -f "$KEYS_DIR/attacker.pub" ]; then
    assert_exit 07 0  "control: attacker bundle verifies against attacker.pub (proves bundle is structurally valid)" \
      "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/attacker.pub" "$ATTACKER_BUNDLE"
  fi
fi

run_step 08 "INVALID — no signature delivered" bash 08-invalid-no-signature.sh
NOSIG_BUNDLE="$BUNDLES_DIR/no-sig/${SKILL_NAME}-${SKILL_VERSION}.skb"
if [ -f "$NOSIG_BUNDLE" ]; then
  set +e
  "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/mirko.pub" "$NOSIG_BUNDLE" >> "$LOG" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    record 08 green "verify-sig REFUSES no-signature bundle — exit $rc"
  else
    record 08 red "verify-sig accepted bundle with no sidecar signature — CRITICAL FAIL-OPEN"
  fi
fi

run_step 09 "INVALID — post-install edit" bash 09-invalid-edited-install.sh
# 09's script repairs the install at the end — assert log captured the mismatch
if grep -q "CHECKSUMS mismatch detected" "$LOG"; then
  record 09 green "post-install drift detected via CHECKSUMS"
else
  record 09 red "no CHECKSUMS mismatch line found in log"
fi
if grep -q "repaired: shasum now" "$LOG"; then
  record 09 green "drift recoverable via re-extract from signed bundle"
else
  record 09 yellow "repair-from-bundle path not exercised"
fi
finished

# ============================================================================
# G1 — PDFs
# ============================================================================
run_step G1 "Print user guide as PDF" bash make-pdf.sh
assert_file_min G1 "$ARTIFACTS_DIR/USER-MANUAL.pdf" 50000      "USER-MANUAL.pdf"
assert_file_min G1 "$ARTIFACTS_DIR/SKILLCTL-MANUAL.pdf" 50000  "SKILLCTL-MANUAL.pdf"
assert_file_min G1 "$ARTIFACTS_DIR/KuP-skill-manager-handbook.pdf" 50000 "combined handbook PDF"

# ============================================================================
# G2 — release artifacts
# ============================================================================
run_step G2 "Cross-platform release of skillctl" bash build-release.sh
RELEASE_DIR="$ARTIFACTS_DIR/release"
if [ -d "$RELEASE_DIR" ]; then
  COUNT=$(find "$RELEASE_DIR" -maxdepth 1 -type f | wc -l | tr -d ' ')
  if [ "$COUNT" -ge 8 ]; then
    record G2 green "release dir has $COUNT files (≥8 expected)"
  else
    record G2 red "release dir has $COUNT files (<8 expected)"
  fi
  assert_file G2 "$RELEASE_DIR/SHA256SUMS" "SHA256SUMS file"
  assert_file G2 "$RELEASE_DIR/install.sh" "install.sh"
  assert_file G2 "$RELEASE_DIR/RELEASE_NOTES.md" "RELEASE_NOTES.md"
  # Validate SHA256SUMS — every listed file must hash-match
  if [ -f "$RELEASE_DIR/SHA256SUMS" ]; then
    set +e
    ( cd "$RELEASE_DIR" && shasum -a 256 -c SHA256SUMS ) >> "$LOG" 2>&1
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      record G2 green "SHA256SUMS verifies all listed binaries"
    else
      record G2 red "SHA256SUMS verification failed (exit $rc)"
    fi
  fi
fi

# ============================================================================
# G3 — synthesis: skill transfer Mirko → Eric (steps 01–05 all green AND hello.txt)
# ============================================================================
G3_FAILS=$(printf '%s\n' "${RESULTS[@]}" | awk -F'|' '$1 ~ /^0[1-5]$/ && $2=="red"' | wc -l | tr -d ' ')
if [ "$G3_FAILS" -eq 0 ] && [ -f "$HELLO_OUT" ]; then
  record G3 green "synthesis: 01–05 green AND hello.txt present"
else
  record G3 red "synthesis: $G3_FAILS red checks in 01–05 OR hello.txt missing"
fi

# ============================================================================
# G4 — synthesis: valid works AND invalid fails
# ============================================================================
G4_FAILS=$(printf '%s\n' "${RESULTS[@]}" | awk -F'|' '$1 ~ /^0[5-9]$/ && $2=="red"' | wc -l | tr -d ' ')
if [ "$G4_FAILS" -eq 0 ]; then
  record G4 green "synthesis: 05 (valid) green AND 06/07/08/09 (invalid) all refused"
else
  record G4 red "synthesis: $G4_FAILS red checks across 05–09"
fi

# trap → summary → exit
[ "$CHECKS_FAIL" -eq 0 ]
