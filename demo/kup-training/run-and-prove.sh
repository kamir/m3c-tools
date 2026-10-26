#!/usr/bin/env bash
# run-and-prove.sh: run the full KuP Release-Gate chain and assert every
# step produced its load-bearing artifact, with real content checks (not
# just exit codes).
#
# Usage:
#   ./run-and-prove.sh                # full chain, fail-fast on first red
#   ./run-and-prove.sh --keep-going   # run all steps even if some fail
#   ./run-and-prove.sh --skip-online  # skip P0+02 (offline-only chain)
#   ./run-and-prove.sh --chain-only   # trust chain only: no PDF (G1), no release (G2)
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
CHAIN_ONLY=0
JSON_OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep-going)  KEEP_GOING=1; shift ;;
    --skip-online) SKIP_ONLINE=1; shift ;;
    --chain-only)  CHAIN_ONLY=1; shift ;;
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
declare -i CHECKS_WARN=0
LOG="$LOG_DIR/run-and-prove.log"

mkdir -p "$LOG_DIR"
: > "$LOG"

record() {
  local id="$1" verdict="$2" msg="$3"
  RESULTS+=("${id}|${verdict}|${msg}")
  CHECKS_TOTAL=$((CHECKS_TOTAL+1))
  case "$verdict" in
    green)  CHECKS_PASS=$((CHECKS_PASS+1)); c_green  "  ✓ [$id] $msg" ;;
    red)    CHECKS_FAIL=$((CHECKS_FAIL+1)); c_red    "  ✗ [$id] $msg" ;;
    yellow) CHECKS_WARN=$((CHECKS_WARN+1)); c_yellow "  ! [$id] $msg" ;;
    *)      c_dim "  ? [$id] $msg" ;;
  esac
}

run_step() {
  local id="$1" desc="$2"; shift 2
  c_bold ""
  c_bold "═══════════════════════════════════════"
  c_bold " $id: $desc"
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
    record "$id" green "$desc, exists"
  else
    record "$id" red "$desc, MISSING ($path)"
  fi
}

assert_file_min() {
  local id="$1" path="$2" min="$3" desc="$4"
  if [ ! -e "$path" ]; then
    record "$id" red "$desc, MISSING ($path)"; return
  fi
  local sz; sz=$(wc -c < "$path" | tr -d ' ')
  if [ "$sz" -ge "$min" ]; then
    record "$id" green "$desc, ${sz} bytes ≥ ${min}"
  else
    record "$id" red "$desc: ${sz} bytes < ${min} (truncated?)"
  fi
}

assert_grep() {
  local id="$1" path="$2" pattern="$3" desc="$4"
  if [ ! -e "$path" ]; then
    record "$id" red "$desc, file missing ($path)"; return
  fi
  if grep -qE "$pattern" "$path"; then
    record "$id" green "$desc"
  else
    record "$id" red "$desc, pattern not found"
  fi
}

# Fixed-string variant: use when the value may contain regex metachars
# (base64 strings have + and / which are regex specials in -E mode).
assert_contains() {
  local id="$1" path="$2" needle="$3" desc="$4"
  if [ ! -e "$path" ]; then
    record "$id" red "$desc, file missing ($path)"; return
  fi
  if grep -qF "$needle" "$path"; then
    record "$id" green "$desc"
  else
    record "$id" red "$desc, string not found"
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
    record "$id" green "$desc, exit $actual (expected $expected)"
  else
    record "$id" red "$desc, exit $actual (expected $expected)"
  fi
}

# P0: is <id> registered in the skill registry with the local key?
# register-identity.sh confirms an existing registration with a plain read and
# needs an admin session (AIMS_ADMIN_COOKIE) only to create one: the shared
# ER1_API_KEY is never admin, whatever X-User-ID says. Its instruction for
# exit 3 (no admin session) and its diagnosis for exit 4 (different or revoked
# key) go to the terminal, not just the log: nothing later in the run fixes them.
prove_identity() {
  local id="$1" pub="$2" name="$3" out rc
  out=$(mktemp)
  "$SCRIPT_DIR/register-identity.sh" "$id" "$pub" "$name" > "$out" 2>&1
  rc=$?
  cat "$out" >> "$LOG"
  case "$rc" in
    0) record P0 green "$id registered with the local key" ;;
    3) record P0 red "$id not confirmed registered, and registering it needs an admin session (AIMS_ADMIN_COOKIE)"
       sed -n '/✗/,$p' "$out" | sed 's/^/    /' >&2
       c_dim "    or export AIMS_ADMIN_COOKIE (step 3) and re-run ./run-and-prove.sh: P0 registers what is missing" ;;
    4) record P0 red "$id registered with a different or revoked key"
       sed -n '/✗/,$p' "$out" | sed 's/^/    /' >&2 ;;
    *) record P0 yellow "$id registration returned $rc, see $LOG" ;;
  esac
  rm -f "$out"
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
  if [ "$CHECKS_WARN" -gt 0 ]; then
    c_yellow "  Warn:  $CHECKS_WARN"
  else
    printf "  Warn:  %d\n" "$CHECKS_WARN"
  fi
  if [ "$CHECKS_FAIL" -gt 0 ]; then
    c_red "  Fail:  $CHECKS_FAIL"
  else
    printf "  Fail:  %d\n" "$CHECKS_FAIL"
  fi
  # Sanity: pass + warn + fail must equal total. If not, the loop drifted.
  local sum=$((CHECKS_PASS + CHECKS_WARN + CHECKS_FAIL))
  if [ "$sum" -ne "$CHECKS_TOTAL" ]; then
    c_red "  ⚠ accounting drift: $sum (pass+warn+fail) != $CHECKS_TOTAL (total)"
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
    printf '  "counts": { "total": %d, "green": %d, "yellow": %d, "red": %d },\n' \
      "$CHECKS_TOTAL" "$CHECKS_PASS" "$CHECKS_WARN" "$CHECKS_FAIL"
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

trap 'rc=$?; if [ $rc -ne 0 ] && [ $CHECKS_FAIL -eq 0 ]; then c_red "ABORTED with rc=$rc: see $LOG"; fi; summary' EXIT

# ============================================================================
# Step P0: register identities (skipped in offline mode)
# ============================================================================
if [ "$SKIP_ONLINE" -eq 0 ]; then
  c_bold ""
  c_bold "═══════════════════════════════════════"
  c_bold " P0: register identities (one-time)"
  c_bold "═══════════════════════════════════════"
  # Only register if keys already exist (otherwise this fails: let 01/03 generate first)
  if [ -f "$KEYS_DIR/bob.pub" ]; then
    prove_identity id:bob@m3c "$KEYS_DIR/bob.pub" "Bob (KuP demo author)"
  else
    record P0 yellow "skipping Bob registration (keys not yet generated, will run after step 01)"
  fi
fi

# ============================================================================
# Step 00: Preflight
# ============================================================================
run_step 00 "Preflight" bash 00-preflight.sh
assert_file        00 "$SKILLCTL"               "skillctl binary built"
assert_exit        00 0 "skillctl --help runs"  "$SKILLCTL" --help
finished

# ============================================================================
# Step 01: Bob authors and signs
# ============================================================================
run_step 01 "Bob authors and signs" bash 01-bob-author.sh
assert_file 01 "$KEYS_DIR/bob.priv"             "bob.priv keypair"
assert_file 01 "$KEYS_DIR/bob.pub"              "bob.pub keypair"
BUNDLE="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.skb"
assert_file_min 01 "$BUNDLE" 256                  "bundle .skb"
assert_file 01 "$ARTIFACTS_DIR/digest.txt"        "digest.txt"
DIGEST=$(cat "$ARTIFACTS_DIR/digest.txt" 2>/dev/null || echo "")
SIG="${BUNDLE}.${DIGEST#sha256:}.author.sig"
assert_file_min 01 "$SIG" 64                      "author signature (64 bytes)"
assert_exit 01 0 "verify-sig accepts genuine bundle" \
  "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/bob.pub" "$BUNDLE"
finished

# ============================================================================
# (Re-)register Bob now that keys exist
# ============================================================================
if [ "$SKIP_ONLINE" -eq 0 ]; then
  prove_identity id:bob@m3c "$KEYS_DIR/bob.pub" "Bob (KuP demo author)"
fi

# ============================================================================
# Step 02: Bob publishes (online stretch)
# ============================================================================
if [ "$SKIP_ONLINE" -eq 0 ]; then
  run_step 02 "Bob publishes to ER1 self" bash 02-bob-publish.sh
  # 02 publishes through the ER1 `self` transport (skillctl publish
  # --registry self, SPEC-0246) and is best-effort by contract: it prints its
  # outcome and exits 0 either way, and it never consults the skill registry's
  # identities. It used to POST /api/skills/bundles into logs/admit.json, and
  # this block graded that file; nothing has written it since, so a fresh
  # workspace read MISSING and an older one re-read a stale response. $LOG is
  # truncated per run, so grading what 02 printed cannot see an earlier run.
  if grep -q "published to ER1 self" "$LOG"; then
    record 02 green "published to ER1 self (skillctl publish --registry self)"
  elif grep -q "skipping the ER1 self publish" "$LOG"; then
    record 02 yellow "02 found no reachable registry and skipped itself (the chain proof in 05 doesn't depend on it)"
  elif grep -q "publish --registry self exit" "$LOG"; then
    record 02 yellow "ER1 self publish failed, best-effort (needs an ER1 login + target; see logs/full.log; 05 doesn't depend on it)"
  else
    record 02 red "02 printed no publish outcome, see $LOG"
  fi
fi

# ============================================================================
# Step 03: Reviewer attests
# ============================================================================
run_step 03 "Reviewer attests" bash 03-reviewer-attest.sh
assert_file 03 "$KEYS_DIR/reviewer.priv"          "reviewer.priv keypair"
assert_file 03 "$KEYS_DIR/reviewer.pub"           "reviewer.pub keypair"
assert_file 03 "$ARTIFACTS_DIR/attestation.json"  "attestation.json"
assert_grep 03 "$ARTIFACTS_DIR/attestation.json"  '"level"\s*:\s*"green"' 'attestation level=green'
finished

# Register reviewer too (online)
if [ "$SKIP_ONLINE" -eq 0 ] && [ -f "$KEYS_DIR/reviewer.pub" ]; then
  prove_identity id:reviewer@m3c "$KEYS_DIR/reviewer.pub" "Reviewer (KuP demo)"
fi

# ============================================================================
# Step 04: Alice pins trust root
# ============================================================================
run_step 04 "Alice pins trust root" bash 04-alice-trust-root.sh
TRUST_FILE="$INSTALL_HOME/.claude/skill-trust-roots.yaml"
assert_file 04 "$TRUST_FILE"                       "trust-roots.yaml"
# Verify Bob's pubkey is actually in there
MIRKO_PUB_B64=$(openssl pkey -in "$KEYS_DIR/bob.pub" -pubin -outform DER 2>/dev/null \
  | tail -c 32 | base64 | tr -d '\n')
if [ -f "$TRUST_FILE" ] && [ -n "$MIRKO_PUB_B64" ]; then
  # base64 contains + and / which are regex metachars; use fixed-string match.
  assert_contains 04 "$TRUST_FILE" "$MIRKO_PUB_B64" 'Bob pubkey pinned in trust roots'
fi
finished

# ============================================================================
# Step 05. Alice installs and runs (LOAD-BEARING)
# ============================================================================
run_step 05 "Alice installs and runs (VALID)" bash 05-alice-install-and-run.sh
HELLO_OUT="$INSTALL_HOME/output/hello.txt"
assert_file 05 "$HELLO_OUT"                        "★ hello.txt: load-bearing valid-path proof"
if [ -f "$HELLO_OUT" ]; then
  assert_grep 05 "$HELLO_OUT" 'kup-hello|Hello' 'hello.txt has canonical greeting content'
fi
finished

# ============================================================================
# Steps 06–09, INVALID paths (must refuse)
# ============================================================================
run_step 06 "INVALID, tampered bytes" bash 06-invalid-tampered.sh
TAMPERED="$BUNDLES_DIR/tampered.skb"
if [ -f "$TAMPERED" ]; then
  assert_exit 06 11 "verify-sig REFUSES tampered bundle (signature_invalid)" \
    "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/bob.pub" "$TAMPERED"
else
  record 06 red "tampered bundle not produced"
fi

run_step 07 "INVALID: wrong key (impersonation)" bash 07-invalid-wrong-key.sh
ATTACKER_BUNDLE="$BUNDLES_DIR/attacker-${SKILL_NAME}-${SKILL_VERSION}.skb"
if [ -f "$ATTACKER_BUNDLE" ]; then
  assert_exit 07 11 "verify-sig REFUSES attacker bundle against pinned bob.pub" \
    "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/bob.pub" "$ATTACKER_BUNDLE"
  if [ -f "$KEYS_DIR/attacker.pub" ]; then
    assert_exit 07 0  "control: attacker bundle verifies against attacker.pub (proves bundle is structurally valid)" \
      "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/attacker.pub" "$ATTACKER_BUNDLE"
  fi
fi

run_step 08 "INVALID: no signature delivered" bash 08-invalid-no-signature.sh
NOSIG_BUNDLE="$BUNDLES_DIR/no-sig/${SKILL_NAME}-${SKILL_VERSION}.skb"
if [ -f "$NOSIG_BUNDLE" ]; then
  set +e
  "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/bob.pub" "$NOSIG_BUNDLE" >> "$LOG" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    record 08 green "verify-sig REFUSES no-signature bundle, exit $rc"
  else
    record 08 red "verify-sig accepted bundle with no sidecar signature, CRITICAL FAIL-OPEN"
  fi
fi

run_step 09 "INVALID: post-install edit" bash 09-invalid-edited-install.sh
# 09's script repairs the install at the end: assert log captured the mismatch
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
# G1: PDFs   (maintainer gate, skipped by --chain-only)
# ============================================================================
#
# G1 renders a manual that lives on the PRIVATE maintenance plane, so it needs
# $M3C_MAINTENANCE_DIR. A learner running the Test Ride (TUTORIAL.md) does not
# have that checkout, and this used to ABORT the whole proof at rc=1 after every
# trust check had passed: a red verdict for a missing document, on a run whose
# subject is the trust chain. --chain-only skips G1 and G2 for that case; a
# maintainer running the release gate still gets both, unskipped and blocking.
if [ "$CHAIN_ONLY" -eq 1 ]; then
  record G1 yellow "skipped by --chain-only (PDF render needs the private manual)"
  record G2 yellow "skipped by --chain-only (cross-platform release build)"
else
run_step G1 "Print user guide as PDF" bash make-pdf.sh
assert_file_min G1 "$ARTIFACTS_DIR/USER-MANUAL.pdf" 50000      "USER-MANUAL.pdf"
assert_file_min G1 "$ARTIFACTS_DIR/SKILLCTL-MANUAL.pdf" 50000  "SKILLCTL-MANUAL.pdf"
assert_file_min G1 "$ARTIFACTS_DIR/KuP-skill-manager-handbook.pdf" 50000 "combined handbook PDF"

# ============================================================================
# G2: release artifacts
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
  # Validate SHA256SUMS. Every listed file must hash-match
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
fi   # end of the --chain-only guard around G1 + G2

# ============================================================================
# G3, synthesis: skill transfer Bob → Alice (steps 01–05 all green AND hello.txt)
# ============================================================================
G3_FAILS=$(printf '%s\n' "${RESULTS[@]}" | awk -F'|' '$1 ~ /^0[1-5]$/ && $2=="red"' | wc -l | tr -d ' ')
if [ "$G3_FAILS" -eq 0 ] && [ -f "$HELLO_OUT" ]; then
  record G3 green "synthesis: 01–05 green AND hello.txt present"
else
  record G3 red "synthesis: $G3_FAILS red checks in 01–05 OR hello.txt missing"
fi

# ============================================================================
# G4. Synthesis: valid works AND invalid fails
# ============================================================================
G4_FAILS=$(printf '%s\n' "${RESULTS[@]}" | awk -F'|' '$1 ~ /^0[5-9]$/ && $2=="red"' | wc -l | tr -d ' ')
if [ "$G4_FAILS" -eq 0 ]; then
  record G4 green "synthesis: 05 (valid) green AND 06/07/08/09 (invalid) all refused"
else
  record G4 red "synthesis: $G4_FAILS red checks across 05–09"
fi

# trap → summary → exit
[ "$CHECKS_FAIL" -eq 0 ]
