#!/usr/bin/env bash
# run-all — Master orchestrator. Walks every step in the demo and asserts
# the four release-gate items.
#
# Usage:
#   ./run-all.sh                    # run the full demo
#   ./run-all.sh --offline-only     # skip the online registry stretch goal
#   ./run-all.sh --no-pdf           # skip PDF generation
#   ./run-all.sh --no-release       # skip cross-platform binary build
#
# Exit code summary:
#   0   all gates passed
#   1   a step failed (look at the LAST FAIL line)
#   2   environment problem (preflight failed)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

OFFLINE_ONLY=0
SKIP_PDF=0
SKIP_RELEASE=0
for arg in "$@"; do
  case "$arg" in
    --offline-only) OFFLINE_ONLY=1 ;;
    --no-pdf)       SKIP_PDF=1 ;;
    --no-release)   SKIP_RELEASE=1 ;;
    *) fail "unknown arg: $arg"; exit 2 ;;
  esac
done
if [[ "$OFFLINE_ONLY" -eq 1 ]]; then
  unset ER1_API_KEY
  REGISTRY_URL="https://localhost:0"  # force online_mode_available to fail
fi

START_TS=$(date +%s)

step() {
  local label="$1" script="$2"
  if bash "$SCRIPT_DIR/$script"; then
    return 0
  else
    fail "STEP FAILED: $label ($script)"
    return 1
  fi
}

PASSED=()
FAILED=()
run_step() {
  local label="$1" script="$2"
  if step "$label" "$script"; then PASSED+=("$label"); else FAILED+=("$label"); fi
}

run_step "00 preflight"             "00-preflight.sh"
run_step "01 mirko authors + signs" "01-mirko-author.sh"
run_step "02 mirko publishes"       "02-mirko-publish.sh"
run_step "03 reviewer attests"      "03-reviewer-attest.sh"
run_step "04 eric pins trust"       "04-eric-trust-root.sh"
run_step "05 eric installs + runs"  "05-eric-install-and-run.sh"
run_step "06 invalid: tampered"     "06-invalid-tampered.sh"
run_step "07 invalid: wrong key"    "07-invalid-wrong-key.sh"
run_step "08 invalid: no sig"       "08-invalid-no-signature.sh"
run_step "09 invalid: edited"       "09-invalid-edited-install.sh"

if [[ "$SKIP_PDF" -ne 1 ]]; then
  run_step "G1 user manual PDF"     "make-pdf.sh"
fi
if [[ "$SKIP_RELEASE" -ne 1 ]]; then
  run_step "G2 cross-platform release"   "build-release.sh"
fi

DURATION=$(( $(date +%s) - START_TS ))

# ─────────────────────────────────────────────────────────────────────
# Final report
# ─────────────────────────────────────────────────────────────────────
header "RELEASE-GATE REPORT  (elapsed ${DURATION}s)"
printf "${C_GREEN}PASSED:${C_RESET}\n"
for s in "${PASSED[@]:-}"; do printf "  ✓ %s\n" "$s"; done
if [[ "${#FAILED[@]}" -gt 0 ]]; then
  printf "${C_RED}FAILED:${C_RESET}\n"
  for s in "${FAILED[@]:-}"; do printf "  ✗ %s\n" "$s"; done
fi
echo

cat <<EOF
Release-gate items vs proofs
============================

  G1  Print the user manual as PDF
        proof: $ARTIFACTS_DIR/USER-MANUAL.pdf  (run ./make-pdf.sh)

  G2  Release skillctl via GitHub download + installer
        proof: $ARTIFACTS_DIR/release/   (run ./build-release.sh)
              binaries: skillctl-{darwin,linux,windows}-{amd64,arm64}
              checksums: SHA256SUMS
              installer: install.sh
              draft notes: RELEASE_NOTES.md
              gh CLI command: see "gh release create" in build-release.sh

  G3  Run the skill transfer Mirko → Eric via aims
        proof: steps 01–05 above.
              valid path: 05 ends with $INSTALL_HOME/output/hello.txt
              (a file ONLY produced by Eric running a skill that survived
               keygen → pack → sign → verify-sig → atomic-extract).

  G4  Prove a valid skill works for Eric AND an invalid skill fails
        proof:
          VALID:        step 05 ✓ (chain accepted, file produced)
          INVALID #1:   step 06 ✓ (tampered bytes — exit 11)
          INVALID #2:   step 07 ✓ (wrong key — exit 11)
          INVALID #3:   step 08 ✓ (no signature — non-zero refusal)
          INVALID #4:   step 09 ✓ (post-install edit — CHECKSUMS detected)

EOF

if [[ "${#FAILED[@]}" -gt 0 ]]; then
  fail "RELEASE-GATE: NOT READY"
  exit 1
fi
ok "RELEASE-GATE: ALL PROOFS GREEN"
