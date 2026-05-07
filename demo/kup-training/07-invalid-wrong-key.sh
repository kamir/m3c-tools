#!/usr/bin/env bash
# 07-invalid-wrong-key — A bundle signed by an attacker, presented under
# Mirko's identity, must fail when Eric verifies against Mirko's pinned pubkey.
# Expected: skillctl verify-sig exits 11.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "07 — INVALID: bundle signed by an unauthorized key"

# 1) Generate an attacker key (idempotent)
rm -f "$KEYS_DIR/attacker.priv" "$KEYS_DIR/attacker.pub"
"$SKILLCTL" keygen --out "$KEYS_DIR/attacker" >>"$LOG_DIR/full.log" 2>&1
ok "attacker keypair: $KEYS_DIR/attacker.{priv,pub}"

# 2) Re-stage and pack a fresh bundle with the same name/version
SRC="$BUNDLES_DIR/src/$SKILL_NAME"
ATTACKER_BUNDLE="$BUNDLES_DIR/attacker-${SKILL_NAME}-${SKILL_VERSION}.skb"
"$SKILLCTL" pack \
    --skill "$SRC" \
    -o "$ATTACKER_BUNDLE" \
    --name "$SKILL_NAME" \
    --version "$SKILL_VERSION" \
    --summary "Attacker bundle — same shape, different signing key." \
    --source-repo "attacker/spoof" \
    --source-path "." \
    --author-intent yellow \
    --author-intent-rationale "Identical content; this is a key-impersonation test." \
    >>"$LOG_DIR/full.log" 2>&1
ok "attacker built a fresh bundle: $(basename "$ATTACKER_BUNDLE")"

# 3) Sign it with the attacker key but claim it's Mirko's
log "attacker signs with attacker.priv but claims --identity-id $MIRKO_ID"
rm -f "${ATTACKER_BUNDLE}".*.author.sig
"$SKILLCTL" sign --key "$KEYS_DIR/attacker.priv" --identity-id "$MIRKO_ID" "$ATTACKER_BUNDLE" \
  >>"$LOG_DIR/full.log" 2>&1
ok "attacker bundle signed (under attacker key)"

# 4) Eric verifies with MIRKO's pinned pubkey — must refuse with exit 11.
log "Eric: skillctl verify-sig (expecting exit 11 — sig invalid against pinned key)"
assert_exit 11 -- "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/mirko.pub" "$ATTACKER_BUNDLE"

# 5) Sanity check — the attacker's own key DOES validate (proving the test
#    rules out "the attacker bundle is structurally broken"); the failure in
#    step 4 is specifically the wrong-key signal.
log "control: same bundle verifies fine against the attacker's own pubkey"
assert_exit 0  -- "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/attacker.pub" "$ATTACKER_BUNDLE"

header "07 — done — IMPERSONATION DETECTED, INVALID SKILL REFUSED ✓"
