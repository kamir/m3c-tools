#!/usr/bin/env bash
# 06-invalid-tampered — Tamper one byte inside the bundle.
# Expected: skillctl verify-sig exits 11 (signature invalid).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "06 — INVALID: tampered bundle bytes"

DIGEST=$(cat "$ARTIFACTS_DIR/digest.txt")
BUNDLE="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.skb"
TAMPERED="$BUNDLES_DIR/tampered.skb"

# Copy and corrupt one byte deep inside the gzip stream.
cp "$BUNDLE" "$TAMPERED"
SIZE=$(wc -c < "$TAMPERED" | tr -d ' ')
OFFSET=$(( SIZE / 2 ))
log "flipping one byte at offset $OFFSET inside $TAMPERED"
ORIG=$(dd if="$TAMPERED" bs=1 skip="$OFFSET" count=1 2>/dev/null | od -An -tx1 | tr -d ' ')
NEW=$(printf '%02x\n' $(( 0x$ORIG ^ 0xff )))
printf '\\x%s' "$NEW" | xargs -I{} printf '{}' | dd of="$TAMPERED" bs=1 seek="$OFFSET" count=1 conv=notrunc 2>/dev/null
ok "tampered bundle: $TAMPERED"

# Compute the new (tampered) digest so the .sig filename matches.
# The attack scenario: an attacker who has the original signature renames
# it to match the tampered bundle's digest — the verifier finds a sig but
# the cryptographic check refuses (exit 11). This is the "lying signature"
# attack the chain protects against.
TAMPERED_DIGEST=$(shasum -a 256 "$TAMPERED" | awk '{print $1}')
SIG_OLD="${BUNDLE}.${DIGEST#sha256:}.author.sig"
SIG_NEW="${TAMPERED}.${TAMPERED_DIGEST}.author.sig"
cp "$SIG_OLD" "$SIG_NEW"
ok "original digest:  ${DIGEST#sha256:}"
ok "tampered digest:  $TAMPERED_DIGEST"
ok "sig renamed to match tampered digest: $(basename "$SIG_NEW")"

# verify-sig MUST refuse with exit 11 (cryptographic verification fails).
log "Eric: skillctl verify-sig (expecting exit 11 — signature invalid)"
assert_exit 11 -- "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/mirko.pub" "$TAMPERED"

header "06 — done — TAMPER DETECTED, INVALID SKILL REFUSED ✓"
