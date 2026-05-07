#!/usr/bin/env bash
# 03-reviewer-attest — A reviewer signs a 🟢 governance attestation.
# Online: posts to /api/skills/attestations.
# Offline: produces a local attestation file the install path can consume.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "03 — Reviewer attests 🟢 (governance verdict)"

DIGEST=$(cat "$ARTIFACTS_DIR/digest.txt")

# 1) Reviewer keypair (idempotent)
rm -f "$KEYS_DIR/reviewer.priv" "$KEYS_DIR/reviewer.pub"
"$SKILLCTL" keygen --out "$KEYS_DIR/reviewer" >>"$LOG_DIR/full.log" 2>&1
ok "reviewer keypair: $KEYS_DIR/reviewer.{priv,pub}"

# 2) Online path: skillctl attest
if online_mode_available; then
  log "skillctl attest $DIGEST --level green --reviewer-id $REVIEWER_ID"
  set +e
  "$SKILLCTL" attest "$DIGEST" \
      --level green \
      --rationale "KuP training demo — Activation Gate satisfied (smoke test, intent matches data_deps)." \
      --reviewer-id "$REVIEWER_ID" \
      --key "$KEYS_DIR/reviewer.priv" \
      --registry "$REGISTRY_URL/api/skills" \
      >>"$LOG_DIR/full.log" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    ok "reviewer attestation accepted by registry"
  else
    warn "skillctl attest exit $rc — registry may reject identity_mismatch (19) until reviewer is registered"
    warn "demo continues; offline attestation file is generated below"
  fi
fi

# 3) Offline path: write a local "attestation OK" marker and the reviewer's
#    public key. The invalid-skill scripts in 06-/07-/08- key off the
#    presence/absence of this file to demonstrate exit 13 (governance below
#    minimum) without needing a registry round-trip.
cat > "$ARTIFACTS_DIR/attestation.json" <<EOF
{
  "schema": "m3c-skill-attestation/v1",
  "bundle_digest": "$DIGEST",
  "level": "green",
  "rationale": "KuP training demo — Activation Gate satisfied.",
  "reviewer_id": "$REVIEWER_ID",
  "reviewer_pubkey_path": "$KEYS_DIR/reviewer.pub",
  "attested_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
ok "wrote $ARTIFACTS_DIR/attestation.json (level: green)"

header "03 — done"
note "Reviewer ID:  $REVIEWER_ID"
note "Reviewer pub: $KEYS_DIR/reviewer.pub"
note "Attestation:  $ARTIFACTS_DIR/attestation.json"
