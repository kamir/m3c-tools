#!/usr/bin/env bash
# 02-mirko-publish — Mirko publishes the bundle to the registry (online).
# This step is BEST-EFFORT. If the registry isn't reachable or
# ER1_API_KEY isn't set, the demo continues offline (the cryptographic
# chain is fully provable without it).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "02 — Mirko publishes to aims registry"

if ! online_mode_available; then
  warn "online mode not available — skipping POST /api/skills/bundles"
  warn "the chain proof in steps 03–10 still runs end-to-end (offline)"
  exit 0
fi

DIGEST=$(cat "$ARTIFACTS_DIR/digest.txt")
BUNDLE="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.skb"
SIG="${BUNDLE}.${DIGEST#sha256:}.author.sig"

# 1) Register Mirko's identity (idempotent on the registry side)
log "registering Mirko's identity"
PUB_B64=$(base64 < "$KEYS_DIR/mirko.pub" | tr -d '\n')
auth_curl "$MIRKO_ID" -- -X POST "$REGISTRY_URL/api/skills/identities" \
    -d "{\"id\":\"$MIRKO_ID\",\"ed25519_pubkey_pem\":\"$PUB_B64\",\"tier\":\"user\",\"rationale\":\"KuP training demo\"}" \
    -o "$LOG_DIR/identity-mirko.json" -w "HTTP %{http_code}\n" \
  | tee -a "$LOG_DIR/full.log"

# 2) POST the bundle (multipart: blob + raw 64-byte signature + identity_id)
# Field names per server contract — flask/modules/skill_registry/api.py:458
# admit_bundle() reads:
#   - bundle      (file)  — the .skb tarball
#   - signature   (file)  — raw 64-byte ed25519 signature over the bundle digest
#   - identity_id (form)  — author identity (e.g. id:mirko@m3c)
# An earlier version of this script sent author_sig + author_identity, which
# the server rejected with HTTP 400 "Missing required field: signature (file)"
# during the 2026-05-08 KuP release-gate run.
log "POST $REGISTRY_URL/api/skills/bundles"
HTTP=$(curl -sk \
  -H "X-API-KEY: ${ER1_API_KEY}" \
  -H "X-User-ID: $MIRKO_ID" \
  -F "bundle=@$BUNDLE" \
  -F "signature=@$SIG" \
  -F "identity_id=$MIRKO_ID" \
  -o "$LOG_DIR/admit.json" -w "%{http_code}" \
  "$REGISTRY_URL/api/skills/bundles") || true
echo "HTTP $HTTP" | tee -a "$LOG_DIR/full.log"

if [[ "$HTTP" =~ ^(200|201)$ ]]; then
  ok "registry accepted bundle"
  note "$(head -3 "$LOG_DIR/admit.json")"
elif [[ "$HTTP" == "409" ]]; then
  warn "registry returned 409 (already admitted) — re-running is safe"
else
  warn "registry returned HTTP $HTTP — see $LOG_DIR/admit.json"
  warn "demo continues offline; the chain proof does not depend on this step"
fi

header "02 — done (online attempt complete)"
