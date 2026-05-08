#!/usr/bin/env bash
# register-mirko-identity.sh — one-shot, idempotent registration of
# id:mirko@m3c as a SPEC-0188 author identity in the local skill registry.
#
# Why this exists
#   Step 02 of the KuP release-gate (`02-mirko-publish.sh`) calls
#   POST /api/skills/identities to register Mirko. That endpoint is
#   @require_admin (skill_registry/api.py:373) and the request body must
#   carry pubkey_b64 = base64(raw 32-byte ed25519 key) — NOT the base64
#   of the full PEM file. Step 02's existing call sends the PEM blob and
#   gets HTTP 400. This script does the right thing once; subsequent runs
#   short-circuit on 409 (already exists).
#
# Inputs
#   - ER1_API_KEY: resolved from the macOS keychain (service aims-core-er1,
#     account $USER) — same convention as push-to-er1.sh and step 02.
#   - X-User-ID:    read from ~/.m3c-tools.env (ER1_CONTEXT_ID).
#   - Pubkey:       extracted from artifacts/keys/mirko.pub via openssl.
#                   PEM → DER → tail -c 32 → base64.
#
# Outputs
#   - HTTP 201 first time, HTTP 409 idempotent on re-run.
#   - 403 means the operator's account isn't tagged admin in the registry's
#     tenant-CISO RBAC; surface and exit 1.

set -euo pipefail

REGISTRY="${REGISTRY_URL:-https://127.0.0.1:8081}"
MIRKO_ID="${MIRKO_ID:-id:mirko@m3c}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="${KEYS_DIR:-$SCRIPT_DIR/artifacts/keys}"
PUB_PEM="$KEYS_DIR/mirko.pub"

c_red()    { printf "\033[31m%s\033[0m\n" "$*" >&2; }
c_green()  { printf "\033[32m%s\033[0m\n" "$*"; }
c_yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
c_dim()    { printf "\033[2m%s\033[0m\n" "$*"; }

# ---- 1. Resolve API key from keychain --------------------------------------
ER1_API_KEY=$(security find-generic-password -s aims-core-er1 -a "$USER" -w 2>/dev/null || true)
if [[ -z "${ER1_API_KEY}" ]]; then
  c_red "ER1_API_KEY not found in keychain (service=aims-core-er1, account=$USER)."
  c_red "Add it once with:"
  c_red "  security add-generic-password -s aims-core-er1 -a \"\$USER\" -w"
  exit 2
fi
c_dim "✓ ER1_API_KEY resolved from keychain"

# ---- 2. Resolve X-User-ID --------------------------------------------------
# Per BUG-0021: normalize to the canonical form by stripping the legacy
# `___mft` suffix that the dual-auth migration left in some profiles. The
# server's ADMIN_USER_IDS check (modules/skill_registry/api.py _APIKeyUser
# constructor) compares against the unsuffixed Google numeric user ID.
USER_ID=""
if [[ -f "$HOME/.m3c-tools.env" ]]; then
  USER_ID=$(grep -E '^ER1_CONTEXT_ID=' "$HOME/.m3c-tools.env" | head -1 | cut -d= -f2- | tr -d '"')
fi
if [[ -z "$USER_ID" ]]; then
  c_red "X-User-ID not derivable: ER1_CONTEXT_ID missing in ~/.m3c-tools.env."
  c_red "Set it manually: export ER1_USER_ID=...   then re-run."
  exit 2
fi
USER_ID="${USER_ID%___mft}"   # BUG-0021: drop legacy ___mft suffix
c_dim "✓ X-User-ID = $USER_ID"

# ---- 3. Extract raw 32-byte ed25519 pubkey from PEM ------------------------
if [[ ! -f "$PUB_PEM" ]]; then
  c_red "Public key file missing: $PUB_PEM"
  c_red "Run step 01 first (bash 01-mirko-author.sh) to generate the keypair."
  exit 2
fi
PUBKEY_B64=$(openssl pkey -in "$PUB_PEM" -pubin -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n')
if [[ ${#PUBKEY_B64} -lt 40 || ${#PUBKEY_B64} -gt 48 ]]; then
  c_red "Extracted pubkey is the wrong length (got ${#PUBKEY_B64} chars, expected ~44)."
  c_red "The PEM file may not be ed25519. Check artifacts/keys/mirko.pub manually."
  exit 2
fi
c_dim "✓ pubkey_b64 = $PUBKEY_B64"

# ---- 4. POST /api/skills/identities ----------------------------------------
PAYLOAD=$(printf '{"id":"%s","pubkey_b64":"%s","auth_source":"manual","display_name":"Mirko (KuP demo author)"}' \
  "$MIRKO_ID" "$PUBKEY_B64")
RESP_FILE="$(mktemp -t register-identity.XXXXXX.json)"
HTTP=$(curl -sk \
  -H "X-API-KEY: ${ER1_API_KEY}" \
  -H "X-User-ID: ${USER_ID}" \
  -H "Content-Type: application/json" \
  -X POST "$REGISTRY/api/skills/identities" \
  -d "$PAYLOAD" \
  -o "$RESP_FILE" -w "%{http_code}")

case "$HTTP" in
  200|201)
    c_green "✓ identity registered: $MIRKO_ID (HTTP $HTTP)"
    cat "$RESP_FILE" | python3 -m json.tool 2>/dev/null || cat "$RESP_FILE"
    ;;
  409)
    c_yellow "✓ identity already exists: $MIRKO_ID (HTTP 409 — idempotent, no-op)"
    cat "$RESP_FILE" | python3 -m json.tool 2>/dev/null || cat "$RESP_FILE"
    ;;
  403)
    c_red "✗ HTTP 403 — your account ($USER_ID) is not tagged admin on the local stack."
    c_red "  Identity registration is gated by @require_admin. Either:"
    c_red "    a) flip your tenant_ciso role for the local tenant in Firestore, OR"
    c_red "    b) run aims-core in a dev mode that bypasses admin checks (env: M3C_DEV_BYPASS_ADMIN=1)"
    c_red "  Server response:"
    cat "$RESP_FILE" >&2
    exit 1
    ;;
  *)
    c_red "✗ unexpected HTTP $HTTP"
    cat "$RESP_FILE" >&2
    exit 1
    ;;
esac
rm -f "$RESP_FILE"
