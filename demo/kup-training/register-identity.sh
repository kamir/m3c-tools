#!/usr/bin/env bash
# register-identity.sh — one-shot, idempotent registration of a SPEC-0188
# author/reviewer identity in the local skill registry.
#
# Generalized from register-mirko-identity.sh (2026-05-08 KuP fix). Used
# directly to register the reviewer before step 03 if you want a fully
# green online run.
#
# Usage
#   ./register-identity.sh <identity-id> <path-to-pubkey-pem> [display-name]
#
# Examples
#   ./register-identity.sh id:mirko@m3c    artifacts/keys/mirko.pub    "Mirko (KuP demo author)"
#   ./register-identity.sh id:reviewer@m3c artifacts/keys/reviewer.pub "Reviewer (KuP demo)"
#
# Inputs (resolved automatically)
#   - ER1_API_KEY: macOS keychain (service=aims-core-er1, account=$USER)
#   - X-User-ID:   ~/.m3c-tools.env ER1_CONTEXT_ID, normalized per BUG-0021
#   - pubkey_b64:  raw 32-byte ed25519 key extracted from the PEM via openssl
#
# Server contract (flask/modules/skill_registry/api.py register_identity)
#   POST /api/skills/identities
#   body: {id, pubkey_b64, auth_source, display_name?}
#   auth: @require_admin → granted to API-key callers whose X-User-ID is
#         in ADMIN_USER_IDS (set in tools/config/environments/docker-local.env).
#
# Exit codes
#   0  — registered (HTTP 201) or already registered (HTTP 409, idempotent)
#   1  — server error (403/500/etc.) — message printed
#   2  — local input/setup error (missing keychain, missing pubkey, etc.)

set -euo pipefail

# ---- Args ------------------------------------------------------------------
IDENTITY_ID="${1:-}"
PUB_PEM="${2:-}"
DISPLAY_NAME="${3:-}"

if [[ -z "$IDENTITY_ID" || -z "$PUB_PEM" ]]; then
  echo "usage: $0 <identity-id> <path-to-pubkey-pem> [display-name]" >&2
  echo "example: $0 id:reviewer@m3c artifacts/keys/reviewer.pub 'Reviewer (KuP demo)'" >&2
  exit 2
fi

REGISTRY="${REGISTRY_URL:-https://127.0.0.1:8081}"
DISPLAY_NAME="${DISPLAY_NAME:-${IDENTITY_ID}}"

c_red()    { printf "\033[31m%s\033[0m\n" "$*" >&2; }
c_green()  { printf "\033[32m%s\033[0m\n" "$*"; }
c_yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
c_dim()    { printf "\033[2m%s\033[0m\n" "$*"; }

# ---- 1. ER1_API_KEY from keychain ------------------------------------------
ER1_API_KEY=$(security find-generic-password -s aims-core-er1 -a "$USER" -w 2>/dev/null || true)
if [[ -z "${ER1_API_KEY}" ]]; then
  c_red "ER1_API_KEY not found in keychain (service=aims-core-er1, account=$USER)."
  c_red "Add it once with:"
  c_red "  security add-generic-password -s aims-core-er1 -a \"\$USER\" -w"
  exit 2
fi
c_dim "✓ ER1_API_KEY resolved from keychain"

# ---- 2. X-User-ID — normalized per BUG-0021 --------------------------------
USER_ID=""
if [[ -f "$HOME/.m3c-tools.env" ]]; then
  USER_ID=$(grep -E '^ER1_CONTEXT_ID=' "$HOME/.m3c-tools.env" | head -1 | cut -d= -f2- | tr -d '"')
fi
if [[ -z "$USER_ID" ]]; then
  c_red "X-User-ID not derivable: ER1_CONTEXT_ID missing in ~/.m3c-tools.env."
  exit 2
fi
USER_ID="${USER_ID%___mft}"
c_dim "✓ X-User-ID = $USER_ID"

# ---- 3. Extract raw 32-byte ed25519 pubkey from PEM ------------------------
if [[ ! -f "$PUB_PEM" ]]; then
  c_red "Public key file missing: $PUB_PEM"
  c_red "Run the corresponding step (01 for mirko, 03 for reviewer) first to generate the keypair."
  exit 2
fi
PUBKEY_B64=$(openssl pkey -in "$PUB_PEM" -pubin -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n')
if [[ ${#PUBKEY_B64} -lt 40 || ${#PUBKEY_B64} -gt 48 ]]; then
  c_red "Extracted pubkey is the wrong length (got ${#PUBKEY_B64} chars, expected ~44)."
  c_red "The PEM file may not be ed25519. Check $PUB_PEM manually."
  exit 2
fi
c_dim "✓ pubkey_b64 = $PUBKEY_B64"

# ---- 4. POST /api/skills/identities ----------------------------------------
PAYLOAD=$(printf '{"id":"%s","pubkey_b64":"%s","auth_source":"manual","display_name":"%s"}' \
  "$IDENTITY_ID" "$PUBKEY_B64" "$DISPLAY_NAME")
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
    c_green "✓ identity registered: $IDENTITY_ID (HTTP $HTTP)"
    cat "$RESP_FILE" | python3 -m json.tool 2>/dev/null || cat "$RESP_FILE"
    ;;
  409)
    c_yellow "✓ identity already exists: $IDENTITY_ID (HTTP 409 — idempotent, no-op)"
    cat "$RESP_FILE" | python3 -m json.tool 2>/dev/null || cat "$RESP_FILE"
    ;;
  403)
    c_red "✗ HTTP 403 — your account ($USER_ID) is not tagged admin on the local stack."
    c_red "  Check ADMIN_USER_IDS in tools/config/environments/docker-local.env."
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
