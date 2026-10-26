#!/usr/bin/env bash
# register-identity.sh: one-shot, idempotent registration of a SPEC-0188
# author/reviewer identity in the local skill registry.
#
# Generalized from register-bob-identity.sh (2026-05-08 KuP fix). Used
# directly to register the reviewer before step 03 if you want a fully
# green online run.
#
# Usage
#   ./register-identity.sh <identity-id> <path-to-pubkey-pem> [display-name]
#
# Examples
#   ./register-identity.sh id:bob@m3c    artifacts/keys/bob.pub    "Bob (KuP demo author)"
#   ./register-identity.sh id:reviewer@m3c artifacts/keys/reviewer.pub "Reviewer (KuP demo)"
#
# Inputs (resolved automatically)
#   - pubkey_b64:        raw 32-byte ed25519 key extracted from the PEM via openssl
#   - AIMS_ADMIN_COOKIE: an admin's browser session, needed only to CREATE the
#                        identity (see the server contract below). Supply it
#                        without echo:  read -rs AIMS_ADMIN_COOKIE && export AIMS_ADMIN_COOKIE
#   - ER1_API_KEY:       env, else macOS keychain (service=aims-core-er1,
#                        account=$USER). Sent only on the read in step 4.
#   - X-User-ID:         ~/.m3c-tools.env ER1_CONTEXT_ID, normalized per BUG-0021.
#                        Sent only on the read in step 4.
#
# Server contract (flask/modules/skill_registry/api.py)
#   GET  /api/skills/identities/<id>
#        the lookup skillctl's verifier makes (pkg/skillctl/registry GetIdentity)
#        → {id, pubkey_b64, auth_source, revoked_at}
#   POST /api/skills/identities   (register_identity)
#        body: {id, pubkey_b64, auth_source, display_name?}
#        auth: @require_admin → an authenticated Flask-Login session whose user
#              is admin by RBAC. An API-key caller is never admin, whatever
#              X-User-ID says, so ER1_API_KEY cannot register. skill_registry_bp
#              is CSRF-exempt behind an origin check, and curl sends no Origin
#              header, so the session cookie alone is enough.
#
# Exit codes
#   0, registered (HTTP 201), or already registered with this key
#   1, server error (unreachable, 500, etc.), message printed
#   2, local input/setup error (missing pubkey, etc.)
#   3, not confirmed registered, and no admin session to register it:
#      AIMS_ADMIN_COOKIE is unset, or the server did not take it as an admin
#      session
#   4, registered with a different key, or revoked: registering again cannot
#      change that

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# ---- Args ------------------------------------------------------------------
IDENTITY_ID="${1:-}"
PUB_PEM="${2:-}"
DISPLAY_NAME="${3:-}"

if [[ -z "$IDENTITY_ID" || -z "$PUB_PEM" ]]; then
  echo "usage: $0 <identity-id> <path-to-pubkey-pem> [display-name]" >&2
  echo "example: $0 id:reviewer@m3c artifacts/keys/reviewer.pub 'Reviewer (KuP demo)'" >&2
  exit 2
fi

REGISTRY="$REGISTRY_URL"
DISPLAY_NAME="${DISPLAY_NAME:-${IDENTITY_ID}}"

c_red()    { printf "\033[31m%s\033[0m\n" "$*" >&2; }
c_green()  { printf "\033[32m%s\033[0m\n" "$*"; }
c_yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
c_dim()    { printf "\033[2m%s\033[0m\n" "$*"; }

# ---- 1. ER1_API_KEY: env, else keychain (optional) -------------------------
ensure_er1_api_key_from_keychain
if [[ -n "${ER1_API_KEY:-}" ]]; then
  c_dim "✓ ER1_API_KEY resolved (used for the read only: it is never admin)"
else
  c_dim "· ER1_API_KEY not set: the read in step 4 goes without it"
fi

# ---- 2. X-User-ID: normalized per BUG-0021 (optional) ----------------------
USER_ID=""
if [[ -f "$HOME/.m3c-tools.env" ]]; then
  USER_ID=$(grep -E '^ER1_CONTEXT_ID=' "$HOME/.m3c-tools.env" | head -1 | cut -d= -f2- | tr -d '"' || true)
fi
USER_ID="${USER_ID%___mft}"
c_dim "· X-User-ID = ${USER_ID:-(none)}"

# ---- 3. Extract raw 32-byte ed25519 pubkey from PEM ------------------------
if [[ ! -f "$PUB_PEM" ]]; then
  c_red "Public key file missing: $PUB_PEM"
  c_red "Run the corresponding step (01 for bob, 03 for reviewer) first to generate the keypair."
  exit 2
fi
PUBKEY_B64=$(openssl pkey -in "$PUB_PEM" -pubin -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n')
if [[ ${#PUBKEY_B64} -lt 40 || ${#PUBKEY_B64} -gt 48 ]]; then
  c_red "Extracted pubkey is the wrong length (got ${#PUBKEY_B64} chars, expected ~44)."
  c_red "The PEM file may not be ed25519. Check $PUB_PEM manually."
  exit 2
fi
c_dim "✓ pubkey_b64 = $PUBKEY_B64"

RESP_FILE="$(mktemp -t register-identity.XXXXXX.json)"
trap 'rm -f "$RESP_FILE"' EXIT

# ---- 4. Already registered? GET /api/skills/identities/<id> ----------------
# Settles the common case without an admin session: the registry keeps an
# identity once registered, and 00-preflight keeps the local keys across runs.
# The key is compared, not just the id: a 409 on POST says the id exists, not
# that it carries THIS key.
LOOKUP=$(auth_curl "$USER_ID" -- "$REGISTRY/api/skills/identities/$IDENTITY_ID" \
  -o "$RESP_FILE" -w "%{http_code}") || LOOKUP="000"

case "$LOOKUP" in
  200)
    REGISTERED=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
print(d.get("pubkey_b64") or d.get("pubkey") or "", d.get("revoked_at") or "", sep="|")
' "$RESP_FILE" 2>/dev/null || echo "|")
    REG_KEY="${REGISTERED%%|*}"
    REG_REVOKED="${REGISTERED#*|}"
    if [[ -n "$REG_REVOKED" ]]; then
      c_red "✗ $IDENTITY_ID is registered but revoked (revoked_at $REG_REVOKED)."
      c_red "  Registering it again cannot lift a revocation."
      exit 4
    elif [[ "$REG_KEY" == "$PUBKEY_B64" ]]; then
      c_green "✓ identity already registered with this key: $IDENTITY_ID (no admin session needed)"
      exit 0
    elif [[ -n "$REG_KEY" ]]; then
      c_red "✗ $IDENTITY_ID is registered with a DIFFERENT key:"
      c_red "    registry: $REG_KEY"
      c_red "    local:    $PUBKEY_B64 ($PUB_PEM)"
      c_red "  Registering again cannot replace it. Restore the key pair the registry knows"
      c_red "  (artifacts/keys/ survives runs unless 00-preflight.sh --reset-all wiped it)."
      exit 4
    fi
    c_dim "· lookup answered 200 without a key field: letting the POST decide"
    ;;
  404)
    c_dim "· $IDENTITY_ID is not registered yet"
    ;;
  000)
    c_red "✗ registry not reachable at $REGISTRY"
    exit 1
    ;;
  *)
    c_dim "· lookup answered HTTP $LOOKUP: cannot tell, trying to register"
    ;;
esac

# ---- 5. POST /api/skills/identities in an admin session --------------------
if [[ -z "${AIMS_ADMIN_COOKIE:-}" ]]; then
  if [[ "$LOOKUP" == "404" ]]; then
    STATE="is not registered"
  else
    STATE="could not be confirmed (lookup HTTP $LOOKUP)"
  fi
  c_red "✗ $IDENTITY_ID $STATE, and registering it needs an admin session (AIMS_ADMIN_COOKIE is unset)."
  admin_session_hint
  note "  4. ./register-identity.sh $IDENTITY_ID $PUB_PEM \"$DISPLAY_NAME\""
  exit 3
fi

PAYLOAD=$(printf '{"id":"%s","pubkey_b64":"%s","auth_source":"manual","display_name":"%s"}' \
  "$IDENTITY_ID" "$PUBKEY_B64" "$DISPLAY_NAME")
HTTP=$(admin_curl -X POST "$REGISTRY/api/skills/identities" \
  -d "$PAYLOAD" \
  -o "$RESP_FILE" -w "%{http_code}") || HTTP="000"

case "$HTTP" in
  200|201)
    c_green "✓ identity registered: $IDENTITY_ID (HTTP $HTTP)"
    python3 -m json.tool < "$RESP_FILE" 2>/dev/null || cat "$RESP_FILE"
    ;;
  409)
    c_yellow "✓ identity already exists: $IDENTITY_ID (HTTP 409, idempotent, no-op)"
    c_yellow "  key not compared: the lookup in step 4 answered HTTP $LOOKUP"
    python3 -m json.tool < "$RESP_FILE" 2>/dev/null || cat "$RESP_FILE"
    ;;
  302|401|403)
    c_red "✗ HTTP $HTTP: the registry did not take AIMS_ADMIN_COOKIE as an admin session."
    c_red "  The session may have expired, or its user is not admin by RBAC."
    { cat "$RESP_FILE"; echo; } >&2
    admin_session_hint
    exit 3
    ;;
  *)
    c_red "✗ unexpected HTTP $HTTP"
    { cat "$RESP_FILE"; echo; } >&2
    exit 1
    ;;
esac
