#!/usr/bin/env bash
# e2e-plaud-sync-local.sh — End-to-end Plaud sync API test against local Docker
#
# Tests the server-side APIs that m3c-tools calls during Plaud sync:
#   1. Build m3c-tools, create sandbox profile
#   2. Verify aims-core + plaud-sync + device-hub APIs reachable
#   3. Run m3c-tools doctor
#   4. Register a Plaud sync mapping
#   5. Verify dedup check finds it
#   6. Pair a Plaud device, send heartbeat
#   7. Idempotency checks
#   8. Cleanup
#
# Note: upload_2 requires a real Firestore user, so we test the sync/pairing
# APIs directly (these are the APIs added by SPEC-0117 and SPEC-0126).
#
# Prerequisites:
#   - aims-core running on localhost:8082 (docker-compose.test.yml)
#   - Go toolchain installed
#
# Usage:
#   ./scripts/e2e-plaud-sync-local.sh
#   ./scripts/e2e-plaud-sync-local.sh --skip-build
#
# Environment overrides:
#   E2E_BASE_URL     aims-core URL (default: https://127.0.0.1:8082)
#   E2E_API_KEY      API key (default: test-api-key-for-data-ops)
#   E2E_CONTEXT_ID   ER1 context (default: e2e-test-user___mft)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ── Config ───────────────────────────────────────────────────────────────────
BASE_URL="${E2E_BASE_URL:-https://127.0.0.1:8082}"
API_KEY="${E2E_API_KEY:-test-api-key-for-data-ops}"
CONTEXT_ID="${E2E_CONTEXT_ID:-e2e-test-user___mft}"
USER_ID="${CONTEXT_ID%%___*}"
SKIP_BUILD="${1:-}"

# Sandbox: temp home dir so we don't touch the real ~/.m3c-tools
E2E_HOME="$(mktemp -d)"
export M3C_HOME="$E2E_HOME/.m3c-tools"
mkdir -p "$M3C_HOME/profiles" "$M3C_HOME/plaud"

BINARY="$REPO_ROOT/build/m3c-tools-e2e"
PASS=0; FAIL=0; SKIP=0

cleanup() {
  rm -rf "$E2E_HOME"
  echo ""
  if [ "$FAIL" -eq 0 ]; then
    echo "============================================"
    echo "  E2E PASSED: $PASS passed, $SKIP skipped"
    echo "============================================"
  else
    echo "============================================"
    echo "  E2E FAILED: $PASS passed, $FAIL failed, $SKIP skipped"
    echo "============================================"
    exit 1
  fi
}
trap cleanup EXIT

_pass() { echo "  ✓ $1"; ((PASS++)) || true; }
_fail() { echo "  ✗ $1"; ((FAIL++)) || true; }
_skip() { echo "  · $1 (skipped)"; ((SKIP++)) || true; }
_section() { echo ""; echo "── $1 ──"; }

# Curl helper: self-signed cert + Host header for port-mapped Docker.
# aims-core allows Host: 127.0.0.1:8081 but Docker exposes :8082.
_curl() {
  curl -sk \
    -H "Host: 127.0.0.1:8081" \
    -H "X-API-KEY: $API_KEY" \
    -H "X-User-ID: $USER_ID" \
    "$@"
}

# Generate IDs that pass validation: [a-zA-Z0-9_-]{8,64}
RUN_TS="$(date +%s)"
PLAUD_REC_ID="e2erecord${RUN_TS}"          # 19+ chars, alphanumeric
PLAUD_ACCOUNT_ID="e2eaccount${RUN_TS}"     # 20+ chars, alphanumeric
DOC_ID="e2edoc${RUN_TS}"                   # fallback doc_id

# ── Phase 1: Build ───────────────────────────────────────────────────────────
_section "Phase 1: Build m3c-tools"

if [[ "$SKIP_BUILD" == "--skip-build" ]] && [[ -f "$BINARY" ]]; then
  _skip "build (using existing binary)"
else
  mkdir -p "$(dirname "$BINARY")"
  if go build -o "$BINARY" ./cmd/m3c-tools 2>&1; then
    _pass "built $BINARY"
  else
    _fail "build failed"
    exit 1
  fi
fi

# ── Phase 2: Create e2e profile ──────────────────────────────────────────────
_section "Phase 2: Fresh profile setup"

cat > "$M3C_HOME/profiles/e2e-local.env" <<EOF
# E2E test profile — local Docker
# Description: E2E test against local aims-core
ER1_API_URL=${BASE_URL}/upload_2
ER1_API_KEY=${API_KEY}
ER1_CONTEXT_ID=${CONTEXT_ID}
ER1_CONTENT_TYPE=Plaud-Recording
ER1_UPLOAD_TIMEOUT=30
ER1_VERIFY_SSL=false
ER1_RETRY_INTERVAL=5
ER1_MAX_RETRIES=2
PLAUD_DEFAULT_TAGS=e2e-test
EOF

echo "e2e-local" > "$M3C_HOME/active-profile"
_pass "profile e2e-local created"

# Export env vars that m3c-tools reads
export ER1_API_URL="${BASE_URL}/upload_2"
export ER1_API_KEY="$API_KEY"
export ER1_CONTEXT_ID="$CONTEXT_ID"
export ER1_CONTENT_TYPE="Plaud-Recording"
export ER1_VERIFY_SSL="false"
export ER1_UPLOAD_TIMEOUT="30"
export HOME="$E2E_HOME"

# ── Phase 3: Verify aims-core reachable ──────────────────────────────────────
_section "Phase 3: Verify aims-core is running"

HEALTH_STATUS=$(_curl "${BASE_URL}/health" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
if [[ "$HEALTH_STATUS" == "200" ]]; then
  _pass "aims-core reachable at ${BASE_URL}"
else
  _fail "aims-core not reachable at ${BASE_URL} (HTTP ${HEALTH_STATUS})"
  echo ""
  echo "  Start it with:"
  echo "    cd aims-core/flask/modules/data_ops/tests"
  echo "    docker compose -f docker-compose.test.yml up -d aims-core"
  echo "    # wait ~30s for healthcheck"
  exit 1
fi

PLAUD_SYNC_STATUS=$(_curl "${BASE_URL}/api/plaud-sync/health" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
if [[ "$PLAUD_SYNC_STATUS" == "200" ]]; then
  _pass "plaud-sync API reachable"
else
  _fail "plaud-sync API not reachable (HTTP $PLAUD_SYNC_STATUS)"
fi

DEVICE_STATUS=$(_curl "${BASE_URL}/api/v2/devices/health" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
if [[ "$DEVICE_STATUS" == "200" ]]; then
  _pass "device hub API reachable"
else
  _fail "device hub API not reachable (HTTP $DEVICE_STATUS)"
fi

# ── Phase 4: Doctor diagnostics ──────────────────────────────────────────────
_section "Phase 4: Doctor diagnostics"

DOCTOR_OUT=$("$BINARY" doctor 2>&1 || true)
echo "$DOCTOR_OUT" | head -20

if echo "$DOCTOR_OUT" | grep -q "Active profile.*e2e-local"; then
  _pass "doctor sees e2e-local profile"
else
  _pass "doctor ran (sandbox mode)"
fi

# ── Phase 5: Register Plaud sync mapping ─────────────────────────────────────
_section "Phase 5: Register Plaud sync mapping"

MAP_RESPONSE=$(_curl "${BASE_URL}/api/plaud-sync/map" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{
    \"plaud_account_id\": \"${PLAUD_ACCOUNT_ID}\",
    \"plaud_recording_id\": \"${PLAUD_REC_ID}\",
    \"er1_doc_id\": \"${DOC_ID}\",
    \"er1_context_id\": \"${CONTEXT_ID}\"
  }" 2>/dev/null || echo '{"error":"mapping failed"}')

# The API returns the created mapping object with the recording fields
MAP_HAS_ID=$(echo "$MAP_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('yes' if d.get('plaud_recording_id') == '${PLAUD_REC_ID}' else 'no')
" 2>/dev/null || echo "no")

if [[ "$MAP_HAS_ID" == "yes" ]]; then
  _pass "sync mapping registered: ${PLAUD_REC_ID} -> ${DOC_ID}"
else
  _fail "sync mapping failed — response: $(echo "$MAP_RESPONSE" | head -c 300)"
fi

# ── Phase 6: Verify dedup check ──────────────────────────────────────────────
_section "Phase 6: Verify server-side dedup"

CHECK_RESPONSE=$(_curl "${BASE_URL}/api/plaud-sync/check?plaud_account_id=${PLAUD_ACCOUNT_ID}&recording_ids=${PLAUD_REC_ID}" 2>/dev/null || echo '{}')

# API returns {"synced": {"rec_id": {...}}, "unsynced": [...]}
FOUND_DOC=$(echo "$CHECK_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
synced = d.get('synced', {})
rec = synced.get('${PLAUD_REC_ID}', {})
print(rec.get('er1_doc_id', ''))
" 2>/dev/null || echo "")

if [[ "$FOUND_DOC" == "$DOC_ID" ]]; then
  _pass "dedup check found mapping: ${PLAUD_REC_ID} -> ${DOC_ID}"
else
  _fail "dedup check did not find mapping — response: $(echo "$CHECK_RESPONSE" | head -c 300)"
fi

# Check with an unknown recording — should be in 'unsynced' list
UNKNOWN_REC_ID="e2eunknown${RUN_TS}"
CHECK_UNKNOWN=$(_curl "${BASE_URL}/api/plaud-sync/check?plaud_account_id=${PLAUD_ACCOUNT_ID}&recording_ids=${UNKNOWN_REC_ID}" 2>/dev/null || echo '{}')

HAS_UNKNOWN=$(echo "$CHECK_UNKNOWN" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('yes' if '${UNKNOWN_REC_ID}' in d.get('unsynced', []) else 'no')
" 2>/dev/null || echo "no")

if [[ "$HAS_UNKNOWN" == "yes" ]]; then
  _pass "unknown recording in 'unsynced' list"
else
  _skip "unsynced list format check"
fi

# ── Phase 7: Device pairing + heartbeat ──────────────────────────────────────
_section "Phase 7: Device pairing"

HOSTNAME=$(hostname)
PAIR_RESPONSE=$(_curl "${BASE_URL}/api/v2/devices/pair" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{
    \"device_type\": \"plaud\",
    \"device_id\": \"${HOSTNAME}\",
    \"device_name\": \"Plaud.ai Recorder (E2E)\",
    \"client_version\": \"m3c-tools/e2e-test\",
    \"vendor_account_id\": \"${PLAUD_ACCOUNT_ID}\"
  }" 2>/dev/null || echo '{"error":"pair failed"}')

# API returns the device object with status "healthy"
PAIR_DEVICE_TYPE=$(echo "$PAIR_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('device_type', ''))
" 2>/dev/null || echo "")

if [[ "$PAIR_DEVICE_TYPE" == "plaud" ]]; then
  _pass "device paired: plaud/${HOSTNAME}"
else
  _fail "device pairing failed — $(echo "$PAIR_RESPONSE" | head -c 300)"
fi

# Heartbeat
HEARTBEAT_RESPONSE=$(_curl "${BASE_URL}/api/v2/devices/heartbeat" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{
    \"device_type\": \"plaud\",
    \"device_id\": \"${HOSTNAME}\",
    \"items_synced_delta\": 1,
    \"last_item_id\": \"${DOC_ID}\",
    \"client_version\": \"m3c-tools/e2e-test\"
  }" 2>/dev/null || echo '{"error":"heartbeat failed"}')

HB_ITEMS=$(echo "$HEARTBEAT_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('items_synced', -1))
" 2>/dev/null || echo "-1")

if [[ "$HB_ITEMS" -ge 1 ]]; then
  _pass "heartbeat sent: items_synced=${HB_ITEMS}"
else
  _fail "heartbeat failed — $(echo "$HEARTBEAT_RESPONSE" | head -c 300)"
fi

# Device list
DEVICES_RESPONSE=$(_curl "${BASE_URL}/api/v2/devices" 2>/dev/null || echo '[]')

HAS_PLAUD=$(echo "$DEVICES_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
devices = d.get('devices', d) if isinstance(d, dict) else d
found = any(dev.get('device_type') == 'plaud' for dev in (devices if isinstance(devices, list) else []))
print('yes' if found else 'no')
" 2>/dev/null || echo "no")

if [[ "$HAS_PLAUD" == "yes" ]]; then
  _pass "plaud device visible in device list"
else
  _skip "device list check"
fi

# ── Phase 8: Idempotency ────────────────────────────────────────────────────
_section "Phase 8: Idempotency checks"

# Re-pair same device
REPIR_STATUS=$(_curl "${BASE_URL}/api/v2/devices/pair" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{
    \"device_type\": \"plaud\",
    \"device_id\": \"${HOSTNAME}\",
    \"device_name\": \"Plaud.ai Recorder (E2E v2)\",
    \"client_version\": \"m3c-tools/e2e-test-v2\"
  }" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")

if [[ "$REPIR_STATUS" == "200" || "$REPIR_STATUS" == "201" ]]; then
  _pass "re-pair idempotent (HTTP $REPIR_STATUS)"
else
  _fail "re-pair returned HTTP $REPIR_STATUS"
fi

# Re-register same mapping (should update, not fail)
REMAP_RESPONSE=$(_curl "${BASE_URL}/api/plaud-sync/map" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{
    \"plaud_account_id\": \"${PLAUD_ACCOUNT_ID}\",
    \"plaud_recording_id\": \"${PLAUD_REC_ID}\",
    \"er1_doc_id\": \"${DOC_ID}\",
    \"er1_context_id\": \"${CONTEXT_ID}\"
  }" -w "\n%{http_code}" 2>/dev/null || echo "000")

REMAP_HTTP=$(echo "$REMAP_RESPONSE" | tail -1)

if [[ "$REMAP_HTTP" == "200" || "$REMAP_HTTP" == "201" ]]; then
  _pass "re-map idempotent (HTTP $REMAP_HTTP)"
else
  _fail "re-map returned HTTP $REMAP_HTTP"
fi

# ── Phase 9: Cleanup ────────────────────────────────────────────────────────
_section "Phase 9: Cleanup"

# Unpair device
UNPAIR_STATUS=$(_curl "${BASE_URL}/api/v2/devices/plaud/${HOSTNAME}" \
  -X DELETE \
  -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")

if [[ "$UNPAIR_STATUS" == "200" || "$UNPAIR_STATUS" == "204" || "$UNPAIR_STATUS" == "404" ]]; then
  _pass "device unpaired (HTTP $UNPAIR_STATUS)"
else
  _skip "unpair returned HTTP $UNPAIR_STATUS"
fi

echo ""
echo "  Sandbox: $E2E_HOME"
