#!/usr/bin/env bash
# 11-use-skill — drive a profile entry through aware → practiced (lifecycle phase 5: USE).
#
# Posts 5 synthetic usage events for SKILL_NAME (kup-hello) against the
# operator's profile via POST /api/v2/skills/usage. Each call:
#   - increments use_count by 1, stamps last_used = now
#   - returns 202 with the recomputed mastery level
#
# Mastery thresholds (flask/modules/skillprofile/mastery.py):
#   use_count == 0  → aware
#   use_count 1–4   → practiced (any usage promotes out of aware)
#   use_count >= 5  → practiced (the formal PRACTICED_MIN_USES threshold)
#   uses_last_30d >= 20  → fluent (or use_count >= 20)
#
# This step is real: the events land in _user_skill_profiles/{uid} and the
# Skill Profile Admin page picks them up on next refresh. To see the
# "fluent" promotion you'd post 20+ events; the demo stops at 5 because
# crossing the practiced threshold is the visible win.
#
# In a real deployment, /usage is called automatically by the Claude Code
# PostToolUse hook every time the user invokes a SkillTool. This script
# emulates that hook so we can prove the wiring without a live Claude Code
# session.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

USE_COUNT="${USE_COUNT:-5}"
USE_SKILL="${USE_SKILL:-$SKILL_NAME}"

ensure_er1_api_key_from_keychain
if ! online_mode_available; then
  warn "online mode not available — skipping (this step requires the registry)"
  exit 0
fi

USER_ID=$(grep -E '^ER1_CONTEXT_ID=' "$HOME/.m3c-tools.env" 2>/dev/null \
  | head -1 | cut -d= -f2- | tr -d '"' | sed 's/___mft$//')
if [[ -z "$USER_ID" ]]; then
  fail "ER1 user-id not derivable from ~/.m3c-tools.env"
  exit 2
fi

header "11 — USE: post $USE_COUNT usage events for '$USE_SKILL'"
note "endpoint:  POST $REGISTRY_URL/api/v2/skills/usage"
note "user_id:   $USER_ID"

LAST_RESP="$LOG_DIR/usage-last.json"
LAST_MASTERY=""
LAST_COUNT=""

for i in $(seq 1 "$USE_COUNT"); do
  TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  PAYLOAD=$(printf '{"skill_id":"%s","user_id":"%s","timestamp":"%s","context":{"source":"kup-demo-step-11","iter":%d}}' \
    "$USE_SKILL" "$USER_ID" "$TS" "$i")
  HTTP=$(curl -sk \
    -H "X-API-KEY: ${ER1_API_KEY}" \
    -H "X-User-ID: ${USER_ID}" \
    -H "Content-Type: application/json" \
    -X POST "$REGISTRY_URL/api/v2/skills/usage" \
    -d "$PAYLOAD" \
    -o "$LAST_RESP" -w "%{http_code}") || true

  if [[ "$HTTP" != "202" ]]; then
    warn "iter $i: unexpected HTTP $HTTP — body: $(head -c 200 "$LAST_RESP")"
    continue
  fi

  LAST_MASTERY=$(python3 -c "import json;print(json.load(open('$LAST_RESP')).get('new_mastery',''))" 2>/dev/null || echo "")
  LAST_COUNT=$(python3 -c "import json;print(json.load(open('$LAST_RESP')).get('use_count',''))" 2>/dev/null || echo "")
  ok "iter $i: HTTP 202  use_count=$LAST_COUNT  mastery=$LAST_MASTERY"
done

header "11 — done"
note "skill:        $USE_SKILL"
note "final count:  $LAST_COUNT"
note "final master: $LAST_MASTERY"
note "Admin page:   $REGISTRY_URL/v2/skills/admin"
