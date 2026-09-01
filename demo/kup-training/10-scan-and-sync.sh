#!/usr/bin/env bash
# 10-scan-and-sync — close the supply→demand loop (lifecycle phase 4: SCAN).
#
# Steps 01–09 prove the SUPPLY chain (_skill_* collections):
#   author → sign → admit → attest → install → trust enforcement.
#
# Step 10 projects what is INSTALLED on disk into the DEMAND surface
# (_user_skill_profiles), so the Skill Profile Admin page reflects adoption.
#
# Two modes:
#   default   — scan Eric's isolated $HOME (artifacts/eric-home/) and import.
#   --operator — scan the trainer's REAL ~/.claude/skills/ tree and import.
#
# Mechanics:
#   skillctl awareness sync --dry-run --source claude  →  jsonl inventory
#   transform → SkillImportPayload                     →  /api/v2/skills/profile/import
#
# Why we don't use `skillctl awareness sync --confirm` directly: skillctl has
# no --insecure flag, so it refuses the local stack's self-signed cert. curl -k
# does. Future: add M3C_TLS_INSECURE env hook to awareness client.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

OPERATOR_MODE=0
for arg in "$@"; do
  case "$arg" in
    --operator) OPERATOR_MODE=1 ;;
  esac
done

require_skillctl
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

if [ "$OPERATOR_MODE" -eq 1 ]; then
  header "10 — SCAN + sync OPERATOR's skills (~/.claude/skills/)"
  SCAN_HOME="$HOME"
  SESSION_TAG="kup-operator-$(date +%Y-%m-%d)"
else
  header "10 — SCAN + sync ERIC's installed skills (artifacts/eric-home/)"
  SCAN_HOME="$INSTALL_HOME"
  SESSION_TAG="kup-eric-$(date +%Y-%m-%d)"
fi

log "scanning skills under $SCAN_HOME/.claude/skills/"
INVENTORY=$(HOME="$SCAN_HOME" "$SKILLCTL" awareness sync \
  --source claude \
  --registry "$REGISTRY_URL" \
  --session "$SESSION_TAG" \
  --dry-run 2>/dev/null) || true

if [[ -z "$INVENTORY" ]]; then
  warn "no skills found under $SCAN_HOME/.claude/skills/"
  warn "(if running for Eric, run 05-eric-install-and-run.sh first)"
  exit 0
fi

# Transform skillctl jsonl inventory → /profile/import payload shape.
SKILLS_JSON=$(echo "$INVENTORY" | python3 -c '
import json, sys
out = []
seen = set()
for line in sys.stdin:
    line = line.strip()
    if not line or not line.startswith("{"):
        continue
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        continue
    name = rec.get("name") or rec.get("frontmatter", {}).get("name")
    if not name or name in seen:
        continue
    seen.add(name)
    fm = rec.get("frontmatter") or {}
    out.append({
        "skill_id": name,
        "name": name,
        "category": rec.get("tier", "skill"),
        "skill_type": "claude-skill",
        "notes": (fm.get("description", "") or "")[:200],
    })
print(json.dumps({"skills": out}))
')

COUNT=$(echo "$SKILLS_JSON" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["skills"]))')
log "enumerated $COUNT distinct skill(s) → POSTing as profile import"

RESP_FILE="$LOG_DIR/skillprofile-import.json"
HTTP=$(curl -sk \
  -H "X-API-KEY: ${ER1_API_KEY}" \
  -H "X-User-ID: ${USER_ID}" \
  -H "Content-Type: application/json" \
  -X POST "$REGISTRY_URL/api/v2/skills/profile/import" \
  -d "$SKILLS_JSON" \
  -o "$RESP_FILE" -w "%{http_code}") || true

if [[ "$HTTP" =~ ^(200|201)$ ]]; then
  SUMMARY=$(python3 -c "
import json
d = json.load(open('$RESP_FILE'))
print(f\"imported={d.get('imported', d.get('new_count', 0))} \"
      f\"already_known={d.get('already_known', 0)} \"
      f\"total={d.get('total_skills', 0)}\")
" 2>/dev/null || head -c 200 "$RESP_FILE")
  ok "profile import HTTP $HTTP — $SUMMARY"
else
  warn "profile import returned HTTP $HTTP — see $RESP_FILE"
fi

header "10 — done"
note "Session tag:  $SESSION_TAG"
note "User ID:      $USER_ID"
note "Skills count: $COUNT"
note "Admin page:   $REGISTRY_URL/v2/skills/admin"
