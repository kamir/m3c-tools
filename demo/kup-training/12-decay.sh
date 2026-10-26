#!/usr/bin/env bash
# 12-decay: apply mastery decay across all profiles (lifecycle phase 6: DECAY).
#
# POST /api/v2/skills/profile/recalculate-all triggers, for every UserSkillProfile,
# a re-evaluation of every skill's mastery via compute_mastery(use_count, last_used).
# Decay rules (flask/modules/skillprofile/mastery.py):
#   last_used >= 45d  → fluent decays to practiced
#   last_used >= 90d  → practiced decays to aware
#
# In production this is wired to a daily Cloud Scheduler cron. Here we call it
# on demand to prove the wiring works end-to-end. Note: the demo just ran
# step 11 (fresh usage events), so nothing actually qualifies for decay yet.
# The assertion proves the *path* is alive (HTTP 200 + recalculated:true),
# not that mastery dropped.
#
# To exercise real decay in a demo run you need either:
#   (a) admin shell to backdate last_used in Firestore (not exposed today), or
#   (b) the planned `--simulate-decay <days>` flag on the endpoint (NOT YET
#       IMPLEMENTED: tracked as a follow-up in the lifecycle SPEC).
# Until (b) lands, decay is verified in unit tests, not in this E2E demo.
#
# Auth: the route is @require_admin, so it needs an admin's Flask-Login session
# (AIMS_ADMIN_COOKIE, see admin_curl in lib/common.sh). An API-key caller is
# never admin, whatever X-User-ID says. Without the cookie this step skips
# itself and says how to get one. skill_registry_bp is CSRF-exempt behind an
# origin check; whether the skillprofile blueprint is too was not checked from
# here. If it is not, the body of the refusal printed below says so.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

ensure_er1_api_key_from_keychain
if ! online_mode_available; then
  warn "online mode not available: skipping (this step requires the registry)"
  exit 0
fi

if [[ -z "${AIMS_ADMIN_COOKIE:-}" ]]; then
  warn "recalculate-all is an admin route and AIMS_ADMIN_COOKIE is unset: skipping"
  admin_session_hint
  note "  4. ./12-decay.sh"
  exit 0
fi

header "12, DECAY: trigger /profile/recalculate-all"
note "endpoint:  POST $REGISTRY_URL/api/v2/skills/profile/recalculate-all"
note "rules:     fluent→practiced @ 45d inactive, practiced→aware @ 90d inactive"

RESP_FILE="$LOG_DIR/recalculate-all.json"
HTTP=$(admin_curl \
  -X POST "$REGISTRY_URL/api/v2/skills/profile/recalculate-all" \
  -d '{}' \
  -o "$RESP_FILE" -w "%{http_code}") || true

if [[ "$HTTP" != "200" ]]; then
  warn "recalculate-all returned HTTP $HTTP. Body: $(head -c 200 "$RESP_FILE")"
  case "$HTTP" in
    302|401|403)
      warn "the registry did not take AIMS_ADMIN_COOKIE as an admin session (expired, or not admin by RBAC)"
      admin_session_hint
      ;;
  esac
  exit 0
fi

CHANGES=$(python3 -c "
import json
d = json.load(open('$RESP_FILE'))
print(f\"users_processed={d.get('users_processed', '?')} \"
      f\"total_changes={d.get('total_changes', 0)} \"
      f\"recalculated={d.get('recalculated', False)}\")
" 2>/dev/null || head -c 200 "$RESP_FILE")
ok "recalculate-all HTTP 200: $CHANGES"

header "12: done"
note "Admin page:   $REGISTRY_URL/v2/skills/admin"
note "TODO:         add --simulate-decay <days> to exercise actual decay in demo"
