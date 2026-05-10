#!/usr/bin/env bash
#
# skill-usage-tracker.sh — Claude Code PostToolUse / SkillEnd hook.
#
# Posts a single skill-usage event to aims-core so the user's skill
# profile (SPEC-0121) accumulates use_count + last_used + auto-mastery
# without any manual bookkeeping.
#
# Triggered by Claude Code via .claude/settings.json after a Skill
# invocation completes. Idempotent and non-blocking: any failure is
# logged to ~/.claude/skill-usage-tracker.log and silently swallowed
# so the host session is never broken.
#
# Inputs (env vars set by Claude Code):
#   CLAUDE_TOOL_NAME           — the tool that just ran (often "Skill")
#   CLAUDE_SKILL_NAME          — the invoked skill (preferred id)
#   CLAUDE_HOOK_EVENT          — the hook trigger ("PostToolUse" etc.)
#
# Optional environment overrides (read from ~/.claude/skill-usage-tracker.env
# or set directly in the shell):
#   AIMS_CORE                  — base URL, default https://onboarding.guide
#   ER1_API_KEY                — server-side API key (REQUIRED to send)
#   ER1_USER_ID                — caller identity (REQUIRED to send)
#   SKILL_USAGE_TRACKER_OFF=1  — kill switch for the operator
#
# Exit status is always 0 (we never block the parent invocation).

set -u  # NOT -e: we want to keep going on transient failures.

LOG_FILE="${HOME}/.claude/skill-usage-tracker.log"
ENV_FILE="${HOME}/.claude/skill-usage-tracker.env"
mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"${LOG_FILE}" 2>/dev/null || true
}

# Optional per-machine override file.
if [ -f "${ENV_FILE}" ]; then
  # shellcheck disable=SC1090
  . "${ENV_FILE}" 2>/dev/null || log "warn: failed to source ${ENV_FILE}"
fi

if [ "${SKILL_USAGE_TRACKER_OFF:-0}" = "1" ]; then
  exit 0
fi

SKILL_ID="${CLAUDE_SKILL_NAME:-${CLAUDE_TOOL_NAME:-}}"
if [ -z "${SKILL_ID}" ]; then
  log "skip: no skill name in env"
  exit 0
fi

API_KEY="${ER1_API_KEY:-}"
USER_ID="${ER1_USER_ID:-}"
BASE_URL="${AIMS_CORE:-https://onboarding.guide}"

if [ -z "${API_KEY}" ] || [ -z "${USER_ID}" ]; then
  log "skip skill=${SKILL_ID}: ER1_API_KEY or ER1_USER_ID not set"
  exit 0
fi

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PAYLOAD=$(printf '{"skill_id":"%s","timestamp":"%s","context":{"hook":"%s","tool":"%s"}}' \
  "${SKILL_ID}" "${NOW}" \
  "${CLAUDE_HOOK_EVENT:-PostToolUse}" "${CLAUDE_TOOL_NAME:-}")

HTTP_CODE=$(curl -sS -o /tmp/skill-usage-resp.$$ -w '%{http_code}' \
  --max-time 5 \
  -X POST "${BASE_URL%/}/api/v2/skills/usage" \
  -H 'Content-Type: application/json' \
  -H "X-API-KEY: ${API_KEY}" \
  -H "X-User-ID: ${USER_ID}" \
  -d "${PAYLOAD}" 2>>"${LOG_FILE}" || echo "000")

if [ "${HTTP_CODE}" = "200" ] || [ "${HTTP_CODE}" = "202" ]; then
  log "ok ${HTTP_CODE} skill=${SKILL_ID}"
else
  RESP="$(cat /tmp/skill-usage-resp.$$ 2>/dev/null || true)"
  log "fail ${HTTP_CODE} skill=${SKILL_ID} resp=${RESP}"
fi
rm -f /tmp/skill-usage-resp.$$ 2>/dev/null || true

exit 0
