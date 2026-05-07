#!/usr/bin/env bash
# push-to-er1 — Take a release-gate JSON exported by release-gate-form.html
# and push each step (plus a summary item) into the ER1 memory layer with
# the right tags so the thinker's main view filters them out by default.
#
# Usage:
#   ./push-to-er1.sh <session-export.json>
#   ./push-to-er1.sh <session-export.json> --dry-run     # show what would be sent
#   ./push-to-er1.sh <session-export.json> --base URL    # override $REGISTRY_URL
#
# Required env:
#   ER1_API_KEY    — dual-auth API key
#
# What it does:
#   - Splits the document into one POST per step (item body = intent + commands + observation).
#   - Adds a final summary item that links the whole gate together.
#   - Applies tags per the system-insight pattern (see SYSTEM-INSIGHTS-PATTERN.md):
#       system:insight  auto:generated  release-gate  skill-manager
#       <cohort>  step:<id>  verdict:<v>  session:<session-id>
#   - The thinker's main view filters out (auto:generated OR system:insight) by default.
#     Items remain searchable; explicit "Show system insights" toggle surfaces them.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

INPUT="${1:-}"
DRY_RUN=0
BASE="$REGISTRY_URL"
shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --base)    BASE="$2"; shift 2 ;;
    *) fail "unknown arg: $1"; exit 2 ;;
  esac
done

if [[ -z "$INPUT" || ! -f "$INPUT" ]]; then
  fail "usage: $0 <session-export.json> [--dry-run] [--base URL]"
  fail "(no input file or file not found: $INPUT)"
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  fail "jq is required (brew install jq)"
  exit 2
fi
if [[ "$DRY_RUN" -eq 0 && -z "${ER1_API_KEY:-}" ]]; then
  fail "ER1_API_KEY not set — required for live push (or pass --dry-run)"
  exit 2
fi

header "Push release-gate insights → ER1"
note "Input:    $INPUT"
note "Base URL: $BASE"
note "Mode:     $([ "$DRY_RUN" -eq 1 ] && echo DRY-RUN || echo LIVE)"

SESSION=$(jq -r '.session_id // "unknown"' "$INPUT")
COHORT=$(jq -r '.cohort // "unknown"' "$INPUT")
USER_ID=$(jq -r '.captured_by // "id:unknown@m3c"' "$INPUT")
OVERALL=$(jq -r '.overall_verdict // "unknown"' "$INPUT")
COUNT=$(jq '.items | length' "$INPUT")

note "Session:  $SESSION"
note "Cohort:   $COHORT"
note "Overall:  $OVERALL"
note "Steps:    $COUNT"
echo

post_one() {
  local title="$1" body="$2" tags_json="$3"
  local payload
  payload=$(jq -nc \
    --arg title "$title" \
    --arg body  "$body" \
    --argjson tags "$tags_json" \
    '{title:$title, body:$body, tags:$tags, kind:"system_insight"}')

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "─── DRY-RUN ───────────────────────────────"
    echo "$payload" | jq .
    echo
    return 0
  fi

  local rc
  HTTP=$(curl -sk \
    -H "X-API-KEY: $ER1_API_KEY" \
    -H "X-User-ID: $USER_ID" \
    -H "Content-Type: application/json" \
    -X POST \
    -d "$payload" \
    -o "$LOG_DIR/er1-push-$$-resp.json" \
    -w "%{http_code}" \
    "$BASE/api/v2/memory/items")
  rc=$?
  if [[ "$rc" -ne 0 ]]; then
    fail "curl failed (rc=$rc) for: $title"
    return 1
  fi
  case "$HTTP" in
    200|201) ok "$title  →  HTTP $HTTP" ;;
    *)       warn "$title  →  HTTP $HTTP"; warn "$(head -1 "$LOG_DIR/er1-push-$$-resp.json")"; return 1 ;;
  esac
}

# Per-step items
FAILED=0
jq -c '.items[]' "$INPUT" | while IFS= read -r item; do
  step_id=$(echo "$item"   | jq -r '.step_id')
  title=$(echo "$item"     | jq -r '.title')
  intent=$(echo "$item"    | jq -r '.intent')
  cmds=$(echo "$item"      | jq -r '.commands | join("\n")')
  expected=$(echo "$item"  | jq -r '.expected')
  verdict=$(echo "$item"   | jq -r '.verdict // "unset"')
  feedback=$(echo "$item"  | jq -r '.feedback // ""')
  captured=$(echo "$item"  | jq -r '.captured_at // "unset"')

  body=$(cat <<EOF
**Release-gate step:** ${step_id} — ${title}

**Verdict:** \`${verdict}\`
**Captured at:** ${captured}
**Session:** ${SESSION}
**Cohort:** ${COHORT}

### Intent
${intent}

### Commands
\`\`\`bash
${cmds}
\`\`\`

### Expected
${expected}

### Observation
${feedback:-_no feedback recorded_}
EOF
)

  tags=$(echo "$item" | jq -c '.tags + ["session:'"$SESSION"'", "cohort:'"$COHORT"'"]')
  full_title="release-gate / $SESSION / $step_id — $title"

  if ! post_one "$full_title" "$body" "$tags"; then
    FAILED=$(( FAILED + 1 ))
  fi
done

# Summary item
SUMMARY_BODY=$(cat <<EOF
**Release-gate session:** ${SESSION}
**Overall verdict:** \`${OVERALL}\`
**Cohort:** ${COHORT}
**Steps:** ${COUNT}

This is the system-generated summary of a KuP release-gate run. The
per-step insights live in sibling memory items tagged with the same
\`session:${SESSION}\` tag — pull them as a bundle to see the full chronology.

\`\`\`json
$(jq '.counts' "$INPUT")
\`\`\`

The chain proof (steps 01–09) demonstrates the m3c Skill-Manager's offline
cryptographic guarantees end-to-end. The release gates (G1, G2) produce the
trainer-facing artifacts (PDF handbook + cross-platform skillctl release).

By design, this item is filtered OUT of the thinker's main view (tags include
\`system:insight\` + \`auto:generated\`). It is reachable via the explicit
"Show system insights" toggle, or by tag-search on \`session:${SESSION}\`.
EOF
)
SUMMARY_TAGS=$(jq -c '.summary_tags' "$INPUT")
post_one "release-gate / $SESSION / SUMMARY" "$SUMMARY_BODY" "$SUMMARY_TAGS" || FAILED=$(( FAILED + 1 ))

echo
if [[ "$FAILED" -gt 0 ]]; then
  fail "$FAILED item(s) failed"
  exit 1
fi
ok "all items pushed to ER1"
note "search them later via tag intersection: \`session:${SESSION}\` + \`system:insight\`"
note "the thinker's main view does NOT show these by default — toggle 'Show system insights' to surface."
