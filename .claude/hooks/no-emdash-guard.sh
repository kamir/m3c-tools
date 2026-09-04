#!/usr/bin/env bash
# no-emdash-guard.sh: PreToolUse hook. Refuse a Write/Edit whose payload
# contains U+2014 EM DASH, before the bytes reach disk.
#
# The repo gate (scripts/check-no-emdash.sh) catches it at commit and in CI.
# This catches it one step earlier, where fixing it is free.
#
# Wire it up in .claude/settings.json (that file is git-ignored, so this hook
# ships in the repo and each checkout opts in):
#
#   {
#     "hooks": {
#       "PreToolUse": [
#         {
#           "matcher": "Write|Edit|NotebookEdit",
#           "hooks": [
#             { "type": "command",
#               "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/no-emdash-guard.sh" }
#           ]
#         }
#       ]
#     }
#   }
#
# Exit 2 tells Claude Code to block the call and feed stderr back to the model.
set -uo pipefail

INPUT=$(cat)
EM=$(printf '\xe2\x80\x94')   # U+2014 EM DASH

# Only the fields that carry file content. tool_input.file_path is checked too,
# because a path with a dash in it is just as wrong.
PAYLOAD=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
ti = d.get("tool_input") or {}
parts = []
for k in ("content", "new_string", "new_source", "file_path"):
    v = ti.get(k)
    if isinstance(v, str):
        parts.append(v)
sys.stdout.write("\n".join(parts))
' 2>/dev/null || true)

case "$PAYLOAD" in
  *"$EM"*)
    cat >&2 <<'MSG'
BLOCKED: the payload contains U+2014 EM DASH, which this repository does not allow.

Rewrite it with the punctuation the sentence actually needs:
  a label and its expansion     -> ":"     Command surface: authoring
  two independent statements    -> "."     The gate is blocking. A failure stops the release.
  two clauses too close to split-> ";"     no admin rights; the installer differs
  an aside inside one sentence  -> ", ,"   The seam, on the hot path, is stateless
  a continuation                -> ","     signed, not merely checksummed
  an empty table cell           -> "n/a"

Do not substitute a hyphen or a double hyphen for the dash. See
.claude/rules/prose-style.md and CODESTYLE.md ("Prose: no em dashes").
MSG
    exit 2
    ;;
esac
exit 0
