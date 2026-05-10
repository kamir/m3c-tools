---
name: skillprofile-track
description: Reports skill invocations to aims-core (SPEC-0121 P4) so the user's skill profile accumulates use_count, last_used and auto-promotes mastery (aware → practiced → fluent). Wired as a PostToolUse hook, not invoked directly.
metadata:
  version: 1.0.0
  category: telemetry
  tags: [skill-profile, telemetry, hook, aims-core, SPEC-0121]
  governance_level: green
  owner: kamir
  status: hook
---

# skillprofile-track

This is **not a Claude Code command you invoke**; it is a hook side-channel
that reports skill execution to the aims-core Personal Skill Profile
service.

## What it does

After every Claude Code skill invocation, the bash hook at
`.claude/hooks/skill-usage-tracker.sh` POSTs to
`POST /api/v2/skills/usage` on aims-core with:

```json
{
  "skill_id": "<CLAUDE_SKILL_NAME>",
  "timestamp": "<iso-8601 utc>",
  "context": { "hook": "PostToolUse", "tool": "<CLAUDE_TOOL_NAME>" }
}
```

The aims-core endpoint:
1. Increments the user's `use_count` and `last_used` for that skill in
   `_user_skill_profiles`.
2. Auto-creates the skill (status = aware) if it isn't already in the
   profile.
3. Auto-promotes mastery per SPEC-0121 §6 thresholds:
   - aware → practiced: `use_count >= 3` AND elapsed since `first_seen` >= 1 day
   - practiced → fluent: `use_count >= 10` AND elapsed >= 7 days
4. Writes one row to `_skill_audit_log` with a per-second dedupe key
   (so retries inside the same wall-second don't double-count).

The hook is **non-blocking**: any failure is logged to
`~/.claude/skill-usage-tracker.log` and silently swallowed. It never
interferes with the parent skill's exit status.

## How to enable it

1. Drop a per-machine credentials file at
   `~/.claude/skill-usage-tracker.env` containing:

   ```sh
   ER1_API_KEY="<your aims-core API key>"
   ER1_USER_ID="<your aims-core user id>"
   AIMS_CORE="https://onboarding.guide"   # optional override
   ```

2. Wire the hook in `~/.claude/settings.json` (or this project's
   `.claude/settings.local.json`) under the `hooks` block:

   ```json
   {
     "hooks": {
       "PostToolUse": [
         {
           "matcher": "Skill",
           "hooks": [
             {
               "type": "command",
               "command": "${CLAUDE_PROJECT_DIR}/.claude/hooks/skill-usage-tracker.sh"
             }
           ]
         }
       ]
     }
   }
   ```

3. To temporarily disable without un-wiring, set
   `SKILL_USAGE_TRACKER_OFF=1` in the env file.

## Verifying

After invoking any skill, check the tail of the log:

```sh
tail -1 ~/.claude/skill-usage-tracker.log
# → [<iso-time>] ok 202 skill=<name>
```

A `200` response with `recorded=false` means the dedupe layer
suppressed an immediate retry — that's expected.

## Why this lives in m3c-tools

The hook ships with the same repo that vendors all m3c skills, so any
operator who clones `m3c-tools` and configures their API key gets
profile tracking out of the box.
