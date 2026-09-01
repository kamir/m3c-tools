#!/usr/bin/env python3
"""Observation probe — SPEC-0247 OQ-1 (temporary instrument).

Captures the RAW stdin of a Claude Code hook event to a log so we can resolve
the remaining OQ-1 unknowns empirically instead of guessing:
  - the exact PreToolUse envelope (hook_event_name / tool_name / permission_mode)
  - whether UserPromptSubmit fires for a user-typed /slash command (and shows it)

Safety contract: NEVER blocks, NEVER emits a permission decision, ALWAYS exits 0.
It only appends to a local log. Remove the two hook entries from
~/.claude/settings.json (and delete this file) once the capture is done.
"""
import json
import os
import sys
from datetime import datetime, timezone

LOG = os.path.expanduser("~/.claude/skillctl/hook-probe.log")


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        data = None

    rec = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "probe_label": sys.argv[1] if len(sys.argv) > 1 else "",
        "hook_event_name": (data or {}).get("hook_event_name") if isinstance(data, dict) else None,
        "tool_name": (data or {}).get("tool_name") if isinstance(data, dict) else None,
        "permission_mode": (data or {}).get("permission_mode") if isinstance(data, dict) else None,
        "top_level_keys": sorted(data.keys()) if isinstance(data, dict) else None,
        "tool_input": (data or {}).get("tool_input") if isinstance(data, dict) else None,
        # prompt prefix lets us see whether a /slash command surfaces here
        "prompt_prefix": ((data or {}).get("prompt") or "")[:160] if isinstance(data, dict) else None,
        "raw_prefix": raw[:2000],
    }
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass

    # Observation only. Allow everything, decide nothing.
    sys.exit(0)


if __name__ == "__main__":
    main()
