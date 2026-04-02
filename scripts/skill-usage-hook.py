#!/usr/bin/env python3
"""PostToolUse hook: track skill usage for mastery progression.

Runs after every Skill tool invocation in Claude Code.
Sends usage events to aims-core and always saves locally to SQLite.
Never blocks Claude Code — always exits 0, completes in under 2 seconds.
"""
import json
import sys
import os
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime, timezone


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return  # not valid JSON, skip

    tool_input = data.get("tool_input", {})
    skill_name = tool_input.get("skill", "")
    if not skill_name:
        return  # not a skill invocation

    user_id = os.environ.get("USER", "unknown")
    timestamp = datetime.now(timezone.utc).isoformat()
    session_id = data.get("session_id", "")
    project = os.path.basename(data.get("cwd", ""))

    event = {
        "skill_id": skill_name,
        "user_id": user_id,
        "timestamp": timestamp,
        "context": {
            "project": project,
            "session_id": session_id,
            "source": "claude_code_hook",
        },
    }

    # Try to send to aims-core
    synced = send_to_api(event)

    # Always save locally
    save_local(event, synced)


def send_to_api(event):
    """POST to aims-core usage endpoint. Returns True if successful."""
    # Read API config
    api_url = os.environ.get("M3C_API_URL", "https://onboarding.guide")
    api_key = os.environ.get("M3C_API_KEY", "")

    if not api_key:
        # Try reading from er1_session.json
        session_path = os.path.expanduser("~/.m3c-tools/er1_session.json")
        try:
            with open(session_path) as f:
                session = json.load(f)
                api_key = session.get("api_key", "")
        except Exception:
            pass

    if not api_key:
        return False

    try:
        url = f"{api_url}/api/v2/skills/usage"
        req_data = json.dumps(event).encode()
        req = urllib.request.Request(url, data=req_data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-API-KEY", api_key)
        req.add_header("X-User-ID", event["user_id"])
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 202 or resp.status == 200
    except Exception:
        return False


def save_local(event, synced):
    """Save to local SQLite for offline tracking and sync."""
    db_path = os.path.expanduser("~/.m3c-tools/skill-usage.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    try:
        conn = sqlite3.connect(db_path)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS skill_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            skill_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            project TEXT DEFAULT '',
            session_id TEXT DEFAULT '',
            synced INTEGER DEFAULT 0,
            synced_at TEXT DEFAULT ''
        )"""
        )
        conn.execute(
            """CREATE INDEX IF NOT EXISTS idx_usage_synced
            ON skill_usage(synced)"""
        )
        conn.execute(
            "INSERT INTO skill_usage (skill_id, user_id, timestamp, project, session_id, synced, synced_at) VALUES (?,?,?,?,?,?,?)",
            (
                event["skill_id"],
                event["user_id"],
                event["timestamp"],
                event["context"]["project"],
                event["context"]["session_id"],
                1 if synced else 0,
                event["timestamp"] if synced else "",
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # never fail


if __name__ == "__main__":
    main()
