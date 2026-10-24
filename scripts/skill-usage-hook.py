#!/usr/bin/env python3
"""PostToolUse hook: track skill usage for mastery progression.

When registered as a PostToolUse hook, handles Skill tool invocations.
Attempts remote delivery, then best-effort local SQLite recording.
No hard total deadline or guaranteed durable recording is provided.
Network delivery requires the canonical api_connection.py installed beside this file.
"""
import importlib.util
import json
import sys
import os
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path


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

    # Attempt local recording after delivery, including a refused delivery.
    save_local(event, synced)


def _load_api_policy():
    """Load only the installed sibling, never CWD, PYTHONPATH or a repo fallback."""
    path = Path(__file__).resolve().with_name("api_connection.py")
    spec = importlib.util.spec_from_file_location("_m3c_hook_api_connection", path)
    if spec is None or spec.loader is None:
        raise ValueError("hook API policy unavailable")
    module = importlib.util.module_from_spec(spec)
    # Dataclass annotations require the module to be registered during execution.
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(spec.name, None)
        raise
    return module


def _read_legacy_api_key():
    """Reject ambiguous decoded fields before selecting the legacy API key."""
    def unique_object(pairs):
        fields = {}
        for name, value in pairs:
            if name in fields or (name.casefold() == "api_key" and name != "api_key"):
                raise ValueError("ambiguous legacy session")
            fields[name] = value
        return fields

    path = Path.home() / ".m3c-tools" / "er1_session.json"
    with open(path) as stream:
        session = json.load(stream, object_pairs_hook=unique_object)
    return session.get("api_key", "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect blocked", headers, fp)


def send_to_api(event):
    """Attempt one bound POST. Redirects and unsafe configuration return False."""
    try:
        policy = _load_api_policy()
        connection = policy.resolve_api_connection(os.environ.get, _read_legacy_api_key)
        if connection.error:
            print("skill usage: API configuration blocked; local recording is best effort.", file=sys.stderr)
            return False
        url = connection.base_url.rstrip("/") + "/api/v2/skills/usage"
        req = urllib.request.Request(url, data=json.dumps(event).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-API-KEY", connection.key)
        req.add_header("X-User-ID", event["user_id"])
        # Opted-in HTTP is loopback only. Ambient HTTP proxies must not receive
        # its credential or body. Preserve ordinary HTTPS proxy behavior.
        handlers = [_NoRedirect()]
        if connection.origin[0] == "http":
            handlers.append(urllib.request.ProxyHandler({}))
        # Reject every redirect, including same-origin method changes/replays.
        with urllib.request.build_opener(*handlers).open(req, timeout=3) as resp:
            return resp.status in (200, 202)
    except Exception:
        print("skill usage: API delivery unavailable; local recording is best effort.", file=sys.stderr)
        return False


def save_local(event, synced):
    """Attempt a local SQLite record; failures do not establish persistence."""
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
        pass  # Best effort; there is no durable acknowledgement.


if __name__ == "__main__":
    main()
