#!/usr/bin/env python3
"""MCP Skill Server — exposes the skill lifecycle as Claude Code tools.

Wraps skillctl (Go CLI) and aims-core (REST API) into native MCP tools
so Claude Code can directly browse, query, import, and track skills.

Transport: stdio (standard for Claude Code)
Registration: ~/.claude/mcp.json
"""
import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# ── Configuration ──────────────────────────────────────────────────────

SKILLCTL = os.environ.get(
    "SKILLCTL_BIN",
    str(Path.home() / "GITHUB.kamir" / "m3c-tools" / "build" / "skillctl"),
)
GRAPH_DB = os.environ.get(
    "SKILL_GRAPH_DB",
    str(Path.home() / ".m3c-tools" / "skill-graph.db"),
)
USAGE_DB = os.environ.get(
    "SKILL_USAGE_DB",
    str(Path.home() / ".m3c-tools" / "skill-usage.db"),
)
API_URL = os.environ.get("M3C_API_URL", "https://onboarding.guide")
API_KEY = os.environ.get("M3C_API_KEY", "")

# Try loading API key from session file
if not API_KEY:
    session_path = Path.home() / ".m3c-tools" / "er1_session.json"
    try:
        with open(session_path) as f:
            API_KEY = json.load(f).get("api_key", "")
    except Exception:
        pass

# ── Server ─────────────────────────────────────────────────────────────

mcp = FastMCP(
    "skill-server",
    instructions="Skill lifecycle tools — browse, query, import, track, discover skills across all projects.",
)


# ── Tool: skill_scan ──────────────────────────────────────────────────

@mcp.tool()
async def skill_scan(
    path: str = "",
    recursive: bool = True,
    include_home: bool = True,
) -> str:
    """Scan directories for Claude Code skills, commands, agents, and skill indexes.
    Returns a summary of discovered skills by type and project."""
    args = [SKILLCTL, "scan", "--output", "json"]
    if path:
        args += ["--path", path]
    else:
        args += ["--path", str(Path.home())]
    if recursive:
        args.append("--recursive")
    if include_home:
        args.append("--include-home")

    result = await _run_skillctl(args)
    if result.get("error"):
        return f"Scan failed: {result['error']}"

    inv = json.loads(result["stdout"])
    total = inv.get("total_count", 0)
    by_type = inv.get("by_type", {})
    by_project = inv.get("by_project", {})

    lines = [f"Scanned {total} skills across {len(by_project)} projects\n"]
    lines.append("By type:")
    for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
        lines.append(f"  {t}: {c}")
    lines.append("\nBy project:")
    for p, c in sorted(by_project.items(), key=lambda x: -x[1])[:15]:
        lines.append(f"  {p}: {c}")
    if len(by_project) > 15:
        lines.append(f"  ... and {len(by_project) - 15} more")

    return "\n".join(lines)


# ── Tool: skill_browse ────────────────────────────────────────────────

@mcp.tool()
async def skill_browse(
    project: str = "",
    skill_type: str = "",
    category: str = "",
    tag: str = "",
    limit: int = 50,
) -> str:
    """Browse the skill graph. Filter by project, type, category, or tag.
    Returns matching skills with their connections."""
    conn = _open_graph_db()
    if not conn:
        return "Graph database not found. Run `skillctl browse` first to build it."

    query = "SELECT id, label, kind, skill_type, project, description, category, degree FROM nodes WHERE 1=1"
    params = []

    if project:
        query += " AND project = ?"
        params.append(project)
    if skill_type:
        query += " AND skill_type = ?"
        params.append(skill_type)
    if category:
        query += " AND category = ?"
        params.append(category)
    if tag:
        # Join with node_tags
        query = query.replace("FROM nodes", "FROM nodes JOIN node_tags ON nodes.id = node_tags.node_id")
        query += " AND node_tags.tag = ?"
        params.append(tag)

    # Only content nodes (not project/category/tag meta-nodes)
    query += " AND kind IN ('skill', 'agent', 'command', 'skill_index')"
    query += f" ORDER BY degree DESC LIMIT {min(limit, 200)}"

    try:
        rows = conn.execute(query, params).fetchall()
        conn.close()
    except Exception as e:
        conn.close()
        return f"Query error: {e}"

    if not rows:
        return "No skills found matching the filter."

    lines = [f"Found {len(rows)} skills:\n"]
    for row in rows:
        id_, label, kind, stype, proj, desc, cat, degree = row
        desc_short = (desc or "")[:80].replace("\n", " ").strip()
        lines.append(f"  {label} [{stype}] — {proj} (degree:{degree})")
        if cat:
            lines.append(f"    category: {cat}")
        if desc_short:
            lines.append(f"    {desc_short}")

    return "\n".join(lines)


# ── Tool: skill_search ────────────────────────────────────────────────

@mcp.tool()
async def skill_search(query: str, limit: int = 20) -> str:
    """Full-text search across skill names and descriptions."""
    conn = _open_graph_db()
    if not conn:
        return "Graph database not found. Run `skillctl browse` first."

    q = f"%{query.lower()}%"
    rows = conn.execute(
        """SELECT id, label, kind, skill_type, project, description, category, degree
           FROM nodes
           WHERE kind IN ('skill', 'agent', 'command', 'skill_index')
             AND (LOWER(label) LIKE ? OR LOWER(description) LIKE ?)
           ORDER BY degree DESC LIMIT ?""",
        (q, q, min(limit, 100)),
    ).fetchall()
    conn.close()

    if not rows:
        return f"No skills matching '{query}'."

    lines = [f"Found {len(rows)} skills matching '{query}':\n"]
    for row in rows:
        id_, label, kind, stype, proj, desc, cat, degree = row
        desc_short = (desc or "")[:80].replace("\n", " ").strip()
        lines.append(f"  {label} [{stype}] — {proj}")
        if desc_short:
            lines.append(f"    {desc_short}")

    return "\n".join(lines)


# ── Tool: skill_detail ────────────────────────────────────────────────

@mcp.tool()
async def skill_detail(skill_name: str) -> str:
    """Get full detail for a skill: content, connections, metadata, source path."""
    conn = _open_graph_db()
    if not conn:
        return "Graph database not found."

    row = conn.execute(
        """SELECT id, label, kind, skill_type, project, description, category,
                  source_path, size_bytes, has_fm, degree
           FROM nodes WHERE LOWER(label) = ? AND kind IN ('skill','agent','command','skill_index')
           LIMIT 1""",
        (skill_name.lower(),),
    ).fetchone()

    if not row:
        conn.close()
        return f"Skill '{skill_name}' not found."

    id_, label, kind, stype, proj, desc, cat, path, size, has_fm, degree = row

    # Get tags
    tags = [r[0] for r in conn.execute(
        "SELECT tag FROM node_tags WHERE node_id = ?", (id_,)
    ).fetchall()]

    # Get connections
    edges = conn.execute(
        """SELECT e.kind, e.weight, e.evidence, n.label, n.kind
           FROM edges e JOIN nodes n ON (e.target = n.id OR e.source = n.id)
           WHERE (e.source = ? OR e.target = ?) AND n.id != ?
           LIMIT 30""",
        (id_, id_, id_),
    ).fetchall()
    conn.close()

    lines = [
        f"# {label}",
        f"Type: {stype}  |  Kind: {kind}  |  Project: {proj}",
        f"Category: {cat or '-'}  |  Degree: {degree}  |  Size: {size} bytes  |  Frontmatter: {'yes' if has_fm else 'no'}",
    ]
    if tags:
        lines.append(f"Tags: {', '.join(tags)}")
    if path:
        lines.append(f"Path: {path}")
    if desc:
        lines.append(f"\nDescription:\n{desc.strip()}")

    if edges:
        lines.append(f"\nConnections ({len(edges)}):")
        for ekind, weight, evidence, nlabel, nkind in edges:
            lines.append(f"  {ekind} → {nlabel} ({nkind})")

    # Try reading file content
    if path and os.path.exists(path):
        try:
            content = Path(path).read_text()[:2000]
            lines.append(f"\nContent (first 2000 chars):\n{content}")
        except Exception:
            pass

    return "\n".join(lines)


# ── Tool: skill_consolidate ───────────────────────────────────────────

@mcp.tool()
async def skill_consolidate(path: str = "") -> str:
    """Analyze skill sprawl: duplicates, orphans, drift, annotation gaps."""
    args = [SKILLCTL, "consolidate", "--report-only", "--output", "text"]
    if path:
        args += ["--path", path]
    else:
        args += ["--path", str(Path.home())]
    args += ["--recursive", "--include-home"]

    result = await _run_skillctl(args)
    if result.get("error"):
        return f"Consolidation failed: {result['error']}"

    return result["stdout"]


# ── Tool: skill_graph_stats ───────────────────────────────────────────

@mcp.tool()
async def skill_graph_stats() -> str:
    """Get skill graph statistics: node/edge counts by type."""
    conn = _open_graph_db()
    if not conn:
        return "Graph database not found."

    nodes_by_kind = conn.execute(
        "SELECT kind, COUNT(*) FROM nodes GROUP BY kind ORDER BY COUNT(*) DESC"
    ).fetchall()
    edges_by_kind = conn.execute(
        "SELECT kind, COUNT(*) FROM edges GROUP BY kind ORDER BY COUNT(*) DESC"
    ).fetchall()
    total_nodes = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    total_edges = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]

    # Check metadata
    built_at = ""
    try:
        row = conn.execute("SELECT value FROM graph_meta WHERE key = 'built_at'").fetchone()
        if row:
            built_at = row[0]
    except Exception:
        pass
    conn.close()

    lines = [
        f"Skill Graph Statistics",
        f"Built: {built_at or 'unknown'}",
        f"Total nodes: {total_nodes}  |  Total edges: {total_edges}\n",
        "Nodes by kind:",
    ]
    for kind, count in nodes_by_kind:
        lines.append(f"  {kind}: {count}")
    lines.append("\nEdges by kind:")
    for kind, count in edges_by_kind:
        lines.append(f"  {kind}: {count}")

    return "\n".join(lines)


# ── Tool: skill_profile ───────────────────────────────────────────────

@mcp.tool()
async def skill_profile() -> str:
    """Get your personal skill profile: mastery summary, skill list, categories."""
    data = await _api_get("/api/v2/skills/profile")
    if isinstance(data, str):
        return data  # error message

    summary = data.get("mastery_summary", {})
    skills = data.get("skills", [])
    categories = data.get("categories", {})

    lines = [
        f"Skill Profile — {data.get('display_name', 'You')}",
        f"Total skills: {data.get('skill_count', len(skills))}",
        f"Fluent: {summary.get('fluent', 0)}  |  Practiced: {summary.get('practiced', 0)}  |  Aware: {summary.get('aware', 0)}\n",
    ]

    if categories:
        lines.append("Categories:")
        for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
            lines.append(f"  {cat}: {count}")
        lines.append("")

    if skills:
        lines.append("Skills:")
        for s in sorted(skills, key=lambda x: {"fluent": 0, "practiced": 1, "aware": 2}.get(x.get("status", "aware"), 3)):
            lines.append(f"  [{s.get('status', '?'):9}] {s.get('name', '?')} ({s.get('category', '-')}) — {s.get('use_count', 0)} uses")

    return "\n".join(lines)


# ── Tool: skill_import ────────────────────────────────────────────────

@mcp.tool()
async def skill_import(scan_json_path: str = "") -> str:
    """Import skills from a scan JSON file into your aims-core profile.
    If no path given, runs a fresh scan first."""
    if scan_json_path and os.path.exists(scan_json_path):
        with open(scan_json_path) as f:
            inv = json.load(f)
    else:
        # Run a fresh scan
        args = [SKILLCTL, "scan", "--path", str(Path.home()), "--recursive",
                "--include-home", "--output", "json"]
        result = await _run_skillctl(args)
        if result.get("error"):
            return f"Scan failed: {result['error']}"
        inv = json.loads(result["stdout"])

    skills = inv.get("skills", [])
    data = await _api_post("/api/v2/skills/profile/import", {"skills": skills})
    if isinstance(data, str):
        return data

    return (
        f"Import complete: {data.get('imported', 0)} skills imported, "
        f"{data.get('new_candidates', 0)} new candidates, "
        f"{data.get('already_known', 0)} already known."
    )


# ── Tool: skill_usage ─────────────────────────────────────────────────

@mcp.tool()
async def skill_usage(skill_name: str) -> str:
    """Record that a skill was used. Updates mastery progression."""
    event = {
        "skill_id": skill_name,
        "user_id": os.environ.get("USER", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "context": {"source": "mcp_tool"},
    }

    data = await _api_post("/api/v2/skills/usage", event)
    if isinstance(data, str):
        # Fallback: save locally
        _save_usage_local(event)
        return f"Recorded locally (aims-core unreachable). Sync later with `skillctl sync-usage`."

    new_mastery = data.get("new_mastery", "?")
    return f"Usage recorded for '{skill_name}'. Current mastery: {new_mastery}"


# ── Tool: skill_discover ──────────────────────────────────────────────

@mcp.tool()
async def skill_discover(limit: int = 10) -> str:
    """Get personalized skill suggestions based on role, team, and graph proximity."""
    data = await _api_get(f"/api/v2/skills/discover?limit={limit}")
    if isinstance(data, str):
        return data

    suggestions = data.get("suggestions", data if isinstance(data, list) else [])
    if not suggestions:
        return "No skill suggestions available. Import skills first to build your profile."

    lines = [f"Skill Suggestions ({len(suggestions)}):\n"]
    for s in suggestions:
        score = s.get("score", 0)
        lines.append(f"  {s.get('name', '?')} [{s.get('category', '-')}] — score: {score:.1f}")
        lines.append(f"    {s.get('reason', '')}")
        lines.append(f"    Strategy: {s.get('strategy', '?')}")

    return "\n".join(lines)


# ── Helpers ────────────────────────────────────────────────────────────

async def _run_skillctl(args: list[str]) -> dict:
    """Run a skillctl command and return {"stdout": ..., "stderr": ..., "error": ...}."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        if proc.returncode != 0:
            return {"error": stderr.decode().strip(), "stdout": "", "stderr": stderr.decode()}
        return {"stdout": stdout.decode(), "stderr": stderr.decode(), "error": ""}
    except asyncio.TimeoutError:
        return {"error": "skillctl timed out after 120s", "stdout": "", "stderr": ""}
    except FileNotFoundError:
        return {"error": f"skillctl not found at {SKILLCTL}", "stdout": "", "stderr": ""}


def _open_graph_db() -> sqlite3.Connection | None:
    """Open the skill graph SQLite database."""
    if not os.path.exists(GRAPH_DB):
        return None
    try:
        return sqlite3.connect(GRAPH_DB)
    except Exception:
        return None


async def _api_get(path: str) -> dict | str:
    """GET from aims-core API. Returns parsed JSON or error string."""
    if not API_KEY:
        return "No API key configured. Set M3C_API_KEY or authenticate via skillctl."
    try:
        url = f"{API_URL}{path}"
        req = urllib.request.Request(url)
        req.add_header("X-API-KEY", API_KEY)
        req.add_header("X-User-ID", os.environ.get("USER", "unknown"))
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return f"API error: HTTP {e.code} — {e.read().decode()[:200]}"
    except Exception as e:
        return f"API unreachable: {e}"


async def _api_post(path: str, body: dict) -> dict | str:
    """POST to aims-core API. Returns parsed JSON or error string."""
    if not API_KEY:
        return "No API key configured. Set M3C_API_KEY or authenticate via skillctl."
    try:
        url = f"{API_URL}{path}"
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-API-KEY", API_KEY)
        req.add_header("X-User-ID", os.environ.get("USER", "unknown"))
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return f"API error: HTTP {e.code} — {e.read().decode()[:200]}"
    except Exception as e:
        return f"API unreachable: {e}"


def _save_usage_local(event: dict):
    """Save usage event to local SQLite fallback."""
    try:
        os.makedirs(os.path.dirname(USAGE_DB), exist_ok=True)
        conn = sqlite3.connect(USAGE_DB)
        conn.execute("""CREATE TABLE IF NOT EXISTS skill_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            skill_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            project TEXT DEFAULT '',
            session_id TEXT DEFAULT '',
            synced INTEGER DEFAULT 0,
            synced_at TEXT DEFAULT ''
        )""")
        conn.execute(
            "INSERT INTO skill_usage (skill_id, user_id, timestamp, synced) VALUES (?,?,?,0)",
            (event["skill_id"], event["user_id"], event["timestamp"]),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ── Entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
