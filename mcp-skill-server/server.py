#!/usr/bin/env python3
"""MCP Skill Server: exposes the skill lifecycle as Claude Code tools.

Wraps skillctl (Go CLI) and aims-core (REST API) into native MCP tools
so Claude Code can directly browse, query, import, and track skills.

Transport: stdio (standard for Claude Code)
Registration: ~/.claude/mcp.json
"""
import asyncio
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from api_connection import parse_api_base, resolve_api_connection

logger = logging.getLogger("skill-server")

# ── Configuration ──────────────────────────────────────────────────────

# Standard install locations, searched in order AFTER $PATH. Until AUDIT-0001
# the default was str(Path.home() / "GITHUB.kamir" / "m3c-tools" / "build" /
# "skillctl"): one developer's unpinned dev-build directory, which resolves on
# exactly one machine and fails silently everywhere else.
_SKILLCTL_INSTALL_DIRS = (
    Path("/usr/local/bin"),
    Path("/opt/homebrew/bin"),
    Path.home() / ".local" / "bin",
    Path.home() / "bin",
    Path.home() / ".claude" / "bin",
)


def _discover_skillctl() -> str:
    """Best-effort skillctl path: $PATH first, then the standard install dirs.

    Returns the empty string when nothing is found. Callers go through
    _resolve_skillctl_bin(), which turns that into a remediation message
    instead of exec'ing a path that does not exist.
    """
    on_path = shutil.which("skillctl")
    if on_path:
        return on_path
    for directory in _SKILLCTL_INSTALL_DIRS:
        candidate = directory / "skillctl"
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        except OSError:
            continue
    return ""


SKILLCTL = os.environ.get("SKILLCTL_BIN") or _discover_skillctl()
GRAPH_DB = os.environ.get(
    "SKILL_GRAPH_DB",
    str(Path.home() / ".m3c-tools" / "skill-graph.db"),
)
USAGE_DB = os.environ.get(
    "SKILL_USAGE_DB",
    str(Path.home() / ".m3c-tools" / "skill-usage.db"),
)
def _read_legacy_api_key() -> str:
    """Read only the legacy API-key field, after independent origin validation."""
    def unique_object(pairs):
        fields = {}
        for name, value in pairs:
            if name in fields:
                raise ValueError("ambiguous legacy session JSON")
            fields[name] = value
        return fields

    session_path = Path.home() / ".m3c-tools" / "er1_session.json"
    with open(session_path) as stream:
        return json.load(stream, object_pairs_hook=unique_object).get("api_key", "")


_api_connection = resolve_api_connection(os.environ.get, _read_legacy_api_key)
API_URL = _api_connection.base_url
API_KEY = _api_connection.key
API_KEY_ORIGIN = _api_connection.origin
API_CONFIG_ERROR = _api_connection.error
ALLOW_LOOPBACK_HTTP = _api_connection.allow_loopback_http

# ── Server ─────────────────────────────────────────────────────────────

mcp = FastMCP(
    "skill-server",
    instructions="Skill lifecycle tools: browse, query, import, track, discover skills across all projects.",
)


# ── Tool: skill_scan ──────────────────────────────────────────────────

@mcp.tool()
async def skill_scan(
    source: str = "claude",
    path: list[str] | None = None,
    with_trust: bool = False,
    include_shadowed: bool = False,
    # Legacy SPEC-0115 args (preserved for backwards compat).
    recursive: bool = False,
    include_home: bool = False,
) -> str:
    """Scan Claude Code skill surfaces (user, project, plugin) per SPEC-0189.

    Args:
        source: One of "claude" (default, user + plugin tiers, matches what
            Claude Code resolves at runtime), "user" (user tier only),
            "projects" (legacy SPEC-0115 mode, requires path), "plugins"
            (plugin tier only), or "all" (union).
        path: Additional roots to scan as project tier (repeatable).
        with_trust: If True, cross-reference each skill against SPEC-0188
            install state via the sibling .skb. Adds Bundle{TrustChain}
            block per skill.
        include_shadowed: If True, emit ALL occurrences across tiers
            (default emits winners only: project > user > plugin).

    Returns a summary by type/project + tier breakdown. JSON output is
    available via the `skillctl scan --format json` CLI directly.
    """
    skillctl, bin_err = _resolve_skillctl_bin()
    if bin_err:
        return f"Scan failed: {bin_err}"
    args = [skillctl, "scan", "--source", source, "--format", "json"]
    if with_trust:
        args.append("--with-trust")
    if include_shadowed:
        args.append("--include-shadowed")
    for p in path or []:
        args += ["--path", p]
    # Legacy flags only emitted if explicitly set + source=projects.
    if source == "projects":
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

    # SPEC-0189 tier breakdown.
    by_tier: dict[str, int] = {}
    trust_breakdown: dict[str, int] = {}
    for sk in inv.get("skills", []):
        tier = sk.get("tier") or "untiered"
        by_tier[tier] = by_tier.get(tier, 0) + 1
        if with_trust and sk.get("bundle"):
            tc = sk["bundle"].get("trust_chain", "unknown")
            trust_breakdown[tc] = trust_breakdown.get(tc, 0) + 1

    lines = [f"Scanned {total} skills across {len(by_project)} projects (source={source})\n"]
    if by_tier:
        lines.append("By tier:")
        for t, c in sorted(by_tier.items(), key=lambda x: -x[1]):
            lines.append(f"  {t}: {c}")
        lines.append("")
    lines.append("By type:")
    for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
        lines.append(f"  {t}: {c}")
    if with_trust and trust_breakdown:
        lines.append("\nTrust chain (SPEC-0188 cross-ref):")
        for tc, c in sorted(trust_breakdown.items(), key=lambda x: -x[1]):
            lines.append(f"  {tc}: {c}")
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
        lines.append(f"  {label} [{stype}]: {proj} (degree:{degree})")
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
        lines.append(f"  {label} [{stype}]: {proj}")
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
    skillctl, bin_err = _resolve_skillctl_bin()
    if bin_err:
        return f"Consolidation failed: {bin_err}"
    args = [skillctl, "consolidate", "--report-only", "--output", "text"]
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
        "Skill Graph Statistics",
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
        f"Skill Profile: {data.get('display_name', 'You')}",
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
            lines.append(f"  [{s.get('status', '?'):9}] {s.get('name', '?')} ({s.get('category', '-')}): {s.get('use_count', 0)} uses")

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
        skillctl, bin_err = _resolve_skillctl_bin()
        if bin_err:
            return f"Scan failed: {bin_err}"
        args = [skillctl, "scan", "--path", str(Path.home()), "--recursive",
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
        return f"Recorded locally. {data} Sync later with `skillctl sync-usage`."

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
        lines.append(f"  {s.get('name', '?')} [{s.get('category', '-')}], score: {score:.1f}")
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
        tried = args[0] if args else "<empty argv>"
        return {"error": f"skillctl not found at {tried}", "stdout": "", "stderr": ""}


def _open_graph_db() -> sqlite3.Connection | None:
    """Open the skill graph SQLite database."""
    if not os.path.exists(GRAPH_DB):
        return None
    try:
        return sqlite3.connect(GRAPH_DB)
    except Exception:
        return None


def _api_origin(url: str) -> tuple[str, str, int]:
    """Validate request transport without rejecting legitimate query parameters."""
    return parse_api_base(url, ALLOW_LOOPBACK_HTTP, request=True)[1]


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects that could disclose credentials or request bodies."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            same_origin = _api_origin(req.full_url) == _api_origin(newurl)
        except ValueError as exc:
            raise urllib.error.URLError("Unsafe API redirect blocked") from exc
        if not same_origin:
            raise urllib.error.URLError("Cross-origin API redirect blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_api_request(req: urllib.request.Request, timeout: int, *, allow_anonymous: bool = False):
    """Apply the same transport and redirect policy to every API request."""
    origin = _api_origin(req.full_url)
    credential_headers = {"authorization", "proxy-authorization", "cookie", "x-api-key", "x-user-id", "x-context-id", "x-device-id"}
    carries_credentials = any(name.lower() in credential_headers for name, _ in req.header_items())
    anonymous_get = allow_anonymous and req.get_method() == "GET" and not carries_credentials and req.data is None
    if API_CONFIG_ERROR and not anonymous_get:
        raise ValueError(API_CONFIG_ERROR)
    if origin != API_KEY_ORIGIN and (carries_credentials or req.data is not None):
        raise ValueError("Unbound API request blocked")
    return urllib.request.build_opener(_SameOriginRedirectHandler()).open(req, timeout=timeout)


def _api_credentials(url: str, user_id: str, *, require_bound: bool = False) -> dict[str, str]:
    """Use the independent bootstrap pin, never the mutable configured target."""
    origin = _api_origin(url)
    if API_CONFIG_ERROR:
        if require_bound:
            raise ValueError(API_CONFIG_ERROR)
        return {}
    if require_bound and origin != API_KEY_ORIGIN:
        raise ValueError("Unbound API target blocked")
    if API_KEY and origin == API_KEY_ORIGIN:
        return {"X-API-KEY": API_KEY, "X-User-ID": user_id}
    return {}


_UNSAFE_API_RESPONSE = "API response blocked: loaded credential reflected in decoded JSON."


class _UnsafeAPIResponse(ValueError):
    """A decoded response contains the currently loaded API key in cleartext."""


def _checked_api_response(payload):
    """Reject the whole response on a known-key substring; do not mutate JSON.

    This checks decoded string values and object keys only, not arbitrary
    credentials or additional encodings. With no loaded key, nothing matches.
    """
    if not API_KEY:
        return payload
    pending = [payload]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            if API_KEY in value:
                raise _UnsafeAPIResponse(_UNSAFE_API_RESPONSE)
        elif isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return payload


async def _api_get(path: str) -> dict | str:
    """GET from aims-core API. Returns parsed JSON or error string."""
    if API_CONFIG_ERROR:
        return API_CONFIG_ERROR
    if not API_KEY:
        return "API key unavailable; explicitly configure an API key and its independent origin pin."
    try:
        url = f"{API_URL.rstrip('/')}{path}"
        req = urllib.request.Request(url, headers=_api_credentials(url, os.environ.get("USER", "unknown"), require_bound=True))
        with _open_api_request(req, timeout=10) as resp:
            return _checked_api_response(json.loads(resp.read()))
    except _UnsafeAPIResponse:
        return _UNSAFE_API_RESPONSE
    except urllib.error.HTTPError as e:
        return f"API error: HTTP {e.code}"
    except Exception:
        return "API request failed; check the configured origin and connectivity."


async def _api_post(path: str, body: dict) -> dict | str:
    """POST to aims-core API. Returns parsed JSON or error string."""
    if API_CONFIG_ERROR:
        return API_CONFIG_ERROR
    if not API_KEY:
        return "API key unavailable; explicitly configure an API key and its independent origin pin."
    try:
        url = f"{API_URL.rstrip('/')}{path}"
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers=_api_credentials(url, os.environ.get("USER", "unknown"), require_bound=True),
        )
        req.add_header("Content-Type", "application/json")
        with _open_api_request(req, timeout=15) as resp:
            return _checked_api_response(json.loads(resp.read()))
    except _UnsafeAPIResponse:
        return _UNSAFE_API_RESPONSE
    except urllib.error.HTTPError as e:
        return f"API error: HTTP {e.code}"
    except Exception:
        return "API request failed; check the configured origin and connectivity."


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


# === SPEC-0188 S11-mcp: skill_install / skill_verify / skill_attest ===
#
# Three MCP tools that expose the SPEC-0188 trust-chain CLI surface
# (skillctl install / verify / attest) over the Model Context Protocol so
# Claude Code can drive end-to-end verified skill installs.
#
# Design notes:
#   - All three exec the skillctl Go binary via subprocess (no shell=True;
#     args are passed as a list so user-supplied strings can never spawn
#     extra commands). The binary is resolved via the SKILLCTL_BIN env var,
#     falling back to a PATH lookup, falling back to the standard install
#     dirs probed at import time. Each helper emits a structured error dict
#     if the binary cannot be located.
#   - Inputs are validated BEFORE exec'ing (defense in depth): digests
#     must match sha256:[0-9a-f]{64}; governance levels must be one of
#     {green, yellow, red}; names/reviewer IDs must be free of newlines
#     and null bytes.
#   - Exit codes are mapped to error_class strings per SPEC-0188 §11.
#   - Install, verify, inventory sweeps and attest decode versioned JSON
#     from the actual CLI. Missing or contradictory proof fields cannot be
#     filled from human output or caller inputs.

# Exit code → error_class mapping (SPEC-0188 §11). Any code not in this
# table maps to "generic_error" so callers always get a machine-checkable
# class string.
_EXIT_CODE_TO_CLASS = {
    0: None,
    1: "generic_error",
    2: "usage_error",
    10: "digest_mismatch",
    11: "author_sig_invalid",
    12: "registry_not_trusted",
    13: "governance_below_min",
    14: "deps_unsatisfied",
    15: "blob_missing",
    16: "tenant_blocked",
    17: "source_policy_denied",
    18: "intent_inconsistent",
    19: "identity_mismatch",
    20: "self_attested",
    22: "revocation_stale",
    23: "log_inclusion_missing",
}

# Human-readable remediation strings, indexed by error_class.
_REMEDIATION = {
    "digest_mismatch": "Bundle blob differs from advertised digest. Re-fetch or contact the registry operator.",
    "author_sig_invalid": "Author signature does not verify against the bound identity public key. The bundle has been tampered with or the identity record is wrong.",
    "registry_not_trusted": "Registry signing key is not pinned in ~/.claude/skill-trust-roots.yaml. Run `skillctl trust add --registry <url> --pubkey <path>` to pin it, or refuse the install.",
    "governance_below_min": "Bundle governance level is below the trust-root minimum. Review the bundle's attestations or pass --allow-yellow if your policy allows it.",
    "deps_unsatisfied": "One or more depends_on entries cannot be satisfied. Install the missing skill/package, or pass --ignore-deps to override (audited).",
    "blob_missing": "Registry has metadata for the digest but the blob storage is unreachable. Try again or contact the registry operator.",
    "tenant_blocked": "The tenant policy blocked this bundle. Contact the tenant policy owner.",
    "source_policy_denied": "Source policy, identity revocation or bundle revocation denied this bundle. Inspect the verifier diagnostic.",
    "intent_inconsistent": "The declared intent contradicts the bundle data dependencies. Review the signed manifest.",
    "identity_mismatch": "The identity binding does not match the required identity. Inspect the verifier diagnostic.",
    "self_attested": "The configured verifier policy requires an eligible reviewer. Supply a qualifying signed attestation.",
    "revocation_stale": "The revocation snapshot is stale. Refresh the trusted revocation evidence.",
    "log_inclusion_missing": "The required log inclusion evidence is missing or invalid. Obtain a trusted inclusion receipt.",
    "usage_error": "skillctl rejected the invocation. Check the stderr message for the specific flag/argument issue.",
    "generic_error": "skillctl exited with a non-zero status that does not map to a SPEC-0188 §11 sentinel. See stderr.",
}

# Regexes for input validation (cheap, non-allocating, called per-invocation).
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_VALID_LEVELS = frozenset({"green", "yellow", "red"})


def _resolve_skillctl_bin() -> tuple[str | None, str | None]:
    """Locate the skillctl binary.

    Resolution order: SKILLCTL_BIN env var, then a $PATH lookup, then the
    SKILLCTL value discovered at import time (see _discover_skillctl).

    Returns (path, error). On success, path is set and error is None. On
    failure, path is None and error is a human-readable message with a
    remediation hint that the MCP caller can surface to the user.
    """
    env_path = os.environ.get("SKILLCTL_BIN")
    if env_path:
        if os.path.isfile(env_path) and os.access(env_path, os.X_OK):
            return env_path, None
        return None, (
            f"SKILLCTL_BIN={env_path!r} is set but not an executable file. "
            "Point it at a built skillctl binary (e.g. `go build -o /usr/local/bin/skillctl ./cmd/skillctl`)."
        )
    # PATH lookup.
    on_path = shutil.which("skillctl")
    if on_path:
        return on_path, None
    # Whatever _discover_skillctl found at import time. Re-checked here
    # because tests patch it and because a binary can vanish between calls.
    if os.path.isfile(SKILLCTL) and os.access(SKILLCTL, os.X_OK):
        return SKILLCTL, None
    searched = ", ".join(str(d / "skillctl") for d in _SKILLCTL_INSTALL_DIRS)
    return None, (
        "skillctl not found. Install it, put it on $PATH, or set SKILLCTL_BIN "
        "to its absolute path. Searched: $SKILLCTL_BIN, $PATH, " + searched + "."
    )


def _validate_safe_token(value: str, label: str) -> str | None:
    """Return an error message if value contains newline or NUL; else None.

    Defense-in-depth: subprocess argv-list already prevents shell
    injection, but newlines/NULs in CLI args can confuse log parsers and
    audit trails downstream. We refuse them at the MCP boundary.
    """
    if value is None:
        return f"{label} must not be empty"
    if not isinstance(value, str):
        return f"{label} must be a string"
    if not value:
        return f"{label} must not be empty"
    if "\n" in value or "\r" in value or "\x00" in value:
        return f"{label} must not contain newlines or null bytes"
    return None


def _run_skillctl_blocking(argv: list[str], timeout: int = 120) -> dict:
    """Synchronous subprocess.run wrapper that returns a normalized dict.

    Returns:
        {
          "exit_code": int,
          "stdout": str,
          "stderr": str,
          "error": str | None,   # set if exec itself failed (timeout, missing binary)
        }

    We use subprocess.run (not asyncio) here because the existing async
    helpers in this file are oriented around streaming long-running graph
    builds; install/verify/attest are short, blocking calls and the test
    surface mocks subprocess.run directly.
    """
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "exit_code": -1,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "error": f"skillctl timed out after {timeout}s",
        }
    except FileNotFoundError as exc:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "error": f"skillctl binary not found: {exc}",
        }
    except (OSError, UnicodeError) as exc:
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "error": f"skillctl exec failed: {exc}",
        }
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
        "error": None,
    }


def _classify_failure(exit_code: int, stderr: str) -> dict:
    """Build the failure-shaped response dict for a non-zero exit."""
    error_class = _EXIT_CODE_TO_CLASS.get(exit_code, "generic_error")
    if error_class is None:
        # Defensive: caller passed a 0 exit by mistake.
        error_class = "generic_error"
    remediation = _REMEDIATION.get(error_class, _REMEDIATION["generic_error"])
    # Stream non-zero stderr to the server log at WARN so operators can
    # correlate MCP-tool failures with the underlying CLI error.
    if stderr.strip():
        logger.warning("skillctl failure (exit=%d, class=%s): %s", exit_code, error_class, stderr.strip())
    return {
        "ok": False,
        "exit_code": exit_code,
        "error_class": error_class,
        "stderr": stderr.strip(),
        "remediation": remediation,
    }


def _do_install_or_verify(argv_tail: list[str], timeout: int) -> dict:
    """Shared exec + parse path for install and verify (same response shape
    minus install_path)."""
    skillctl, err = _resolve_skillctl_bin()
    if err:
        return {
            "ok": False,
            "exit_code": -1,
            "error_class": "skillctl_not_found",
            "stderr": err,
            "remediation": "Install / build skillctl, or set SKILLCTL_BIN to its absolute path.",
        }

    argv = [skillctl] + argv_tail
    result = _run_skillctl_blocking(argv, timeout=timeout)

    if result["error"]:
        # Exec itself failed (timeout, missing binary). Surface as
        # generic_error with the OS-level message.
        logger.warning("skillctl exec error: %s", result["error"])
        return {
            "ok": False,
            "exit_code": result["exit_code"],
            "error_class": "exec_error",
            "stderr": result["error"],
            "remediation": "Check the server log; the skillctl process did not run to completion.",
        }

    return _decode_trust_result(result, argv_tail[0])


def _decode_trust_result(result: dict, operation: str) -> dict:
    """Accept one typed CLI result; a process success alone proves no trust fields."""
    code = result["exit_code"]

    def protocol_error(reason: str) -> dict:
        return {
            "ok": False,
            "exit_code": code if code != 0 else 1,
            "process_exit_code": code,
            "error_class": "protocol_error",
            "stderr": reason,
            "remediation": "Use a compatible skillctl with the versioned JSON trust contract.",
        }

    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate JSON field")
            obj[key] = value
        return obj

    def reject_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")

    try:
        payload = json.loads(result["stdout"], object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, TypeError):
        # Preserve a failing process's numeric diagnosis, including older CLIs.
        if code != 0 and not result["stdout"].strip():
            return _classify_failure(code, result["stderr"])
        return protocol_error("skillctl did not emit one valid JSON object")
    if not isinstance(payload, dict):
        return protocol_error("skillctl result must be a JSON object")
    if payload.get("schema") != "m3c.skillctl.trust-result/v1" or payload.get("operation") != operation:
        return protocol_error("skillctl result has an unsupported schema or mismatched operation")
    if type(payload.get("ok")) is not bool or type(payload.get("exit_code")) is not int:
        return protocol_error("skillctl result has invalid status types")
    if payload["exit_code"] != code or payload["ok"] != (code == 0):
        return protocol_error("skillctl JSON status contradicts the process exit code")
    if code != 0:
        if not isinstance(payload.get("error"), str) or not payload["error"].strip():
            return protocol_error("skillctl failure result lacks an error")
        return _classify_failure(code, payload["error"])
    if "error" in payload:
        return protocol_error("skillctl success result carries a contradictory error")
    if not isinstance(payload.get("digest"), str) or not _DIGEST_RE.fullmatch(payload["digest"]):
        return protocol_error("skillctl success result lacks a canonical digest")
    for field in ("author_identity", "registry_key_id", "chain_summary"):
        if not isinstance(payload.get(field), str) or not payload[field].strip():
            return protocol_error(f"skillctl success result lacks {field}")
    if not isinstance(payload.get("governance_level"), str) or payload["governance_level"] not in _VALID_LEVELS:
        return protocol_error("skillctl success result has an invalid governance level")
    if type(payload.get("governance_verified")) is not bool:
        return protocol_error("skillctl result lacks a boolean governance_verified")
    if "self_attested" not in payload or (payload["self_attested"] is not None and type(payload["self_attested"]) is not bool):
        return protocol_error("skillctl result lacks a nullable boolean self_attested")
    if operation == "install" and (not isinstance(payload.get("install_path"), str) or not payload["install_path"].strip()):
        return protocol_error("skillctl install result lacks install_path")
    return payload


@mcp.tool()
async def skill_install(
    name: str,
    version: str = "",
    registry: str = "",
    governance_min: str = "",
    allow_yellow: bool = False,
    ignore_deps: bool = False,
    timeout: int = 120,
) -> dict:
    """Install a signed skill bundle from the registry, running the SPEC-0188
    §7 verifier (digest, author signature, registry signature, governance
    gate, depends_on resolution) before atomic install.

    Args:
        name: Bundle name (e.g. "fetch-contract"). Required.
        version: Optional version string ("1.0.0") or digest pin
            ("sha256:..."). Empty = newest admitted.
        registry: Optional registry URL override; required only when the
            trust-roots file pins multiple registries.
        governance_min: Optional override for the trust-root's
            governance_minimum ("green" | "yellow").
        allow_yellow: Lower the gate from green to yellow for this install
            (audited).
        ignore_deps: Skip depends_on resolution (audited).
        timeout: Per-call timeout in seconds (default 120).

    Returns a JSON-serializable dict. On success: ok=True with digest,
    author_identity, registry_key_id, governance_level, chain_summary,
    install_path. On failure: ok=False with exit_code, error_class
    (per SPEC-0188 §11), stderr, remediation.
    """
    # ----- input validation (before any exec) -----
    err = _validate_safe_token(name, "name")
    if err:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": err, "remediation": "Pass a non-empty name without newlines or null bytes."}
    if version:
        err = _validate_safe_token(version, "version")
        if err:
            return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": err, "remediation": "Pass a clean version string."}
    if governance_min and governance_min not in _VALID_LEVELS:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": f"governance_min must be one of {sorted(_VALID_LEVELS)}", "remediation": "Use 'green', 'yellow', or 'red'."}

    # ----- assemble argv -----
    spec_arg = f"{name}@{version}" if version else name
    argv: list[str] = ["install", "--json"]
    if registry:
        argv += ["--registry", registry]
    if governance_min:
        argv += ["--governance-min", governance_min]
    if allow_yellow:
        argv.append("--allow-yellow")
    if ignore_deps:
        argv.append("--ignore-deps")

    argv.extend(["--", spec_arg])
    return _do_install_or_verify(argv, timeout=timeout)


@mcp.tool()
async def skill_verify(
    name: str,
    registry: str = "",
    governance_min: str = "",
    allow_yellow: bool = False,
    timeout: int = 120,
) -> dict:
    """Re-run the SPEC-0188 §7 trust-chain check against an already-installed
    skill. No filesystem mutation: useful for catching post-install
    registry revocations or trust-root rotations.

    Same response shape as skill_install minus install_path.
    """
    err = _validate_safe_token(name, "name")
    if err:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": err, "remediation": "Pass a non-empty name without newlines or null bytes."}
    if "@" in name:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": "name must not contain @<version> for verify (verify checks whatever is installed)", "remediation": "Pass just the bundle name, no @version pin."}
    if governance_min and governance_min not in _VALID_LEVELS:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": f"governance_min must be one of {sorted(_VALID_LEVELS)}", "remediation": "Use 'green', 'yellow', or 'red'."}

    argv: list[str] = ["verify", "--json"]
    if registry:
        argv += ["--registry", registry]
    if governance_min:
        argv += ["--governance-min", governance_min]
    if allow_yellow:
        argv.append("--allow-yellow")

    argv.extend(["--", name])
    return _do_install_or_verify(argv, timeout=timeout)


def _decode_sweep_result(result: dict) -> dict:
    """Retain every typed sweep decision, including failed or incomplete entries."""
    code = result["exit_code"]

    def protocol_error(reason: str) -> dict:
        return {"ok": False, "exit_code": code if code != 0 else 1,
                "process_exit_code": code, "error_class": "protocol_error", "stderr": reason,
                "remediation": "Use a compatible skillctl with the versioned sweep JSON contract."}

    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate JSON field")
            obj[key] = value
        return obj

    def reject_constant(value):
        raise ValueError("non-finite JSON constant")

    try:
        payload = json.loads(result["stdout"], object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, TypeError):
        return protocol_error("skillctl did not emit one valid sweep JSON object")
    required = {"schema", "operation", "ok", "complete", "exit_code", "skills_dir", "total", "verified",
                "invalid", "quarantined", "quarantine_candidates", "unverified", "skipped", "entries"}
    optional = {"error", "roots_error", "revocation_unavailable"}
    if not isinstance(payload, dict) or not required <= payload.keys() or payload.keys() - required - optional:
        return protocol_error("skillctl sweep has missing or unsupported fields")
    if payload["schema"] != "m3c.skillctl.sweep-result/v1" or payload["operation"] != "verify_all":
        return protocol_error("skillctl sweep has an unsupported schema or operation")
    if type(payload["ok"]) is not bool or type(payload["complete"]) is not bool or type(payload["exit_code"]) is not int:
        return protocol_error("skillctl sweep has invalid status types")
    if type(code) is not int or code not in (0, 1, 2) or payload["exit_code"] != code or payload["ok"] != (code == 0):
        return protocol_error("skillctl sweep status contradicts the process exit code")
    if not isinstance(payload["skills_dir"], str) or (code == 0 and not payload["skills_dir"]):
        return protocol_error("skillctl sweep has no skills directory")
    if any(type(payload[field]) is not int or payload[field] < 0 for field in
           ("total", "verified", "invalid", "quarantined", "quarantine_candidates", "unverified", "skipped")):
        return protocol_error("skillctl sweep has invalid counters")
    for field in optional:
        if field in payload and (not isinstance(payload[field], str) or not payload[field].strip()):
            return protocol_error("skillctl sweep has an invalid diagnostic")
    if (code == 0 and "error" in payload) or (code != 0 and "error" not in payload):
        return protocol_error("skillctl sweep has a contradictory error")
    entries = payload["entries"]
    if not isinstance(entries, list) or len(entries) != payload["total"]:
        return protocol_error("skillctl sweep entries do not match the total")
    entry_required = {"skill", "state", "status", "disposition", "complete", "exit", "reason", "check_scope",
                      "revocation_source", "checks", "governance_verified", "self_attested", "digest_verified"}
    entry_optional = {"digest", "digest_source", "quarantine_path", "action_error"}
    scopes = {"online_trust_chain", "offline_trust_chain", "sidecar_reanchored", "sidecar_legacy",
              "revocation_policy", "unmanaged_policy", "not_checked"}
    counts = {"valid": 0, "invalid": 0, "incomplete": 0, "skipped": 0}
    names = set()
    quarantined = candidates = 0
    for entry in entries:
        if not isinstance(entry, dict) or not entry_required <= entry.keys() or entry.keys() - entry_required - entry_optional:
            return protocol_error("skillctl sweep entry has missing or unsupported fields")
        if _validate_safe_token(entry["skill"], "skill") or entry["skill"] in names:
            return protocol_error("skillctl sweep has an invalid or duplicate skill")
        names.add(entry["skill"])
        if entry["state"] not in ("verified", "quarantined", "unverified", "skipped") or not isinstance(entry["status"], str) or entry["status"] not in counts:
            return protocol_error("skillctl sweep entry has an invalid status")
        if entry["disposition"] not in ("unchanged", "would_quarantine", "quarantined", "quarantine_failed"):
            return protocol_error("skillctl sweep entry has an invalid disposition")
        if type(entry["exit"]) is not int or not 0 <= entry["exit"] <= 255 or not isinstance(entry["reason"], str):
            return protocol_error("skillctl sweep entry has invalid exit or reason")
        if any(type(entry[field]) is not bool for field in ("complete", "digest_verified", "governance_verified")):
            return protocol_error("skillctl sweep entry has invalid proof types")
        if entry["self_attested"] is not None and type(entry["self_attested"]) is not bool:
            return protocol_error("skillctl sweep entry has invalid self-attestation provenance")
        if not isinstance(entry["check_scope"], str) or entry["check_scope"] not in scopes or entry["revocation_source"] not in ("online", "cached", "gossip", "unconfirmed", "unavailable"):
            return protocol_error("skillctl sweep entry has invalid verification scope")
        if not isinstance(entry["checks"], list):
            return protocol_error("skillctl sweep entry lacks checks")
        checks = {}
        for check in entry["checks"]:
            if not isinstance(check, dict) or set(check) != {"name", "status"}:
                return protocol_error("skillctl sweep check has invalid fields")
            name = check["name"]
            if not isinstance(name, str) or name in checks or check["status"] not in ("pass", "fail", "unconfirmed", "not_checked"):
                return protocol_error("skillctl sweep check has an invalid or duplicate decision")
            checks[name] = check["status"]
        if set(checks) != {"content_binding", "trust_chain", "governance", "dependencies", "revocation"}:
            return protocol_error("skillctl sweep entry has missing or unsupported checks")
        if checks["revocation"] == "pass" and entry["revocation_source"] not in ("online", "cached"):
            return protocol_error("skillctl sweep asserts unconfirmed revocation freshness")
        if "digest" in entry:
            if not isinstance(entry["digest"], str) or not _DIGEST_RE.fullmatch(entry["digest"]) or entry.get("digest_source") != "actual_bundle":
                return protocol_error("skillctl sweep entry has an invalid digest or provenance")
        elif "digest_source" in entry or entry["digest_verified"]:
            return protocol_error("skillctl sweep entry lacks its asserted bundle digest")
        authenticated_scopes = ("online_trust_chain", "offline_trust_chain", "sidecar_reanchored")
        if entry["digest_verified"] and (entry["check_scope"] not in authenticated_scopes or checks["content_binding"] != "pass" or
                                         checks["trust_chain"] != "pass" or entry["status"] in ("invalid", "skipped")):
            return protocol_error("skillctl sweep digest assertion contradicts its checks")
        if entry["governance_verified"] and (entry["check_scope"] not in authenticated_scopes or checks["governance"] != "pass"):
            return protocol_error("skillctl sweep governance assertion contradicts its scope or checks")
        if checks["trust_chain"] == "pass" and not entry["digest_verified"]:
            return protocol_error("skillctl sweep trust-chain success lacks its authenticated digest")
        if checks["dependencies"] == "pass" and not entry["digest_verified"]:
            return protocol_error("skillctl sweep dependency declaration lacks its authenticated digest")
        if entry["check_scope"] in ("not_checked", "unmanaged_policy", "revocation_policy") and any(value == "pass" for value in checks.values()):
            return protocol_error("skillctl sweep policy-only entry asserts unperformed verification")
        if entry["check_scope"] == "sidecar_legacy" and any(checks[name] == "pass" for name in ("trust_chain", "governance", "dependencies")):
            return protocol_error("skillctl sweep legacy sidecar asserts authenticated checks")
        moved = entry["disposition"] == "quarantined"
        if moved != ("quarantine_path" in entry):
            return protocol_error("skillctl sweep quarantine action lacks its actual path")
        if moved and (not isinstance(entry["quarantine_path"], str) or not entry["quarantine_path"].strip()):
            return protocol_error("skillctl sweep quarantine path is invalid")
        if "action_error" in entry and (not isinstance(entry["action_error"], str) or not entry["action_error"].strip() or entry["complete"]):
            return protocol_error("skillctl sweep action error contradicts completion")
        if entry["disposition"] == "quarantine_failed" and "action_error" not in entry:
            return protocol_error("skillctl sweep failed quarantine lacks its action error")
        if entry["status"] == "invalid" and (entry["exit"] == 0 or entry["state"] != "quarantined" or entry["disposition"] == "unchanged"):
            return protocol_error("skillctl sweep invalid decision contradicts its state or refusal")
        if entry["status"] != "valid" and not entry["reason"].strip():
            return protocol_error("skillctl sweep failed or skipped entry lacks its reason")
        if entry["status"] == "skipped" and (entry["state"] != "skipped" or entry["exit"] != 0 or entry["disposition"] != "unchanged" or
                                             entry["digest_verified"] or entry["governance_verified"]):
            return protocol_error("skillctl sweep skipped decision asserts verification or an action")
        if entry["status"] == "incomplete" and (entry["state"] not in ("verified", "unverified") or entry["disposition"] != "unchanged"):
            return protocol_error("skillctl sweep incomplete decision contradicts its state or action")
        if entry["status"] == "valid" and (not entry["complete"] or entry["exit"] != 0 or entry["state"] != "verified" or
                                           not entry["digest_verified"] or any(value != "pass" for value in checks.values()) or
                                           entry["disposition"] != "unchanged"):
            return protocol_error("skillctl sweep asserts validity without complete verification")
        if entry["status"] in ("incomplete", "skipped") and entry["complete"]:
            return protocol_error("skillctl sweep asserts completion for an unverified skill")
        counts[entry["status"]] += 1
        quarantined += moved
        candidates += entry["disposition"] != "unchanged"
    if any(payload[field] != counts[status] for field, status in
           (("verified", "valid"), ("invalid", "invalid"), ("unverified", "incomplete"), ("skipped", "skipped"))):
        return protocol_error("skillctl sweep counters contradict individual decisions")
    if payload["quarantined"] != quarantined or payload["quarantine_candidates"] != candidates:
        return protocol_error("skillctl sweep counters contradict actual quarantine actions")
    if payload["complete"] and any(not entry["complete"] for entry in entries):
        return protocol_error("skillctl sweep completion contradicts an incomplete entry")
    if payload["ok"] and (not payload["complete"] or any(entry["status"] != "valid" for entry in entries)):
        return protocol_error("skillctl sweep success contradicts individual decisions")
    return payload


@mcp.tool()
async def skill_verify_all(
    quarantine: bool = False,
    registry: str = "",
    governance_min: str = "",
    budget_seconds: int = 60,
    timeout: int = 90,
) -> dict:
    """Verify the installed inventory and preserve every result, including failures.

    The sweep updates verdict/audit caches. Skills move only when quarantine=True.
    Incomplete, skipped and unconfirmed checks cannot become overall success.
    Budget is 1..300 seconds; timeout must exceed budget and be at most 600 seconds.
    """
    def invalid(reason):
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": reason,
                "remediation": "Use a positive bounded budget, a larger timeout and valid registry/governance values."}

    if type(quarantine) is not bool or type(budget_seconds) is not int or not 1 <= budget_seconds <= 300:
        return invalid("quarantine must be boolean and budget_seconds an integer in 1..300")
    if type(timeout) is not int or not budget_seconds < timeout <= 600:
        return invalid("timeout must exceed budget_seconds and be at most 600 seconds")
    if not isinstance(registry, str) or (registry and _validate_safe_token(registry, "registry")):
        return invalid("registry must be a string without newlines or null bytes")
    if not isinstance(governance_min, str) or governance_min not in ("", "green", "yellow"):
        return invalid("governance_min must be empty, green or yellow")
    binary, err = _resolve_skillctl_bin()
    if err:
        return {"ok": False, "exit_code": -1, "error_class": "skillctl_not_found", "stderr": err,
                "remediation": "Install skillctl or set SKILLCTL_BIN to its absolute path."}
    argv = [binary, "verify", "--json", "--all", "--budget", f"{budget_seconds}s"]
    if quarantine:
        argv.append("--quarantine")
    if registry:
        argv.extend(["--registry", registry])
    if governance_min:
        argv.extend(["--governance-min", governance_min])
    result = _run_skillctl_blocking(argv, timeout=timeout)
    if result["error"]:
        return {"ok": False, "exit_code": result["exit_code"], "error_class": "exec_error", "stderr": result["error"],
                "remediation": "The sweep did not finish; inspect the registry and installed inventory before retrying quarantine."}
    return _decode_sweep_result(result)


def _decode_attest_receipt(result: dict, digest: str, level: str, reviewer_id: str) -> dict:
    """Validate a registry POST receipt, without inferring independent review."""
    code = result["exit_code"]

    def refused(reason):
        return {"ok": False, "exit_code": code if code != 0 else 1,
                "process_exit_code": code, "error_class": "protocol_error", "stderr": reason,
                "remediation": "Use a compatible skillctl with the versioned attestation receipt contract."}

    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate JSON field")
            obj[key] = value
        return obj

    def reject_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")

    try:
        payload = json.loads(result["stdout"], object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, TypeError):
        return refused("skillctl did not emit one valid JSON receipt")
    if not isinstance(payload, dict):
        return refused("attestation receipt must be an object")
    fields = {"schema", "operation", "ok", "exit_code", "attestation_id", "bundle_digest",
              "governance_level", "reviewer_id", "attested_at", "error"}
    if set(payload) - fields:
        return refused("attestation receipt contains unsupported fields")
    if payload.get("schema") != "m3c.skillctl.attestation-receipt/v1" or payload.get("operation") != "attest":
        return refused("unsupported attestation receipt schema or operation")
    if type(payload.get("ok")) is not bool or type(payload.get("exit_code")) is not int:
        return refused("invalid attestation receipt status types")
    if payload["exit_code"] != code or payload["ok"] != (code == 0):
        return refused("attestation receipt contradicts the process exit code")
    if code != 0:
        if not isinstance(payload.get("error"), str) or not payload["error"].strip():
            return refused("attestation failure lacks an error")
        return _classify_failure(code, payload["error"])
    if "error" in payload:
        return refused("attestation success carries an error")
    for field in ("attestation_id", "bundle_digest", "governance_level", "reviewer_id", "attested_at"):
        value = payload.get(field)
        if _validate_safe_token(value, field) or not value.strip():
            return refused(f"attestation receipt lacks a valid {field}")
    if not _DIGEST_RE.fullmatch(payload["bundle_digest"]):
        return refused("attestation receipt digest is not canonical")
    if (payload["bundle_digest"], payload["governance_level"], payload["reviewer_id"]) != (digest, level, reviewer_id):
        return refused("attestation receipt does not match the submitted digest, level and reviewer")
    timestamp = payload["attested_at"]
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", timestamp):
        return refused("attestation receipt time is not canonical UTC")
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return refused("attestation receipt time is invalid")
    return payload


@mcp.tool()
async def skill_attest(
    digest: str,
    level: str,
    rationale: str,
    reviewer_id: str,
    key: str,
    registry: str = "",
    timeout: int = 120,
) -> dict:
    """Sign and POST a governance attestation for a bundle digest.

    Args:
        digest: Bundle digest, must match sha256:[0-9a-f]{64}.
        level: Governance verdict, one of "green" | "yellow" | "red".
        rationale: Free-text rationale for the audit log.
        reviewer_id: Reviewer identity ID (e.g. "id:reviewer@m3c").
        key: Absolute path to the reviewer's PEM PKCS#8 ed25519 private
            key (mode 0600). Required.
        registry: Optional registry base URL; defaults to
            http://localhost:8080/api/skills.
        timeout: Per-call timeout in seconds (default 120).

    Returns ok=True with attestation_id, bundle_digest, governance_level,
    reviewer_id on success; ok=False with exit_code/error_class/stderr/
    remediation on failure.
    """
    # ----- input validation BEFORE exec -----
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest or ""):
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": "digest must match sha256:[0-9a-f]{64}", "remediation": "Pass a canonical 'sha256:<64-hex-chars>' digest string."}
    if level not in _VALID_LEVELS:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": f"level must be one of {sorted(_VALID_LEVELS)}", "remediation": "Use 'green', 'yellow', or 'red'."}
    err = _validate_safe_token(rationale, "rationale")
    if err:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": err, "remediation": "Pass a non-empty rationale without newlines or null bytes."}
    err = _validate_safe_token(reviewer_id, "reviewer_id")
    if err:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": err, "remediation": "Pass a non-empty reviewer_id without newlines or null bytes."}
    err = _validate_safe_token(key, "key")
    if err:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error", "stderr": err, "remediation": "Pass a non-empty private-key path."}

    skillctl, bin_err = _resolve_skillctl_bin()
    if bin_err:
        return {"ok": False, "exit_code": -1, "error_class": "skillctl_not_found", "stderr": bin_err, "remediation": "Install / build skillctl, or set SKILLCTL_BIN to its absolute path."}

    argv = [
        skillctl, "attest", "--json",
        "--level", level,
        "--rationale", rationale,
        "--reviewer-id", reviewer_id,
        "--key", key,
    ]
    if registry:
        argv += ["--registry", registry]

    argv.extend(["--", digest])

    result = _run_skillctl_blocking(argv, timeout=timeout)
    if result["error"]:
        logger.warning("skillctl attest exec error: %s", result["error"])
        return {"ok": False, "exit_code": result["exit_code"], "error_class": "exec_error", "stderr": result["error"], "remediation": "Check the server log; the skillctl process did not run to completion."}
    return _decode_attest_receipt(result, digest, level, reviewer_id)


# === end SPEC-0188 S11-mcp ===


# === SPEC-0122 v1.2 (S6.3 closure 2026-05-07): MCP coverage for every CLI ===
#
# Five new tools wrap the CLI surfaces shipped in S2/S3/S5:
#   skill_awareness_sync, SPEC-0195 awareness sync
#   skill_audit, SPEC-0189 §14 audit antivirus mode
#   skill_propose, SPEC-0194 propose + 10-check gate
#   skill_revoke, SPEC-0188 §4.5 bundle revocation
#   skill_data_source_query: SPEC-0196 §4.2 chip state lookup
#
# All five follow the existing pattern: validate args → exec skillctl
# (or REST GET) → classify by exit code → return structured dict.


@mcp.tool()
async def skill_awareness_sync(
    source: str = "claude",
    registry: str = "",
    default_attest: str = "none",
    default_intent: str = "",
    require_intent: bool = False,
    dry_run: bool = True,
    confirm: bool = False,
    inventory: str = "",
    timeout: int = 180,
) -> dict:
    """Run `skillctl awareness sync` per SPEC-0195. Default is dry-run; pass
    confirm=true to actually POST.

    Returns a structured outcome from the JSON-shape stderr lines the CLI
    emits (one envelope per skill in dry-run, one admit summary in confirm).
    """
    if source not in {"claude", "user", "plugins", "all"}:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": f"source must be claude|user|plugins|all; got {source!r}",
                "remediation": "Pass a known --source value."}
    if default_attest not in {"none", "green", "yellow"}:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": "default_attest must be none|green|yellow",
                "remediation": "Use 'green', 'yellow', or 'none'."}

    argv: list[str] = ["awareness", "sync", "--source", source]
    if registry:
        argv += ["--registry", registry]
    if default_attest != "none":
        argv += ["--default-attest", default_attest]
    if default_intent:
        argv += ["--default-intent", default_intent]
    if require_intent:
        argv.append("--require-intent")
    if dry_run:
        argv.append("--dry-run")
    if confirm:
        argv.append("--confirm")
    if inventory:
        argv += ["--inventory", inventory]

    skillctl, bin_err = _resolve_skillctl_bin()
    if bin_err:
        return {"ok": False, "exit_code": -1, "error_class": "skillctl_not_found",
                "stderr": bin_err,
                "remediation": "Install / build skillctl, or set SKILLCTL_BIN."}

    result = _run_skillctl_blocking([skillctl] + argv, timeout=timeout)
    if result["error"]:
        return {"ok": False, "exit_code": result["exit_code"],
                "error_class": "exec_error", "stderr": result["error"],
                "remediation": "Check server log; skillctl did not run to completion."}
    if result["exit_code"] != 0:
        return _classify_failure(result["exit_code"], result["stderr"])

    return {
        "ok": True,
        "exit_code": 0,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "mode": "dry-run" if dry_run else "confirm",
    }


@mcp.tool()
async def skill_audit(
    source: str = "claude",
    minimum_governance: str = "",
    cleanup: bool = False,
    dry_run_cleanup: bool = False,
    timeout: int = 120,
) -> dict:
    """Run `skillctl audit` per SPEC-0189 §14 (antivirus UX).

    Default mode: read-only audit; returns the verdict counts and
    exit code (0 = clean, 2 = unverified/below_min, 3 = broken).

    Cleanup mode requires either dry_run_cleanup=true (Step 1: produces
    a token; no deletion): confirming the deletion via MCP is NOT
    supported (the second step requires a live `--dry-run-cleanup-token`
    that only the operator's terminal session has).
    """
    if source not in {"claude", "user", "plugins", "all"}:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": "source must be claude|user|plugins|all",
                "remediation": "Use a known --source value."}
    if minimum_governance and minimum_governance not in _VALID_LEVELS:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": f"minimum_governance must be one of {sorted(_VALID_LEVELS)}",
                "remediation": "Use 'green', 'yellow', or 'red'."}

    argv: list[str] = ["audit", "--source", source, "--format", "json"]
    if minimum_governance:
        argv += ["--minimum-governance", minimum_governance]
    if cleanup:
        argv.append("--cleanup")
        if dry_run_cleanup:
            argv.append("--dry-run-cleanup")
        else:
            return {"ok": False, "exit_code": 2,
                    "error_class": "validation_error",
                    "stderr": "MCP wrapper supports cleanup only with dry_run_cleanup=true",
                    "remediation": "Run --confirm-delete --dry-run-cleanup-token interactively from a terminal."}

    skillctl, bin_err = _resolve_skillctl_bin()
    if bin_err:
        return {"ok": False, "exit_code": -1, "error_class": "skillctl_not_found",
                "stderr": bin_err,
                "remediation": "Install / build skillctl, or set SKILLCTL_BIN."}

    result = _run_skillctl_blocking([skillctl] + argv, timeout=timeout)
    if result["error"]:
        return {"ok": False, "exit_code": result["exit_code"],
                "error_class": "exec_error", "stderr": result["error"],
                "remediation": "Check the server log."}
    # exit codes 0/2/3 are all "ran successfully, here's the verdict"
    parsed: dict = {}
    try:
        parsed = json.loads(result["stdout"]) if result["stdout"] else {}
    except json.JSONDecodeError:
        pass
    return {
        "ok": result["exit_code"] in (0, 2, 3),
        "exit_code": result["exit_code"],
        "verdict": (
            "clean" if result["exit_code"] == 0
            else ("flagged" if result["exit_code"] == 2
                  else ("broken" if result["exit_code"] == 3 else "error"))
        ),
        "report": parsed,
        "stderr": result["stderr"][:2000],
    }


@mcp.tool()
async def skill_propose(
    skill_name: str,
    source: str = "",
    intent: str = "",
    rationale: str = "",
    skip_smoke: bool = False,
    dry_run: bool = True,
    registry: str = "",
    timeout: int = 60,
) -> dict:
    """Run `skillctl propose <skill_name>` per SPEC-0194 (10-check gate).

    Default dry_run=true so the trainer sees the gate report without a
    proposal record being created. Set dry_run=false to register a
    proposal in `_skill_proposals` (state=pending).
    """
    err = _validate_safe_token(skill_name, "skill_name")
    if err:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": err, "remediation": "Pass a clean skill name."}
    if intent and intent not in _VALID_LEVELS:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": f"intent must be one of {sorted(_VALID_LEVELS)}",
                "remediation": "Use 'green', 'yellow', or 'red'."}

    argv: list[str] = ["propose", skill_name]
    if source:
        argv += ["--source", source]
    if intent:
        argv += ["--intent", intent]
    if rationale:
        argv += ["--rationale", rationale]
    if skip_smoke:
        argv.append("--skip-smoke")
    if dry_run:
        argv.append("--dry-run")
    if registry:
        argv += ["--registry", registry]

    skillctl, bin_err = _resolve_skillctl_bin()
    if bin_err:
        return {"ok": False, "exit_code": -1, "error_class": "skillctl_not_found",
                "stderr": bin_err, "remediation": "Install / build skillctl."}
    result = _run_skillctl_blocking([skillctl] + argv, timeout=timeout)
    if result["error"]:
        return {"ok": False, "exit_code": result["exit_code"],
                "error_class": "exec_error", "stderr": result["error"],
                "remediation": "Check server log."}
    return {
        "ok": result["exit_code"] == 0,
        "exit_code": result["exit_code"],
        "stdout": result["stdout"],
        "stderr": result["stderr"][:2000],
        "mode": "dry-run" if dry_run else "register-proposal",
    }


@mcp.tool()
async def skill_revoke(
    digest: str,
    reason: str,
    role: str = "original_author",
    actor_identity: str = "",
    registry: str = "",
    timeout: int = 60,
) -> dict:
    """Run `skillctl revoke <digest>` per SPEC-0188 §4.5.

    Three actor roles per S3.6 Q1=A:
      - original_author (default): signs with ~/.claude/skillctl-keys/author.key
      - governance_reviewer: requires actor_identity
      - registry_operator: unsigned; HTTP-layer admin auth at the registry
    """
    if not digest or not digest.startswith("sha256:"):
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": "digest must be 'sha256:<64 hex>'",
                "remediation": "Pass a canonical bundle digest."}
    if reason not in {"key_compromise", "vulnerability", "governance_retraction",
                      "author_request", "duplicate"}:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": "invalid reason",
                "remediation": "Use a SPEC-0188 §4.5 reason enum value."}
    if role not in {"original_author", "governance_reviewer", "registry_operator"}:
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": "invalid role",
                "remediation": "Use original_author | governance_reviewer | registry_operator."}

    argv: list[str] = ["revoke", digest, "--reason", reason, "--role", role]
    if actor_identity:
        argv += ["--actor-identity", actor_identity]
    if registry:
        argv += ["--registry", registry]

    skillctl, bin_err = _resolve_skillctl_bin()
    if bin_err:
        return {"ok": False, "exit_code": -1, "error_class": "skillctl_not_found",
                "stderr": bin_err, "remediation": "Install / build skillctl."}
    result = _run_skillctl_blocking([skillctl] + argv, timeout=timeout)
    if result["error"]:
        return {"ok": False, "exit_code": result["exit_code"],
                "error_class": "exec_error", "stderr": result["error"],
                "remediation": "Check server log."}
    if result["exit_code"] not in (0, 15):
        return _classify_failure(result["exit_code"], result["stderr"])
    return {
        "ok": result["exit_code"] == 0,
        "exit_code": result["exit_code"],
        "stdout": result["stdout"],
        "stderr": result["stderr"][:1000],
    }


@mcp.tool()
async def skill_data_source_query(
    data_source_id: str,
    bundle_digest: str = "",
    registry_url: str = "",
    timeout: int = 30,
) -> dict:
    """Query `_data_sources` for a chip state per SPEC-0196 §4.2.

    Returns the DataSource doc plus, when bundle_digest is set, the
    chip state (authorized | denied | pending | unknown) for that
    (skill, data_source) pair.
    """
    if not data_source_id or not data_source_id.startswith("ds:"):
        return {"ok": False, "exit_code": 2, "error_class": "validation_error",
                "stderr": "data_source_id must start with 'ds:'",
                "remediation": "Pass a canonical ds:... id."}

    base = (registry_url or API_URL).rstrip("/")
    # ds:... ids contain ':' and '/': both URL-safe in path segments per
    # RFC 3986 §3.3, but we still pass via path-component-encode to be safe
    # against future schemes that introduce reserved characters.
    encoded_id = urllib.parse.quote(data_source_id, safe=":/.{}")
    url = f"{base}/api/skills/data-sources/{encoded_id}"
    headers = {"Accept": "application/json"}
    try:
        headers.update(_api_credentials(url, os.environ.get("M3C_USER_ID", ""), require_bound=not registry_url))
        req = urllib.request.Request(url, headers=headers)
        with _open_api_request(req, timeout=timeout, allow_anonymous=bool(registry_url)) as r:
            doc = _checked_api_response(json.loads(r.read().decode()))
    except _UnsafeAPIResponse:
        return {"ok": False, "exit_code": 1, "error_class": "unsafe_response",
                "stderr": _UNSAFE_API_RESPONSE,
                "remediation": "Check API response handling."}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ok": False, "exit_code": 2, "error_class": "not_found",
                    "stderr": f"data_source not registered: {data_source_id}",
                    "remediation": "Register it via POST /api/skills/data-sources (admin)."}
        return {"ok": False, "exit_code": 1, "error_class": "http_error",
                "stderr": f"HTTP {e.code}",
                "remediation": "Check registry URL + API key."}
    except ValueError:
        return {"ok": False, "exit_code": 1, "error_class": "configuration",
                "stderr": API_CONFIG_ERROR or "Invalid API transport or origin; HTTPS required unless loopback HTTP is explicitly enabled.",
                "remediation": "Check independent API origin assignment and transport."}
    except Exception:
        return {"ok": False, "exit_code": 1, "error_class": "network",
                "stderr": "API request failed.", "remediation": "Check connectivity."}

    state = "n/a"
    if bundle_digest:
        if bundle_digest in (doc.get("authorized_skills") or []):
            state = "authorized"
        elif bundle_digest in (doc.get("denied_skills") or []):
            state = "denied"
        else:
            state = "pending"

    return {
        "ok": True,
        "exit_code": 0,
        "data_source": doc,
        "chip_state": state,
        "bundle_digest": bundle_digest or None,
    }


# === end SPEC-0122 v1.2 (S6.3) ===


# ── Entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
