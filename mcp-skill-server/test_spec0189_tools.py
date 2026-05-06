"""Unit tests for the SPEC-0189 args added to the MCP `skill_scan` tool.

The tool itself (server.skill_scan) is the same coroutine used in production;
we exercise it by mocking `_run_skillctl` so we don't need a real Go binary.

Each test asserts:
  - the argv that flowed to `_run_skillctl` matches the SPEC-0189 §7 CLI shape
  - the rendered text output contains the expected SPEC-0189 §6 fields
    (tier breakdown when skills carry a tier, trust-chain breakdown when
    `with_trust=True`)

Run:
    cd mcp-skill-server
    python3 -m pytest test_spec0189_tools.py -v
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch, AsyncMock

import server  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _ok(payload: dict) -> dict:
    """Shape `_run_skillctl` returns on a clean exec."""
    return {"stdout": json.dumps(payload), "stderr": "", "error": ""}


# ---------- argv shape (SPEC-0189 §7 contract) ----------


def test_default_source_claude_argv_is_clean():
    """Default call → `skillctl scan --source claude --format json` and nothing else.
    No legacy --path/--recursive/--include-home leaks through."""
    captured = {}

    async def fake_runner(argv):
        captured["argv"] = argv
        return _ok({"total_count": 0, "by_type": {}, "by_project": {}, "skills": []})

    with patch("server._run_skillctl", side_effect=fake_runner):
        _run(server.skill_scan())

    argv = captured["argv"]
    assert argv[1:] == ["scan", "--source", "claude", "--format", "json"]


def test_source_user_passes_through():
    captured = {}

    async def fake_runner(argv):
        captured["argv"] = argv
        return _ok({"total_count": 0, "by_type": {}, "by_project": {}, "skills": []})

    with patch("server._run_skillctl", side_effect=fake_runner):
        _run(server.skill_scan(source="user"))

    assert "--source" in captured["argv"]
    assert captured["argv"][captured["argv"].index("--source") + 1] == "user"


def test_with_trust_and_include_shadowed_emit_flags():
    """SPEC-0189 §7: --with-trust + --include-shadowed emitted iff requested."""
    captured = {}

    async def fake_runner(argv):
        captured["argv"] = argv
        return _ok({"total_count": 0, "by_type": {}, "by_project": {}, "skills": []})

    with patch("server._run_skillctl", side_effect=fake_runner):
        _run(server.skill_scan(source="claude", with_trust=True, include_shadowed=True))

    assert "--with-trust" in captured["argv"]
    assert "--include-shadowed" in captured["argv"]


def test_path_is_repeatable():
    """SPEC-0189 §7: --path can repeat. The tool must emit one --path
    per entry in the list."""
    captured = {}

    async def fake_runner(argv):
        captured["argv"] = argv
        return _ok({"total_count": 0, "by_type": {}, "by_project": {}, "skills": []})

    with patch("server._run_skillctl", side_effect=fake_runner):
        _run(server.skill_scan(source="all", path=["/repo/a", "/repo/b"]))

    argv = captured["argv"]
    # Each path argument appears as its own --path / value pair.
    indices = [i for i, v in enumerate(argv) if v == "--path"]
    assert len(indices) == 2
    assert argv[indices[0] + 1] == "/repo/a"
    assert argv[indices[1] + 1] == "/repo/b"


def test_legacy_flags_only_with_source_projects():
    """`recursive=True` / `include_home=True` ONLY emit the legacy flags
    if `source='projects'` (SPEC-0115 mode). Under `source='claude'` they
    must be silently ignored — otherwise we'd corrupt the new tier-aware
    discovery path."""
    captured = {}

    async def fake_runner(argv):
        captured["argv"] = argv
        return _ok({"total_count": 0, "by_type": {}, "by_project": {}, "skills": []})

    # Modern source: legacy flags ignored.
    with patch("server._run_skillctl", side_effect=fake_runner):
        _run(server.skill_scan(source="claude", recursive=True, include_home=True))
    assert "--recursive" not in captured["argv"]
    assert "--include-home" not in captured["argv"]

    # Legacy source: flags emitted.
    with patch("server._run_skillctl", side_effect=fake_runner):
        _run(server.skill_scan(source="projects", path=["/x"], recursive=True, include_home=True))
    assert "--recursive" in captured["argv"]
    assert "--include-home" in captured["argv"]


# ---------- output rendering (SPEC-0189 §6 fields) ----------


def test_output_includes_tier_breakdown():
    """When the inventory carries `tier` per skill, the rendered text
    contains a `By tier:` section with the right counts."""
    payload = {
        "total_count": 3,
        "by_type": {"claude_code_skill": 3},
        "by_project": {"user-global": 2, "marketplace:foo": 1},
        "skills": [
            {"tier": "user", "name": "a"},
            {"tier": "user", "name": "b"},
            {"tier": "plugin", "name": "c"},
        ],
    }

    async def fake_runner(argv):
        return _ok(payload)

    with patch("server._run_skillctl", side_effect=fake_runner):
        out = _run(server.skill_scan(source="claude"))

    assert "By tier:" in out
    assert "user: 2" in out
    assert "plugin: 1" in out
    assert "(source=claude)" in out


def test_output_includes_trust_chain_when_with_trust():
    """If `with_trust=True` and the inventory carries bundle.trust_chain,
    a `Trust chain` section is rendered."""
    payload = {
        "total_count": 2,
        "by_type": {"claude_code_skill": 2},
        "by_project": {"user-global": 2},
        "skills": [
            {"tier": "user", "name": "trusted-a", "bundle": {"trust_chain": "verified"}},
            {"tier": "user", "name": "no-bundle", "bundle": {"trust_chain": "no_bundle"}},
        ],
    }

    async def fake_runner(argv):
        return _ok(payload)

    with patch("server._run_skillctl", side_effect=fake_runner):
        out = _run(server.skill_scan(source="claude", with_trust=True))

    assert "Trust chain" in out
    assert "verified: 1" in out
    assert "no_bundle: 1" in out


def test_runner_error_is_surfaced():
    """If `_run_skillctl` returns an error, the tool returns a human
    message rather than raising."""
    async def fake_runner(argv):
        return {"error": "skillctl not found at /nope", "stdout": "", "stderr": ""}

    with patch("server._run_skillctl", side_effect=fake_runner):
        out = _run(server.skill_scan(source="claude"))

    assert out.startswith("Scan failed:")
    assert "skillctl not found" in out
