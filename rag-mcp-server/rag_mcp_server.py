#!/usr/bin/env python3
"""rag MCP server (SPEC-0268) — FastMCP stdio, mirrors mcp-skill-server.

Exposes local workspace RAG search/stats/sync as Claude Code tools.
Launch:  rag_mcp_server.py --workspace <repo>
Register in <repo>/.mcp.json (see README).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from mcp.server.fastmcp import FastMCP  # noqa: E402

_ap = argparse.ArgumentParser()
_ap.add_argument("--workspace", "-w", required=True)
ARGS, _ = _ap.parse_known_args()


def _cfg(ws):
    rc = Path(ws).resolve() / ".rag" / "config.yaml"
    default = HERE / "config.default.yaml"
    return yaml.safe_load((rc if rc.exists() else default).read_text())


mcp = FastMCP("rag")
_ix = None


def _indexer():
    global _ix
    if _ix is None:
        from indexer import Indexer
        _ix = Indexer(ARGS.workspace, _cfg(ARGS.workspace))
    return _ix


@mcp.tool()
def rag_search(query: str, k: int = 8, path_prefix: str = "", since_days: int = 0) -> list:
    """Semantic search over the local workspace index.

    Returns up to k chunks as {path, heading, lines, score, snippet}, each citing
    a clickable path:line. Use path_prefix (e.g. "SPEC/") or since_days to scope.
    """
    return _indexer().search(query, k=k, path_prefix=path_prefix, since_days=since_days)


@mcp.tool()
def rag_stats() -> dict:
    """Index statistics: file/chunk counts, model, dim, last-sync git commit, size."""
    return _indexer().stats()


@mcp.tool()
def rag_sync() -> dict:
    """Incrementally re-index files changed/added/deleted since the last sync (local-only)."""
    return _indexer().sync()


@mcp.tool()
def rag_verify() -> dict:
    """Is the committed index FRESH vs the current workspace? Returns fresh + corpus hashes."""
    return _indexer().verify()


if __name__ == "__main__":
    mcp.run(transport="stdio")
