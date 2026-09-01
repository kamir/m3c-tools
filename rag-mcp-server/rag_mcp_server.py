#!/usr/bin/env python3
"""rag MCP server (SPEC-0268) — FastMCP stdio, mirrors mcp-skill-server.

Exposes local workspace RAG search/stats/sync as Claude Code tools.

Launch:  rag_mcp_server.py --workspace <repo> [--workspace <repo> ...]

`--workspace` is repeatable (and $RAG_WORKSPACES is honoured), so ONE registered
server can answer across several repos — e.g. the thinking corpus, the private
SPEC/intent repo and the running code. `rag_search` then merges by score and
labels every hit with its workspace; pass `workspace="<name>"` to scope to one.
The FIRST workspace is the primary: it is what a single-target call defaults to.

Register in <repo>/.mcp.json (see README).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from rag import load_cfg, resolve_workspaces, _search_many  # noqa: E402

_ap = argparse.ArgumentParser()
_ap.add_argument("--workspace", "-w", action="append")
ARGS, _ = _ap.parse_known_args()

WORKSPACES = resolve_workspaces(ARGS.workspace)
if not WORKSPACES:
    sys.exit("rag_mcp_server: no workspace — pass --workspace <repo> or set $RAG_WORKSPACES")
PRIMARY = WORKSPACES[0]


def _label(ws):
    return Path(ws).name


def _resolve_one(workspace):
    """Map a tool's `workspace` argument (a name or a path) onto a registered
    workspace. Empty -> the primary. An unknown value is an error rather than a
    silent fallback: quietly answering from the wrong repo is worse than failing."""
    if not workspace:
        return PRIMARY
    for w in WORKSPACES:
        if workspace in (w, _label(w)):
            return w
    raise ValueError(f"unknown workspace {workspace!r}; registered: "
                     + ", ".join(_label(w) for w in WORKSPACES))


mcp = FastMCP("rag")
_ixs = {}


def _indexer(ws):
    """One cached Indexer per workspace, all sharing a single embedder so the
    model is loaded once no matter how many repos are registered."""
    if ws not in _ixs:
        from indexer import Indexer
        # Only hand over an embedder that is ALREADY materialized — `.embedder` is
        # a lazy property, so touching it here would load the model even for a
        # stats-only call that never needs it.
        shared = next((i._embedder for i in _ixs.values() if i._embedder is not None), None)
        _ixs[ws] = Indexer(ws, load_cfg(ws), embedder=shared)
    return _ixs[ws]


@mcp.tool()
def rag_search(query: str, k: int = 8, path_prefix: str = "",
               since_days: int = 0, workspace: str = "") -> list:
    """Semantic search over the local workspace index(es).

    Returns up to k chunks as {path, heading, lines, score, snippet, workspace},
    each citing a clickable path:line. Scope with path_prefix (e.g. "SPEC/"),
    since_days, or workspace (a registered name; empty searches all of them and
    merges by score).
    """
    if workspace:
        ws = _resolve_one(workspace)
        hits = _indexer(ws).search(query, k=k, path_prefix=path_prefix, since_days=since_days)
        for h in hits:
            h["workspace"] = _label(ws)
        return hits
    return _search_many(WORKSPACES, query, k, path_prefix, since_days,
                        get_indexer=_indexer)


@mcp.tool()
def rag_workspaces() -> list:
    """The workspaces this server can search, in merge order (first = primary)."""
    return [{"name": _label(w), "path": w} for w in WORKSPACES]


@mcp.tool()
def rag_stats(workspace: str = "") -> dict:
    """Index statistics per workspace: file/chunk counts, model, dim, last-sync commit, size.

    Empty workspace reports every registered one.
    """
    targets = WORKSPACES if not workspace else [_resolve_one(workspace)]
    return {_label(w): _indexer(w).stats() for w in targets}


@mcp.tool()
def rag_sync(workspace: str = "") -> dict:
    """Incrementally re-index files changed/added/deleted since the last sync (local-only).

    Empty workspace syncs every registered one.
    """
    targets = WORKSPACES if not workspace else [_resolve_one(workspace)]
    return {_label(w): _indexer(w).sync() for w in targets}


@mcp.tool()
def rag_verify(workspace: str = "") -> dict:
    """Is each index FRESH vs its current workspace? Returns fresh + corpus hashes.

    Empty workspace verifies every registered one.
    """
    targets = WORKSPACES if not workspace else [_resolve_one(workspace)]
    return {_label(w): _indexer(w).verify() for w in targets}


if __name__ == "__main__":
    mcp.run(transport="stdio")
