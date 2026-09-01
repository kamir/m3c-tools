#!/usr/bin/env python3
"""rag — local workspace RAG CLI (SPEC-0268).

    rag index  -w <workspace>
    rag sync   -w <workspace>
    rag search -w <workspace> "<query>" [-k 8] [--path-prefix SPEC/] [--since-days 30] [--json]
    rag status -w <workspace>
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent


def load_cfg(ws):
    ws = Path(ws).resolve()
    rag_cfg = ws / ".rag" / "config.yaml"
    default = HERE / "config.default.yaml"
    if rag_cfg.exists():
        return yaml.safe_load(rag_cfg.read_text())
    (ws / ".rag").mkdir(exist_ok=True)
    rag_cfg.write_text(default.read_text())          # seed a per-repo, editable copy
    return yaml.safe_load(default.read_text())


def ensure_git_tracking(ws):
    """Track the index in git (SPEC-0268): LFS for the binary, ignore only the
    derived SQLite cache. Idempotent; removes any stale bare `.rag/` ignore."""
    ws = Path(ws).resolve()

    gi = ws / ".gitignore"
    lines = gi.read_text().splitlines() if gi.exists() else []
    lines = [ln for ln in lines if ln.strip() not in (".rag", ".rag/", "/.rag", "/.rag/")]
    if ".rag/meta.sqlite" not in [ln.strip() for ln in lines]:
        lines.append(".rag/meta.sqlite")
    gi.write_text("\n".join(lines).strip() + "\n")

    ga = ws / ".gitattributes"
    atxt = ga.read_text() if ga.exists() else ""
    if "index.tvim" not in atxt:
        with open(ga, "a") as f:
            if atxt and not atxt.endswith("\n"):
                f.write("\n")
            f.write(".rag/index.tvim filter=lfs diff=lfs merge=lfs -text\n")


def resolve_workspaces(arg):
    """`-w` may be repeated; without it, fall back to $RAG_WORKSPACES (os.pathsep-
    separated). Order is preserved and duplicates are dropped, so a caller can
    export a standing fan-out set once and still override it per invocation."""
    ws = list(arg or [])
    if not ws:
        ws = [w for w in os.environ.get("RAG_WORKSPACES", "").split(os.pathsep) if w]
    seen, out = set(), []
    for w in ws:
        r = str(Path(w).expanduser().resolve())
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _search_many(workspaces, query, k, path_prefix, since_days, get_indexer=None):
    """Fan out one query across several workspaces and merge by score.

    Three things make the merge honest and cheap:

    * **One embedder for all of them.** Each Indexer would otherwise load its own
      copy of the model; `Indexer(ws, cfg, embedder=...)` lets them share it, so
      the query vector is computed exactly once.
    * **`get_indexer` lets a caller supply CACHED indexers.** A long-lived host
      (the MCP server) must not rebuild them per call — without this the model is
      re-loaded on every fan-out search, which costs seconds each time.
    * **Scores are only comparable under the same model.** Cosine scores from two
      different embedders mean nothing side by side, so a model mismatch is a hard
      error rather than a silently mis-ranked list. A differing `bit_width` only
      adds quantization noise -> warn, continue.
    """
    from indexer import Indexer
    from embedder import Embedder

    cfgs = {w: load_cfg(w) for w in workspaces}
    models = {w: c["model"] for w, c in cfgs.items()}
    if len(set(models.values())) > 1:
        detail = "; ".join(f"{Path(w).name}={m}" for w, m in models.items())
        raise ValueError(f"refusing to merge results across different models ({detail}). "
                         f"Re-index the odd one out, or search them separately.")

    widths = {c.get("bit_width") for c in cfgs.values()}
    if len(widths) > 1:
        print(f"rag: warning — mixed bit_width across workspaces ({sorted(widths)}); "
              f"ranking carries extra quantization noise", file=sys.stderr)

    if get_indexer is None:
        first = cfgs[workspaces[0]]
        shared = Embedder(first["model"], max_seq_length=first.get("max_seq_length", 512))

        def get_indexer(w, _shared=shared):
            return Indexer(w, cfgs[w], embedder=_shared)

    merged = []
    for w in workspaces:
        ix = get_indexer(w)
        try:
            hits = ix.search(query, k=k, path_prefix=path_prefix, since_days=since_days)
        except Exception as e:  # a broken/absent index must not sink the whole fan-out
            print(f"rag: warning — {Path(w).name}: {e}", file=sys.stderr)
            continue
        label = Path(w).name
        for h in hits:
            h["workspace"] = label
            h["workspace_path"] = w
            merged.append(h)
    merged.sort(key=lambda h: h["score"], reverse=True)
    return merged[:k]


def main():
    ap = argparse.ArgumentParser(prog="rag")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("index", "sync", "status", "verify"):
        s = sub.add_parser(name)
        s.add_argument("--workspace", "-w", action="append")
    ss = sub.add_parser("search")
    ss.add_argument("--workspace", "-w", action="append",
                    help="repeatable; fans the query out and merges by score. "
                         "Defaults to $RAG_WORKSPACES.")
    ss.add_argument("query")
    ss.add_argument("-k", type=int, default=8)
    ss.add_argument("--path-prefix", default="")
    ss.add_argument("--since-days", type=int, default=0)
    ss.add_argument("--json", action="store_true")
    a = ap.parse_args()

    workspaces = resolve_workspaces(a.workspace)
    if not workspaces:
        ap.error("no workspace: pass -w <repo> (repeatable) or set $RAG_WORKSPACES")

    # Write/state commands act on exactly one workspace: building or committing
    # several indexes from a single invocation would hide which one failed.
    if a.cmd != "search" and len(workspaces) > 1:
        ap.error(f"'{a.cmd}' takes a single -w; got {len(workspaces)}")

    from indexer import Indexer

    if a.cmd == "search":
        try:
            res = _search_many(workspaces, a.query, a.k, a.path_prefix, a.since_days)
        except ValueError as e:
            sys.exit(f"rag: {e}")
        if a.json:
            print(json.dumps(res, indent=2))
            return
        if not res:
            print("(no results)", file=sys.stderr)
        multi = len(workspaces) > 1
        for r in res:
            where = f"{r['workspace']}:{r['path']}" if multi else r["path"]
            print(f"\n{r['score']:.3f}  {where}:{r['lines']}  [{r['heading']}]")
            print("    " + r["snippet"].replace("\n", " ")[:240])
        return

    ws = workspaces[0]
    ix = Indexer(ws, load_cfg(ws))
    if a.cmd == "index":
        ensure_git_tracking(ws)
        print(json.dumps(ix.build(), indent=2))
    elif a.cmd == "sync":
        print(json.dumps(ix.sync(), indent=2))
    elif a.cmd == "status":
        print(json.dumps(ix.stats(), indent=2))
    elif a.cmd == "verify":
        r = ix.verify()
        print(json.dumps(r, indent=2))
        sys.exit(0 if r.get("fresh") else 2)


if __name__ == "__main__":
    main()
