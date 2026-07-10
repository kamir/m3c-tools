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


def main():
    ap = argparse.ArgumentParser(prog="rag")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("index", "sync", "status", "verify"):
        s = sub.add_parser(name)
        s.add_argument("--workspace", "-w", required=True)
    ss = sub.add_parser("search")
    ss.add_argument("--workspace", "-w", required=True)
    ss.add_argument("query")
    ss.add_argument("-k", type=int, default=8)
    ss.add_argument("--path-prefix", default="")
    ss.add_argument("--since-days", type=int, default=0)
    ss.add_argument("--json", action="store_true")
    a = ap.parse_args()

    from indexer import Indexer
    cfg = load_cfg(a.workspace)
    ix = Indexer(a.workspace, cfg)

    if a.cmd == "index":
        ensure_git_tracking(a.workspace)
        print(json.dumps(ix.build(), indent=2))
    elif a.cmd == "sync":
        print(json.dumps(ix.sync(), indent=2))
    elif a.cmd == "status":
        print(json.dumps(ix.stats(), indent=2))
    elif a.cmd == "verify":
        r = ix.verify()
        print(json.dumps(r, indent=2))
        sys.exit(0 if r.get("fresh") else 2)
    elif a.cmd == "search":
        res = ix.search(a.query, k=a.k, path_prefix=a.path_prefix, since_days=a.since_days)
        if a.json:
            print(json.dumps(res, indent=2))
            return
        if not res:
            print("(no results)", file=sys.stderr)
        for r in res:
            print(f"\n{r['score']:.3f}  {r['path']}:{r['lines']}  [{r['heading']}]")
            print("    " + r["snippet"].replace("\n", " ")[:240])


if __name__ == "__main__":
    main()
