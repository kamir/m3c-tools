#!/usr/bin/env python3
"""rag: local workspace RAG CLI (SPEC-0268).

    rag index  -w <workspace>
    rag sync   -w <workspace>
    rag search -w <workspace> "<query>" [-k 8] [--path-prefix SPEC/] [--since-days 30] [--json]
    rag status -w <workspace>
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
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


_RAG_IGNORE_LINES = (".rag", ".rag/", "/.rag", "/.rag/")
_LFS_ATTR = ".rag/index.tvim filter=lfs diff=lfs merge=lfs -text"


def _git_root(ws):
    try:
        r = subprocess.run(["git", "-C", str(ws), "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, timeout=5)
        return Path(r.stdout.strip()).resolve() if r.stdout.strip() else None
    except Exception:  # noqa: BLE001: no git, no worktree: nothing to arrange
        return None


def _set_gitignore(ws, keep, add):
    """Rewrite <ws>/.gitignore: drop every line in `keep`-negated set, ensure `add`."""
    gi = ws / ".gitignore"
    lines = gi.read_text().splitlines() if gi.exists() else []
    lines = [ln for ln in lines if ln.strip() not in keep]
    if add and add not in [ln.strip() for ln in lines]:
        lines.append(add)
    gi.write_text("\n".join(lines).strip() + "\n")


def _persist_git_tracking(ws, value):
    """Record the choice in .rag/config.yaml so a later plain `index` cannot
    silently flip a deliberately-untracked workspace back to tracked."""
    cfg_path = Path(ws) / ".rag" / "config.yaml"
    if not cfg_path.exists():
        return
    txt = cfg_path.read_text()
    line = f"git_tracking: {value}"
    if "git_tracking:" in txt:
        txt = "\n".join(line if ln.startswith("git_tracking:") else ln
                        for ln in txt.splitlines()) + "\n"
    else:
        txt = txt.rstrip("\n") + (
            "\n\n# tracked = index committed to git (LFS); none = machine-local artifact,\n"
            "# .rag/ ignored wholesale. Set by `index [--no-track]`; sticky across runs.\n"
            f"{line}\n")
    cfg_path.write_text(txt)


def ensure_git_tracking(ws, track=True):
    """Arrange git so the index behaves the way this workspace intends.

    TRACKED (the SPEC-0268 default): LFS for the binary, ignore only the derived
    SQLite cache, so a fresh clone is searchable with no re-embedding.

    UNTRACKED: ignore `.rag/` wholesale and add no LFS rule. Two cases need this,
    and both were found the hard way:

    * **The workspace is not the git root.** Indexing a SUBDIRECTORY of a repo
      (e.g. an app inside a monorepo) otherwise leaves tens of megabytes of
      untracked index sitting in the PARENT repo's `git status`, one `git add -A`
      away from being committed there, plus an LFS rule for a file that repo was
      never going to carry. This is detected, not configured.
    * **`track=False`** (`index --no-track`), for a repo whose index is
      deliberately a machine-local artifact. Committing a rebuilt index costs a
      new LFS object every time; when a second machine can just rebuild, the
      index is cheaper than its transport.

    Idempotent either way, and it converts between the two states: flipping a
    workspace to untracked removes the LFS attribute it previously added.
    """
    ws = Path(ws).resolve()
    root = _git_root(ws)
    if root is None:
        return "no-git"

    if track and root == ws:
        _persist_git_tracking(ws, "tracked")
        _set_gitignore(ws, keep=set(_RAG_IGNORE_LINES), add=".rag/meta.sqlite")
        ga = ws / ".gitattributes"
        atxt = ga.read_text() if ga.exists() else ""
        if "index.tvim" not in atxt:
            with open(ga, "a") as f:
                if atxt and not atxt.endswith("\n"):
                    f.write("\n")
                f.write(_LFS_ATTR + "\n")
        return "tracked"

    # Untracked: the whole .rag/ is ignored and any LFS rule we added is removed.
    _persist_git_tracking(ws, "none")
    _set_gitignore(ws, keep={".rag/meta.sqlite"}, add=".rag/")
    ga = ws / ".gitattributes"
    if ga.exists():
        kept = [ln for ln in ga.read_text().splitlines() if ln.strip() != _LFS_ATTR]
        if any(k.strip() for k in kept):
            ga.write_text("\n".join(kept).strip() + "\n")
        else:
            # The file held nothing but our LFS rule -> we created it. Leaving an
            # empty .gitattributes behind is litter in someone else's repo.
            ga.unlink()
    return "untracked (workspace is not the git root)" if root != ws else "untracked (--no-track)"


def resolve_workspaces(arg):
    """`-w` may be repeated; without it, fall back to $RAG_WORKSPACES (os.pathsep-
    separated). Order is preserved and duplicates are dropped, so a caller can
    export a standing fan-out set once and still override it per invocation."""
    ws = list(arg or [])
    if not ws:
        ws = [w for w in os.environ.get("RAG_WORKSPACES", "").split(os.pathsep) if w]
    seen, out = set(), []
    for w in ws:
        pw = Path(w).expanduser().resolve()
        # A standing fan-out set (a committed .mcp.json, $RAG_WORKSPACES in a
        # profile) is shared across machines that do not all have every repo
        # checked out. A missing one must not take the whole server down.
        if not pw.is_dir():
            print(f"rag: warning: skipping missing workspace {w}", file=sys.stderr)
            continue
        r = str(pw)
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _search_many(workspaces, query, k, path_prefix, since_days, get_indexer=None, mode="hybrid"):
    """Fan out one query across several workspaces and merge by score.

    Three things make the merge honest and cheap:

    * **One embedder for all of them.** Each Indexer would otherwise load its own
      copy of the model; `Indexer(ws, cfg, embedder=...)` lets them share it, so
      the query vector is computed exactly once.
    * **`get_indexer` lets a caller supply CACHED indexers.** A long-lived host
      (the MCP server) must not rebuild them per call, without this the model is
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
        print(f"rag: warning: mixed bit_width across workspaces ({sorted(widths)}); "
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
            # TIEFER als k je Workspace holen. Sonst liefert jeder nur seine
            # Spitze, die Fusion interleavt round-robin, und der eine Workspace,
            # der die Antwort WIRKLICH hat, kommt mit Rang 5 nie durch.
            # Gemessen: admission.py steht in aims-core auf Rang 5 und fehlte im
            # Verbund-Top-10 vollstaendig.
            hits = ix.search(query, k=max(k * 3, 30), path_prefix=path_prefix,
                             since_days=since_days, mode=mode)
        except Exception as e:  # a broken/absent index must not sink the whole fan-out
            print(f"rag: warning: {Path(w).name}: {e}", file=sys.stderr)
            continue
        label = Path(w).name
        for h in hits:
            h["workspace"] = label
            h["workspace_path"] = w
            merged.append(h)
    # Bei hybrid tragen rein-lexikalische Treffer keinen Kosinus-Score. Nach score
    # zu sortieren wuerde sie ans Ende schieben und den Fan-out um genau die
    # Treffer bringen, wegen derer die lexikalische Haelfte existiert. Deshalb
    # wird ueber die Workspaces erneut per RRF fusioniert.
    # Global nach dem Fusionswert sortieren, den jeder Workspace SELBST vergeben
    # hat: nicht die Workspaces gegeneinander round-robin interleaven. Ein stark
    # fusionierter Treffer aus einem Repo schlaegt damit die schwache Spitze eines
    # anderen, was der ganze Punkt des Verbundes ist.
    if any(h.get("rrf") for h in merged):
        merged.sort(key=lambda h: (h.get("rrf", 0.0), h["score"]), reverse=True)
    else:
        merged.sort(key=lambda h: h["score"], reverse=True)
    return merged[:k]


def main():
    ap = argparse.ArgumentParser(prog="rag")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("index", "sync", "status", "verify"):
        s = sub.add_parser(name)
        s.add_argument("--workspace", "-w", action="append")
        if name == "index":
            s.add_argument("--no-track", action="store_true",
                           help="keep the index out of git: ignore .rag/ wholesale "
                                "and add no LFS rule (machine-local artifact)")
    ss = sub.add_parser("search")
    ss.add_argument("--workspace", "-w", action="append",
                    help="repeatable; fans the query out and merges by score. "
                         "Defaults to $RAG_WORKSPACES.")
    ss.add_argument("query")
    ss.add_argument("-k", type=int, default=8)
    ss.add_argument("--path-prefix", default="")
    ss.add_argument("--since-days", type=int, default=0)
    ss.add_argument("--mode", choices=["hybrid", "dense", "lexical"], default="hybrid",
                    help="hybrid (default): dense + BM25, fused by rank. dense: wie bisher. "
                         "lexical: nur BM25: nuetzlich, um einen exakten Begriff zu pruefen.")
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
            res = _search_many(workspaces, a.query, a.k, a.path_prefix, a.since_days, mode=a.mode)
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
            via = r.get("via", "")
            tag = {"both": " ‡", "lexical": " ¶"}.get(via, "")
            print(f"\n{r['score']:.3f}{tag}  {where}:{r['lines']}  [{r['heading']}]")
            print("    " + r["snippet"].replace("\n", " ")[:240])
        return

    ws = workspaces[0]
    ix = Indexer(ws, load_cfg(ws))
    if a.cmd == "index":
        # A recorded `git_tracking: none` outlives the flag: re-indexing a
        # deliberately-untracked workspace must not quietly re-arm LFS tracking.
        track = not a.no_track and load_cfg(ws).get("git_tracking", "auto") != "none"
        mode = ensure_git_tracking(ws, track=track)
        print(f"[index] git: {mode}", file=sys.stderr)
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
