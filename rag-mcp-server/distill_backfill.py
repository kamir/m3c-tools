#!/usr/bin/env python3
"""distill_backfill — wave-by-wave distillation backfill runner (SPEC-0269 P1).

Turns raw ER1/braindump notes into a distilled knowledge layer + cumulative
knowledge graph, resumably, mostly on Sonnet with Opus reserved for strategic
notes. The same per-item distill is reused by the streaming consumer (P2).

Subcommands:
  manifest      build the item manifest: hashes, tags, tier (opus/sonnet),
                RAG-clustered batches of ~15, wave assignment.
  prepare-wave  emit per-batch input files (+ allids) for wave N, skipping
                items already in the ledger; print the spawn plan (batch/tier).
  merge-wave    after the distiller subagents write their outputs, validate +
                build WIKI/<id>.md notes + merge into knowledge-graph.json +
                append the ledger.
  status        progress: done/total overall and per wave.

Idempotency: ledger keyed on (id, content_hash). Re-running skips done items.
Batches are semantic (greedy nearest-neighbour over bge-m3) so the analyzer sees
related notes together → richer builds_on/contradicts edges.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from wiki_scaffold import read_meta  # (tags, title)  # noqa: E402

STRATEGIC_TAGS = {"vision", "strategy", "scalytics", "aims2", "lascaris", "henka",
                  "sovereignty", "kafgraph", "plm", "skillr", "confluent", "kup", "ceo"}
LONG_CHARS = 9000


def _now():
    return datetime.now(timezone.utc).isoformat()


def _ua(ws):
    d = ws / ".understand-anything"
    d.mkdir(exist_ok=True)
    return d


def _files_hashes(ws):
    fj = ws / ".rag" / "files.jsonl"
    h = {}
    if fj.exists():
        for ln in fj.read_text().splitlines():
            o = json.loads(ln)
            h[o["path"]] = o["file_hash"]
    return h


def _overrides(ws):
    ov = set()
    for f in (HERE / "opus-overrides.txt", ws / ".understand-anything" / "opus-overrides.txt"):
        if f.exists():
            ov |= {l.strip() for l in f.read_text().splitlines() if l.strip() and not l.startswith("#")}
    return ov


def _ledger_done(ws):
    f = _ua(ws) / "distill-ledger.jsonl"
    done = {}
    if f.exists():
        for ln in f.read_text().splitlines():
            if ln.strip():
                o = json.loads(ln)
                done[o["id"]] = o.get("hash", "")
    return done


def _greedy_batches(V, ids, bs):
    """Greedy nearest-neighbour batching over unit vectors → coherent groups."""
    n = len(ids)
    used = np.zeros(n, bool)
    sims = V @ V.T
    out = []
    for i in range(n):
        if used[i]:
            continue
        used[i] = True
        grp = [i]
        s = sims[i].copy()
        s[used] = -2.0
        for j in np.argsort(-s):
            if len(grp) >= bs:
                break
            if not used[j] and s[j] > -2.0:
                used[j] = True
                grp.append(int(j))
                s = sims[i].copy()
                s[used] = -2.0
        out.append([ids[k] for k in grp])
    return out


def cmd_manifest(a):
    ws = Path(a.workspace).resolve()
    sub = a.notes_subdir
    ua = _ua(ws)
    overrides = _overrides(ws)
    hashes = _files_hashes(ws)
    notes = sorted((ws / sub).rglob("*.md"))

    items, reps, ids = {}, [], []
    for p in notes:
        rel = p.relative_to(ws).as_posix()
        tags, title = read_meta(p)
        txt = p.read_text(encoding="utf-8", errors="replace")
        nid = p.stem
        strat = bool({t.lower() for t in tags} & STRATEGIC_TAGS) or nid in overrides
        tier = "opus" if (strat or len(txt) > LONG_CHARS) else "sonnet"
        items[nid] = {"path": rel, "hash": hashes.get(rel, ""), "tags": tags,
                      "title": title, "length": len(txt), "tier": tier, "strategic": strat}
        reps.append((title + " " + re.sub(r"\s+", " ", txt)[:600]).strip())
        ids.append(nid)

    print(f"[manifest] embedding {len(ids)} note representatives (bge-m3, local)...", file=sys.stderr)
    from embedder import Embedder
    V = Embedder("BAAI/bge-m3", max_seq_length=512).encode(reps, batch_size=32)
    batches = _greedy_batches(V, ids, a.batch_size)

    per = (len(batches) + a.waves - 1) // a.waves
    batchrecs = []
    for bi, grp in enumerate(batches):
        wave = bi // per + 1
        ot = sum(1 for x in grp if items[x]["tier"] == "opus")
        btier = "opus" if (ot * 2 >= len(grp) and ot > 0) else "sonnet"
        bid = f"w{wave}b{bi % per + 1:02d}"
        for x in grp:
            items[x]["batch"] = bid
            items[x]["wave"] = wave
        batchrecs.append({"batch_id": bid, "wave": wave, "tier": btier, "opus_items": ot,
                          "items": [{"id": x, "path": items[x]["path"], "name": items[x]["title"]} for x in grp]})

    man = {"workspace": str(ws), "notes_subdir": sub, "batch_size": a.batch_size,
           "n_items": len(items), "n_batches": len(batches), "n_waves": a.waves,
           "batches_per_wave": per, "created_at": _now(), "items": items, "batches": batchrecs}
    (ua / "distill-manifest.json").write_text(json.dumps(man, ensure_ascii=False))
    (ua / "distill-allids.json").write_text(json.dumps([f"article:{sub}/{x}" for x in ids]))

    from collections import Counter
    bt = Counter((b["wave"], b["tier"]) for b in batchrecs)
    print(json.dumps({
        "items": len(items), "batches": len(batches), "waves": a.waves, "batches_per_wave": per,
        "opus_items": sum(1 for v in items.values() if v["tier"] == "opus"),
        "sonnet_items": sum(1 for v in items.values() if v["tier"] == "sonnet"),
        "wave_tier_batches": {f"w{w}-{t}": c for (w, t), c in sorted(bt.items())},
    }, indent=2))


def cmd_prepare_wave(a):
    ws = Path(a.workspace).resolve()
    ua = _ua(ws)
    man = json.loads((ua / "distill-manifest.json").read_text())
    done = _ledger_done(ws)
    wdir = ua / "waves" / f"w{a.wave}"
    (wdir / "out").mkdir(parents=True, exist_ok=True)
    (wdir / "allids.json").write_text((ua / "distill-allids.json").read_text())

    plan = []
    for b in man["batches"]:
        if b["wave"] != a.wave:
            continue
        pend = [it for it in b["items"] if done.get(it["id"]) != man["items"][it["id"]]["hash"] or it["id"] not in done]
        if not pend:
            continue
        (wdir / f"batch-{b['batch_id']}.json").write_text(json.dumps(pend, ensure_ascii=False, indent=1))
        plan.append({"batch_id": b["batch_id"], "tier": b["tier"], "items": len(pend)})
    (wdir / "plan.json").write_text(json.dumps(plan, indent=1))
    print(json.dumps({"wave": a.wave, "batches": len(plan),
                      "sonnet": sum(p["items"] for p in plan if p["tier"] == "sonnet"),
                      "opus": sum(p["items"] for p in plan if p["tier"] == "opus"),
                      "out_dir": str(wdir), "plan": plan}, indent=2))


def _load_graph(ua, ws):
    import subprocess
    f = ua / "knowledge-graph.json"
    g = json.loads(f.read_text()) if f.exists() else {
        "version": "1.0.0", "kind": "knowledge", "project": {},
        "nodes": [], "edges": [], "layers": [], "tour": []}
    pm = g.get("project") or {}
    try:
        commit = subprocess.run(["git", "-C", str(ws), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:  # noqa: BLE001
        commit = ""
    # Understand-Anything's ProjectMetaSchema requires all six fields (string / string[]).
    g["project"] = {
        "name": pm.get("name") or ws.name,
        "languages": pm.get("languages") or ["Markdown", "German", "English"],
        "frameworks": pm.get("frameworks") or [],
        "description": pm.get("description")
        or "Distilled knowledge layer (SPEC-0269): ER1 notes distilled into articles, entities, and claims.",
        "analyzedAt": _now_iso(),
        "gitCommitHash": commit or pm.get("gitCommitHash", ""),
    }
    g.setdefault("kind", "knowledge")
    g.setdefault("layers", [])
    g.setdefault("tour", [])
    return g


def cmd_merge_wave(a):
    ws = Path(a.workspace).resolve()
    ua = _ua(ws)
    man = json.loads((ua / "distill-manifest.json").read_text())
    sub = man["notes_subdir"]
    wdir = ua / "waves" / f"w{a.wave}" / "out"
    wiki = ws / "WIKI"
    wiki.mkdir(exist_ok=True)
    graph = _load_graph(ua, ws)
    nodes = {n["id"]: n for n in graph["nodes"]}
    edges = {(e["source"], e["target"], e.get("type")): e for e in graph["edges"]}
    ledger = (ua / "distill-ledger.jsonl").open("a")

    merged, n_dist, n_ent, n_claim, n_edge = [], 0, 0, 0, 0
    for dfile in sorted(wdir.glob("distilled-*.json")):
        bid = dfile.stem.split("distilled-")[1]
        dist = json.loads(dfile.read_text())
        afile = wdir / f"analysis-{bid}.json"
        analysis = json.loads(afile.read_text()) if afile.exists() else {"nodes": [], "edges": []}

        for d in dist:
            nid = d["id"]
            stem = nid.split("article:")[-1]
            note_id = stem.split("/")[-1]
            meta = man["items"].get(note_id, {})
            nodes[nid] = {"id": nid, "type": "article", "name": d.get("title") or meta.get("title") or note_id,
                          "summary": d.get("summary", ""), "tags": meta.get("tags", []),
                          "filePath": meta.get("path", f"{sub}/{note_id}.md"), "complexity": "simple",
                          "kind": "knowledge"}
            # topic edge from primary content tag
            for t in d.get("entities", [])[:0]:
                pass
            prim = next((t for t in meta.get("tags", []) if t.lower() in STRATEGIC_TAGS), None) \
                or (meta.get("tags") or [None])[0]
            if prim:
                tid = f"topic:{prim}"
                nodes.setdefault(tid, {"id": tid, "type": "topic", "name": prim, "summary": "",
                                       "tags": ["topic"], "complexity": "simple", "kind": "knowledge"})
                edges[(nid, tid, "categorized_under")] = {"source": nid, "target": tid,
                                                          "type": "categorized_under", "direction": "forward", "weight": 0.5}
            # WIKI note
            rel = [e["target"] for e in analysis.get("edges", [])
                   if e.get("source") == nid and str(e.get("target", "")).startswith("article:")]
            fm = [f"---", f"id: {note_id}", f"title: {json.dumps(d.get('title',''), ensure_ascii=False)}",
                  f"source: {meta.get('path','')}", f"tags: {json.dumps(meta.get('tags',[]), ensure_ascii=False)}",
                  f"model: {man['items'].get(note_id,{}).get('tier','sonnet')}", f"distilled_at: {_now()}", "---", ""]
            body = [f"# {d.get('title','')}", "", d.get("summary", ""), "", "## Key points"]
            body += [f"- {k}" for k in d.get("key_points", [])]
            if d.get("claims"):
                body += ["", "## Claims"] + [f"- {c}" for c in d["claims"]]
            if d.get("entities"):
                body += ["", "## Entities"] + [f"- {e}" for e in d["entities"]]
            if rel:
                body += ["", "## Related"] + [f"- [[{r.split('article:')[-1]}]]" for r in rel]
            (wiki / f"{note_id}.md").write_text("\n".join(fm + body), encoding="utf-8")

            ledger.write(json.dumps({"id": note_id, "hash": meta.get("hash", ""),
                                     "model": man["items"].get(note_id, {}).get("tier", "sonnet"),
                                     "wave": a.wave, "ts": _now()}) + "\n")
            merged.append(note_id)
            n_dist += 1

        for n in analysis.get("nodes", []):
            if n["id"] not in nodes:
                n.setdefault("kind", "knowledge")
                nodes[n["id"]] = n
                if n.get("type") == "entity":
                    n_ent += 1
                elif n.get("type") == "claim":
                    n_claim += 1
        for e in analysis.get("edges", []):
            edges[(e["source"], e["target"], e.get("type"))] = e

        mdir = wdir / "_merged"
        mdir.mkdir(exist_ok=True)
        dfile.rename(mdir / dfile.name)
        if afile.exists():
            afile.rename(mdir / afile.name)

    ledger.close()
    # drop dangling edges
    idset = set(nodes)
    clean = [e for e in edges.values() if e["source"] in idset and e["target"] in idset]
    graph["nodes"] = list(nodes.values())
    graph["edges"] = clean
    (ua / "knowledge-graph.json").write_text(json.dumps(graph, ensure_ascii=False, indent=1))
    print(json.dumps({"wave": a.wave, "distilled_now": n_dist, "entities_added": n_ent,
                      "claims_added": n_claim, "graph_nodes": len(nodes), "graph_edges": len(clean),
                      "wiki_dir": str(wiki)}, indent=2))


def cmd_status(a):
    ws = Path(a.workspace).resolve()
    ua = _ua(ws)
    man = json.loads((ua / "distill-manifest.json").read_text())
    done = _ledger_done(ws)
    from collections import Counter
    per_wave_total = Counter(v["wave"] for v in man["items"].values())
    per_wave_done = Counter(man["items"][i]["wave"] for i in done if i in man["items"])
    print(json.dumps({"total": man["n_items"], "done": len(done),
                      "remaining": man["n_items"] - len(done),
                      "per_wave": {f"w{w}": f"{per_wave_done.get(w,0)}/{per_wave_total[w]}"
                                   for w in sorted(per_wave_total)}}, indent=2))


def _note_ctx(p, default):
    try:
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()[:40]:
            m = re.match(r"^context_id:\s*(\S+)", ln)
            if m:
                return m.group(1)
    except Exception:  # noqa: BLE001
        pass
    return default


def cmd_er1_sync(a):
    """Sync distilled WIKI notes to ER1 as linked children of their raw items.

    LOCAL TARGET ONLY (https://127.0.0.1:8081), matching the er1-comment skill —
    prod/stage are gated by design. Dry-run by default; pass --confirm to POST.
    Idempotent via er1-sync-ledger.jsonl. NOTE: raw parents must exist in the
    target ER1 or the link/parent tag orphans (SPEC-0269 OQ — prod path is P3).
    """
    import os
    import subprocess
    import tempfile

    ws = Path(a.workspace).resolve()
    ua = _ua(ws)
    ER1 = "https://127.0.0.1:8081"
    man = json.loads((ua / "distill-manifest.json").read_text())
    led = ua / "distill-ledger.jsonl"
    entries = [json.loads(l) for l in led.read_text().splitlines() if l.strip()] if led.exists() else []
    sledp = ua / "er1-sync-ledger.jsonl"
    synced = {json.loads(l)["id"] for l in sledp.read_text().splitlines() if l.strip()} if sledp.exists() else set()

    key = ""
    if a.confirm:
        key = subprocess.run(["security", "find-generic-password", "-s", "aims-core-er1",
                              "-a", os.environ.get("USER", ""), "-w"],
                             capture_output=True, text=True).stdout.strip()
        if not key:
            print("ERROR: ER1_API_KEY not in keychain (aims-core-er1)", file=sys.stderr)
            sys.exit(1)

    pending = [e for e in entries if e["id"] not in synced]
    plan, posted = [], 0
    sled = sledp.open("a") if a.confirm else None
    for e in pending:
        nid = e["id"]
        wiki = ws / "WIKI" / f"{nid}.md"
        if not wiki.exists():
            continue
        src = ws / man["items"].get(nid, {}).get("path", f"{man['notes_subdir']}/{nid}.md")
        ctx = _note_ctx(src, a.ctx)
        tags = f"link/parent/{ctx}/{nid},claude-code.distilled,distilled,spec-0269,project:mirkos-braindump"
        plan.append({"id": nid, "ctx": ctx, "tags": tags})
        if not a.confirm:
            if a.limit and len(plan) >= a.limit:
                break
            continue
        bt = tempfile.NamedTemporaryFile("w", suffix=".md", delete=False)
        bt.write(wiki.read_text(encoding="utf-8"))
        bt.close()
        r = subprocess.run(["curl", "-sk", "-X", "POST", f"{ER1}/upload_2",
                            "-H", f"X-API-KEY: {key}", "-F", f"context_id={ctx}",
                            "-F", "content_type=text-note", "-F", "comment_text_only=true",
                            "-F", f"tags={tags}", "-F", f"transcript=<{bt.name}",
                            "-F", f"description=Distilled: {nid}", "--max-time", "30"],
                           capture_output=True, text=True)
        os.unlink(bt.name)
        doc = ""
        m = re.search(r'"(?:doc_id|id)"\s*:\s*"([^"]+)"', r.stdout)
        if m:
            doc = m.group(1)
        if doc:
            sled.write(json.dumps({"id": nid, "er1_id": doc, "ctx": ctx, "ts": _now()}) + "\n")
            posted += 1
        else:
            print(f"[er1-sync] WARN no doc_id for {nid}: {r.stdout[:120]}", file=sys.stderr)
        if a.limit and posted >= a.limit:
            break
    if sled:
        sled.close()
    if not a.confirm:
        (ua / "er1-sync-plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=1))
        print(json.dumps({"mode": "DRY-RUN (no writes)", "target": ER1,
                          "pending": len(pending), "planned_preview": len(plan),
                          "note": "local-only target; raw parents must exist there (prod path = SPEC-0269 P3)",
                          "sample": plan[:3]}, indent=2))
    else:
        print(json.dumps({"mode": "LIVE", "target": ER1, "posted": posted,
                          "remaining": len(pending) - posted}, indent=2))


def cmd_export_gephi(a):
    """Export the distilled knowledge graph to Gephi-native GEXF (+ GraphML).

    Nodes colored by type (article/entity/topic/claim), sized by degree; edges
    carry their relation type (builds_on/contradicts/…) + weight.
    """
    from xml.sax.saxutils import quoteattr
    ws = Path(a.workspace).resolve()
    ua = _ua(ws)
    g = json.loads((ua / "knowledge-graph.json").read_text())
    nodes, edges = g["nodes"], g["edges"]
    deg = {}
    for e in edges:
        deg[e["source"]] = deg.get(e["source"], 0) + 1
        deg[e["target"]] = deg.get(e["target"], 0) + 1
    COLORS = {"article": (79, 120, 200), "entity": (224, 104, 60),
              "claim": (52, 168, 83), "topic": (168, 85, 247)}

    def q(s):
        return quoteattr("" if s is None else str(s))

    out = []
    if a.format in ("gexf", "both"):
        L = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<gexf xmlns="http://gexf.net/1.3" xmlns:viz="http://gexf.net/1.3/viz" version="1.3">',
             '<meta><creator>m3c distill_backfill (SPEC-0269)</creator>'
             '<description>mirkos-braindump distilled knowledge graph</description></meta>',
             '<graph defaultedgetype="directed" mode="static">',
             '<attributes class="node"><attribute id="0" title="type" type="string"/>'
             '<attribute id="1" title="path" type="string"/>'
             '<attribute id="2" title="summary" type="string"/></attributes>',
             '<attributes class="edge"><attribute id="0" title="reltype" type="string"/></attributes>',
             '<nodes>']
        for n in nodes:
            nid = n["id"]
            t = n.get("type", "")
            r, gg, b = COLORS.get(t, (150, 150, 150))
            size = 5 + (deg.get(nid, 0) ** 0.5) * 4
            L.append(f'<node id={q(nid)} label={q(n.get("name") or nid)}>')
            L.append(f'<attvalues><attvalue for="0" value={q(t)}/>'
                     f'<attvalue for="1" value={q(n.get("filePath", ""))}/>'
                     f'<attvalue for="2" value={q((n.get("summary") or "")[:240])}/></attvalues>')
            L.append(f'<viz:color r="{r}" g="{gg}" b="{b}"/><viz:size value="{size:.1f}"/>')
            L.append('</node>')
        L.append('</nodes><edges>')
        for i, e in enumerate(edges):
            L.append(f'<edge id="{i}" source={q(e["source"])} target={q(e["target"])} '
                     f'weight="{e.get("weight", 1)}" label={q(e.get("type", ""))}>'
                     f'<attvalues><attvalue for="0" value={q(e.get("type", ""))}/></attvalues></edge>')
        L.append('</edges></graph></gexf>')
        p = ua / "braindump.gexf"
        p.write_text("\n".join(L), encoding="utf-8")
        out.append(str(p))
    if a.format in ("graphml", "both"):
        L = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
             '<key id="label" for="node" attr.name="label" attr.type="string"/>',
             '<key id="ntype" for="node" attr.name="type" attr.type="string"/>',
             '<key id="summary" for="node" attr.name="summary" attr.type="string"/>',
             '<key id="reltype" for="edge" attr.name="reltype" attr.type="string"/>',
             '<key id="weight" for="edge" attr.name="weight" attr.type="double"/>',
             '<graph edgedefault="directed">']
        for n in nodes:
            L.append(f'<node id={q(n["id"])}><data key="label">{q(n.get("name") or n["id"])[1:-1]}</data>'
                     f'<data key="ntype">{q(n.get("type", ""))[1:-1]}</data>'
                     f'<data key="summary">{q((n.get("summary") or "")[:240])[1:-1]}</data></node>')
        for i, e in enumerate(edges):
            L.append(f'<edge id="e{i}" source={q(e["source"])} target={q(e["target"])}>'
                     f'<data key="reltype">{q(e.get("type", ""))[1:-1]}</data>'
                     f'<data key="weight">{e.get("weight", 1)}</data></edge>')
        L.append('</graph></graphml>')
        p = ua / "braindump.graphml"
        p.write_text("\n".join(L), encoding="utf-8")
        out.append(str(p))
    print(json.dumps({"nodes": len(nodes), "edges": len(edges), "files": out}, indent=2))


def main():
    ap = argparse.ArgumentParser(prog="distill_backfill")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("manifest"); m.add_argument("-w", "--workspace", required=True)
    m.add_argument("--notes-subdir", default="NOTES/mft"); m.add_argument("--batch-size", type=int, default=15)
    m.add_argument("--waves", type=int, default=5)
    for name in ("prepare-wave", "merge-wave"):
        s = sub.add_parser(name); s.add_argument("-w", "--workspace", required=True)
        s.add_argument("--wave", type=int, required=True)
    st = sub.add_parser("status"); st.add_argument("-w", "--workspace", required=True)
    es = sub.add_parser("er1-sync"); es.add_argument("-w", "--workspace", required=True)
    es.add_argument("--confirm", action="store_true", help="actually POST (default: dry-run)")
    es.add_argument("--limit", type=int, default=0)
    es.add_argument("--ctx", default="107677460544181387647___mft")
    eg = sub.add_parser("export-gephi"); eg.add_argument("-w", "--workspace", required=True)
    eg.add_argument("--format", choices=["gexf", "graphml", "both"], default="both")
    a = ap.parse_args()
    {"manifest": cmd_manifest, "prepare-wave": cmd_prepare_wave,
     "merge-wave": cmd_merge_wave, "status": cmd_status,
     "er1-sync": cmd_er1_sync, "export-gephi": cmd_export_gephi}[a.cmd](a)


if __name__ == "__main__":
    main()
