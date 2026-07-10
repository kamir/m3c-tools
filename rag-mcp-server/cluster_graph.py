#!/usr/bin/env python3
"""cluster_graph — community detection + interactive cluster viewer (SPEC-0269).

Runs Louvain community detection (networkx) on the distilled knowledge graph,
writes the cluster id + color back onto every node, emits `clusters.json`
(ranked summary), and renders a self-contained `cluster-viewer.html` that shows
the **top 3 clusters** by default with toggle-on/off for the rest.

  cluster_graph.py -w <repo> [--no-viewer]

Called automatically by `distill_backfill.py merge-wave` so clusters are always
precomputed whenever the graph is recreated.
"""
from __future__ import annotations

import argparse
import colorsys
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
N_NAMED = 24          # clusters that get a distinct hue; the rest share a muted gray
GRAY = "#596072"


def _color(rank):
    if rank < N_NAMED:
        h = (rank * 0.61803398875) % 1.0           # golden-ratio hue spacing
        r, g, b = colorsys.hls_to_rgb(h, 0.56, 0.62)
        return "#%02x%02x%02x" % (int(r * 255), int(g * 255), int(b * 255))
    return GRAY


def run(ws_path, viewer=True):
    import networkx as nx
    from networkx.algorithms import community

    ws = Path(ws_path).resolve()
    ua = ws / ".understand-anything"
    gp = ua / "knowledge-graph.json"
    g = json.loads(gp.read_text())
    nodes, edges = g["nodes"], g["edges"]

    deg = {}
    for e in edges:
        deg[e["source"]] = deg.get(e["source"], 0) + 1
        deg[e["target"]] = deg.get(e["target"], 0) + 1

    G = nx.Graph()
    G.add_nodes_from(n["id"] for n in nodes)
    for e in edges:
        s, t = e["source"], e["target"]
        if s != t and G.has_node(s) and G.has_node(t):
            w = float(e.get("weight", 1) or 1)
            if G.has_edge(s, t):
                G[s][t]["weight"] += w
            else:
                G.add_edge(s, t, weight=w)

    comms = community.louvain_communities(G, weight="weight", seed=42)
    comms = sorted(comms, key=len, reverse=True)          # rank 0 = largest
    rank_of = {nid: r for r, c in enumerate(comms) for nid in c}

    nname = {n["id"]: (n.get("name") or n["id"]) for n in nodes}
    ntype = {n["id"]: n.get("type") for n in nodes}

    clusters = []
    for r, c in enumerate(comms):
        members = list(c)
        topics = [m for m in members if ntype.get(m) == "topic"]
        pick = max(topics or members, key=lambda m: deg.get(m, 0))
        label = nname.get(pick, "?")
        label = label[:40] + "…" if len(label) > 41 else label
        top = sorted(members, key=lambda m: deg.get(m, 0), reverse=True)[:5]
        clusters.append({"rank": r, "size": len(members), "color": _color(r),
                         "label": label, "top": [nname.get(m, "")[:60] for m in top]})

    for n in nodes:
        r = rank_of.get(n["id"], len(comms))
        n["cluster"] = r
        n["clusterColor"] = _color(r)
    g["clusters"] = [{"rank": c["rank"], "size": c["size"], "color": c["color"], "label": c["label"]}
                     for c in clusters]
    gp.write_text(json.dumps(g, ensure_ascii=False, indent=1))
    (ua / "clusters.json").write_text(json.dumps(clusters, ensure_ascii=False, indent=1))

    if viewer:
        vnodes = [{"id": n["id"], "label": nname[n["id"]][:80], "type": ntype.get(n["id"]),
                   "cluster": n["cluster"], "color": n["clusterColor"], "deg": deg.get(n["id"], 0),
                   "summary": (n.get("summary") or "")[:180]} for n in nodes]
        vlinks = [{"source": e["source"], "target": e["target"], "type": e.get("type")} for e in edges]
        vclusters = [{"rank": c["rank"], "size": c["size"], "color": c["color"], "label": c["label"]}
                     for c in clusters]
        data = {"nodes": vnodes, "links": vlinks, "clusters": vclusters}
        tpl = (HERE / "cluster_viewer_template.html").read_text()
        (ua / "cluster-viewer.html").write_text(
            tpl.replace("/*__DATA__*/", json.dumps(data, ensure_ascii=False)))

    return {"communities": len(comms),
            "top3": [{"label": c["label"], "size": c["size"]} for c in clusters[:3]],
            "nodes_in_top3": sum(c["size"] for c in clusters[:3]),
            "viewer": str(ua / "cluster-viewer.html") if viewer else None}


def main():
    ap = argparse.ArgumentParser(prog="cluster_graph")
    ap.add_argument("-w", "--workspace", required=True)
    ap.add_argument("--no-viewer", action="store_true")
    a = ap.parse_args()
    print(json.dumps(run(a.workspace, viewer=not a.no_viewer), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
