#!/usr/bin/env python3
"""temporal_deltas — monthly graph-layer evolution + local/global deltas (SPEC-0270).

Slices the SPEC-0269 distilled knowledge graph into monthly layers (by note date),
clusters each layer (Louvain), and computes two delta series of "adding month m_k":
  V1 local  — baseline = the previous month only (sliding 2-month window)
  V2 global — baseline = the whole cumulative history so far
Each delta carries scalar metrics + a cluster correspondence; V2 also yields
per-cluster size-over-month trajectories.

  temporal_deltas.py -w <repo>

Outputs to <repo>/.understand-anything/: temporal-local.json, temporal-global.json,
temporal-summary.csv, temporal-trajectories.json, temporal-chart.html.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
_DATE = re.compile(r"^date:\s*(\d{4}-\d{2})", re.M)
CONTINUITY = {"builds_on", "cites", "exemplifies"}


# ---------- graph plumbing ----------
def _article_month(ws, nodes):
    am = {}
    for n in nodes:
        if n.get("type") != "article" or not n.get("filePath"):
            continue
        try:
            txt = open(os.path.join(ws, n["filePath"]), encoding="utf-8", errors="replace").read()[:800]
        except Exception:  # noqa: BLE001
            continue
        m = _DATE.search(txt)
        if m:
            am[n["id"]] = m.group(1)
    return am


def _louvain(node_ids, edge_triples):
    import networkx as nx
    from networkx.algorithms import community
    G = nx.Graph()
    G.add_nodes_from(node_ids)
    for s, t, w in edge_triples:
        if s != t and G.has_node(s) and G.has_node(t):
            if G.has_edge(s, t):
                G[s][t]["weight"] += w
            else:
                G.add_edge(s, t, weight=w)
    comms = sorted(community.louvain_communities(G, weight="weight", seed=42), key=len, reverse=True)
    mem = {nid: r for r, c in enumerate(comms) for nid in c}
    mod = community.modularity(G, comms, weight="weight") if G.number_of_edges() else 0.0
    return comms, mem, mod


class Graph:
    def __init__(self, ws):
        ws = Path(ws).resolve()
        self.ws = ws
        g = json.loads((ws / ".understand-anything" / "knowledge-graph.json").read_text())
        self.nodes = {n["id"]: n for n in g["nodes"]}
        self.edges = g["edges"]
        self.am = _article_month(str(ws), g["nodes"])
        self.deg = defaultdict(int)
        self.adj = defaultdict(set)
        self.etyped = []  # (s,t,weight,type)
        for e in self.edges:
            s, t = e["source"], e["target"]
            if s not in self.nodes or t not in self.nodes:
                continue
            w = float(e.get("weight", 1) or 1)
            self.deg[s] += 1
            self.deg[t] += 1
            self.adj[s].add(t)
            self.adj[t].add(s)
            self.etyped.append((s, t, w, e.get("type", "")))
        # non-article first-appearance month = earliest adjacent article month
        self.node_month = dict(self.am)
        for nid, n in self.nodes.items():
            if n.get("type") == "article":
                continue
            ms = [self.am[a] for a in self.adj[nid] if a in self.am]
            if ms:
                self.node_month[nid] = min(ms)
        self.months = sorted({m for m in self.am.values()})

    def label(self, members):
        members = list(members)
        topics = [m for m in members if self.nodes[m].get("type") == "topic"]
        pick = max(topics or members, key=lambda m: self.deg.get(m, 0))
        s = self.nodes[pick].get("name") or pick
        return (s[:36] + "…") if len(s) > 37 else s

    def layer(self, month_set):
        """Induced subgraph for a set of months → (node_ids, edge_triples, membership, modularity)."""
        arts = {a for a, m in self.am.items() if m in month_set}
        nset = set(arts)
        for a in arts:
            for nb in self.adj[a]:
                if self.nodes[nb].get("type") != "article":
                    nset.add(nb)
        etr = [(s, t, w) for (s, t, w, _ty) in self.etyped if s in nset and t in nset]
        comms, mem, mod = _louvain(nset, etr)
        return {"nodes": nset, "edges": etr, "comms": comms, "mem": mem, "mod": mod}


# ---------- delta ----------
def _delta(g: Graph, base, state, cur_month, top=15):
    bn, sn = base["nodes"], state["nodes"]
    added = sn - bn
    base_edges = len(base["edges"])
    state_edges = len(state["edges"])
    new_arts = {a for a in sn if g.am.get(a) == cur_month}
    bridge = cross = 0
    for (s, t, w, ty) in g.etyped:
        if s in sn and t in sn:
            sn_new = (s in new_arts and t in bn) or (t in new_arts and s in bn)
            if sn_new:
                bridge += 1
                if ty in CONTINUITY:
                    cross += 1
    # cluster correspondence (top state clusters by size) vs base clusters
    base_clusters = base["comms"]
    state_clusters = state["comms"]
    base_of = base["mem"]
    transitions, new_clusters = [], []
    # carried-node churn (purity of base→state contingency)
    carried = [n for n in sn if n in bn]
    if carried:
        cont = defaultdict(lambda: defaultdict(int))
        for n in carried:
            cont[base_of.get(n)][state["mem"].get(n)] += 1
        pure = sum(max(d.values()) for d in cont.values())
        churn = round(1 - pure / len(carried), 4)
    else:
        churn = 0.0
    for rank, c in enumerate(state_clusters[:top]):
        members = set(c)
        # best base cluster by overlap
        overlap = defaultdict(int)
        for n in members:
            br = base_of.get(n)
            if br is not None:
                overlap[br] += 1
        if overlap:
            fr = max(overlap, key=overlap.get)
            inter = overlap[fr]
            fsize = len(base_clusters[fr])
            jac = round(inter / (len(members) + fsize - inter), 3)
        else:
            fr, fsize, jac = None, 0, 0.0
        kind = ("new" if jac < 0.1 else "grown" if len(members) > fsize * 1.1
                else "shrunk" if len(members) < fsize * 0.9 else "stable")
        rec = {"to_rank": rank, "to_size": len(members), "label": g.label(members),
               "from_rank": fr, "from_size": fsize, "jaccard": jac,
               "delta_size": len(members) - fsize, "kind": kind}
        transitions.append(rec)
        if kind == "new" and len(members) >= 4:
            new_clusters.append({"rank": rank, "size": len(members), "label": g.label(members)})
    return {
        "month": cur_month,
        "articles_added": len(new_arts),
        "nodes_before": len(bn), "nodes_after": len(sn), "nodes_added": len(added),
        "edges_before": base_edges, "edges_after": state_edges, "edges_added": state_edges - base_edges,
        "clusters_after": len(state_clusters), "modularity_after": round(state["mod"], 4),
        "bridge_edges": bridge, "cross_month_builds_on": cross, "cluster_churn": churn,
        "transitions": transitions, "new_clusters": new_clusters,
    }


def run(ws):
    g = Graph(ws)
    ua = Path(g.ws) / ".understand-anything"
    months = g.months

    # V2 global cumulative + lineage trajectories
    glob, prev_state, prev_lineage = [], None, {}  # prev_lineage: state-rank -> lineage-id
    lineage_size = defaultdict(dict)  # lineage-id -> {month: size}
    lineage_label = {}
    next_lid = 0
    for k, m in enumerate(months):
        state = g.layer(set(months[: k + 1]))
        base = prev_state or {"nodes": set(), "edges": [], "comms": [], "mem": {}, "mod": 0.0}
        glob.append(_delta(g, base, state, m))
        # lineage: match each state cluster to a previous lineage by overlap
        cur_lineage = {}
        for rank, c in enumerate(state["comms"][:30]):
            members = set(c)
            best, bestov = None, 0
            for prank, lid in prev_lineage.items():
                if prank < len(prev_state["comms"]) if prev_state else False:
                    ov = len(members & set(prev_state["comms"][prank]))
                    if ov > bestov:
                        bestov, best = ov, lid
            if best is None or bestov < max(3, 0.2 * len(members)):
                lid = next_lid
                next_lid += 1
            else:
                lid = best
            cur_lineage[rank] = lid
            lineage_size[lid][m] = len(members)
            lineage_label[lid] = g.label(members)
        prev_lineage = cur_lineage
        prev_state = state

    # V1 local sliding 2-month window
    loc = []
    for k in range(1, len(months)):
        base = g.layer({months[k - 1]})
        state = g.layer({months[k - 1], months[k]})
        loc.append(_delta(g, base, state, months[k]))

    # trajectories: top final-size lineages
    traj = sorted(({"lineage": lid, "label": lineage_label[lid],
                    "final_size": max(sizes.values()), "sizes": sizes}
                   for lid, sizes in lineage_size.items()),
                  key=lambda x: x["final_size"], reverse=True)[:14]

    (ua / "temporal-global.json").write_text(json.dumps(glob, ensure_ascii=False, indent=1))
    (ua / "temporal-local.json").write_text(json.dumps(loc, ensure_ascii=False, indent=1))
    (ua / "temporal-trajectories.json").write_text(json.dumps(traj, ensure_ascii=False, indent=1))

    with open(ua / "temporal-summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["month", "series", "articles_added", "nodes_after", "edges_after",
                    "clusters", "modularity", "bridge_edges", "cross_builds_on", "churn"])
        for series, data in (("global", glob), ("local", loc)):
            for d in data:
                w.writerow([d["month"], series, d["articles_added"], d["nodes_after"], d["edges_after"],
                            d["clusters_after"], d["modularity_after"], d["bridge_edges"],
                            d["cross_month_builds_on"], d["cluster_churn"]])

    _chart(ua, months, glob, loc, traj)
    return {"months": len(months), "global_steps": len(glob), "local_steps": len(loc),
            "lineages": len(lineage_size), "outputs": [str(ua / x) for x in
            ("temporal-global.json", "temporal-local.json", "temporal-summary.csv",
             "temporal-trajectories.json", "temporal-chart.html")]}


def _chart(ua, months, glob, loc, traj):
    data = {"months": months,
            "global": {k: [d[k] for d in glob] for k in
                       ("articles_added", "nodes_added", "edges_added", "clusters_after",
                        "modularity_after", "bridge_edges", "cross_month_builds_on", "cluster_churn")},
            "localMonths": [d["month"] for d in loc],
            "local": {k: [d[k] for d in loc] for k in
                      ("articles_added", "nodes_added", "edges_added", "clusters_after",
                       "modularity_after", "bridge_edges", "cross_month_builds_on", "cluster_churn")},
            "traj": traj}
    tpl = (HERE / "temporal_chart_template.html").read_text()
    (ua / "temporal-chart.html").write_text(tpl.replace("/*__DATA__*/", json.dumps(data, ensure_ascii=False)))


def main():
    ap = argparse.ArgumentParser(prog="temporal_deltas")
    ap.add_argument("-w", "--workspace", required=True)
    a = ap.parse_args()
    print(json.dumps(run(a.workspace), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
