#!/usr/bin/env python3
"""wiki_scaffold — turn frontmatter-tagged notes into a Karpathy-wiki index.md
so Understand-Anything's /understand-knowledge can build a real knowledge graph
(SPEC-0268 companion; the RAG->graph bridge).

v1 derives categories from note frontmatter `tags:` (the user's own labels),
non-destructively: it writes a single <ws>/index.md with `## category` headings
and `[[NOTES/<ctx>/<id>]]` wikilinks. It does NOT modify the notes. A future v2
can cluster by turbovec embeddings instead of tags.

    wiki_scaffold.py -w <repo> [--notes-subdir NOTES] [--top N] [--min-size M]
"""
from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

_TAGS_RE = re.compile(r"^tags:\s*\[(.*?)\]", re.M)
_TITLE_RE = re.compile(r"^title:\s*(.+)$", re.M)
_TT_RE = re.compile(r"^transcript_text:\s*(.+)$", re.M)
_H1_RE = re.compile(r"^#\s+(.+)$", re.M)


def is_content_tag(t: str) -> bool:
    """Keep human theme tags; drop sync/plumbing tags."""
    if not t or any(c in t for c in ":/@."):
        return False
    return t.lower() not in {"github-synced", "synced", "text", "memory", "observation"}


def _clean_title(s: str) -> str:
    s = re.sub(r"[\"'`*_#>]", "", s).strip()
    return (s[:90] + "…") if len(s) > 91 else s


def read_meta(p: Path):
    txt = p.read_text(encoding="utf-8", errors="replace")
    m = _TAGS_RE.search(txt)
    tags = [x.strip().strip("\"'") for x in m.group(1).split(",")] if m else []
    tags = [t for t in tags if is_content_tag(t)]

    title = None
    mt = _TITLE_RE.search(txt)
    if mt and mt.group(1).strip():
        title = mt.group(1).strip()
    if not title:
        mtt = _TT_RE.search(txt)
        if mtt and mtt.group(1).strip() and not set(mtt.group(1).strip()) <= {"-", " "}:
            title = mtt.group(1).strip()
    if not title:
        mh = _H1_RE.search(txt)
        if mh:
            title = mh.group(1).strip()
    if not title:
        title = p.stem
    return tags, _clean_title(title)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", "-w", required=True)
    ap.add_argument("--notes-subdir", default="NOTES")
    ap.add_argument("--top", type=int, default=30, help="max number of categories")
    ap.add_argument("--min-size", type=int, default=3, help="min notes for its own category")
    a = ap.parse_args()

    ws = Path(a.workspace).resolve()
    notes = sorted((ws / a.notes_subdir).rglob("*.md"))
    meta = {}
    freq = Counter()
    for p in notes:
        tags, title = read_meta(p)
        meta[p] = (tags, title)
        freq.update(tags)

    top = {t for t, _ in freq.most_common(a.top) if freq[t] >= a.min_size}

    cats: dict[str, list] = {}
    for p in notes:
        tags, title = meta[p]
        cand = [t for t in tags if t in top]
        cat = max(cand, key=lambda t: freq[t]) if cand else "Uncategorized"
        rel = p.relative_to(ws).with_suffix("").as_posix()
        cats.setdefault(cat, []).append((rel, title))

    ordered = sorted(cats.items(), key=lambda kv: (-len(kv[1]), kv[0]))

    lines = ["# Mirko's Braindump — Knowledge Index", "",
             f"> Auto-generated category catalog for `/understand-knowledge` "
             f"(SPEC-0268 RAG→graph bridge). {len(notes)} notes · "
             f"{len([c for c in cats if c != 'Uncategorized'])} themed categories. "
             f"Categories derived from note frontmatter tags; regenerate with `wiki_scaffold.py`.", ""]
    wl = 0
    for cat, items in ordered:
        lines.append(f"## {cat.replace('-', ' ').title()}")
        for rel, title in sorted(items, key=lambda x: x[1].lower()):
            lines.append(f"- [[{rel}]] — {title}")
            wl += 1
        lines.append("")

    out = ws / "index.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out}")
    print(f"notes={len(notes)} categories={len(cats)} wikilinks={wl}")
    print("top categories:", ", ".join(f"{c}({len(i)})" for c, i in ordered[:12]))


if __name__ == "__main__":
    main()
