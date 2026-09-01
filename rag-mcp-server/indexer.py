"""Workspace indexer + incremental sync over a turbovec IdMapIndex (SPEC-0268).

build()  — full index from scratch.
sync()   — re-embed only files changed/added/deleted since the last sync.
search() — embed a query, optional path_prefix / since_days allowlist, hydrate.
verify() — FRESH/STALE: does the committed index match the current workspace?
stats()  — counts + state, no model load.

Git-tracked artifacts in <ws>/.rag/ (see SPEC-0268 "Tracking the index in git"):
  index.tvim     binary vectors            -> Git LFS
  chunks.jsonl   id->location, sorted       -> plain git (diff-reviewable)
  files.jsonl    path->content hash, sorted -> plain git
  state.json     manifest + corpus_hash     -> plain git
  config.yaml    per-repo config            -> plain git
  meta.sqlite    derived runtime cache      -> gitignored, rebuilt from jsonl
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from chunker import chunk_file
from embedder import Embedder
from store import Store

_ID_MASK = 0x7FFFFFFFFFFFFFFF  # 63-bit: fits SQLite INTEGER, valid uint64 for turbovec


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _chunk_id(rel, ci):
    return int.from_bytes(hashlib.sha1(f"{rel}#{ci}".encode()).digest()[:8], "big") & _ID_MASK


def _tv_search(idx, qv, k, allow):
    kwargs = {"allowlist": allow} if allow is not None else {}
    try:
        res = idx.search(qv, k, **kwargs)
    except TypeError:
        res = idx.search(qv[0], k, **kwargs)
    scores, ids = res
    return np.asarray(scores).reshape(-1), np.asarray(ids).reshape(-1)


class Indexer:
    def __init__(self, workspace, cfg, embedder=None):
        self.ws = Path(workspace).resolve()
        self.cfg = cfg
        self.rag_dir = self.ws / ".rag"
        self.rag_dir.mkdir(exist_ok=True)
        self.index_path = self.rag_dir / "index.tvim"
        self.db_path = self.rag_dir / "meta.sqlite"
        self.state_path = self.rag_dir / "state.json"
        self.chunks_jsonl = self.rag_dir / "chunks.jsonl"
        self.files_jsonl = self.rag_dir / "files.jsonl"
        self.store = Store(str(self.db_path))
        self._embedder = embedder

    @property
    def embedder(self):
        if self._embedder is None:
            self._embedder = Embedder(self.cfg["model"],
                                     max_seq_length=self.cfg.get("max_seq_length", 512))
        return self._embedder

    # ---------- file discovery ----------
    def _iter_files(self):
        inc_ext = {os.path.splitext(g)[1].lower() for g in self.cfg["include"] if os.path.splitext(g)[1]}
        exc_dirs = {e.replace("\\", "/").split("/")[0] for e in self.cfg["exclude"] if e}
        for p in self.ws.rglob("*"):
            if not p.is_file():
                continue
            rel_parts = p.relative_to(self.ws).parts
            if any(seg in exc_dirs for seg in rel_parts):
                continue
            if p.suffix.lower() not in inc_ext:
                continue
            yield p.relative_to(self.ws).as_posix(), p

    @staticmethod
    def _file_hash(p):
        h = hashlib.sha1()
        h.update(p.read_bytes())
        return h.hexdigest()

    def _chunk_one(self, rel, p):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return []
        chunks = chunk_file(rel, text,
                            self.cfg["chunk"]["max_chars"],
                            self.cfg["chunk"]["overlap_chars"])
        return [(_chunk_id(rel, ci), rel, c.heading, c.line_start, c.line_end, c.text)
                for ci, c in enumerate(chunks)]

    @staticmethod
    def _corpus_hash(path_hash_pairs):
        h = hashlib.sha1()
        for path, fh in sorted(path_hash_pairs):
            h.update(f"{path}\t{fh}\n".encode())
        return h.hexdigest()

    # ---------- git-tracked exports ----------
    def _export_jsonl(self):
        with open(self.chunks_jsonl, "w", encoding="utf-8") as f:
            for r in self.store.conn.execute(
                    "SELECT id,path,heading,line_start,line_end FROM chunks "
                    "ORDER BY path,line_start,id"):
                f.write(json.dumps({"id": r[0], "path": r[1], "heading": r[2],
                                    "line_start": r[3], "line_end": r[4]},
                                   ensure_ascii=False) + "\n")
        with open(self.files_jsonl, "w", encoding="utf-8") as f:
            for r in self.store.conn.execute(
                    "SELECT path,file_hash,n_chunks FROM files ORDER BY path"):
                f.write(json.dumps({"path": r[0], "file_hash": r[1], "n_chunks": r[2]},
                                   ensure_ascii=False) + "\n")

    def _ensure_store(self):
        """Rebuild the local SQLite cache from the git-tracked jsonl if absent.

        Hydrates chunk text from the (committed, same-commit) source files, so a
        fresh clone becomes searchable with zero re-embedding.
        """
        if self.store.counts()[0] > 0:
            return
        if not self.chunks_jsonl.exists():
            return
        if self.files_jsonl.exists():
            with open(self.files_jsonl, encoding="utf-8") as f:
                for line in f:
                    o = json.loads(line)
                    p = self.ws / o["path"]
                    mtime = p.stat().st_mtime if p.exists() else 0.0
                    self.store.upsert_file(o["path"], o["file_hash"], mtime, o.get("n_chunks", 0))
        cache, rows = {}, []
        with open(self.chunks_jsonl, encoding="utf-8") as f:
            for line in f:
                o = json.loads(line)
                p = self.ws / o["path"]
                if p not in cache:
                    try:
                        cache[p] = p.read_text(encoding="utf-8", errors="replace").split("\n")
                    except Exception:  # noqa: BLE001
                        cache[p] = []
                lines = cache[p]
                text = "\n".join(lines[o["line_start"] - 1:o["line_end"]]) or o["heading"]
                rows.append((o["id"], o["path"], o["heading"],
                             o["line_start"], o["line_end"], text))
        if rows:
            self.store.insert_chunks(rows)

    # ---------- build ----------
    def build(self):
        from turbovec import IdMapIndex
        emb = self.embedder
        self.store.reset()
        idx = IdMapIndex(emb.dim, self.cfg["bit_width"])

        rows, files_meta, seen = [], [], set()
        dup = 0
        for rel, p in self._iter_files():
            frows = self._chunk_one(rel, p)
            kept = []
            for r in frows:
                if r[0] in seen:
                    dup += 1
                    continue
                seen.add(r[0])
                kept.append(r)
            rows.extend(kept)
            files_meta.append((rel, self._file_hash(p), p.stat().st_mtime, len(kept)))

        print(f"[index] {len(files_meta)} files, {len(rows)} chunks"
              f"{f' ({dup} id-collisions skipped)' if dup else ''}; "
              f"embedding on {emb.device}...", file=sys.stderr)

        if rows:
            vecs = emb.encode([r[5] for r in rows],
                             batch_size=self.cfg.get("embed_batch_size", 16))
            ids = np.array([r[0] for r in rows], dtype=np.uint64)
            idx.add_with_ids(vecs, ids)
            self.store.insert_chunks(rows)
        idx.write(str(self.index_path))
        for fm in files_meta:
            self.store.upsert_file(*fm)
        self._export_jsonl()
        corpus = self._corpus_hash([(fm[0], fm[1]) for fm in files_meta])
        n_chunks, n_files = self.store.counts()
        self._write_state(n_chunks, n_files, corpus)
        return {"files": n_files, "chunks": n_chunks, "device": emb.device,
                "id_collisions": dup, "corpus_hash": corpus[:12]}

    # ---------- incremental sync ----------
    def sync(self):
        from turbovec import IdMapIndex
        if not self.index_path.exists():
            return self.build()
        self._ensure_store()
        st = self._read_state()
        if st.get("model") != self.cfg["model"]:
            print("[sync] model changed -> full rebuild", file=sys.stderr)
            return self.build()

        idx = IdMapIndex.load(str(self.index_path))
        disk = dict(self._iter_files())
        db_files = self.store.all_files()
        added = changed = deleted = 0

        for rel in list(db_files):
            if rel not in disk:
                for cid in self.store.chunk_ids_for_file(rel):
                    try:
                        idx.remove(int(cid))
                    except Exception:  # noqa: BLE001
                        pass
                self.store.delete_file(rel)
                deleted += 1

        to_embed, upd_files = [], []
        for rel, p in disk.items():
            h = self._file_hash(p)
            old = db_files.get(rel)
            if old == h:
                continue
            if old is not None:
                for cid in self.store.chunk_ids_for_file(rel):
                    try:
                        idx.remove(int(cid))
                    except Exception:  # noqa: BLE001
                        pass
                self.store.delete_file(rel)
                changed += 1
            else:
                added += 1
            frows = self._chunk_one(rel, p)
            to_embed.extend(frows)
            upd_files.append((rel, h, p.stat().st_mtime, len(frows)))

        if to_embed:
            vecs = self.embedder.encode([r[5] for r in to_embed],
                                       batch_size=self.cfg.get("embed_batch_size", 16))
            ids = np.array([r[0] for r in to_embed], dtype=np.uint64)
            idx.add_with_ids(vecs, ids)
            self.store.insert_chunks(to_embed)
        for fm in upd_files:
            self.store.upsert_file(*fm)
        idx.write(str(self.index_path))
        self._export_jsonl()
        corpus = self._corpus_hash(list(self.store.all_files().items()))
        n_chunks, n_files = self.store.counts()
        self._write_state(n_chunks, n_files, corpus)
        return {"added": added, "changed": changed, "deleted": deleted,
                "embedded": len(to_embed), "files": n_files, "chunks": n_chunks,
                "corpus_hash": corpus[:12]}

    # ---------- search ----------
    def search(self, query, k=8, path_prefix="", since_days=0):
        from turbovec import IdMapIndex
        if not self.index_path.exists():
            return []
        self._ensure_store()
        idx = IdMapIndex.load(str(self.index_path))
        qv = self.embedder.encode([query], show_progress=False)

        allow_sets = []
        if path_prefix:
            allow_sets.append(set(self.store.ids_for_path_prefix(path_prefix)))
        if since_days:
            allow_sets.append(set(self.store.ids_for_recent(time.time() - since_days * 86400)))
        allow = None
        if allow_sets:
            common = set.intersection(*allow_sets)
            if not common:
                return []
            allow = np.array(sorted(common), dtype=np.uint64)

        scores, ids = _tv_search(idx, qv, k, allow)
        out = []
        for s, i in zip(scores, ids):
            row = self.store.get_chunk(int(i))
            if not row:
                continue
            out.append({
                "path": row["path"],
                "heading": row["heading"],
                "lines": f"{row['line_start']}-{row['line_end']}",
                "score": round(float(s), 4),
                "snippet": row["text"][:500],
            })
        return out

    # ---------- verify (FRESH/STALE) ----------
    def verify(self):
        pairs = [(rel, self._file_hash(p)) for rel, p in self._iter_files()]
        cur = self._corpus_hash(pairs)
        st = self._read_state()
        indexed = st.get("corpus_hash")
        return {"fresh": cur == indexed,
                "files_now": len(pairs),
                "files_indexed": st.get("files"),
                "corpus_hash_now": cur[:12],
                "corpus_hash_indexed": (indexed or "")[:12],
                "index_commit": st.get("git_commit"),
                "has_index": self.index_path.exists()}

    # ---------- state / stats ----------
    def _git_commit(self):
        try:
            r = subprocess.run(["git", "-C", str(self.ws), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=5)
            return r.stdout.strip() or None
        except Exception:  # noqa: BLE001
            return None

    def _write_state(self, n_chunks, n_files, corpus_hash):
        dim = self._embedder.dim if self._embedder else self.cfg.get("dim")
        st = {"model": self.cfg["model"], "dim": dim, "bit_width": self.cfg["bit_width"],
              "chunks": n_chunks, "files": n_files, "corpus_hash": corpus_hash,
              "git_commit": self._git_commit(), "updated_at": _now_iso()}
        self.state_path.write_text(json.dumps(st, indent=2) + "\n")

    def _read_state(self):
        try:
            return json.loads(self.state_path.read_text())
        except Exception:  # noqa: BLE001
            return {}

    def stats(self):
        self._ensure_store()
        n_chunks, n_files = self.store.counts()
        st = self._read_state()
        size = self.index_path.stat().st_size if self.index_path.exists() else 0
        return {"workspace": str(self.ws), "files": n_files, "chunks": n_chunks,
                "model": st.get("model"), "dim": st.get("dim"),
                "bit_width": st.get("bit_width"), "corpus_hash": (st.get("corpus_hash") or "")[:12],
                "git_commit": st.get("git_commit"), "updated_at": st.get("updated_at"),
                "index_bytes": size}
