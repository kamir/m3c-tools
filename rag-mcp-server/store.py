"""SQLite sidecar for the turbovec index (SPEC-0268).

turbovec stores only (vector, uint64 id). This sidecar maps each id back to its
source location + text (for snippet hydration) and tracks per-file content
hashes (for incremental sync) and the path index that powers path_prefix
allowlist filtering.

Note: chunk ids are masked to 63 bits so they fit SQLite's signed INTEGER while
remaining valid uint64 values for turbovec.
"""
from __future__ import annotations

import sqlite3


class Store:
    def __init__(self, path):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS chunks(
              id         INTEGER PRIMARY KEY,
              path       TEXT NOT NULL,
              heading    TEXT,
              line_start INTEGER,
              line_end   INTEGER,
              text       TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS files(
              path      TEXT PRIMARY KEY,
              file_hash TEXT NOT NULL,
              mtime     REAL,
              n_chunks  INTEGER
            );
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
            CREATE INDEX IF NOT EXISTS idx_chunks_path ON chunks(path);
            -- Lexical half of hybrid retrieval. FTS5 ships with SQLite, so this
            -- costs no new dependency and no second model. Derived like the rest
            -- of meta.sqlite: dropped and rebuilt with the index, never committed.
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
                text, heading, path, content='chunks', content_rowid='id',
                tokenize='unicode61 remove_diacritics 2'
            );
            """
        )
        self.conn.commit()

    def reset(self):
        self.conn.executescript("DELETE FROM chunks; DELETE FROM files; DELETE FROM meta;")
        self.conn.commit()

    def rebuild_fts(self):
        """(Re)populate the FTS mirror from `chunks`. Cheap: it is a scan, no model."""
        with self.conn:
            self.conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('delete-all')")
            self.conn.execute(
                "INSERT INTO chunks_fts(rowid, text, heading, path) "
                "SELECT id, text, COALESCE(heading,''), path FROM chunks")

    def search_lexical(self, query, k=50, allow=None):
        """BM25 over the chunk text. Returns `(chunk_ids, n_from_identifier_pass)`.

        The query is reduced to bare terms OR-ed together: a user question is a
        sentence, not an FTS expression, and one stray quote would otherwise be a
        syntax error. Rare terms still dominate: that is exactly what BM25 is for
        and exactly what the dense side loses.
        """
        import re
        terms = [w for w in re.findall(r"[\w][\w.\-/]{2,}", query.lower()) if not w.isdigit()]
        if not terms:
            return []

        # Identifier-artige Begriffe zuerst, und zwar in einem EIGENEN Durchlauf.
        #
        # Ein blosses OR ueber alle Woerter geht hier schief, und nicht subtil:
        # BM25 belohnt Seltenheit, und in einem ueberwiegend englischen Korpus ist
        # ein deutsches Prosawort ("serverseitig") seltener als der gesuchte
        # Fachbegriff. Gemessen: die Frage "Wird propose-by-default serverseitig
        # erzwungen?" lieferte per OR sync_session.py und corps_album: der Begriff
        # ALLEIN findet admission.py auf Rang 2. Die Prosa uebertoent das Signal.
        #
        # Identifier erkennt man an ihrer FORM: Bindestrich, Punkt, Unterstrich,
        # Slash. Bewusst KEINE Laengenregel: "serverseitig" hat 12 Zeichen und
        # waere damit als Identifier durchgegangen, genau das deutsche Prosawort
        # also, das den Fachbegriff ueberstimmt hat. Interpunktion ist das
        # verlaessliche Signal, Laenge ist es nicht.
        def _ident(w):
            return any(c in w for c in "-._/")
        idents = [w for w in terms if _ident(w)]

        def _run(ws, limit):
            if not ws:
                return []
            expr = " OR ".join(f'"{w}"' for w in ws)
            try:
                return [int(r[0]) for r in self.conn.execute(
                    "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH ? "
                    "ORDER BY bm25(chunks_fts, 1.0, 2.0, 0.5) LIMIT ?", (expr, limit)).fetchall()]
            except Exception:  # noqa: BLE001: kein FTS (alter Index) oder unlesbarer Ausdruck
                return []

        ident_hits = _run(idents, k * 4)
        ordered = ident_hits + _run(terms, k * 4)
        n_ident = len(ident_hits)
        out, seen = [], set()
        for cid in ordered:
            if cid in seen:
                continue
            seen.add(cid)
            if allow is not None and cid not in allow:
                continue
            out.append(cid)
            if len(out) >= k:
                break
        # Wieviele der zurueckgegebenen Treffer stammen aus dem Identifier-Durchlauf?
        idset = set(ident_hits)
        return out, sum(1 for c in out if c in idset)

    def has_fts(self):
        try:
            return bool(self.conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name='chunks_fts'").fetchone())
        except Exception:      # noqa: BLE001
            return False

    def insert_chunks(self, rows):
        # rows: (id, path, heading, line_start, line_end, text)
        self.conn.executemany(
            "INSERT OR REPLACE INTO chunks(id,path,heading,line_start,line_end,text) "
            "VALUES(?,?,?,?,?,?)", rows)
        self.conn.commit()

    def upsert_file(self, path, file_hash, mtime, n_chunks):
        self.conn.execute(
            "INSERT OR REPLACE INTO files(path,file_hash,mtime,n_chunks) VALUES(?,?,?,?)",
            (path, file_hash, mtime, n_chunks))
        self.conn.commit()

    def delete_file(self, path):
        self.conn.execute("DELETE FROM chunks WHERE path=?", (path,))
        self.conn.execute("DELETE FROM files WHERE path=?", (path,))
        self.conn.commit()

    def chunk_ids_for_file(self, path):
        return [r[0] for r in self.conn.execute("SELECT id FROM chunks WHERE path=?", (path,))]

    def get_chunk(self, cid):
        return self.conn.execute("SELECT * FROM chunks WHERE id=?", (cid,)).fetchone()

    def ids_for_path_prefix(self, prefix):
        return [r[0] for r in self.conn.execute(
            "SELECT id FROM chunks WHERE path LIKE ?", (prefix + "%",))]

    def ids_for_recent(self, cutoff_ts):
        return [r[0] for r in self.conn.execute(
            "SELECT c.id FROM chunks c JOIN files f ON c.path=f.path WHERE f.mtime>=?",
            (cutoff_ts,))]

    def all_files(self):
        return {r["path"]: r["file_hash"]
                for r in self.conn.execute("SELECT path,file_hash FROM files")}

    def counts(self):
        n = self.conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        f = self.conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        return n, f
