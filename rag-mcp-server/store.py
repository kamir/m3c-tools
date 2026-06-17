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
            """
        )
        self.conn.commit()

    def reset(self):
        self.conn.executescript("DELETE FROM chunks; DELETE FROM files; DELETE FROM meta;")
        self.conn.commit()

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
