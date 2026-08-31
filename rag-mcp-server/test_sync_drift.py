"""Regression tests for store/index drift in `Indexer.sync()` (SPEC-0268).

`sync()` commits its store deletes immediately but only writes index.tvim at the
very end of the pass. A crash in between therefore leaves chunk ids inside
index.tvim whose store rows are already gone. On the next pass those files look
new (`old is None`), so the removal branch never runs and `add_with_ids()` raised

    ValueError: id <n> already present in index

which is self-perpetuating: every following pass drifts the store further from
the index. Observed on mirkos-braindump 2026-08-28..31 — 5 consecutive nightly
failures on the same id, the store down to 5758 files / 50679 chunks against a
persisted index of 6173 / 58954.

Fixed in 05a98f5 ("incremental sync self-heals interrupted index"): dedup the
batch, then drop any already-resident id before `add_with_ids`. These tests pin
that behaviour down — they fail with the original ValueError against the parent
commit and pass against the fix.

A fake embedder keeps these tests model-free — no weights, no GPU, milliseconds.

Run:
    cd rag-mcp-server
    .venv/bin/python -m pytest test_sync_drift.py -v
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import numpy as np
import pytest
import yaml

from indexer import Indexer

HERE = Path(__file__).resolve().parent


class _FakeEmbedder:
    """Deterministic stand-in for the bge-m3 embedder."""

    dim = 32
    device = "cpu"

    def encode(self, texts, batch_size=16, show_progress=False):
        rng = np.random.default_rng(0)
        return rng.random((len(texts), self.dim), dtype=np.float32)


@pytest.fixture
def ws():
    d = Path(tempfile.mkdtemp(prefix="ragdrift-"))
    for i in range(6):
        (d / f"note{i}.md").write_text(f"# Titel {i}\n\n" + f"Inhalt {i}. " * 40 + "\n")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def cfg():
    c = yaml.safe_load((HERE / "config.default.yaml").read_text())
    c["bit_width"] = 4
    return c


def _indexer(ws, cfg):
    return Indexer(str(ws), cfg, embedder=_FakeEmbedder())


def _inject_drift(ix, victim):
    """Reproduce a crashed pass: drop the store rows, leave index.tvim alone."""
    ids = ix.store.chunk_ids_for_file(victim)
    assert ids, "fixture broken: victim file has no chunks"
    ix.store.delete_file(victim)
    return ids


def test_sync_heals_orphaned_index_ids(ws, cfg):
    """A file whose ids linger in the index but not the store re-indexes cleanly."""
    victim = "note3.md"
    _indexer(ws, cfg).build()
    ids_before = _inject_drift(_indexer(ws, cfg), victim)

    ix = _indexer(ws, cfg)
    assert victim not in ix.store.all_files(), "victim must look new to sync()"

    res = ix.sync()  # raised ValueError before the fix

    assert res["added"] == 1
    assert res["embedded"] == len(ids_before)
    # chunk ids are sha1(path#i) — a re-index must reproduce them exactly
    assert set(ix.store.chunk_ids_for_file(victim)) == set(ids_before)


def test_sync_after_healing_is_a_noop(ws, cfg):
    """The healed index converges: a second pass embeds nothing."""
    _indexer(ws, cfg).build()
    _inject_drift(_indexer(ws, cfg), "note3.md")
    _indexer(ws, cfg).sync()

    res = _indexer(ws, cfg).sync()

    assert res["embedded"] == 0
    assert (res["added"], res["changed"], res["deleted"]) == (0, 0, 0)


def test_sync_still_tracks_edits_and_deletes(ws, cfg):
    """The unconditional remove must not break ordinary change detection."""
    _indexer(ws, cfg).build()
    (ws / "note1.md").write_text("# Geaendert\n\n" + "Neuer Inhalt. " * 40 + "\n")
    (ws / "note2.md").unlink()

    res = _indexer(ws, cfg).sync()

    assert res["changed"] == 1
    assert res["deleted"] == 1
    assert res["added"] == 0
