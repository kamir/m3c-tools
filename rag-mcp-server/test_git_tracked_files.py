"""Regression tests: in a git work tree the index covers tracked files only (BUG-0618).

`Indexer._iter_files` walked the file system, so ignored and untracked files of
the machine that built the index ended up in it. A clean clone of the same
commit could never reproduce that file set, and `verify()` reported the
committed index as stale on every clone. These tests fail against the file
system walk and pass when the file list comes from `git ls-files`.

Run:
    cd rag-mcp-server
    .venv/bin/python -m pytest test_git_tracked_files.py -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import numpy as np
import pytest
import yaml

from indexer import Indexer

HERE = Path(__file__).resolve().parent
GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
       "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"]


class _FakeEmbedder:
    dim = 32
    device = "cpu"

    def encode(self, texts, batch_size=16, show_progress=False):
        rng = np.random.default_rng(0)
        return rng.random((len(texts), self.dim), dtype=np.float32)


def _note(path, title):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# {title}\n\n" + f"{title} text. " * 40 + "\n")


@pytest.fixture(autouse=True)
def _no_outer_git(monkeypatch):
    # Under a git hook GIT_DIR and friends point at the outer repository.
    for key in list(os.environ):
        if key.startswith("GIT_"):
            monkeypatch.delenv(key)


@pytest.fixture
def cfg():
    c = yaml.safe_load((HERE / "config.default.yaml").read_text())
    c["bit_width"] = 4
    return c


@pytest.fixture
def repo():
    d = Path(tempfile.mkdtemp(prefix="raggit-"))
    subprocess.run(GIT + ["init", "-q", str(d)], check=True)
    (d / ".gitignore").write_text("private/\n")
    _note(d / "tracked.md", "tracked")
    _note(d / "sub" / "also-tracked.md", "also tracked")
    subprocess.run(GIT + ["-C", str(d), "add", "."], check=True)
    subprocess.run(GIT + ["-C", str(d), "commit", "-q", "-m", "init"], check=True)
    _note(d / "private" / "ignored.md", "ignored")
    _note(d / "untracked.md", "untracked")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _listed(ws, cfg):
    return {rel for rel, _ in Indexer(str(ws), cfg, embedder=_FakeEmbedder())._iter_files()}


def test_git_work_tree_lists_tracked_files_only(repo, cfg):
    assert _listed(repo, cfg) == {"tracked.md", "sub/also-tracked.md"}


def test_tracked_file_missing_on_disk_is_not_listed(repo, cfg):
    (repo / "tracked.md").unlink()
    assert _listed(repo, cfg) == {"sub/also-tracked.md"}


def test_workspace_below_the_repository_root(repo, cfg):
    assert _listed(repo / "sub", cfg) == {"also-tracked.md"}


def test_untracked_files_do_not_make_the_index_stale(repo, cfg):
    Indexer(str(repo), cfg, embedder=_FakeEmbedder()).build()
    _note(repo / "another-untracked.md", "another")
    _note(repo / "private" / "another-ignored.md", "another ignored")

    res = Indexer(str(repo), cfg, embedder=_FakeEmbedder()).verify()

    assert res["fresh"] is True
    assert res["files_now"] == res["files_indexed"] == 2


def test_directory_without_git_keeps_the_file_system_walk(cfg):
    d = Path(tempfile.mkdtemp(prefix="ragplain-"))
    try:
        _note(d / "a.md", "a")
        _note(d / "deep" / "b.md", "b")
        assert _listed(d, cfg) == {"a.md", "deep/b.md"}
    finally:
        shutil.rmtree(d, ignore_errors=True)
