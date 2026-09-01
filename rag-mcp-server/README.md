# rag-mcp-server — local workspace RAG (SPEC-0268)

Local, air-gapped semantic search over a github-backed workspace, built on
[turbovec](https://github.com/RyanCodrai/turbovec) (TurboQuant) + a local
embedding model (`BAAI/bge-m3`, multilingual). The shared engine lives here in
`m3c-tools` (next to `mcp-skill-server/`); the index lives per-repo in a
gitignored `.rag/`. The local twin of SPEC-0222 (ER1/aims-core memory search).

## Setup (once)

```bash
python3 -m venv --system-site-packages .venv      # inherits your system torch
.venv/bin/pip install -r requirements.txt
```

## CLI

```bash
RAG=/Users/kamir/GITHUB.kamir/m3c-tools/rag-mcp-server
WS=/path/to/repo

$RAG/.venv/bin/python $RAG/rag.py index  -w "$WS"           # full build
$RAG/.venv/bin/python $RAG/rag.py sync   -w "$WS"           # incremental
$RAG/.venv/bin/python $RAG/rag.py search -w "$WS" "query" -k 8
$RAG/.venv/bin/python $RAG/rag.py search -w "$WS" "q" --path-prefix SPEC/ --since-days 30 --json
$RAG/.venv/bin/python $RAG/rag.py status -w "$WS"
```

### Searching several repos at once

`-w` is repeatable on `search`: the query is embedded **once**, fanned out across
every index, and the hits are merged by score with a `workspace` label. Intent
(a private SPEC repo), reasoning (a notes repo) and reality (the running code)
are usually three different repos — one question should not have to be asked
three times.

```bash
$RAG/.venv/bin/python $RAG/rag.py search -w "$NOTES" -w "$SPECS" -w "$CODE" "why is X the way it is?" -k 8

export RAG_WORKSPACES="$NOTES:$SPECS:$CODE"      # standing set; -w still overrides
$RAG/.venv/bin/python $RAG/rag.py search "why is X the way it is?"
```

Scores are only comparable under the **same embedding model**, so a model mismatch
across workspaces is a hard error rather than a silently mis-ranked list; a
differing `bit_width` only warns. `index`/`sync`/`status`/`verify` still take a
single `-w` — building or committing several indexes from one invocation would
hide which one failed.

First `index` downloads `bge-m3` (~2.3 GB) to the HuggingFace cache, then runs
offline. The index (`index.tvim`), sidecar (`meta.sqlite`) and `state.json` are
written to `$WS/.rag/` (auto-added to `$WS/.gitignore`).

## MCP exposure

Register in `<repo>/.mcp.json` so agents get `rag_search` / `rag_workspaces` /
`rag_stats` / `rag_sync` / `rag_verify`. `--workspace` is repeatable here too, so
**one** registered server answers across every repo:

```json
{
  "mcpServers": {
    "rag": {
      "command": "/Users/kamir/GITHUB.kamir/m3c-tools/rag-mcp-server/.venv/bin/python",
      "args": [
        "/Users/kamir/GITHUB.kamir/m3c-tools/rag-mcp-server/rag_mcp_server.py",
        "--workspace", "/path/to/notes-repo",
        "--workspace", "/path/to/spec-repo",
        "--workspace", "/path/to/code-repo"
      ]
    }
  }
}
```

| Tool | Behaviour |
|---|---|
| `rag_search(query, k, path_prefix, since_days, workspace="")` | empty `workspace` searches all and merges by score; every hit carries `workspace` |
| `rag_workspaces()` | what this server can search, in merge order (first = primary) |
| `rag_stats(workspace="")` / `rag_verify(workspace="")` | per workspace; empty = all |
| `rag_sync(workspace="")` | incremental re-index, local-only; empty = all |

Indexers are cached per workspace and share one embedder, so the model is loaded
once per server process — not once per query.

## Layout

| File | Role |
|---|---|
| `chunker.py` | markdown/code-aware splitter (heading path + line ranges) |
| `embedder.py` | bge-m3 via sentence-transformers (MPS→CPU fallback) |
| `store.py` | SQLite sidecar (id → location/text, file hashes, path index) |
| `indexer.py` | build / incremental sync / search / stats |
| `rag.py` | CLI |
| `rag_mcp_server.py` | FastMCP stdio server |
| `config.default.yaml` | model, chunking, include/exclude globs |
