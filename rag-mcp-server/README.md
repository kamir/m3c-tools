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

First `index` downloads `bge-m3` (~2.3 GB) to the HuggingFace cache, then runs
offline. The index (`index.tvim`), sidecar (`meta.sqlite`) and `state.json` are
written to `$WS/.rag/` (auto-added to `$WS/.gitignore`).

## MCP exposure

Register in `<repo>/.mcp.json` so agents get `rag_search` / `rag_stats` / `rag_sync`:

```json
{
  "mcpServers": {
    "rag": {
      "command": "/Users/kamir/GITHUB.kamir/m3c-tools/rag-mcp-server/.venv/bin/python",
      "args": [
        "/Users/kamir/GITHUB.kamir/m3c-tools/rag-mcp-server/rag_mcp_server.py",
        "--workspace", "/path/to/repo"
      ]
    }
  }
}
```

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
