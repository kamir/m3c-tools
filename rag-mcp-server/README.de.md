# rag-mcp-server: lokales Workspace-RAG (SPEC-0268)

[Deutsch](README.de.md) | [English](README.md)

Lokale, vom Netzwerk getrennte semantische Suche über einen GitHub-gestützten
Workspace, auf Basis von [turbovec](https://github.com/RyanCodrai/turbovec)
(TurboQuant) und einem lokalen mehrsprachigen Embedding-Modell (`BAAI/bge-m3`).
Die gemeinsame Engine liegt hier in `m3c-tools` neben `mcp-skill-server/`;
der Index liegt je Repository unter `.rag/`, durch gitignore ausgeschlossen.
Die lokale Entsprechung zur Speichersuche von SPEC-0222 in ER1/aims-core.

## Einmalige Einrichtung

```bash
python3 -m venv --system-site-packages .venv      # inherits your system torch
.venv/bin/pip install -r requirements.txt
```

## CLI

```bash
RAG="$(git rev-parse --show-toplevel)/rag-mcp-server"
WS=/path/to/repo

$RAG/.venv/bin/python $RAG/rag.py index  -w "$WS"           # full build
$RAG/.venv/bin/python $RAG/rag.py sync   -w "$WS"           # incremental
$RAG/.venv/bin/python $RAG/rag.py search -w "$WS" "query" -k 8
$RAG/.venv/bin/python $RAG/rag.py search -w "$WS" "q" --path-prefix SPEC/ --since-days 30 --json
$RAG/.venv/bin/python $RAG/rag.py status -w "$WS"
```

### Mehrere Repositories gemeinsam durchsuchen

Bei `search` ist `-w` wiederholbar: Die Anfrage wird **einmal** eingebettet und
an alle Indizes verteilt. Treffer werden nach Score mit einer Kennzeichnung
`workspace` zusammengeführt. Absicht im privaten SPEC-Repository, Überlegungen
im Notiz-Repository und Realität im laufenden Code liegen üblicherweise in drei
verschiedenen Repositories. Dieselbe Frage sollte nicht dreimal gestellt werden müssen.

```bash
$RAG/.venv/bin/python $RAG/rag.py search -w "$NOTES" -w "$SPECS" -w "$CODE" "why is X the way it is?" -k 8

export RAG_WORKSPACES="$NOTES:$SPECS:$CODE"      # standing set; -w still overrides
$RAG/.venv/bin/python $RAG/rag.py search "why is X the way it is?"
```

Scores sind nur unter **demselben Embedding-Modell** vergleichbar. Unterschiedliche
Modelle zwischen Workspaces führen daher zu einem Fehler statt einer unbemerkt
falsch sortierten Liste. Abweichende `bit_width` erzeugt nur eine Warnung.
`index`/`sync`/`status`/`verify` akzeptieren weiterhin nur ein `-w`: Mehrere Indizes
in einem Aufruf zu erstellen oder zu speichern würde verbergen, welcher scheiterte.

Der erste Lauf von `index` lädt `bge-m3` mit etwa 2,3 GB in den HuggingFace-Cache;
anschließend ist der Betrieb offline. Index (`index.tvim`), Begleitdatei
(`meta.sqlite`) und `state.json` werden nach `$WS/.rag/` geschrieben.

### Versioniert oder nur auf der lokalen Maschine

Standardmäßig richtet `index` Git so ein, dass der Index **versioniert** wird:
LFS für `index.tvim`, nur `meta.sqlite` wird ignoriert. Ein frischer Klon ist
dadurch ohne erneute Embeddings durchsuchbar. In zwei Fällen ist das Gegenteil
gewünscht; `index` berücksichtigt beide:

| Situation | Verhalten |
|---|---|
| Workspace ist **nicht die Git-Wurzel**, etwa eine App im Monorepo | Automatisch erkannt: `.rag/` wird vollständig ignoriert, ohne LFS-Regel. Sonst lägen im **übergeordneten** Repository mehrere zehn MB unversionierter Index, die ein einziges `git add -A` versehentlich einchecken könnte. |
| `index --no-track` | Der Index ist bewusst ein maschinenlokales Artefakt. Jeder eingecheckte Neuaufbau kostet ein neues LFS-Objekt; kann eine zweite Maschine ihn einfach selbst aufbauen, ist das günstiger als die Übertragung. |

Die Auswahl steht als `git_tracking: tracked|none` in `.rag/config.yaml` und
bleibt **dauerhaft erhalten**. Ein späteres gewöhnliches `index` aktiviert die
LFS-Versionierung nicht stillschweigend wieder für einen bewusst lokal gehaltenen
Workspace. Zurückgeschaltet wird mit `index` ohne das Flag.

## Bereitstellung über MCP

In `<repo>/.mcp.json` registrieren, damit Agenten `rag_search` / `rag_workspaces` /
`rag_stats` / `rag_sync` / `rag_verify` erhalten. Auch hier ist `--workspace`
wiederholbar: **Ein** registrierter Server beantwortet Anfragen über alle Repositories.

```json
{
  "mcpServers": {
    "rag": {
      "command": "<REPO>/rag-mcp-server/.venv/bin/python",
      "args": [
        "<REPO>/rag-mcp-server/rag_mcp_server.py",
        "--workspace", "/path/to/notes-repo",
        "--workspace", "/path/to/spec-repo",
        "--workspace", "/path/to/code-repo"
      ]
    }
  }
}
```

| Werkzeug | Verhalten |
|---|---|
| `rag_search(query, k, path_prefix, since_days, workspace="")` | Leeres `workspace` durchsucht alle und führt nach Score zusammen; jeder Treffer enthält `workspace`. |
| `rag_workspaces()` | Durchsuchbare Workspaces dieses Servers in Zusammenführungsreihenfolge; erster = primärer Workspace. |
| `rag_stats(workspace="")` / `rag_verify(workspace="")` | Je Workspace; leer = alle. |
| `rag_sync(workspace="")` | Inkrementelle Neuindizierung, ausschließlich lokal; leer = alle. |

Indexer werden je Workspace zwischengespeichert und teilen einen Embedder.
Das Modell wird daher einmal je Serverprozess geladen, nicht je Anfrage.

## Dateiaufbau

| Datei | Aufgabe |
|---|---|
| `chunker.py` | Markdown-/Code-bewusste Aufteilung mit Überschriftenpfad und Zeilenbereichen |
| `embedder.py` | bge-m3 über sentence-transformers, Ausweichpfad MPS→CPU |
| `store.py` | SQLite-Begleitdatei: ID → Speicherort/Text, Datei-Hashes, Pfadindex |
| `indexer.py` | Aufbau, inkrementelle Synchronisierung, Suche und Statistiken |
| `rag.py` | CLI |
| `rag_mcp_server.py` | FastMCP-Server über stdio |
| `config.default.yaml` | Modell, Aufteilung und Glob-Muster für Ein-/Ausschlüsse |
