---
layout: default
title: Programme
---

# Programme

Sprachen / Languages: [Deutsch](program-index.de.md) | [English](program-index.md)

**Was du ausführst.** Alle baubaren beziehungsweise ausführbaren Einstiegspunkte
im Repository: Go-Binärdateien, Python-MCP-Server und der Evaluations-Harness.

> Go-Modul: `github.com/kamir/m3c-tools`. Alle Go-Binärdateien landen in `./build/`.
> Ausführbare Dateien an der Wurzel (`m3c-tools`, `skillctl`, `skillctl`,
> `m3c-tools.exe`) sind von Git ignorierte Build-Artefakte statt Quellcode.

Siehe auch: [Dienste](service-index.de.md), die dauerhaft laufen, und
[Komponenten](component-index.de.md), aus denen die Programme bestehen.

## Go-Binärdateien unter `cmd/`

| Programm | Einstiegspunkt | Build | Aufgabe |
|---------|-------------|-------|------------|
| **m3c-tools** | `cmd/m3c-tools/` | `make build` | Haupt-CLI für multimodales Wissen; startet mit `--menubar` auch die macOS-Menüleisten-App. |
| **skillctl** | `cmd/skillctl/` | `make build-skillctl` | Vertrauens-CLI: Skills signieren, zulassen, offline prüfen, widerrufen und auditieren. |
| **skillctl-demo** | `cmd/skillctl-demo/` | `make build-skillctl-demo` | Eigenständige Offline-Demo, die einem CISO die live wirksame Angriffseindämmung der Szenarien S1/S2A/S5 mit echten Exit-Codes zeigt. |
| **secretctl** | `cmd/secretctl/` | `make build-secretctl` | Lesender Teil der Geheimnisrotations-CLI (SPEC-0438): `inventory` zeigt Ort und Aktualität eines Wertes, `verify` prüft dessen Akzeptanz beim Dienst. Werte werden nie ausgegeben, Vergleiche verwenden Fingerabdrücke. |
| **poc-menubar** | `cmd/poc-menubar/` | `make build-all` | Referenz-POC für die macOS-Menüleiste über `menuet`. |
| **poc-recorder** | `cmd/poc-recorder/` | `make build-all` | Referenz-POC für Mikrofonaufnahme über PortAudio. |
| **poc-transcript** | `cmd/poc-transcript/` | `make build-all` | Referenz-POC zum Laden von YouTube-Transkripten als Portierung der Kernbibliothek. |
| **poc-whisper** | `cmd/poc-whisper/` | `make build-all` | Referenz-POC für Whisper-Transkription als CLI-Unterprozess. |
| **skillctl-sim** | `cmd/skillctl-sim/` | `make build-skillctl-sim` | Simulation der Vertrauensebene: erzeugte Szenarien mit mehreren Akteuren, jeweils mit SPEC-abgeleiteter Erwartung, gegen echtes `skillctl` und echtes Git-Registry ausgeführt. `make sim`. |
| **docaudit** | `cmd/docaudit/` | `make build-gates` | Sperrende Prüfung der per AST erfassten CLI-Flags gegen das Handbuch in beiden Richtungen; zusätzlich alle dispatchten Verben gegen `--help`. |
| **exitaudit** | `cmd/exitaudit/` | `make build-gates` | Sperrende Prüfung aller Exit-Codes im Handbuch und [CLI-VERBS](v2/referenz/CLI-VERBS.de.md) gegen `pkg/skillctl/exitcode` sowie des als Code gelesenen `pull`-Gates. Meldet nicht vergleichbare Verbzeilen. |
| **verbaudit** | `cmd/verbaudit/` | `make build-gates` | Sperrende Prüfung der dispatchten skillctl-Verben gegen die Zuordnung in [CLI-VERBS](v2/referenz/CLI-VERBS.de.md), FR-0113. |
| **structural** | `cmd/structural/` | `make build-gates` | Erfasst Entscheidungen im Vertrauenspfad und ihre MC/DC-Prüfpflicht. Liefert die Pflicht, keine Coverage-Messung. |
| **release-evidence** | `cmd/release-evidence/` | `make build-gates` | Erstellt das Release Evidence Bundle („Trust Binder“), dessen Index Release-Artefakte an Commit und verpflichtenden Prüfsatz bindet. |

> Die vier `poc-*`-Programme sind geprüfte Referenzimplementierungen statt Produktionscode;
> siehe `CLAUDE.md`. Die letzten vier Zeilen beschreiben eigene Prüf- und Messwerkzeuge
> ohne Nutzerfunktion. Die Ausführungsorte unterscheiden sich: `docaudit` und `verbaudit`
> sperren aus `scripts/check-docs.sh` und dem `docs-gate`-Job in `ci.yml`, `release.yml`
> und `skillctl-release.yml`. `structural` berichtet nur: Der Schritt in `freeze-manifest`
> von `ci.yml` leitet nach `tail` weiter, ohne `pipefail`, daher sperrt sein Status den Lauf nicht.
> `release-evidence` läuft in `skillctl-release.yml`. Keines der vier läuft in `make ci`.

### Unterbefehle

Die Dispatch-Ebene liest `os.Args` ohne Cobra. `m3c-tools` parst Argumente von Hand;
`skillctl` nutzt bei einzelnen Unterbefehlen zusätzlich die Go-Standardbibliothek `flag`.
Die Verblisten werden hier nicht dupliziert: Eine frühere Kopie dokumentierte fünf
nicht vorhandene Unterbefehle und ließ zehn echte aus. Jedes Programm ist die eigene
Wahrheitsquelle; beide werden geprüft:

- **m3c-tools:** `m3c-tools help` ausführen. Vollständige Referenz:
  [m3c-tools-Handbuch](v2/referenz/manual-m3c-tools.de.md).
- **skillctl:** `skillctl help` ausführen. Vollständige Referenz:
  [skillctl-Handbuch](v2/referenz/manual-skillctl.de.md), Verbzuordnung:
  [CLI-VERBS](v2/referenz/CLI-VERBS.de.md).

`cmd/docaudit` sperrt Releases, wenn ein dispatchtes Verb in `--help` fehlt oder Flag und
Handbuch nicht übereinstimmen. `cmd/verbaudit` sperrt bei einem Verb ohne Zuordnungszeile.

## Python-Programme als MCP-Server

| Programm | Einstiegspunkt | Aufgabe |
|---------|-------------|------------|
| **mcp-skill-server** | `mcp-skill-server/server.py` | MCP-Server über stdio; stellt den Skill-Lebenszyklus als Claude-Code-Werkzeuge bereit und bindet Go-CLI `skillctl` sowie aims-core-REST ein. |
| **rag-mcp-server** | `rag-mcp-server/rag_mcp_server.py` | MCP-Server über stdio für lokales, netzisoliertes Workspace-RAG (SPEC-0268). Enthält zusätzlich CLI `rag.py` und Pipeline-Skripte `indexer.py`, `embedder.py`, `chunker.py`, `distill_backfill.py`. |

Beide laufen dauerhaft: siehe [Dienste](service-index.de.md).

## Evaluations-Harness

| Programm | Ort | Build | Aufgabe |
|---------|----------|-------|------------|
| **trust-layer evaluation** | `evaluation/` | `make eval` (`make eval-fast`) | Mess-Harness SPEC-0280 ohne Produktionscode. Die Messungen liegen ausschließlich in Go-Tests `e1` bis `e10`: Prüflatenz, Widerrufsskalierung, Body-Scan-Korpus, Agentenautorisierung, Inklusionsnachweis, Aktualität und weitere Metriken. |

## Ausführbare Betriebsskripte

| Bereich | Ort | Zweck |
|------|----------|---------|
| Build und Paketierung | `scripts/build-all.sh`, `scripts/build-windows.sh`, `scripts/build-portaudio-universal.sh`, `scripts/make-dmg.sh`, `scripts/make-icns.sh` | Plattformübergreifende Builds, macOS-Bundle/DMG, Windows-Binärdatei. |
| Installer | `scripts/installer.nsi`, `tools/skillctl-install.sh`, `tools/skillctl-install.ps1` | NSIS-Installer und skillctl-Installations-Einzeiler. |
| skillctl-Release/Runbook | `tools/skillctl-release.sh`, `tools/skillctl-runbook.sh`, `tools/skillctl-runbook-publish.sh`, `scripts/publish-skb.sh` | Release, Veröffentlichung von `.skb` und Runbook-Automatisierung. |
| Anmeldung und Prüfung der Aufnahmequellen | `tools/plaud-mcp-login.mjs`, `tools/plaud-e2e-check.sh`, `scripts/e2e-plaud-sync-local.sh` | Plaud-OAuth-Anmeldung und E2E-Synchronisierungsprüfung. |
| CI, Dokumentation und Review | `scripts/code-review.sh`, `scripts/check-docs.sh`, `scripts/check-index.sh`, `scripts/e2e-device-token-proof.sh` | `check-docs.sh` startet lokale docaudit-, verbaudit-, Tutorial- und Indexprüfungen. `check-index.sh` prüft die Indizes; der CI-Job `docs-gate` ruft es direkt auf. |

Alle Build-, Test- und Starteinstiege zeigt `make help`.
