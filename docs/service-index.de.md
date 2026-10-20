---
layout: default
title: Dienste
---

# Dienste

Sprachen / Languages: [Deutsch](service-index.de.md) | [English](service-index.md)

**Was dauerhaft läuft.** Langlebige Prozesse im m3c-tools-Ökosystem mit ihrer
Laufzeitumgebung: `deploy/*`-Stack, Dockerfile, Compose-Datei oder MCP-Registrierung,
die ein [Programm](program-index.de.md) zum laufenden Dienst macht.

Siehe auch: [Programme](program-index.de.md) · [Komponenten](component-index.de.md).

## 1. skillctl-Vertrauensebene im Container

Die reine Go-Vertrauensebene als OCI-Image und `.skb`-Skill-Bundles im Registry
(SPEC-0354). Die Erfassungsebene mit Rekorder und Menüleiste ist wegen cgo und
macOS-Abhängigkeit ausdrücklich ausgeschlossen.

| Aspekt | Details |
|--------|--------|
| Programm | `skillctl` (`cmd/skillctl/`) |
| Laufzeitumgebung | `deploy/skillctl/` (`Dockerfile` und `README.md`) |
| Build | `make skillctl-image`; Prüfung mit `make skillctl-image-smoke` |

## 2. mcp-skill-server für Claude Code

Stellt den Skill-Lebenszyklus als native Claude-Code-Werkzeuge bereit, damit ein
Agent Skills durchsuchen, abfragen, importieren und nachverfolgen kann.

| Aspekt | Details |
|--------|--------|
| Programm | `mcp-skill-server/server.py` |
| Transport | stdio |
| Registrierung | `~/.claude/mcp.json` |
| Bindet ein | die Go-CLI `skillctl` und die aims-core-REST-API |

## 3. rag-mcp-server für Claude Code

Lokale, vom Netz isolierte semantische Suche über einen GitHub-gestützten
Arbeitsbereich (SPEC-0268): das lokale Gegenstück zur ER1/aims-core-Wissenssuche.

| Aspekt | Details |
|--------|--------|
| Programm | `rag-mcp-server/rag_mcp_server.py` |
| Transport | stdio; zusätzlich CLI `rag.py` |
| Engine | `turbovec` (TurboQuant) und lokaler `BAAI/bge-m3`-Embedder; keine Daten verlassen den Rechner |
| Zustand | je Repository im von Git ignorierten `.rag/` |
| Werkzeuge | `rag_search`, `rag_stats`, `rag_sync`, `rag_verify` |

## 4. Menüleisten-App auf dem Desktop

Dauerhaft laufender macOS-Desktopdienst mit vier Erfassungskanälen,
Observation-Window-Pipeline und ER1-Upload.

| Aspekt | Details |
|--------|--------|
| Programm | `m3c-tools --menubar` für Produktion; `poc-menubar` als Referenz-POC |
| Start | `make menubar` / `make menubar-app` |
| UI-Stack | `menuet` für die Menüleiste und natives Cocoa über cgo |
| Details | [Menüleisten-App](v2/nutzer/menubar-app.de.md) |

## Externe Abhängigkeit: ER1 / aims-core

Wird nicht in diesem Repository gebaut, nimmt aber jede Erfassung entgegen.
`m3c-tools` lädt multimodale Beobachtungen über `pkg/er1` hoch; beide MCP-Server
fragen den Dienst ab. Konfiguration über `~/.m3c-tools.env` mit `ER1_API_URL`,
`ER1_API_KEY` und `ER1_CONTEXT_ID`.
