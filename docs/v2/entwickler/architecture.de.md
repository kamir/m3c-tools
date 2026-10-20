# Referenz: Architekturüberblick

Sprachen / Languages: [Deutsch](architecture.de.md) | [English](architecture.md)

Woraus das Repository besteht und wie Daten hindurchfließen, auf einer Seite,
mit Links zu den durch Gates geprüften Indizes für alle Details. Widersprechen
sich diese Seite und ein Index, gilt der Index: [program-index](../../program-index.de.md)
und [component-index](../../component-index.de.md) werden bei jedem CI-Lauf durch
`scripts/check-index.sh` gegen den Verzeichnisbaum geprüft; diese Seite nicht.

Zielgruppe: neue Entwickler im Repository und alle, die vor dem Öffnen des
Codes entscheiden, wohin eine Änderung gehört.

Rolle: Entwickler · Sprache: DE · Stand: 2026-09-16

## Die Grundregel in einem Satz

**Zwei Ebenen, ein Repo: `m3c-tools` füllt den Erinnerungsraum, `skillctl`
steuert die Agent-Skills, die darauf arbeiten**, und die Vertrauensebene bleibt
reines Go, während die Capture-Ebene cgo und reine macOS-Funktionen nutzen darf.

## Die Capture-Pipeline

ER1 ist der persönliche Wissensserver, in den jede Erfassung fließt: ein
externer HTTP-Dienst (aims-core), nicht Teil dieses Repositorys, der multimodale
Beobachtungen speichert; `pkg/er1` ist sein Client
([Client-Implementierung](../../../pkg/er1/),
[service-index](../../service-index.md#external-dependency-er1--aims-core)).
Der Kernablauf, wie ihn `CLAUDE.md` beschreibt und die Packages implementieren:

```
transcript.API.Fetch(videoID)        -> FetchedTranscript (snippets)
impression.CompositeDoc.Build()      -> composite text
transcript.Fetcher.FetchThumbnail()  -> JPEG bytes
er1.Upload(config, payload)          -> ER1 server
er1.Queue.Add(entry)                 -> JSON retry queue, on failure
```

Drei Eigenschaften tragen den Entwurf:

1. **Kern nur mit Standardbibliothek.** `pkg/transcript`, `pkg/er1` und
   `pkg/impression` verwenden ausschließlich die Go-Standardbibliothek;
   externe Abhängigkeiten (menuet, portaudio) bleiben in POC- und
   Desktop-Schichten (`CLAUDE.md`, "Zero external deps").
2. **Kein YouTube-API-Key.** `pkg/transcript` ist eine vollständige Portierung
   von youtube-transcript-api auf YouTubes InnerTube API (die interne API,
   die YouTube-Clients selbst nutzen; deshalb ist kein offizieller Schlüssel
   nötig); die API ist in [pkg/transcript](../../../pkg/transcript/) implementiert.
3. **ER1 verlangt alle drei Felder.** Uploads sind Multipart-Anfragen mit
   `transcript_file_ext`, `audio_data_ext`, `image_data`; der Client sendet
   Platzhalter-Audio oder -Bilder, wenn die echten Daten fehlen (`pkg/er1`).

## Die Vertrauensebene

`skillctl` gibt jedem Agent-Skill eine überprüfbare Identität und einen
Lebenszyklus: author, pack, sign, admit, attest, verify oder install, use,
audit, revoke (admit veröffentlicht ein signiertes Bundle in einem Registry;
attest ist das signierte Governance-Urteil eines Reviewers über denselben
Digest). Die Kette prüft offline; keine gehostete Instanz liegt im Prüfpfad
(Kopf des [Manuals: skillctl](../referenz/manual-skillctl.de.md), Bedrohungsmodell
in [THREAT_MODEL.md](../../../THREAT_MODEL.de.md)). Die Bibliothek liegt unter
`pkg/skillctl/` mit den benachbarten Packages `skillbundle` und `skillgate`;
[component-index, Abschnitt F](../../component-index.md#f-skillctl-trust-subsystem-pkgskillctl--siblings)
enthält die durch ein Gate geprüfte Package-Liste samt Anzahl.

## Einstiegspunkte und Dienste

Gemessen am 2026-09-16 (`ls cmd/`): vierzehn Einstiegspunkte unter `cmd/`.
Die verbindliche, durch ein Gate geprüfte Tabelle steht im
[program-index](../../program-index.de.md); die Kurzfassung:

| Gruppe | Binaries |
|---|---|
| Produkt-CLIs | `m3c-tools` (Erfassung und macOS-Menüleisten-App), `skillctl` (Vertrauen), `secretctl` (Secret-Register, SPEC-0438) |
| Demo und Simulation | `skillctl-demo` (Offline-CISO-Demo), `skillctl-sim` (Szenarienkorpus gegen das echte Binary) |
| Repository-Gates | `docaudit`, `verbaudit`, `exitaudit`, `structural`, `release-evidence` |
| Referenz-POCs | `poc-menubar`, `poc-recorder`, `poc-transcript`, `poc-whisper` |

Was dauerhaft läuft (die beiden MCP-Server: stdio-Prozesse für das Model
Context Protocol, das Tools für Claude Code bereitstellt, die Menüleisten-App
und der skillctl-Container), steht im [service-index](../../service-index.de.md);
die Zuständigkeiten der Packages stehen im
[component-index](../../component-index.de.md).

## Konventionen für Änderungen

| Konvention | Quelle |
|---|---|
| m3c-tools wertet Argumente von Hand aus; skillctl nutzt zusätzlich das `flag`-Package der Standardbibliothek. Der vorhandenen Befehlsimplementierung folgen | [m3c-tools-Befehle](../../../cmd/m3c-tools/), [skillctl-Befehle](../../../cmd/skillctl/) |
| Ein neues skillctl-Verb wird VOR der Implementierung in [CLI-VERBS](../referenz/CLI-VERBS.de.md) REGISTRIERT; andernfalls lässt `verbaudit` CI fehlschlagen | CLI-VERBS.md, entschieden am 2026-09-04 |
| Exit-Codes sind Vertrag: Registerzeile, `Exit:`-Zeile des Manuals und `pkg/skillctl/exitcode` müssen übereinstimmen; `exitaudit` prüft alle drei | CLI-VERBS.md, "Columns" |
| Package-Tests liegen neben der Implementierung; End-to-End-Tests unter `e2e/` | [Entwicklungsumgebung](getting-started.md#part-b-test) |
| Die öffentliche Ebene liefert Code, die private Ebene hält Begründungen; Querverweise nur per ID (SPEC-NNNN) | [CONTENT-TOPOLOGY.md](../../../CONTENT-TOPOLOGY.de.md) |

## Weiterführend

- Build, Tests und Gates: [Entwicklungsumgebung](getting-started.de.md)
- Alle Befehle und Flags: [Manual: m3c-tools](../referenz/manual-m3c-tools.de.md),
  [Manual: skillctl](../referenz/manual-skillctl.de.md)
- Betriebssystemunterstützung: [PLATFORM-DIFFERENCES](../referenz/PLATFORM-DIFFERENCES.de.md)
- Capture-Clients: [ER1](../../../pkg/er1/), [Plaud](../../../pkg/plaud/),
  [Pocket](../../../pkg/pocket/); Befehle und Konfiguration stehen im
  [m3c-tools-Manual](../referenz/manual-m3c-tools.de.md)
