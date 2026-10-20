# Inhaltsverteilung: m3c-tools als öffentlicher Bereich

Sprachen / Languages: [Deutsch](CONTENT-TOPOLOGY.de.md) | [English](CONTENT-TOPOLOGY.md)

`m3c-tools` ist der öffentliche Open-Source-Bereich zur Weitergabe.
Das private Maintenance-Repository enthält die Begründungen hinter dem Code.
Diese Trennung setzt SPEC-0358 um. `tools/boundary-gate.sh` prüft sie bei Pushes
und Pull Requests über `.github/workflows/boundary-gate.yml`.

## Was öffentlich hierher gehört

- **README:** Orientierung und Schnellstart.
- **Nutzer- und API-Dokumentation:** Anleitungen zur Verwendung und zum Aufruf des
  Werkzeugs unter `docs/`, einschließlich ER1-Endpunkten und Standardkontext des
  ausgelieferten Clients als öffentliche Betriebsschnittstelle.
- **Code:** `cmd/`, `pkg/`, `internal/`, `mcp-skill-server/`, `rag-mcp-server/`,
  Tests, `installer/`, `scripts/`, `demo/`.
- **LICENSE**.
- **CHANGELOG:** öffentliche Release-Historie.

## Was in den privaten Maintenance-Bereich gehört

Der separate private Bereich mit Repository, PLM und ER1 enthält Begründungen
und Governance-Artefakte:

- **SPECs, ARCH und ADRs:** Anforderungen, Architekturentwürfe, Entscheidungsaufzeichnungen.
- **OPS / CISO:** interne Runbooks, Compliance-Zuordnungen und Geräteverzeichnisse.
- **FR / Bug / CR:** Funktionsanfragen, Fehler- und Änderungsmeldungen.
- **Onboarding-Guide-Material:** Herausgeber-Runbooks und kundenspezifische Einführungshandbücher.

Diese internen Unterlagen werden nicht mit dem Code ausgeliefert.
Öffentliche Implementierungsübersichten und aktuelle Betriebsanleitungen bleiben
hier, soweit sie das ausgelieferte Produkt erklären. Interne Pläne, Abnahmen,
Audit-Backlogs und veraltete Dokumente gehören nicht hierher.

Vor dem Entfernen oder Ersetzen eines veralteten Dokuments dessen Originalbytes
unter **`Archiv`** im privaten Maintenance-Repository sichern. Originalpfad,
Quellcommit und SHA-256 gehören ins Archivmanifest. Bei Verschiebung einer
aktuellen Anleitung den Ersatzpfad festhalten. Erst archivieren, dann die
öffentliche Kopie entfernen; weder Historie verwerfen noch nützliche Anleitungen
durch kaputte Links ersetzen.

Laufzeitressourcen, Test-Fixtures, maschinenlesbare Schemas, Abhängigkeitsmanifeste
und aktive CI-Eingaben bleiben erhalten. Ein Bezeichner im Dateinamen macht
Quellcode oder Fixtures nicht zu einer narrativen Spezifikation.

## Querverweise nur über IDs

Öffentliche Dateien verweisen auf den privaten Bereich ausschließlich per Kennung:

- Zulässig: `implements SPEC-1234`, `see ADR-0007`, `fixes BUG-0124`.
- Unzulässig: private Repositorypfade oder URLs, interne Endpunkte, geheime Header
  oder rohe ER1-Kontext-IDs.

Eine ID ist ein dauerhafter, bereichsunabhängiger Verweis. Ein Pfad verrät private
Struktur oder lokale Rechnerpfade. Details bleiben privat und werden öffentlich
nur über ihre Kennung zitiert.

## Was das Boundary-Gate erzwingt

`tools/boundary-gate.sh` durchsucht versionierte, nicht binäre Dateien mit einer
kleinen dokumentierten Ausnahmeliste. Folgende Funde führen zum Fehler:

| Grund | Muster | Geltung |
|----------------------------|-------------------------------|-------|
| Narrative Spezifikation oder Planung | Dokumentname oder Haupttitel | narrative Dokumente |
| Veraltete Dokumentation | `docs/old/` | sämtliche versionierten Inhalte |
| Privater Repositoryverweis | Pfad in den privaten Bereich | alle Dateien |
| Interner Endpunkt | `127.0.0.1:8081` | narrative Oberfläche* |
| ER1-Kontext-ID | `<digits>___<slug>` | narrative Oberfläche* |
| Geheimer Header | `X-API-KEY` | narrative Oberfläche* |
| Interner API-Pfad | `/upload_2`, `/api/plm/` | narrative Oberfläche* |

\* Betriebsmuster werden nicht auf der eigenen Betriebsoberfläche des Produkts
geprüft: Quellcode, Tests, Konfiguration, API-/Nutzeranleitungen, Demos und Vorlagen.
Dort gehören Client-Endpunkt, Headername, API-Pfade und Standardkontext zum
Produkt. Die Muster schützen README, Agentenanweisungen und Wurzeldateien vor
versehentlichem Einfügen. Ein privater Repositorypfad bleibt überall ein Verstoß.

Bloße Kennungen `SPEC-1234` und `ADR-1234` sind zulässig.

## Dokumentationssprachen

Veröffentlichte Dokumentation muss auf Deutsch und Englisch mit demselben
fachlichen Inhalt vorliegen. Beide Fassungen verlinken einander. CLI-Befehle,
Flags, Beispiele und maschinenlesbare Verträge bleiben unverändert. Bei
fachlichen Änderungen beide Fassungen prüfen. Eine Zusammenfassung ersetzt
keine Übersetzung. Geprüfte Paare stehen in `docs/languages.json`.
