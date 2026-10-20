---
layout: default
title: Menüleisten-App
---

# M3C Tools: macOS-Menüleisten-App

[Deutsch](menubar-app.de.md) · [English](menubar-app.md)

Eine native macOS-Menüleisten-App zum Erfassen multimodaler Beobachtungen. In Go entwickelt,
mit `caseymrm/menuet` für die Menüleiste und nativem Cocoa (NSWindow, NSTabView) über cgo
für das Observation Window.

## Funktionen

- Native macOS-Menüleiste mit eigenem Symbol
- Vier Erfassungskanäle: YouTube, Screenshot, Impulse, Audio Import
- Gemeinsames **Observation Window** mit drei Tabs: Record, Review, Tags
- VU-Anzeige in Echtzeit mit farbigen Audiopegeln und dB-Wert
- Lokale Whisper-Transkription von Sprachaufnahmen
- Multimodale ER1-Uploads: Bild, Audio und Transkript
- Offline-Warteschlange mit exponentiell wachsenden Wiederholungsabständen
- Verknüpfung des ER1-Browser-Logins mit Kontextübernahme zur Laufzeit
- Transkriptverlauf der letzten 20 Abrufe
- Entwürfe beim Abbrechen speichern: `~/.m3c-tools/drafts/`
- Koordinierte Sperre und Fortschrittsanzeige für Sammelimport und erneute Verarbeitung

## Installation

### Bauen und installieren

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make install
```

### Nur aus dem Quellcode bauen

```bash
make build-app
# Result: build/M3C-Tools.app
```

### Ohne Installation ausführen

```bash
make menubar
```

## Erfassungskanäle

### Kanal A: YouTube

1. **Fetch Transcript...** in der Menüleiste anklicken.
2. YouTube-URL oder Video-ID einfügen.
3. Das Transkript wird abgerufen, das Vorschaubild heruntergeladen.
4. Das **Observation Window** öffnet sich mit dem Vorschaubild.
5. Einen gesprochenen Eindruck zum Video aufnehmen.
6. Transkribierten Text prüfen, Tags bearbeiten und Store oder Cancel wählen.

### Kanal B: Screenshot

1. **Capture Screenshot** in der Menüleiste anklicken.
2. Der Bildschirm wird erfasst, zunächst über die Zwischenablage, ersatzweise interaktiv.
3. Das **Observation Window** öffnet sich mit dem Screenshot.
4. Eigene Beobachtungen zum Bild aufnehmen.
5. Prüfen, taggen und Store oder Cancel wählen.

### Kanal C: Quick Impulse

1. **Quick Impulse** in der Menüleiste anklicken.
2. Die interaktive Bereichsauswahl erscheint.
3. Einen bestimmten Bildschirmbereich erfassen.
4. Das **Observation Window** öffnet sich.
5. Eine kurze Sprachnotiz zum Impuls aufnehmen.
6. Prüfen, taggen und Store oder Cancel wählen.

### Kanal D: Audio Import

1. **Import Audio** in der Menüleiste anklicken.
2. Der konfigurierte Ordner `IMPORT_AUDIO_SOURCE` wird nach Audiodateien durchsucht.
3. Für jede Datei wird ihr Status als erfasst, neu oder hochgeladen angezeigt.
4. Die zu importierenden Dateien auswählen.
5. Jede Datei wird durch Whisper transkribiert und nach ER1 hochgeladen.

### Bedienung bei Sammelimport und erneuter Verarbeitung

- Das Tracking-DB-Fenster zeigt einen laufend aktualisierten Fortschrittsbereich:
  - Fortschrittsbalken mit bekanntem Gesamtumfang
  - Aktuelle Datei und Phase
  - Erfolgs- und Fehlerzähler
  - Letzte Fehlermeldung
- In der Quelltabelle erscheinen die Zustände der laufenden Verarbeitung:
  - `queued`, `importing`, `transcribing`, `uploading`, `done`, `failed`, `skipped`
- Schaltflächen für Sammelaktionen sind während einer aktiven Sitzung deaktiviert.
- Während Whisper oder Upload im Stapel arbeiten, sind andere Erfassungsaktionen gesperrt.

## Observation Window

Das Observation Window ist ein natives NSWindow mit NSTabView, das alle Erfassungskanäle gemeinsam nutzen:

### Tab Record
- Zeigt das erfasste Bild, maximal 50 % von Bildschirmbreite und -höhe.
- VU-Anzeige für den Mikrofoneingang in Grün, Gelb und Rot.
- Verstrichene Aufnahmezeit als MM:SS.
- Schaltfläche Stop Recording.
- Schließen über das rote X stoppt und fragt "Keep this recording?".

### Tab Review
- Metadatenkopf mit Video-ID, Sprache, Anzahl der Abschnitte und Zeichen.
- Scrollbarer, bearbeitbarer Transkripttext.
- Aufnahmedetails: Dauer, Dateigröße, Abtastrate.

### Tab Tags
- Pro Kanal vorbelegte Tags, als bearbeitbares kommasepariertes Feld.
- **[Store]**: Upload nach ER1; bei Fehler zur Wiederholung einreihen.
- **[Cancel]**: Entwurf nach `~/.m3c-tools/drafts/` speichern und in den Ruhezustand zurückkehren.

## Menüeinträge

| Eintrag | Aktion |
|---|---|
| Status line | Aktueller App-Zustand, etwa Idle, Fetching, Recording... |
| Fetch Transcript... | Kanal A: YouTube |
| Capture Screenshot | Kanal B: Screenshot |
| Quick Impulse | Kanal C: interaktive Bereichserfassung |
| Import Audio | Kanal D: Audio-Stapelimport |
| Login to ER1... | ER1-Login in Chrome öffnen |
| Logout from ER1 | ER1-Sitzung der laufenden App löschen |
| History submenu | Letzte 20 Transkripte; anklicken zum erneuten Kopieren |
| Open Log File | Öffnet `/tmp/m3c-tools.log` |
| Mein Nutzerkonto | ER1-Profilseite in Chrome öffnen |

## Projektzeiterfassung

m3c-tools führt je Projekt ein Zeitkonto. So lässt sich nachträglich erkennen,
wie viel Zeit in welches Projekt geflossen ist, auch wenn kein Timer gestartet
wurde. Zwei ergänzende Mechanismen füllen das Konto:

1. **Explizite Sitzungen**: Im Untermenü **Projects ▶** ein Projekt starten und
   stoppen. Die Zeit zwischen Aktivierung und Deaktivierung wird addiert.
2. **Rückwirkende Zeiterfassung**: Jede erfasste Beobachtung, also Transkript,
   Screenshot, Sprachimpuls oder Audioimport, wird untersucht. Passen ihre Tags
   zu einem Projekt, erhält dieses automatisch einen 15-Minuten-Block mit dem
   Beobachtungszeitpunkt als Mittelpunkt.

Beide schreiben in denselben Speicher `~/.m3c-tools/timetracking.db` und sind
im Gantt-Diagramm sichtbar, erreichbar über **Projects ▶ Show Time Tracker…**.

> **Spezifikationen:**
> **SPEC-0007: Project Time Tracking** auf der privaten Maintenance-Ebene
> beschreibt den vollständigen Entwurf samt den unten genannten Anforderungen.

### Funktionsweise der rückwirkenden Zuordnung

Beim Speichern einer Beobachtung führt die Menüleisten-App folgende Schritte aus:

1. **Tags der Beobachtung aus dem Upload-Payload entnehmen**. Je nach
   Erfassungstyp stammen sie aus `impression.BuildTags`, `BuildVideoTags`
   oder `ParseMetadataTags`.
2. **Tags mit allen aktiven oder in Validierung befindlichen Projekten vergleichen**,
   geladen aus PLM über `~/.m3c-tools/timetracking.db`, alle fünf Minuten aktualisiert.
   Priorität der Übereinstimmung nach SPEC-0007 REQ-9:

   | Stärke | Auslöser | Beispiel |
   |---|---|---|
   | **Stark** | Beobachtungstag `project:<slug>` entspricht dem `<slug>` eines Projekts | Audiodatei `project_alpha_braindump.wav` → Tag `project:alpha` → Projekt Alpha |
   | **Mittel** | Beobachtungstag `client:<name>` entspricht dem Projektfeld `client` oder dessen Tag `client:<name>` | `ZOOM0001_client_acme.wav` → Tag `client:acme` → ACME Onboarding |
   | **Schwach** | Mindestens zwei normale Tags überschneiden sich zwischen Beobachtung und Projekt | `braindump,sprint,review` überschneidet sich mit `sprint,review,agile` → Sprint-Projekt |

3. **Am besten passendes Projekt wählen.** Bei Gleichstand entscheidet `updated_at`:
   Das zuletzt aktive Projekt gewinnt. Passt keines, wird kein Block angelegt;
   im Log erscheint `[reverse-tracking] no project match`. Dies ist eine Diagnose,
   kein Fehler.
4. **Abgeleiteten Zeitblock anlegen**, standardmäßig 15 Minuten rund um den
   Beobachtungszeitpunkt, mit `trigger="observation_inferred"` und
   `content_ref=<doc_id>`. Im Gantt-Diagramm erscheinen abgeleitete Blöcke mit
   halbtransparenter Füllung und gestricheltem Rand, um sie von expliziten Sitzungen zu unterscheiden.
5. **Bei vorhandener Abdeckung überspringen.** War für das zugeordnete Projekt
   zu diesem Zeitpunkt bereits eine explizite Sitzung aktiv, entsteht kein
   abgeleiteter Block: Die explizite Sitzung berücksichtigt diese Zeit bereits.
6. **Nahe Dublette überspringen.** Liegt für das Projekt bereits ein abgeleiteter
   Block innerhalb der **halben Blockdauer** um die Beobachtung, standardmäßig
   ±7,5 Minuten oder `M3C_REVERSE_BLOCK_DURATION`/2, entsteht kein zweiter Block
   (`hasInferredNearby`). Viele kurz aufeinanderfolgende Aufnahmen erscheinen
   dadurch als ein Block statt als mehrere überlappende Fragmente.

### Nachtragen: frühere Beobachtungen erneut auswerten

Tagregeln und Projektlisten ändern sich. Damit auch ältere Beobachtungen zugeordnet
werden, wenn ihr Projekt später angelegt oder neu getaggt wird, wertet m3c-tools
Beobachtungen bei zwei Auslösern erneut aus, nach SPEC-0007 REQ-10:

| Auslöser | Zeitraum |
|---|---|
| App-Start | Alle Beobachtungen des **aktuellen Kalendermonats** |
| Navigation im Gantt-Diagramm | Beobachtungen des vom Nutzer aufgerufenen Zeitraums |

Die Wiederholung ist **idempotent**. Bereits einem Projekt gutgeschriebene
Beobachtungen werden übersprungen; wiederholtes Nachtragen erzeugt keine zusätzlichen Einträge.

Eine typische Logzeile beim Start:

```
[reverse-tracking] backfill 2026-04-01–2026-05-01: 41/41 observations processed
[reverse-tracking] startup backfill: processed 41 observations for April 2026
```

### Rückwirkende Zeiterfassung für eigene Aufnahmen einrichten

Bleibt die Zuordnung still, mit vielen `no project match`-Zeilen und ohne abgeleitete
Gantt-Blöcke, liegt es fast immer an **fehlenden Tagüberschneidungen**.
Zwei Möglichkeiten helfen:

1. **Projektdatensatz um Tags ergänzen.** Auf der PLM-Projektseite Begriffe eintragen,
   die in den Aufnahmen vorkommen, etwa `nate's thoughts`, `scalytics strategy`, `s3`
   beim passenden Projekt. Die nächste Aktualisierung innerhalb von fünf Minuten
   und das nächste Nachtragen berücksichtigen sie.
2. **Aufnahmen mit Projektankern taggen.** Bei der Erfassung `project:<slug>` oder
   `client:<name>` angeben. Starke Übereinstimmungen gewinnen immer: Ein expliziter
   Anker ist verlässlicher als eine schwache Überschneidung.

### Konfiguration

Nach SPEC-0007 REQ-9 steuern drei Umgebungsvariablen das Verhalten. Im aktiven Profil
`~/.m3c-tools/profiles/<name>.env` oder in `~/.m3c-tools/preferences.env` setzen:

| Variable | Standard | Wirkung |
|---|---|---|
| `M3C_REVERSE_BLOCK_ENABLED` | `true` | Hauptschalter. `false` deaktiviert abgeleitete Blöcke vollständig. |
| `M3C_REVERSE_BLOCK_DURATION` | `900` | Blockdauer in Sekunden. 900 entspricht 15 Minuten rund um die Beobachtung. |
| `M3C_REVERSE_MIN_TAG_OVERLAP` | `2` | Mindestanzahl gemeinsamer Tags für eine schwache Übereinstimmung. Ein höherer Wert ist strenger, ein niedrigerer erzeugt mehr und möglicherweise ungenauere Zuordnungen. |

### Fehlerbehebung

| Symptom | Wahrscheinliche Ursache | Abhilfe |
|---|---|---|
| Projects-Untermenü leer | PLM-Authentisierung beim Start fehlgeschlagen | `m3c-tools doctor`: Die Geräte-Token-/API-Key-Prüfung grenzt den Fehler ein. Siehe auch BUG-0124 auf der privaten Maintenance-Ebene zum Fix in v2.7.0. |
| Viele `no project match`-Zeilen, keine abgeleiteten Blöcke | Projekttags überschneiden sich nicht mit Aufnahmetags | Siehe oben die Einrichtung der rückwirkenden Zeiterfassung. |
| Abgeleitete Blöcke beim falschen Projekt | Tagüberschneidung zu allgemein | Projekt- oder Aufnahmetags um `project:<slug>` ergänzen. Starke Treffer haben Vorrang. |
| Profil fehlerhaft, etwa mit Platzhalter-API-Key | Der Einrichtungsassistent hinterließ `once-only` oder `minimal-key` | `m3c-tools config doctor`: Der Profilvalidator, siehe SPEC-0177 auf der privaten Maintenance-Ebene, meldet Platzhalterschlüssel, fehlende Kontext-IDs, fehlerhafte URLs und mehrfach verwendete Schlüssel über Profile hinweg. |

## Logs

```
/tmp/m3c-tools.log
```

Strukturierte Logpräfixe: `[fetch]`, `[cache]`, `[store]`, `[auth]`, `[whisper]`, `[recorder]`

Lebenszyklusmarker für Sammelimport und erneute Verarbeitung:

- `[bulk][RUN_START]`
- `[bulk][ITEM_START]`
- `[bulk][PHASE]`
- `[bulk][ITEM_DONE]`
- `[bulk][RUN_DONE]`

## Deinstallieren

```bash
make uninstall
```

Alternativ von Hand:
```bash
rm -f /usr/local/bin/m3c-tools
rm -rf /Applications/M3C-Tools.app
# Data preserved at ~/.m3c-tools/: remove manually if desired
```

---

Zurück: [Erste Schritte](getting-started.de.md) | [Startseite](/)
