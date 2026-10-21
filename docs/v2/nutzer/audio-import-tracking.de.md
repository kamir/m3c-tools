---
layout: default
title: Audioimport und Tracking
---

# Audioimport und Upload-Tracking

[Deutsch](audio-import-tracking.de.md) · [English](audio-import-tracking.md)

Dieses Dokument beschreibt die Audioimport-Pipeline, die Tracking-Datenbank und
die Initialisierung ihres Zustands aus einem vorhandenen Tracker.

## Überblick

Die Audioimport-Pipeline verarbeitet Dateien aus einem Quellverzeichnis in vier Stufen:

```
Source folder (IMPORT_AUDIO_SOURCE)
    → Scan & deduplicate (tracking DB)
    → Copy to MEMORY folder (IMPORT_AUDIO_DEST)
    → Transcribe via Whisper
    → Upload to ER1
```

Der Fortschritt jeder Datei wird in der **SQLite-Tracking-Datenbank** unter
`~/.m3c-tools/tracking.db` erfasst.

## Lebenszyklus einer Datei

| Status | Bedeutung |
|---|---|
| `new` | Datei liegt auf der Festplatte, aber noch nicht in der DB: bereit zum Import |
| `imported` | In den MEMORY-Ordner kopiert und in der DB erfasst |
| `uploaded` | Erfolgreich nach ER1 hochgeladen; `upload_doc_id` ist vorhanden |
| `failed` | Import oder Upload fehlgeschlagen; siehe Spalte `upload_error` |

## Schema der Tracking-Datenbank

```sql
CREATE TABLE processed_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path       TEXT NOT NULL,        -- Full source path
    file_hash       TEXT NOT NULL,        -- SHA-256 of file content
    file_size       INTEGER NOT NULL,     -- File size in bytes
    import_type     TEXT DEFAULT 'audio', -- Always 'audio' for this pipeline
    status          TEXT DEFAULT 'imported',
    memory_id       TEXT,                 -- MEMORY folder name
    processed_at    TEXT NOT NULL,        -- ISO 8601 timestamp
    transcript_text TEXT,                 -- Full whisper transcript
    transcript_lang TEXT,                 -- Language code (e.g. 'de')
    transcript_len  INTEGER DEFAULT 0,   -- Character count of transcript
    upload_doc_id   TEXT,                 -- ER1 document ID on success
    upload_error    TEXT,                 -- Error message on failure
    uploaded_at     TEXT,                 -- ISO 8601 upload timestamp
    UNIQUE(file_hash, import_type)
);
```

### Wichtige Tracking-Spalten

- **transcript_text / transcript_lang / transcript_len**: Werden nach Abschluss
  der Whisper-Transkription gespeichert. Bei einem Transkriptionsfehler enthält
  `transcript_text` die Fehlermeldung mit dem Präfix `[Transcription failed: ...]`.
- **upload_doc_id**: Die nach erfolgreichem Upload zurückgegebene ER1-Dokument-ID.
  Sie ist der maßgebliche Nachweis, dass die Datei ER1 erreicht hat.
- **upload_error**: Speichert die Fehlermeldung eines fehlgeschlagenen Uploads.
  Wird nach einem erfolgreichen Wiederholungsversuch geleert.
- **uploaded_at**: Zeitstempel des erfolgreichen Uploads.

## Initialisierung aus einem Tracker

Bei der ersten Einrichtung von m3c-tools oder beim Zurücksetzen des Tracking-Zustands
stellen die folgenden Schritte den korrekten Ausgangszustand her.

### Voraussetzungen

- Die **maßgebliche Trackerdatei** listet die Dateinamen auf, die bereits mit dem
  bisherigen Python-Werkzeug nach ER1 hochgeladen wurden. Standardpfad:
  `$AIMS_CORE_ROOT/../experiments/audio-checklist-checker-py/bin/transcript_tracker.md`
- Der **Audio-Quellordner** (`IMPORT_AUDIO_SOURCE`) enthält alle Audiodateien.
- Bereits hochgeladene Dateien liegen im Unterordner `DONE/` der Quelle.

### Schritte

1. **Vorhandene DB sichern**, sofern eine existiert:
   ```bash
   cp ~/.m3c-tools/tracking.db ~/.m3c-tools/tracking.db.bak
   ```

2. **Vorhandene DB löschen**:
   ```bash
   rm ~/.m3c-tools/tracking.db
   ```

3. **Aus der maßgeblichen Trackerdatei initialisieren**. Für jede dort aufgeführte
   Datei den SHA-256-Hash berechnen und sie mit `status='uploaded'` in die DB eintragen:
   ```bash
   SOURCE_DIR="$AUDIO_SOURCE_DIR"   # aus .claude/local-paths.env
   TRACKER="$AIMS_CORE_ROOT/../experiments/audio-checklist-checker-py/bin/transcript_tracker.md"
   DB="$HOME/.m3c-tools/tracking.db"

   # The app will create the schema on first open. Alternatively, start the
   # menubar app once to initialize: m3c-tools menubar &; sleep 2; kill %1

   while IFS= read -r basename; do
     [ -z "$basename" ] && continue
     [[ "$basename" =~ ^# ]] && continue
     fullpath="$SOURCE_DIR/DONE/$basename"
     [ ! -f "$fullpath" ] && echo "SKIP (not found): $basename" && continue
     hash=$(shasum -a 256 "$fullpath" | cut -d' ' -f1)
     size=$(stat -f%z "$fullpath")
     sqlite3 "$DB" "INSERT OR IGNORE INTO processed_files
       (file_path, file_hash, file_size, import_type, status, processed_at)
       VALUES ('$fullpath', '$hash', $size, 'audio', 'uploaded', datetime('now'));"
   done < "$TRACKER"
   ```

4. **Den m3c-tools-Tracker entsprechend aktualisieren**:
   ```bash
   cp "$TRACKER" ~/.m3c-tools/transcript_tracker.md
   ```

5. **Prüfen**:
   ```bash
   sqlite3 "$DB" "SELECT status, COUNT(*) FROM processed_files GROUP BY status;"
   # Expected: uploaded|6 (or however many files are in DONE/)
   ```

### Nach der Initialisierung

- Alle Dateien direkt im Quellordner, außerhalb von `DONE/`, erscheinen im
  Audio-Import-Menü als **"new"**.
- Einzelne Dateien auswählen oder "Run Import Pipeline" für den Stapelimport nutzen.
- Jede Datei durchläuft `new → imported → uploaded` oder endet als `failed`.
- Das Untermenü "Tracking DB" zeigt alle Datensätze mit Status, Transkriptlänge
  und Upload-Dokument-ID.

## Importmodi

### Einzeldatei importieren (Menüklick)

Ein Klick auf eine Datei im Audio-Import-Untermenü löst Folgendes aus:
1. Nur diese Datei wird importiert, über `ImportAudioFiltered`.
2. Whisper transkribiert sie.
3. Die Transkriptdetails werden in der DB gespeichert.
4. Der Upload nach ER1 wird versucht.
5. Das Upload-Ergebnis, doc_id oder Fehler, wird in der DB gespeichert.
6. Das Menü wird aktualisiert; die Datei verschwindet aus der Liste "new".

### Stapelimport ("Run Import Pipeline")

Importiert ALLE neuen Dateien im Quellverzeichnis, transkribiert jede und lädt sie hoch.
Die Erfassung je Datei entspricht dem Einzeldateimodus.

## Bedienung, Sperren und Logs bei Sammelaktionen

Sammelaktionen im Tab **Tracking DB → Source Files** laufen als explizite
Sitzungen mit einer `run_id` und laufender Fortschrittsanzeige.

### Verhalten der Sperre

- Solange eine Sammelaktion läuft, sind neue Importaktionen gesperrt:
  - YouTube-Abruf und Aufnahme
  - Screenshot-Ablauf
  - Quick Impulse
  - Audioimport, einzeln und im Stapel
  - Weitere Sammelaktionen des Trackings
- Der Nutzer erhält eine Benachrichtigung mit dem Fortschritt und der Zahl verbleibender Elemente.

### Anzeigen des laufenden Fortschritts

- Das **Tracking-Fenster** zeigt:
  - Oben einen Fortschrittsbalken mit bekanntem Gesamtumfang
  - Sitzungszähler: `done/total`, `ok`, `fail`
  - Aktuelle Datei und Phase
  - Letzte Fehlerzeile, falls vorhanden
  - Deaktivierte Sammelaktionsschaltflächen während der Sitzung
- **Audio Import in der Menüleiste** zeigt:
  - `Running X/Y`
  - Aktuelle Datei
  - Anzahl fehlgeschlagener Elemente
  - Verstrichene Zeit

### Statusanzeigen der Quelldateien

Ausgewählte Dateien durchlaufen während der Verarbeitung diese Kennzeichnungen:

- `queued`
- `importing`
- `transcribing`
- `uploading`
- Abschließend: `done`, `failed` oder `skipped`

### Strukturierte Logs der Sammelaktionen

Jede Sitzung schreibt maschinenlesbare Lebenszyklusmarker:

- `[bulk][RUN_START]`
- `[bulk][ITEM_START]`
- `[bulk][PHASE] phase=import|whisper|upload`
- `[bulk][ITEM_DONE]`
- `[bulk][RUN_DONE]`

Jede Zeile enthält `run_id`, gegebenenfalls den Elementindex und Gesamtumfang,
sowie Ergebnis oder Fehlercode.

## Umgebungsvariablen

| Variable | Standard | Beschreibung |
|---|---|---|
| `IMPORT_AUDIO_SOURCE` | erforderlich | Quellverzeichnis der Audiodateien |
| `IMPORT_AUDIO_DEST` | `~/ER1` | Ziel für MEMORY-Ordner |
| `IMPORT_CONTENT_TYPE` | erforderlich | ER1-Inhaltstypbezeichnung |
| `IMPORT_TRACKER_FILE` | `~/.m3c-tools/transcript_tracker.md` | Pfad der bisherigen Trackerdatei |

## Tracking-Verlauf ansehen

Das Untermenü **"Tracking DB"** in der Menüleiste zeigt bis zu 50 aktuelle Datensätze.
Jeder Eintrag zeigt:
- Statussymbol: ✅ hochgeladen, 📦 importiert, ❌ fehlgeschlagen
- Dateiname
- Aufklappbare Details: Transkriptlänge und -sprache, ER1-Dokument-ID, Fehlermeldung
