# Ops-Runbook: die Capture-Seite von m3c-tools

Was mit einem Upload passiert, der ER1 nicht erreicht: wo die Wartenden
liegen, in welchem Format, und wie der Wiederanlauf funktioniert. Diese Seite
deckt den Upload-Pfad und die Retry-Queue ab; die englische Kurzfassung fuer
Nutzer steht im
[Manual, "Exit behavior & the retry queue"](../referenz/manual-m3c-tools.md#exit-behavior--the-retry-queue).

Zielgruppe: die Person, die eine Maschine betreibt, auf der m3c-tools
Beobachtungen nach ER1 laedt, und die nach einem Ausfall wissen muss, was
noch aussteht und wie es abfliesst.

Rolle: Betrieb · Sprache: DE · Stand: 2026-09-16

**Wie weit dieses Runbook gemessen ist.** Die zwei Bloecke, die mit "Gemessen"
beginnen, sind am 2026-09-16 gegen ein lokales Binary aus diesem Baum
gelaufen (`make build`, meldet sich als `skillctl/v0.5.1-6-g307b414`), gegen
eine Wegwerf-Datenbank im Scratchpad; Pfade sind mit `/…/` gekuerzt. Alle
uebrigen Aussagen sind aus dem Code gelesen (Datei und Zeile stehen jeweils
dabei) und nicht durch einen Lauf belegt; wo das einen Unterschied macht,
steht es an der Stelle.

## Die Grundregel in einem Satz

**Es gibt zwei Buecher, nicht eins: `m3c-tools retry` arbeitet die JSON-Queue
`~/.m3c-tools/queue.json` ab, waehrend `status`, `schedule` und `cancel` die
getrennte SQLite-Datei `~/.m3c-tools/exports.db` lesen und schreiben**; wer
nach einem Ausfall nur eines der beiden prueft, uebersieht die andere
Haelfte (Queue: `pkg/er1/queue.go`; Tracking-DB:
`cmd/m3c-tools/commands_shared.go`, `defaultExportsDBPath`).

## 1. Der Upload-Pfad, und was ein Fehlschlag hinterlaesst

Ein Upload (`m3c-tools upload <video-id> ...` oder Store aus der
Menueleisten-App) geht als Multipart-Request mit den drei Feldern
`transcript_file_ext`, `audio_data_ext`, `image_data` an ER1
(`pkg/er1/upload.go`); fehlt echtes Audio oder Bild, gehen Platzhalter mit.

Schlaegt der Upload fehl, tut `HandleUploadFailure`
(`pkg/er1/failure.go:23`) zwei Dinge:

1. Es haengt einen Eintrag an die JSON-Queue (Abschnitt 2).
2. Es legt einen `MEMORY-<zeitstempel>/`-Ordner an und sichert die
   Payload-Dateien dorthin, damit ein spaeterer Wiederanlauf echte Inhalte
   findet. Wurzel: `ER1_MEMORY_PATH`, sonst `~/.m3c-tools/MEMORY`
   (`pkg/er1/memory.go:29-35`). MEMORY-Ordner entstehen NUR bei einem
   Fehlschlag, nicht bei jedem Upload.

## 2. Die Queue: Ablageort und Format

| Was | Wert | Quelle |
|---|---|---|
| Pfad | `~/.m3c-tools/queue.json` (Flag `--queue` uebersteuert) | `pkg/er1/queue.go:12-26` |
| Rechte | Verzeichnis 0700, Datei 0600 | `queue.go:20`, `queue.go:192` |
| Format | ein JSON-Array von Eintraegen, eingerueckt gespeichert | `queue.go:179` |
| Felder je Eintrag | `id`, `transcript_path`, `audio_path`, `image_path`, `tags`, `current_time` (die echte Aufnahmezeit, bleibt ueber Retries erhalten), `queued_at`, `last_retry`, `retry_count`, `last_error` | `queue.go:29-40` |

Die Datei ist von Hand lesbar; ein leeres oder fehlendes `queue.json` heisst:
nichts wartet. Ein Eintrag traegt Dateipfade, nicht die Inhalte selbst; das
ist der Grund fuer die MEMORY-Ordner aus Abschnitt 1 und fuer die Warnung in
Abschnitt 3.

## 3. Wiederanlauf

### 3a. Von Hand: `m3c-tools retry`

```bash
m3c-tools retry                      # Vorgaben: --interval 30, --max-retries 10
m3c-tools retry --interval 60 --queue /pfad/zu/queue.json
```

Aus dem Code gelesen (`cmd/m3c-tools/commands_shared.go:46-149`,
`pkg/er1/retry.go`):

1. Die Queue wird FIFO abgearbeitet, aelteste zuerst.
2. Backoff je Eintrag: `interval * 2^versuch`, gedeckelt bei 5 Minuten;
   ein Eintrag, dessen Wartezeit nicht um ist, wird im Zyklus uebersprungen.
3. Erfolg entfernt den Eintrag (`[retry] SUCCESS`); ein Fehlschlag erhoeht
   `retry_count` und schreibt `last_error` (`[retry] FAILED`); wer
   `--max-retries` erreicht, wird VERWORFEN und aus der Queue entfernt
   (`[retry] DROPPED`).
4. Der Lauf blockiert bis Ctrl+C und beendet den laufenden Zyklus sauber
   ("Retry loop stopped.").
5. Inhalte werden von den im Eintrag genannten Pfaden neu gelesen. Ist der
   Transkript-Pfad nicht mehr lesbar, geht stattdessen der Platzhaltertext
   `Retry upload for <id>` raus (`commands_shared.go:92-100`).

### 3b. Automatisch, und mit einer Einschraenkung

Zwei Stellen starten von sich aus einen Hintergrund-Wiederanlauf
(`pkg/er1/background.go`):

| Ausloeser | Intervall | Quelle |
|---|---|---|
| `m3c-tools upload` (laeuft neben dem aktuellen Upload) | `ER1_RETRY_INTERVAL`, Vorgabe 300 s; `ER1_MAX_RETRIES`, Vorgabe 10 | `commands_shared.go:424-437`, `pkg/er1/config.go:123-124` |
| die Menueleisten-App beim Start | fest 5 Minuten | `cmd/m3c-tools/main.go:2281-2291` |

**Die Einschraenkung:** der Hintergrundpfad liest die Payload-Dateien NICHT
neu, sondern sendet Platzhalter-Inhalte ("Retry upload for <id>", Audio und
Bild als Platzhalter), weil die Queue nur Dateinamen traegt
(`background.go:38-45`). Wer die echten Inhalte nachgeliefert haben will,
faehrt den Wiederanlauf aus 3a; der Hintergrundpfad raeumt die Queue, ersetzt
aber keine Inhalte. Beides ist aus dem Code gelesen, nicht gegen einen
Server gemessen.

## 4. Inspektion: das zweite Buch

`status`, `schedule` und `cancel` arbeiten auf der SQLite-Tracking-DB
`~/.m3c-tools/exports.db` (`--db` uebersteuert), nicht auf `queue.json`.

Gemessen am 2026-09-16, gegen eine Wegwerf-DB (stderr traegt zusaetzlich
`[config]`/`[auth]`-Zeilen, die hier weggelassen sind):

```
$ m3c-tools status --db /…/exports.db
ER1 Retry Queue Status:
  pending:   0
  retrying:  0
  completed: 0
  failed:    0
  total:     0
$ echo $?
0
```

Gemessen am 2026-09-16, ein `cancel` auf einen Eintrag, den es nicht gibt:

```
$ m3c-tools cancel gibt-es-nicht --db /…/exports.db
Entry not found: gibt-es-nicht
$ echo $?
1
```

`status --entry <id>` zeigt einen einzelnen Eintrag; `cancel <id>` setzt ihn
auf `cancelled` und verweigert bei bereits abgeschlossenen Eintraegen
(`commands_shared.go:248-390`, der Verweigerungszweig ist nicht gemessen).

## 5. Was dieses Runbook nicht loest

1. Kein Block hier hat den Wiederanlauf gegen einen echten oder wieder
   erreichbaren ER1-Server gemessen; Abschnitt 3 ist Code-Lektuere.
2. Whisper-Transkription und der Batch-Import samt seiner eigenen
   Tracking-Tabellen sind nicht abgedeckt; dafuer
   [Audio Import & Tracking](../nutzer/audio-import-tracking.md) (EN).
3. Die skillctl-Seite (Registry, Trust, Widerruf) hat ihre eigenen Runbooks;
   der Einstieg ist die [Betriebs-Uebersicht](ueberblick.de.md).
