---
layout: default
title: 'Handbuch: m3c-tools'
---

# Handbuch: m3c-tools

[Deutsch](manual-m3c-tools.de.md) | [English](manual-m3c-tools.md)

`m3c-tools` (Multi-Modal-Memory Tools) ist eine Erfassungspipeline: Sie wandelt
YouTube-Videos, Audio, Screenshots und Sprachnotizen in strukturierte,
**multimodale Beobachtungen** (Text + Audio + Bild) um und lädt sie auf *Ihren*
persönlichen Wissensserver [ER1](https://er1.io). Unter macOS gibt es eine native
Menüleisten-App **und** eine vollständige CLI; unter Linux und Windows ausschließlich
die CLI. Die Kernpakete (`transcript`, `er1`, `impression`) verwenden nur die
Go-Standardbibliothek. Für den Einstieg in fünf Minuten beginnen Sie mit dem
[Schnellstart](../nutzer/quickstart-m3c-tools.de.md). **Diese Seite ist die vollständige
Referenz** für alle Befehle, Flags und Konfigurationsvariablen.

---

## Installation und Build

Laden Sie die einzelne Binärdatei aus dem
[neuesten Release](https://github.com/kamir/m3c-tools/releases/latest) herunter oder
verwenden Sie die plattformspezifischen Einzeiler im
[Schnellstart](../nutzer/quickstart-m3c-tools.md#1-install) und der
[README](../../../README.md#build-from-source). Build aus dem Quellcode (Go 1.26.10+):

```bash
go build -o m3c-tools ./cmd/m3c-tools   # plain Go build
make build                              # → ./build/m3c-tools
make install                            # build + install CLI (and the macOS app)
make menubar                            # build & launch the menu-bar app (macOS, dev)
```

Die Menüleistenoberfläche benötigt unter macOS zusätzlich
`brew install pkg-config portaudio ffmpeg` und
`python3 -m pip install openai-whisper`. Die vollständige Installationsmatrix steht
in der [README](../../../README.md#build-from-source).

---

## Aufruf und Konventionen

```bash
m3c-tools <command> [args] [flags]
```

- Flags stehen nach dem Befehl und haben die Form `--<flag> <value>`.
- `m3c-tools help` zeigt die Befehlsübersicht, `m3c-tools <command> --help` die
  Hilfe eines Befehls. Bei widersprüchlichen Flag-Angaben ist `--help` maßgeblich.
- Jeder Lauf gibt zuerst zwei informative Logzeilen aus (`[config] profile: …`
  und `[auth] …`). Diese dienen der Diagnose und sind keine Befehlsausgabe.

**Herkunft der Konfiguration.** Einstellungen werden aus benannten, mit
`m3c-tools config` verwalteten **Profilen**, aus `~/.m3c-tools/preferences.env`
und der bisherigen globalen Datei `~/.m3c-tools.env` geladen. Eine projektlokale
`.env` wird ausschließlich nach ausdrücklicher Aktivierung mit `M3C_DOTENV=1`
berücksichtigt. Die vollständige Variablenliste steht in der
[Konfigurationsreferenz](manual-m3c-tools.md#configuration-reference), die Vertrauensregel für eine
`.env` im Arbeitsverzeichnis [hier](manual-m3c-tools.md#the-working-directory-env-is-opt-in).
Verwenden Sie `.env.example` als Vorlage.

**Authentifizierung.** ER1-Uploads verwenden einen **API-Schlüssel** aus
`ER1_API_KEY` im Header `X-API-KEY` **und/oder** ein mit `m3c-tools login`
gekoppeltes **Geräte-Token**. Mindestens eines muss eingerichtet sein.
`m3c-tools token` und `m3c-tools doctor` zeigen, was das Werkzeug erkennt.

---

## Befehlsreferenz

Der Abruf eines YouTube-Transkripts benötigt **weder ER1-Zugangsdaten noch einen
API-Schlüssel**, da er die InnerTube-API von YouTube verwendet. Alle ER1-Zugriffe
(`upload`, `import-audio`, `plaud sync`, `pocket sync` und die Retry-/Queue-Befehle)
benötigen eine funktionierende ER1-Konfiguration.

### Erfassung

#### `transcript`: YouTube-Transkript abrufen

```bash
m3c-tools transcript <video_id> [flags]
```

Ruft das Transkript über die InnerTube-API von YouTube ab und gibt es im gewählten
Format aus. Kann außerdem verfügbare Transkriptspuren auflisten und in eine andere
Sprache übersetzen.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--lang` | `<code>` | `en` | Sprachcode des abzurufenden Transkripts |
| `--format` | `<fmt>` | `text` | Ausgabeformat: `text`, `srt`, `json`, `webvtt` |
| `--translate` | `<code>` | n/a | Transkript in die Sprache dieses Codes übersetzen |
| `--list` | n/a | n/a | Nur verfügbare Transkripte auflisten, nicht abrufen |
| `--exclude-generated` | n/a | n/a | Bei `--list` automatisch erzeugte Transkripte ausschließen |
| `--exclude-manually-created` | n/a | n/a | Bei `--list` manuell erstellte Transkripte ausschließen |
| `--proxy-url` | `<url>` | n/a | HTTP-/SOCKS5-Proxy-URL, etwa `http://host:port` |
| `--proxy-auth` | `<creds>` | n/a | Proxy-Zugangsdaten als `user:password` |

```bash
m3c-tools transcript dQw4w9WgXcQ --format srt
m3c-tools transcript dQw4w9WgXcQ --list --exclude-generated
```

#### `upload`: vollständige Beobachtung in ER1 erfassen

```bash
m3c-tools upload <video_id> [flags]
```

Ruft Transkript **und** Vorschaubild ab, erstellt ein zusammengesetztes Dokument
und lädt es in ER1 hoch. Auch bei deaktivierten Untertiteln bleiben Vorschaubild
und Link erhalten; die Beobachtung ist deshalb nie leer.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--audio` | `<file>` | n/a | Audiodatei zur Beobachtung hinzufügen |
| `--impression` | `<text>` | n/a | Eigene Eindrücke oder Kommentare ergänzen |

```bash
m3c-tools upload dQw4w9WgXcQ --impression "Great intro to the topic"
m3c-tools upload dQw4w9WgXcQ --audio note.wav --impression "My take"
```

#### `whisper`: lokale Audiodatei transkribieren

```bash
m3c-tools whisper <audio_file> [flags]
```

Transkribiert eine Audiodatei durch Aufruf der lokalen `whisper`-Binärdatei als
Unterprozess.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--model` | `<model>` | `base` | Whisper-Modell (`tiny`, `base`, `small`, `medium`, `large`) |
| `--language` | `<lang>` | n/a | Sprachhinweis für die Transkription |

```bash
m3c-tools whisper meeting.wav --model base --language en
```

#### `thumbnail`: Video-Vorschaubild herunterladen

```bash
m3c-tools thumbnail <video_id> [flags]
```

Lädt das bestauflösende verfügbare Vorschaubild herunter und fällt bei Bedarf auf
eine kleinere Variante zurück.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--output` | `<file>` | `<video_id>_thumbnail.jpg` | Pfad der Ausgabedatei |

```bash
m3c-tools thumbnail dQw4w9WgXcQ --output cover.jpg
```

#### `record`: Mikrofonaufnahme

```bash
m3c-tools record [output.wav] [flags]
```

Nimmt vom Standardmikrofon in eine WAV-Datei auf (16 kHz / 16-Bit-PCM, Mono,
whisper-kompatibel). Erfordert PortAudio und ein Mikrofon.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--duration` | `<secs>` | `5` | Aufnahmedauer in Sekunden |

```bash
m3c-tools record note.wav --duration 15
```

#### `screenshot`: Bildschirmaufnahme (nur macOS)

```bash
m3c-tools screenshot [flags]
```

Erfasst Bildschirm, Fenster oder ausgewählten Bereich und schreibt eine Bilddatei.
Nur unter macOS verfügbar.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--mode` | `<mode>` | `full` | Aufnahmemodus: `full`, `window`, `region` |
| `--output` | `<dir>` | aktuelles Verzeichnis | Ausgabeverzeichnis |
| `--filename` | `<name>` | mit Zeitstempel | Name der Ausgabedatei |
| `--silent` | n/a | n/a | Aufnahmeton unterdrücken |
| `--hide-cursor` | n/a | n/a | Mauszeiger in der Aufnahme ausblenden |

```bash
m3c-tools screenshot --mode region --output ~/shots --silent
```

#### `import-audio`: Audioverzeichnis durchsuchen oder importieren

```bash
m3c-tools import-audio <dir> [flags]
```

Durchsucht ein Verzeichnis nach Audiodateien. Mit `--run` werden alle neuen Dateien
vollständig transkribiert, hochgeladen und mit Tags versehen. Eine lokale SQLite-DB
verfolgt den Fortschritt, sodass erneute Läufe erledigte Dateien überspringen.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--run` | n/a | n/a | Vollständig importieren, transkribieren, hochladen und mit Tags versehen |
| `--extensions` | n/a | n/a | Unterstützte Audio-Dateiendungen auflisten |
| `--compact` | n/a | n/a | Maschinenlesbare TSV-Ausgabe (Status, Pfad, Größe, Tags) |
| `--db` | `<path>` | `~/.m3c-tools/tracking.db` | Pfad der Tracking-Datenbank |

```bash
m3c-tools import-audio ~/m3c-inbox/ --run
m3c-tools import-audio --extensions
```

**`import-audio reset`** entfernt Tracking-Einträge, damit Dateien erneut importiert
werden können. Dabei wird nur die DB verändert; Audiodateien werden nie gelöscht.
Mindestens eines von `--status`, `--file` oder `--all` ist erforderlich. Ohne
Auswahl werden die aktuellen Anzahlen je Status ausgegeben; der Exit-Code ist
ungleich null.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--status` | `<state>` | n/a | Einträge dieses Status zurücksetzen (`imported`, `uploaded`, `failed`, `whisper-error`) |
| `--type` | `<kind>` | n/a | `--status` auf einen Importtyp einschränken, etwa `plaud` oder `audio` |
| `--file` | `<path>` | n/a | Den Eintrag mit diesem Dateipfad zurücksetzen |
| `--all` | n/a | n/a | **Alle** Tracking-Einträge entfernen (vollständiges Zurücksetzen) |

```bash
m3c-tools import-audio reset --status failed
m3c-tools import-audio reset --status failed --type plaud
m3c-tools import-audio reset --all
```

### Aufnahmegeräte

#### `plaud`: Integration von Plaud-Recordern

```bash
m3c-tools plaud <subcommand> [flags]
```

Synchronisiert Aufnahmen eines Plaud.ai-Geräts nach ER1. Es gibt **zwei
Transportwege**: die ausgelesene Websitzung (`plaud list` / `plaud sync` mit dem
Token von `web.plaud.ai`) und die offizielle Entwickler-API (`plaud dev …` mit
dem dauerhaften OAuth-Token). Beide schreiben in dasselbe Tracking-Verzeichnis;
eine über einen Weg synchronisierte Aufnahme wird über den anderen nicht erneut
synchronisiert.

| Unterbefehl | Bedeutung |
|------------|---------|
| `plaud list` | Plaud-Aufnahmen mit Synchronisierungsstatus auflisten |
| `plaud sync <#\|ID>` | Eine Plaud-Aufnahme nach ER1 synchronisieren |
| `plaud sync --all` | Alle neuen Plaud-Aufnahmen nach ER1 synchronisieren |
| `plaud dev list` | Aufnahmen über die Entwickler-API auflisten, neueste zuerst |
| `plaud dev sync <#\|ID\|N-M>` | Ausgewählte Aufnahmen über die Entwickler-API synchronisieren |
| `plaud dev status` | Serverseitige Transkriptionswarteschlange anzeigen |
| `plaud check` | Gespeichertes Token gegen die Plaud-API prüfen |
| `plaud fix-times` | Falsche Aufnahmezeitstempel bereits synchronisierter Einträge korrigieren |
| `plaud auth login` | API-Token aus Chrome (`web.plaud.ai`) auslesen |
| `plaud auth paste` | `Authorization`-Header aus der Zwischenablage importieren (für SSO empfohlen) |
| `plaud auth password` | Anmeldung mit E-Mail und Passwort → langlebiges Token |
| `plaud auth` | Token aus `$M3C_PLAUD_TOKEN` speichern (sicher) |
| `plaud auth <token>` | Token aus argv speichern: **veraltet** (über `ps` sichtbar) |

**Flags von `plaud sync`**

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--all` | n/a | n/a | Alle noch nicht synchronisierten Aufnahmen statt einer Auswahl synchronisieren |
| `--force` | n/a | n/a | Erneut von Plaud herunterladen und nach ER1 hochladen (auch `-f`) |
| `--tags` | `<list>` | n/a | Kommagetrennte Tags für alle synchronisierten Einträge |
| `--filter` | `<regex>` | n/a | Nur Aufnahmen synchronisieren, deren Titel diesem regulären Ausdruck entspricht |
| `--dry-run` | n/a | n/a | Nur geplante Synchronisierung anzeigen; weder herunterladen noch hochladen |

**Flags von `plaud fix-times`**: tatsächliche lokale Aufnahmezeit bereits
synchronisierter Einträge nachtragen:

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--apply` | n/a | n/a | Korrigierte Zeiten schreiben; ohne Flag nur geplante Änderungen anzeigen |
| `--since` | `<YYYY-MM-DD>` | n/a | Nur Einträge korrigieren, die an oder nach diesem lokalen Datum synchronisiert wurden |
| `--limit` | `<n>` | n/a | Höchstens diese Anzahl von Einträgen korrigieren |

**Flags von `plaud dev`**: `dev list` verwendet `--preview` (Alias `--transcript`)
und `--limit`; die übrigen gehören zu `dev sync`.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--all` | n/a | n/a | Alle noch nicht synchronisierten Aufnahmen synchronisieren |
| `--limit` | `<n>` | n/a | Auf die `n` neuesten Aufnahmen begrenzen |
| `--preview` | n/a | n/a | Bei `dev list` auch die Transkriptvorschau ausgeben |
| `--whisper` | n/a | n/a | Noch nicht transkribierte Audiodaten lokal transkribieren statt überspringen |
| `--force` | n/a | n/a | Bereits im Tracking erfasste Aufnahmen erneut synchronisieren (auch `-f`) |
| `--tags` | `<list>` | n/a | Kommagetrennte Tags für alle synchronisierten Einträge |
| `--dry-run` | n/a | n/a | Nur geplante Synchronisierung anzeigen; weder herunterladen noch hochladen |

**Flags von `plaud auth`**

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--token-file` | `<path>` | n/a | Token aus einer Datei lesen (sicher, nicht in `ps` sichtbar) |
| `--from-er1` | n/a | n/a | Token aus dem ER1-Zugangsdaten-Tresor abrufen (SPEC-0304) |

**Flags von `plaud fix-times`**

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--apply` | n/a | n/a | Korrigierte Zeitstempel schreiben; ohne Flag wird nur eine Vorschau erzeugt |

```bash
m3c-tools plaud auth login
m3c-tools plaud sync --all
m3c-tools plaud sync --all --filter '^(02-04|03-12)' --tags 'Denny,DV' --dry-run
m3c-tools plaud dev sync --limit 5 --whisper
m3c-tools plaud fix-times --apply
```

#### `pocket`: Integration von Pocket-Recordern

```bash
m3c-tools pocket <subcommand> [flags]
```

Synchronisiert Aufnahmen eines Pocket-Geräts nach ER1. `pocket sync` liest das
**eingehängte Gerät**; `pocket cloud-sync` verwendet stattdessen die
**Cloud-API** von Pocket (SPEC-0173 Path B) und benötigt einen API-Schlüssel
`pk_…`; siehe [`setup pocket-key`](manual-m3c-tools.md#setup-set-up-the-python-venv--whisper).

| Unterbefehl | Bedeutung |
|------------|---------|
| `pocket list` | Pocket-Aufnahmen mit Synchronisierungsstatus auflisten |
| `pocket sync --all` | Alle neuen Pocket-Aufnahmen vom eingehängten Gerät synchronisieren |
| `pocket cloud-sync` | Alle neuen Aufnahmen aus der Pocket-Cloud-API synchronisieren |
| `pocket api <sub>` | Direkte Pocket-API-Aufrufe (`list`, `get`, …) |
| `pocket backfill` | Zuordnung für einen außerhalb des Synchronisierungsablaufs hochgeladenen Eintrag nachtragen |
| `pocket mappings` | Gespeicherte Zuordnungen Aufnahme → ER1-Dokument-ID auflisten |

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--all` | n/a | n/a | Bei `pocket sync` alle neuen Aufnahmen synchronisieren (verpflichtend; keine Einzelauswahl verfügbar) |
| `--path` | `<dir>` | aus Konfiguration | Pfad der Geräteaufnahmen für `pocket list` / `pocket sync` überschreiben |
| `--dry-run` | n/a | n/a | Bei `pocket cloud-sync` geplante Übernahmen auflisten, nichts hochladen (auch `-n`) |

```bash
m3c-tools pocket list
m3c-tools pocket sync --all --path /Volumes/POCKET
m3c-tools pocket cloud-sync --dry-run
```

#### `devices`: Audioeingabegeräte auflisten

```bash
m3c-tools devices
```

Listet verfügbare Audioeingabegeräte auf, etwa vor `record`. Keine Flags.

### ER1 und Warteschlange

#### `check-er1`: Erreichbarkeit von ER1 prüfen

```bash
m3c-tools check-er1
```

Kurze Erreichbarkeitsprüfung des ER1-Servers. Für eine vollständige Diagnose
verwenden Sie `doctor`. Keine Flags.

#### `doctor`: Verbindungs- und Konfigurationsdiagnose

```bash
m3c-tools doctor
```

Führt die vollständige Diagnose durch: aktives Profil, Authentifizierung
(API-Schlüssel und/oder Geräte-Token), DNS, TLS sowie ER1-Health- und
Authentifizierungsendpunkte. Bei Uploadfehlern zuerst ausführen. Keine Flags.

#### `token`: Status des Geräte-Tokens anzeigen

```bash
m3c-tools token [--print]
```

Zeigt an, ob ein Geräte-Token geladen ist.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--print` | n/a | n/a | Bearer-Token auf stdout ausgeben (zur Übernahme in der Shell) |

```bash
m3c-tools token
export TOKEN=$(m3c-tools token --print)
```

#### `retry`: Wiederholungsschleife für ausstehende Uploads starten

```bash
m3c-tools retry [flags]
```

Verarbeitet die lokale Warteschlange fehlgeschlagener Uploads in regelmäßigen
Abständen.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--interval` | `<secs>` | `30` | Abfrageintervall in Sekunden |
| `--max-retries` | `<n>` | `10` | Maximale Wiederholungen pro Eintrag |
| `--queue` | `<path>` | `~/.m3c-tools/queue.json` | Pfad der Warteschlangendatei |

```bash
m3c-tools retry --interval 60 --max-retries 5
```

#### `schedule`: Wiederholungseintrag in der Tracking-DB anlegen

```bash
m3c-tools schedule <entry_id> --transcript <path> [flags]
```

Registriert einen ER1-Wiederholungseintrag in der SQLite-Tracking-Datenbank.
`--transcript` ist erforderlich.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--transcript` | `<path>` |: (verpflichtend) | Pfad der Transkriptdatei |
| `--audio` | `<path>` | n/a | Pfad der Audiodatei |
| `--image` | `<path>` | n/a | Pfad der Bilddatei |
| `--tags` | `<tags>` | n/a | Kommagetrennte Tags |
| `--max-attempts` | `<n>` | `10` | Maximale Anzahl von Wiederholungsversuchen |
| `--db` | `<path>` | `~/.m3c-tools/exports.db` | Pfad der SQLite-Datenbank |

```bash
m3c-tools schedule vid-001 --transcript out.txt --tags progress,youtube
```

#### `status`: Status von Wiederholungseinträgen anzeigen

```bash
m3c-tools status [flags]
```

Zeigt den Status von ER1-Wiederholungseinträgen in der Tracking-Datenbank.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--entry` | `<id>` | n/a | Nur den angegebenen Eintrag anzeigen |
| `--db` | `<path>` | `~/.m3c-tools/exports.db` | Pfad der SQLite-Datenbank |

```bash
m3c-tools status
m3c-tools status --entry vid-001
```

#### `cancel`: ausstehenden Wiederholungseintrag abbrechen

```bash
m3c-tools cancel <entry_id> [flags]
```

Bricht einen ausstehenden ER1-Wiederholungseintrag ab.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--db` | `<path>` | `~/.m3c-tools/exports.db` | Pfad der SQLite-Datenbank |

```bash
m3c-tools cancel vid-001
```

### Konfiguration und App

#### `setup`: Python-Umgebung und whisper einrichten

```bash
m3c-tools setup [flags]
```

**Unter macOS** werden die virtuelle Python-Umgebung eingerichtet und whisper
für lokale Transkription installiert.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--force` | n/a | n/a | Virtuelle Umgebung vollständig neu erstellen |
| `--check` | n/a | n/a | Einrichtungsstatus ohne Installation prüfen |

```bash
m3c-tools setup --check
m3c-tools setup --force
```

**Unter Linux und Windows** ist `setup` stattdessen der interaktive
ER1-Einrichtungsassistent; whisper wird dort manuell installiert. Er fragt den
Server ab, öffnet den Browser zur Gerätekopplung und schreibt das Ergebnis ins
aktive Profil.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--er1-url` | `<url>` | wird abgefragt | ER1-Server-URL vorbelegen statt abfragen |
| `--no-browser` | n/a | n/a | Kopplungs-URL ausgeben statt Browser öffnen (für Rechner ohne grafische Oberfläche) |
| `--tags` | `<list>` | n/a | Im Profil zu speichernde Standard-Tags |

```bash
m3c-tools setup --er1-url https://er1.example.com --no-browser
```

**`setup pocket-key <pk_…>`** (macOS) prüft einen Pocket-API-Schlüssel direkt gegen
die Pocket-API und schreibt ihn bei Erfolg in ein Profil. Eine nicht erreichbare
API ist **kein** fataler Fehler; der Schlüssel wird trotzdem gespeichert. Nur
eine ausdrückliche Antwort *unauthorized* lässt den Befehl fehlschlagen.

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--no-write` | n/a | n/a | Nur prüfen, den Schlüssel in keinem Profil speichern |
| `--profile` | `<name>` | aktives Profil | Schlüssel in dieses Profil statt ins aktive schreiben |

```bash
m3c-tools setup pocket-key pk_… --no-write
m3c-tools setup pocket-key pk_… --profile dev
```

#### `config`: Konfigurationsprofile verwalten

```bash
m3c-tools config <list|show|switch|create|test|import|delete|doctor>
```

Verwaltet benannte Konfigurationsprofile.

| Unterbefehl | Bedeutung |
|------------|---------|
| `config list` | Verfügbare Profile auflisten |
| `config show` | Einstellungen des aktiven Profils anzeigen |
| `config switch` | Aktives Profil wechseln |
| `config create` | Neues Profil erstellen |
| `config test` | ER1-Verbindung eines Profils prüfen |
| `config import` | Profil importieren |
| `config delete` | Profil löschen |
| `config doctor` | Profilkonsistenz prüfen; bei jedem FAIL Exit-Code ungleich null |

`config doctor` erwartet einen Profilnamen oder:

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--all` | n/a | *Standard* | Alle Profile in `~/.m3c-tools/profiles` prüfen; auch das ausgeschriebene Wort `all` funktioniert |

```bash
m3c-tools config list
m3c-tools config switch cloud
m3c-tools config doctor --all
m3c-tools config doctor cloud
```

#### `settings`: Profileinstellungseditor öffnen

```bash
m3c-tools settings
```

Öffnet den Profileinstellungseditor im Browser. Keine Flags.

#### `login`: dieses Gerät über den Browser koppeln

```bash
m3c-tools login
```

Öffnet den Browser zur Anmeldung bei ER1 und verknüpft dieses Gerät. Dabei wird
Ihr Kontext übernommen und gegebenenfalls ein Geräte-Token gespeichert. Kann
jederzeit zur erneuten Kopplung aufgerufen werden. Keine Flags.

#### `menubar`: macOS-Menüleisten-App starten

```bash
m3c-tools menubar [flags]
```

Startet die native Menüleisten-App (nur macOS). Alle Menüeinträge beschreibt die
[Anleitung zur Menüleisten-App](../nutzer/menubar-app.de.md).

| Flag | Argument | Standard | Bedeutung |
|------|----------|---------|---------|
| `--title` | `<text>` | `M3C` | Titeltext in der Menüleiste |
| `--icon` | `<path>` | n/a | PNG-Dateipfad des Menüleistensymbols |
| `--log` | `<path>` | `~/.m3c-tools/m3c-tools.log` | Pfad der Logdatei |
| `--verbose` | n/a | n/a | Log zusätzlich auf stderr im Terminal ausgeben |
| `--quiet` | n/a | n/a | Log ausschließlich in die Datei schreiben; Standard und Aufhebung eines früheren `--verbose` |

```bash
m3c-tools menubar --title "M3C" --icon ~/icons/m3c.png
```

#### `version`: Version ausgeben

```bash
m3c-tools version
```

Gibt die Build-Version aus. Keine eigenen Flags; `--version` und `-v` werden als
oberste Aliasse des Unterbefehls akzeptiert (`m3c-tools --version`). Ebenso sind
`--help` und `-h` Aliasse von `help`.

#### `help`: Befehlsübersicht anzeigen

```bash
m3c-tools help
```

Gibt die vollständige Übersicht aller Befehle und Flags aus. Keine Flags.

---

## Konfigurationsreferenz

Variablen werden aus dem aktiven Profil, aus `~/.m3c-tools/preferences.env` und
der bisherigen Datei `~/.m3c-tools.env` oder nach der unten beschriebenen
Aktivierung aus einer projektlokalen `.env` gelesen. Frühere Quellen haben
Vorrang; spätere füllen nur noch leere Werte. Kopieren Sie `.env.example` als
Vorlage. Die folgenden Beispiele zeigen die dokumentierten Standardwerte;
auskommentierte Zeilen in `.env.example` kennzeichnen optionale Werte.

### `.env` im Arbeitsverzeichnis nur nach ausdrücklicher Aktivierung

Eine `.env` im aktuellen Ausführungsverzeichnis ist eine Datei, die das Werkzeug
**findet**, nicht eine von Ihnen **ausgewählte** Datei. Jedes betretene Repository
kann eine solche Datei enthalten. Sie kann `ER1_API_URL`, `M3C_PLM_BASE_URL`,
`PLAUD_API_URL` oder `YT_PROXY_URL` setzen und damit die Empfänger von
API-Schlüssel und Geräte-Token bestimmen. Deshalb wird sie **standardmäßig
ignoriert**; das Werkzeug weist einmal auf stderr darauf hin.

| `M3C_DOTENV` | Wirkung auf `./.env` |
|--------------|--------------------|
| nicht gesetzt (Standard) | Ignoriert. Eine stderr-Zeile nennt Datei und Schalter. |
| `1`, `true`, `yes`, `on` | Vollständig angewendet. Sicherheitsrelevante beigesteuerte Schlüssel (URL, Token, Schlüssel, Secret, Pfadformen) werden auf stderr mit ihrem **Namen** aufgeführt. |
| `0`, `false`, `no`, `off` | Ohne Hinweis ignoriert. |

```bash
M3C_DOTENV=1 m3c-tools plaud dev sync     # per invocation, in a repo you trust
```

Die Rangfolge bleibt unverändert: Das aktive Profil hat Vorrang;
`~/.m3c-tools/preferences.env` und die bisherige `~/.m3c-tools.env` ergänzen
fehlende Werte. Eine ausdrücklich aktivierte `./.env` setzt nur weiterhin leere
Werte. Dateien im Home-Verzeichnis sind von diesem Schalter nicht betroffen.
Wenn Sie `M3C_DOTENV=1` dauerhaft exportieren möchten, speichern Sie die
Einstellungen stattdessen in einem Profil (`m3c-tools config`). Das ist ebenso
bequem, ohne die Aktivierung in fremde Repositories mitzunehmen.

### ER1-Verbindung (für Uploads erforderlich)

| Variable | Standard | Bedeutung |
|----------|---------|---------|
| `ER1_API_URL` | n/a | URL des ER1-Upload-Endpunkts, etwa `https://onboarding.guide/upload_2` |
| `ER1_API_KEY` | n/a | Als Header `X-API-KEY` gesendeter API-Schlüssel |
| `ER1_CONTEXT_ID` | n/a | Kontextkennung für Uploads |
| `ER1_VERIFY_SSL` | `false` | SSL-Prüfung: `true` \| `false` (für lokale Entwicklung mit selbstsigniertem Zertifikat `false`) |
| `ER1_CONTENT_TYPE` | `YouTube-Video-Impression` | Inhaltstypbezeichnung im Uploadformular |

### ER1-Feinabstimmung

| Variable | Standard | Bedeutung |
|----------|---------|---------|
| `ER1_UPLOAD_TIMEOUT` | `600` | HTTP-Zeitlimit für Uploadanfragen in Sekunden |
| `ER1_RETRY_INTERVAL` | `300` | Sekunden zwischen automatischen Wiederholungszyklen |
| `ER1_MAX_RETRIES` | `10` | Maximale Wiederholungen vor dem Verwerfen eines fehlgeschlagenen Uploads |
| `M3C_ER1_SESSION_PERSIST` | `false` | Bei der Anmeldung verknüpften Kontext über App-Neustarts speichern |
| `M3C_ER1_SESSION_FILE` | `~/.m3c-tools/er1_session.json` | Eigener Pfad für die gespeicherte ER1-Sitzung als JSON |

> Der Retry-Backoff ist in `pkg/er1/retry.go` festgelegt. Die früheren Variablen
> `ER1_RETRY_BASE_DELAY` / `ER1_RETRY_MAX_DELAY` wurden entfernt und haben keine Wirkung.

### YouTube-Ratenbegrenzung abmildern

| Variable | Standard | Bedeutung |
|----------|---------|---------|
| `YT_PROXY_URL` | n/a | HTTP-/SOCKS5-Proxy zur Vermeidung von YouTube-429-Ratenbegrenzungen |
| `YT_PROXY_AUTH` | n/a | Proxy-Zugangsdaten als `user:password` |

> Transkripte werden außerdem unter `~/.m3c-tools/cache/transcripts/` für sieben
> Tage zwischengespeichert. Bei HTTP 429 arbeitet die App ohne Transkript weiter.

### Whisper-Transkription

Für Sprachaufnahmen in der Menüleiste, Audioimport und lokale
Sprache-zu-Text-Verarbeitung. **Nicht** für YouTube-Transkripte; diese werden
direkt abgerufen.

| Variable | Standard | Bedeutung |
|----------|---------|---------|
| `M3C_WHISPER_MODEL` | `large` | Modellgröße: `tiny` \| `base` \| `small` \| `medium` \| `large` |
| `M3C_WHISPER_FALLBACK` | `medium,base,tiny` | Kommagetrennte Ausweichkette bei Ausfall des primären Modells |
| `M3C_WHISPER_TIMEOUT` | `7200` | Zeitlimit für Transkription in Sekunden (`0` = unbegrenzt) |
| `M3C_WHISPER_LANGUAGE` | `de` | Transkriptionssprache als ISO-639-1-Code |
| `M3C_WHISPER_PRELOAD` | `true` | Modell beim Start der Menüleisten-App vorladen, um den ersten Lauf zu beschleunigen |

### Screenshot-Erfassung

| Variable | Standard | Bedeutung |
|----------|---------|---------|
| `M3C_SCREENSHOT_MODE` | `clipboard-first` | `clipboard-first` \| `interactive` \| `screencapture-legacy` |
| `M3C_SCREENSHOT_CLIPBOARD_TIMEOUT_SEC` | `20` | Wartezeit auf einen Screenshot in der Zwischenablage im Modus clipboard-first, in Sekunden |
| `M3C_SCREENSHOT_FOCUS_DELAY_MS` | `700` | Verzögerung vor interaktiver Aufnahme aus Menüleistenaktionen in ms (`0` deaktiviert sie) |
| `YT_MEMORY_DIR` | `~/Library/Application Support/YTTranscript/MEMORY` | Wurzelverzeichnis für MEMORY-Ordner zur Speicherung von Eindrücken |

> Interaktive Aufnahmen erfordern zusätzlich die Berechtigung zur
> Bildschirmaufnahme für `m3c-tools`.

### Audioimport

| Variable | Standard | Bedeutung |
|----------|---------|---------|
| `IMPORT_AUDIO_SOURCE` | n/a | Quellordner für Audiodateien, etwa ein GDrive-Spiegel |
| `IMPORT_AUDIO_DEST` | `~/ER1` | Basiszielordner für importierte MEMORY-Ordner |
| `IMPORT_CONTENT_TYPE` | `Audio-Track vom Diktiergerät` | Inhaltstypbezeichnung für Audioimporte |
| `IMPORT_TRACKER_FILE` | `~/.m3c-tools/transcript_tracker.md` | Verfolgt bereits importierte Dateien |

### Plaud-Integration

| Variable | Standard | Bedeutung |
|----------|---------|---------|
| `PLAUD_API_URL` | `https://api.plaud.ai` | Basis-URL der Plaud-API |
| `PLAUD_TOKEN_FILE` | `~/.m3c-tools/plaud-session.json` | Pfad der Plaud-Sitzungs-Token-Datei |
| `PLAUD_CONTENT_TYPE` | `Plaud-Fieldnote` | Inhaltstypbezeichnung für Plaud-Feldnotizen |
| `M3C_PLAUD_TOKEN` | n/a | Von `plaud auth` verwendetes Plaud-API-Token; vermeidet Offenlegung über argv |
| `PLAUD_TRANSCRIBE_MODE` | `queue` | Für noch nicht transkribierte Aufnahmen in `plaud dev sync`: `queue` (serverseitiges whisper, SPEC-0111), `lazy` (Tag `todo.transcribe`) oder `off` (nur Audio). 🍎 |
| `PLAUD_MAX_AUDIO_MB` | `30` | Maximale an einen ER1-Upload angehängte Audiogröße in MB bei `plaud dev sync`. Größere Aufnahmen werden **nur als Transkript** hochgeladen; der Eintrag wird trotzdem angelegt und die Aufnahme bleibt in Plaud. Dies vermeidet **HTTP 413** am ER1-Eingang: Cloud Run weist Anfragen über etwa 32 MiB zurück. Auf etwa 31 erhöhen, um größere Aufnahmen zu spiegeln. 🍎 |

### Zeiterfassung und rückwirkende Zuordnung (Menüleisten-App)

Die Menüleisten-App kann Projektzeitblöcke aus Ihren Erfassungen **ableiten**:
Nach dem Hochladen einer Beobachtung werden ihre Tags mit den PLM-Projekten
verglichen. Für den besten Treffer wird ein Block von etwa 15 Minuten angelegt.
Dies erfolgt **ausschließlich in der Menüleisten-App**; die reine CLI erfasst
keine Zeiten. Die vollständigen Zuordnungsregeln (stark: `project:<slug>`;
mittel: `client:<name>`; schwach: mindestens zwei gemeinsame Tags), das Nachtragen
des laufenden Monats beim Start und die Diagnose `[reverse-tracking] no project match`
stehen unter **[Menüleisten-App → Funktionsweise der rückwirkenden Zuordnung](../nutzer/menubar-app.md#how-reverse-tracking-works)**.

| Variable | Standard | Bedeutung |
|----------|---------|---------|
| `M3C_REVERSE_BLOCK_ENABLED` | `true` | Hauptschalter für abgeleitete Zeitblöcke. `false` deaktiviert sie. Beobachtungen werden weiter erfasst, damit sie später nachgetragen werden können. |
| `M3C_REVERSE_BLOCK_DURATION` | `900` | Länge eines abgeleiteten Blocks in Sekunden (900 = 15 Minuten, um den Beobachtungszeitstempel zentriert). |
| `M3C_REVERSE_MIN_TAG_OVERLAP` | `2` | Mindestanzahl gemeinsamer einfacher Tags für einen **schwachen** Treffer. Kleinere Werte ergeben mehr, aber ungenauere Treffer. `project:<slug>` oder `client:<name>` genügt unabhängig davon für eine starke Zuordnung. |

---

## Exit-Verhalten und Wiederholungswarteschlange

Fehlgeschlagene Uploads (Netzwerkfehler, ER1 nicht erreichbar oder
Authentifizierungsproblem) gehen **nicht verloren**. Sie werden lokal eingereiht
und können später wiederholt werden.

- **Speicherort.** Die JSON-Warteschlange liegt unter `~/.m3c-tools/queue.json`.
  `schedule`, `status` und `cancel` verwenden eine separate SQLite-Tracking-DB
  unter `~/.m3c-tools/exports.db`.
- **Wiederholen.** `m3c-tools retry` verarbeitet die Warteschlange regelmäßig
  (`--interval`, `--max-retries`, `--queue`). Automatische Zyklen werden durch
  `ER1_RETRY_INTERVAL` und `ER1_MAX_RETRIES` gesteuert. Der Backoff ist in
  `pkg/er1/retry.go` festgelegt.
- **Prüfen oder abbrechen.** `m3c-tools status` listet Tracking-Einträge auf;
  `--entry <id>` wählt einen aus. `m3c-tools cancel <entry_id>` verwirft einen
  ausstehenden Eintrag.

```bash
m3c-tools status
m3c-tools retry --interval 60
m3c-tools cancel vid-001
```

---

## Fehlerbehebung

| Symptom | Abhilfe |
|---------|-----|
| Uploads oder Authentifizierung schlagen fehl (`key_set=false`) | `m3c-tools doctor` ausführen. Das aktive Profil enthält vermutlich einen Platzhalter-Schlüssel: `setup` oder `login` erneut ausführen und einen echten `ER1_API_KEY` sicherstellen. |
| Befehl `whisper` nicht gefunden | Mit `python3 -m pip install openai-whisper` installieren; benötigt `ffmpeg`. Alternativ `m3c-tools setup` ausführen. |
| `subtitles are disabled for this video` | Erwartetes Verhalten. **Vorschaubild und Link** bleiben erhalten. Sprachnotiz oder `--impression` ergänzen. |
| Menü „Projects“ bleibt bei *Loading…* | Keine ER1-Zugangsdaten sind in der App angekommen. Schlüssel im aktiven Profil korrigieren oder `login` ausführen; anschließend **Menüleisten-App neu starten**. |
| `[reverse-tracking] no project match` im Log | Diagnose, kein Fehler: Die Tags der Erfassung passten zu keinem PLM-Projekt. Passende Projekttags ergänzen oder mit `project:<slug>` / `client:<name>` erfassen; siehe [rückwirkende Zuordnung](../nutzer/menubar-app.md#how-to-make-reverse-tracking-work-for-your-captures). |
| Upload schlägt fehl und wird wiederholt | Fehlgeschlagene Uploads stehen in `~/.m3c-tools/queue.json`. `m3c-tools retry` ausführen und `m3c-tools status` prüfen. |
| YouTube 429 / Ratenbegrenzung | `YT_PROXY_URL` setzen. Transkripte werden sieben Tage zwischengespeichert; ohne Transkript arbeitet die App mit eingeschränktem Inhalt weiter. |
| `plaud dev sync` → HTTP 413 | Die Audiodaten überschreiten das ER1-Eingangslimit von etwa 32 MiB. `plaud dev sync` lässt Audio über `PLAUD_MAX_AUDIO_MB` (Standard 30) bereits weg und lädt nur das Transkript hoch. Bei weiterem HTTP 413 den Wert senken; ein strengerer Proxy kann schon unter 30 MB begrenzen. |

---

## Siehe auch

- [Schnellstart: m3c-tools](../nutzer/quickstart-m3c-tools.de.md): Einstieg in fünf Minuten
- [Menüleisten-App](../nutzer/menubar-app.de.md): Projekte, Gantt-Zeiterfassung und rückwirkende Zuordnung im Detail
- [Handbuch: skillctl](manual-skillctl.de.md): Vertrauenslebenszyklus von Agenten-Skills, Befehl für Befehl
- [Plattformunterschiede](PLATFORM-DIFFERENCES.de.md): Verhalten unter macOS, Linux und Windows
