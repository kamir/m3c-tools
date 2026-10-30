---
layout: default
title: "Schnellstart: m3c-tools"
---

# Schnellstart: m3c-tools

[Deutsch](quickstart-m3c-tools.de.md) · [English](quickstart-m3c-tools.md)

In etwa fünf Minuten die erste multimodale Erinnerung erfassen. Anschließend ist
`m3c-tools` installiert, mit einem [ER1](https://er1.io)-Wissensserver verbunden
und ein YouTube-Transkript abgerufen und auf Wunsch hochgeladen.

> **Was ist m3c-tools?** Eine Erfassungspipeline: Sie wandelt YouTube-Videos, Audio,
> Screenshots und Sprachnotizen in strukturierte multimodale Beobachtungen auf
> *Ihrem* ER1-Server um. Auf macOS ist sie eine native Menüleisten-App, auf
> Linux/Windows eine vollständige CLI. Die ausführliche Befehlsreferenz steht
> im [m3c-tools-Handbuch](../referenz/manual-m3c-tools.de.md).

---

## 1. Installieren

Das installiert `m3c-tools` für Ihren Benutzer, ohne Adminrechte. Sie brauchen cosign oder ein OpenSSL mit ed25519-Unterstützung. Führen Sie auf macOS zuerst `brew install cosign` aus.

```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/953dd07dfe440309f5702f296346b5e85bc5c1e1/tools/m3c-tools-install.sh | bash
```

```powershell
irm https://raw.githubusercontent.com/kamir/m3c-tools/953dd07dfe440309f5702f296346b5e85bc5c1e1/tools/m3c-tools-install.ps1 | iex
```

Prüfen Sie die Installation und holen Sie ein erstes Transkript. Dafür brauchen Sie kein Konto:

```bash
m3c-tools version
m3c-tools transcript dQw4w9WgXcQ
```

> **Lieber aus dem Quellcode bauen?** Sie brauchen Go 1.26.10+. Auf macOS braucht die Menüleisten-GUI zusätzlich
> `brew install pkg-config portaudio ffmpeg` und `python3 -m pip install openai-whisper`.
> Danach `make install`. Siehe [Aus dem Quellcode bauen](../../../README.de.md#aus-dem-quellcode-bauen).

---

## 2. Mit ER1 verbinden (geführte Einrichtung)

```bash
m3c-tools setup
```

Der Assistent führt durch:

1. **ER1-Server-URL**: Standard ist `https://onboarding.guide/upload_2`.
2. **Browser-Login**: Öffnet Chrome und übernimmt Ihre Nutzer-ID, den Kontext, automatisch.
3. **API-Key**: Für Uploads erforderlich, im Header `X-API-KEY` gesendet. Zugang erhalten Sie auf Anfrage an mirko.kaempf@gmail.com.
4. **Standard-Tags**: Für die Synchronisation von Aufnahmegeräten.

Alles wird nach `~/.m3c-tools.env` geschrieben.

> **Login und API-Key.** Der Browser-Login erfasst Ihren *Kontext* und kann zusätzlich
> ein Geräte-Token speichern. Uploads authentisieren sich mit API-Key **oder**
> Geräte-Token; mindestens eine Variante einrichten. Mit `m3c-tools login` lässt
> sich die Browserkopplung jederzeit erneut ausführen.

**Lieber manuell konfigurieren?** Vorlage kopieren und bearbeiten:

```bash
cp .env.example ~/.m3c-tools.env
```

```ini
ER1_API_URL=https://onboarding.guide/upload_2
ER1_API_KEY=your-api-key
ER1_CONTEXT_ID=your-context-id
```

Vollständige Variablenreferenz: [m3c-tools-Handbuch → Konfiguration](../referenz/manual-m3c-tools.md#configuration-reference).

---

## 3. Prüfen

```bash
m3c-tools doctor
```

`doctor` prüft das aktive Profil, Authentisierung mit API-Key und/oder Geräte-Token,
DNS, TLS sowie ER1-`/health` und Auth-Endpunkte. Ist alles grün, kann es losgehen.
Für eine reine Erreichbarkeitsprüfung `m3c-tools check-er1` verwenden.
Ist kein ER1 eingerichtet, sagt der Befehl das, nennt, was ohne ER1 funktioniert, und endet mit `0`.

---

## 4. Die erste Aufnahme

### YouTube-Transkript abrufen (ohne ER1)

```bash
m3c-tools transcript dQw4w9WgXcQ                 # plain text
m3c-tools transcript dQw4w9WgXcQ --format srt    # SubRip
m3c-tools transcript dQw4w9WgXcQ --list          # list available languages
m3c-tools transcript dQw4w9WgXcQ --translate de  # translate to German
```

Nutzt YouTubes InnerTube-API: **kein API-Key erforderlich**. Unterstützt `text`,
`srt`, `json`, `webvtt`, Proxys über `--proxy-url` und Übersetzung.

### Vollständige Beobachtung nach ER1 übertragen

```bash
m3c-tools upload dQw4w9WgXcQ --impression "Great intro to the topic"
```

Ruft Transkript **und** Vorschaubild ab, erzeugt ein zusammengesetztes Dokument und
lädt es nach ER1 hoch. Sind Untertitel deaktiviert, bleiben **Vorschaubild und Link**,
damit die Beobachtung nicht leer ist. Eigenes Audio mit `--audio note.wav` hinzufügen.

### Lokales Audio transkribieren

```bash
m3c-tools whisper meeting.wav --model base --language en
```

Führt Ihr lokales `whisper`-Binary aus. Beim ersten Einsatz wird das Modell heruntergeladen,
für `base` etwa 150 MB.

### Audioordner im Stapel importieren (macOS)

```bash
m3c-tools import-audio ~/m3c-inbox/ --run     # transcribe + upload + tag, end-to-end
m3c-tools import-audio --extensions           # show supported formats
```

Der Fortschritt wird in einer lokalen SQLite-DB erfasst. Wiederholte Läufe überspringen
bereits erledigte Dateien.

---

## 5. Menüleisten-App starten (macOS)

```bash
open /Applications/M3C-Tools.app     # after `make install`
# or, in dev:
make menubar
```

Ein Symbol erscheint in der Menüleiste. Darüber:

- **Fetch Transcript…** → YouTube-URL einfügen.
- **Capture Screenshot** → kommentieren und Sprachnotiz aufnehmen → Store nach ER1.
- **Projects** → Ihre PLM-Projektliste mit Zeiterfassung.

Alle Menüeinträge und das Observation Window beschreibt die
[Anleitung zur Menüleisten-App](menubar-app.de.md).

---

## 6. Aufnahmegeräte (optional)

Für einen **Plaud**-Recorder oder ein **Pocket**-Gerät:

```bash
m3c-tools plaud auth login      # pair (auto-launches Chrome): macOS/Windows/Linux
m3c-tools plaud list            # list recordings + sync status
m3c-tools plaud sync all        # sync everything to ER1

m3c-tools pocket ...            # see: m3c-tools pocket --help
```

---

## Fehlerbehebung

| Symptom | Abhilfe |
|---|---|
| `doctor` zeigt `key_set=false` oder Authentisierung schlägt fehl | Das aktive Profil hat keinen echten Schlüssel. `m3c-tools setup` oder `m3c-tools login` erneut ausführen; `ER1_API_KEY` darf kein Platzhalter sein. |
| Projects-Menü bleibt bei *Loading projects…* stehen | Bei der App kam kein ER1-Credential an. Schlüssel im aktiven Profil korrigieren oder `login` ausführen, danach die Menüleisten-App neu starten. |
| `subtitles are disabled for this video` | Erwartetes Verhalten. Vorschaubild und Link bleiben erhalten. Eine Sprachnotiz ergänzen. |
| Whisper meldet "command not found" | Mit `python3 -m pip install openai-whisper` installieren; benötigt `ffmpeg`. |
| `import-audio --run` endet mit `1` und meldet `failed=1` | Eine Transkription oder ein Upload ist fehlgeschlagen. Eine Datei mit fehlgeschlagener Transkription wird nicht hochgeladen und beim nächsten Lauf neu aufgegriffen. Ein fehlgeschlagener Upload liegt in der Warteschlange; führen Sie `m3c-tools retry` aus. |
| Upload schlägt fehl und wird wiederholt | Fehlgeschlagene Uploads liegen lokal in der Warteschlange. `m3c-tools status` zeigt `Uploads waiting for retry`. `m3c-tools retry` liefert sie aus und läuft weiter, bis Sie mit Strg+C stoppen. |

---

## Nächste Schritte

- **Jedes Kommando und Flag:** [m3c-tools-Handbuch](../referenz/manual-m3c-tools.de.md)
- **Die Skills Ihrer Agenten verwalten:** [Schnellstart: skillctl](quickstart-skillctl.de.md)
- **Verhalten je Plattform:** [Plattformunterschiede](../referenz/PLATFORM-DIFFERENCES.de.md)
