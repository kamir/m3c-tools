# Anleitung: der Einstieg in m3c-tools

Wie eine Nutzerin von der leeren Maschine zur ersten eigenen Aufnahme kommt,
und welche der bestehenden Seiten sie danach weiterfuehrt. Diese Seite
konsolidiert den Einstiegsteil aus drei englischen Quellen
([Quickstart: m3c-tools](../../quickstart-m3c-tools.md),
[Getting Started](../../getting-started.md),
[Prerequisites](../../prerequisites.md)); bei Widerspruch gilt das
docaudit-getorte [Manual](../../manual-m3c-tools.md).

Zielgruppe: die Person, die m3c-tools benutzen will. Teil A reicht fuer alle,
die nur das fertige Programm brauchen; Teil B ist fuer den Quell-Build auf
macOS; Teil C weist den Weg zu den Tutorials und zur Menueleisten-App.

Rolle: Nutzer · Sprache: DE · Stand: 2026-09-16

## Die Grundregel in einem Satz

**Erst `m3c-tools doctor` gruen sehen, dann der ersten Aufnahme trauen:**
der Befehl prueft Profil, Anmeldung, DNS, TLS und die ER1-Endpunkte, und
alles Weitere baut auf diesem Befund auf.

## Welcher Weg ist deiner

| Situation | Weg | Abschnitt |
|---|---|---|
| Ich will das Werkzeug benutzen, egal auf welcher Plattform | fertiges Release-Binary | Teil A |
| Ich will die macOS-Menueleisten-App mit Mikrofon und Screenshot | Quell-Build mit cgo | Teil B |
| Ich will zuerst verstehen, was das Werkzeug tut | Lesen, dann Teil A | [Manual: m3c-tools](../../manual-m3c-tools.md) |
| Meine Maschine hat weder git noch Go | nur fuer Teil B noetig | [Prerequisites](../../prerequisites.md) |

## Teil A: das fertige Binary (alle Plattformen)

1. Binary aus dem [aktuellen Release](https://github.com/kamir/m3c-tools/releases/latest)
   holen. Die Plattform-Einzeiler (macOS arm64/amd64, Linux amd64, Windows)
   stehen zum Kopieren in
   [Quickstart: m3c-tools, Abschnitt 1](../../quickstart-m3c-tools.md#1-install).

2. Pruefen, dass das Binary antwortet:

   ```bash
   m3c-tools version
   m3c-tools help
   ```

3. Mit ER1 verbinden, gefuehrt. Der Assistent fragt Server-URL, Browser-Login,
   API-Key und Standard-Tags ab und schreibt alles nach `~/.m3c-tools.env`:

   ```bash
   m3c-tools setup
   ```

   Wer lieber von Hand konfiguriert, kopiert die Vorlage `.env.example` nach
   `~/.m3c-tools.env`; die drei Pflichtvariablen sind `ER1_API_URL`,
   `ER1_API_KEY`, `ER1_CONTEXT_ID`
   ([volle Referenz](../../manual-m3c-tools.md#configuration-reference)).

4. Den Befund einholen:

   ```bash
   m3c-tools doctor
   ```

5. Die erste Aufnahme. Ein Transkript braucht kein ER1:

   ```bash
   m3c-tools transcript dQw4w9WgXcQ
   ```

   Eine vollstaendige Beobachtung (Transkript, Thumbnail, eigener Kommentar)
   geht mit `m3c-tools upload <video-id> --impression "..."` nach ER1; die
   Varianten stehen in
   [Quickstart: m3c-tools, Abschnitt 4](../../quickstart-m3c-tools.md#4-your-first-capture).

## Teil B: Quell-Build auf macOS (Menueleisten-App)

Voraussetzungen: git und Go 1.25 oder neuer (`go.mod` verlangt 1.25.0), dazu
die Homebrew-Pakete fuer cgo und Audio. Die Einzelheiten je Plattform stehen in
[Prerequisites](../../prerequisites.md).

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make deps          # Homebrew- und pip-Abhaengigkeiten, nur beim ersten Mal
make install       # baut, erzeugt M3C-Tools.app, installiert CLI und App
make permissions   # oeffnet die macOS-Berechtigungs-Panes nacheinander
make menubar       # startet die Menueleisten-App
```

Was `make install` im Einzelnen tut (App-Bundle, Pfade, Info.plist) und wie man
wieder deinstalliert, steht in [Getting Started](../../getting-started.md).
Die App selbst, ihre vier Capture-Kanaele und das Observation Window beschreibt
[Menu Bar App](../../menubar-app.md).

## Teil C: wie es weitergeht

| Ich will ... | Seite | Sprache |
|---|---|---|
| ueben, mit echten Exit-Codes als Beleg | [Tutorial: Katas und Test Ride](../../tutorial-katas-und-test-ride.de.md) | DE |
| eigene Skills auf mehreren Maschinen nutzen | [Tutorial, Szenario 01](../../tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md) | DE |
| meinen ersten Skill signieren, mit Pruefung durch einen Zweiten | [Tutorial, Szenario 02](../../tutorial-szenario-02-erster-signierter-skill.de.md) | DE |
| jedes Kommando und jedes Flag nachschlagen | [Manual: m3c-tools](../../manual-m3c-tools.md) | EN |
| Audio-Ordner im Stapel importieren | [Audio Import & Tracking](../../audio-import-tracking.md) | EN |
| ein Aufnahmegeraet (Plaud, Pocket) anbinden | [Quickstart: m3c-tools, Abschnitt 6](../../quickstart-m3c-tools.md#6-capture-devices-optional) | EN |
| wissen, was auf meiner Plattform fehlt | [Platform differences](../../PLATFORM-DIFFERENCES.md) | EN |

Wenn etwas klemmt: die Fehlertabelle in
[Quickstart: m3c-tools, Troubleshooting](../../quickstart-m3c-tools.md#troubleshooting)
und der Abschnitt Troubleshooting im [Manual](../../manual-m3c-tools.md#troubleshooting).
