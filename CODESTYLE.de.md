# CODESTYLE.md: Qualitätsgrundlage des m3c-tools-Codes

[Deutsch](CODESTYLE.de.md) · [English](CODESTYLE.md)

Diese Datei begründet die maschinell erzwungenen Regeln. `.golangci.yml` bestimmt,
was CI ausführt; hier steht **warum** und ebenso ausdrücklich, was **noch nicht**
erzwungen wird. Eine Absicht darf nicht mit einer verbindlichen Prüfung verwechselt werden.

Ergänzende Werkzeuge: `/code-quality` führt die Baseline aus und behebt Befunde,
`/docs-consistency` prüft CLI und Handbuch wie unten beschrieben,
`/slop-check` prüft maschinell wirkende Prosa und überzogene Behauptungen.

---

## Die pragmatic+-Grundlage

"Pragmatic+" bedeutet: **Zuerst berichten, nur bei eindeutigen Regeln blockieren.**
Ein Befund wird durch Codeänderung oder eine schriftliche, begrenzte Ausnahme geschlossen,
niemals durch stilles Aufweichen einer Regel.

| Bereich | Regel | Werkzeuge |
|---|---|---|
| Format | Deterministische Erweiterung von gofmt, Importgruppen Standardbibliothek / extern / `github.com/kamir/m3c-tools` | `gofumpt`, `gci` |
| Korrektheit | `go vet` + `staticcheck` + `unused` + `errcheck` | `golangci-lint` |
| Fehler | Mit `%w` umschließen, Sentinel-Namen `ErrXxx`, kein stilles `_ =` außerhalb von Tests | `errorlint`, `errcheck` |
| Dokumentationskommentare | Exportierte Bezeichner dokumentieren; Kommentare enden mit Punkt | `revive`, `godot` |
| Sauberkeit | Keine unnötigen Konvertierungen, offenen Response-Bodies oder Aliase auf Schleifenvariablen | `gocritic`, `unconvert`, `bodyclose`, `copyloopvar`, `nilerr`, `misspell` |
| Sicherheit (SAST) | Kryptografie, Injection, fest eingebaute Credentials | `gosec` |
| Abhängigkeiten | Erreichbare CVEs, Secret-Scan, `go mod tidy` verändert nichts | `govulncheck`, `gitleaks`, CI-Job |
| CLI-Oberfläche | Jedes echte Flag dokumentiert, jedes dokumentierte Flag vorhanden, jedes aufgerufene Verb in `--help` genannt | `cmd/docaudit`, siehe unten |
| Aktuelle Indizes | Jedes `cmd/`-Binary und `pkg/`-Paket aufgeführt, jeder Eintrag vorhanden, beide Anzahlen korrekt | `scripts/check-index.sh`, CI-`docs-gate` und Abschnitt 7 von `check-docs.sh` |
| Exit-Codes | Jede dokumentierte Zahl registriert oder einem Verantwortlichen zugeordnet; Handbuch und Verbregister stimmen je Verb überein; `pull`-Gate wird als Code gelesen | `cmd/exitaudit`, siehe unten |

### Ehrlichkeitsregel für Kommentare

Ein Kommentar beschreibt, was **existiert**. Grenzen sind erwünscht und sollen auffallen:
`HONEST SCOPE:`, `NOT-YET-WIRED:`, "erkennbar, nicht unmöglich".
Wunschdokumentation, die neben nicht entsprechendem Code einen geplanten Entwurf in der
Gegenwartsform beschreibt, ist ein Fehler und kein Platzhalter.

---

## Was heute maschinell erzwungen wird

In `.golangci.yml` aktiviert und im CI-Job `lint` blockierend:

- `go vet ./...`
- `staticcheck`, `unused`, `errcheck`, mit gepflegter Ausnahmeliste: Jeder Eintrag
  benennt den unbeaufsichtigten Aufruf, dessen Fehlerbehandlung er ausnimmt.

Als eigenständige CI-Jobs blockierend: `govulncheck`, `gitleaks`, die Prüfung auf ein
wirkungsloses `go mod tidy`, Tests mit Race Detector und **`docaudit`** im Job
`docs-gate` von `ci.yml`, `release.yml` und `skillctl-release.yml`.

## Vorbereitet und bewusst noch nicht blockierend

Gemessen in diesem Repository mit golangci-lint v2.11.3 am 2026-09-03.
Die Zahlen machen die Lücke konkret statt zu einer vagen Absicht:

| Regel | Aktueller Einführungsaufwand |
|---|---|
| `gofumpt` + `gci` | **186 Dateien** würden sich ändern, vor allem `0700` → `0o700` und Importgruppen |
| `revive` | 50 Befunde |
| `gocritic` | 31 Befunde |
| `nilerr` | 22 Befunde |
| `errorlint` | 9 Befunde |
| `misspell` | 7 Befunde |
| `unconvert` / `godot` | Je 3 |
| `copyloopvar` | 2 Befunde |
| `bodyclose` | 1 Befund |
| `gosec` | Als golangci-lint-Prüfer nicht anwendbar: gosec läuft eigenständig in CI, siehe unten |
| Coverage-Untergrenze | Noch nicht gemessen; **nie** höher setzen, als die Tests bereits erreichen |

Die Zeile zu `gosec` lautete vom 2026-09-03 bis 2026-09-15 "noch nicht gemessen,
Werkzeug nicht in CI installiert". Beide Aussagen wurden fast sofort falsch.
`.github/workflows/gosec.yml` entstand am selben Tag, `gosec-diff-gate.yml` am Folgetag.
Drei auf master erforderliche Kontexte tragen gosec im Namen: `gosec`,
`gosec SAST (SARIF -> Code Scanning)` und `gosec no-new-findings (in-CI diff gate)`.
Gemessen wird ebenfalls: Die eingecheckte Baseline `docs/security/gosec-inci-baseline.txt`
enthält seit 2026-09-10 insgesamt 454 Signaturen; ein Lauf am 2026-09-15 meldete
525 Befunde. Eine zusätzliche Aktivierung IN golangci-lint würde ein bereits
blockierendes Werkzeug doppeln. Deshalb steht dort nicht anwendbar statt eines Aufwands.

Die übrigen Regeln sind noch nicht aktiviert, weil eine Formatänderung in 186 Dateien
und etwa 128 Lint-Befunde als eigene prüfbare Änderung landen müssen. Als Beifang einer
anderen PR würden sie deren Inhalt verdecken. Je einen Linter einführen, zuerst die
kleinsten Änderungen: `bodyclose`, `copyloopvar`, `unconvert`, `godot`, `misspell`.
Jeder erhält einen eigenen Commit.

---

## Namen in Beispielen: feste Rollen

Beispiele, Fixtures, Tutorials, Demoskripte und Testidentitäten nutzen eine feste Gruppe
erfundener Personen. Niemals Namen tatsächlicher Kollegen, Kunden oder Kontakte.

| Person | Im gesamten Baum gleichbleibende Rolle |
|---|---|
| Bob | Autor: paketiert, signiert, veröffentlicht |
| Alice | Empfängerin: pinnt Vertrauen, prüft, installiert |
| Charlie | Reviewer oder Attestierer |
| Diana | Registry- oder Governance-Betreiberin |
| Eddy, Freddy, Gustav, Hans | Weitere Beteiligte nach Bedarf |

Identitäts-IDs folgen derselben Regel: `id:bob@example`, `id:alice@example`.
Eine Person bleibt überall in derselben Rolle, damit Leser die Zuordnung von einem
Dokument zum nächsten mitnehmen können.

**Urheberschaft ist keine Beispielrolle.** Commit-Autor, Copyrightzeile und
`PRODUCT_PUBLISHER` eines signierten Installers nennen eine reale juristisch relevante
Person, weil dies ihr Zweck ist. Ein Ersatz durch einen Beispielnamen anonymisiert
nicht, sondern verfälscht Provenance. Das ist hier der schwerwiegendere Fehler.
Die Prüfung nimmt diese Zeilen einzeln mit jeweils angegebener Begründung aus.

Warum maschinell: Dieser Baum ist öffentlich und wird alle dreißig Minuten in das
GitLab eines Kunden gespiegelt. Namen gelangen über viele einzeln harmlose Ergänzungen
hinein. Wer sie in Prosa erkennt, übersieht sie möglicherweise in Fixtures,
Dateinamen oder Shellvariablen.

```bash
./scripts/check-no-real-names.sh            # whole tree, exit 1 on any hit
./scripts/check-no-real-names.sh --staged   # only what you are about to commit
```

Die Prüfung untersucht Dateinamen ebenso wie Inhalte und ist Teil des blockierenden
CI-Jobs `prose-gate`. Eine schmerzlich erlernte Besonderheit:
`git grep -E` versteht `\b` nicht, findet deshalb nichts und meldet Erfolg.
`-w` verwenden.

## Prosa ohne lange Gedankenstriche

**Regel.** Das Zeichen U+2014 EM DASH kommt nirgendwo im Repository vor:
weder in Go-Code, Kommentaren oder Dokumentationskommentaren noch in Markdown,
YAML, Shell, HTML oder SVG; auch nicht in Benutzertexten, CLI-Ausgaben,
Fehlermeldungen, Commitnachrichten, PR-Beschreibungen oder Issues.
`scripts/check-no-emdash.sh` erzwingt dies maschinell, siehe unten.

**Begründung.** Zwei Gründe, wobei der zweite schwerer wiegt:

1. Der lange Gedankenstrich ist ein besonders auffälliges stilistisches Merkmal
   maschinell erzeugter Texte. Dieses Repository baut auf Nachweisen und Provenance:
   signierte Releases, prüfbare Bundles und ehrlicher Funktionsumfang. Generiert
   wirkende Prosa untergräbt dies schon vor dem Lesen des Codes.
2. Der lange Gedankenstrich ist ein **bequemes** Satzzeichen. Er ersetzt Doppelpunkt,
   Punkt, Semikolon, Kommapaar und Klammern gleichzeitig und wird deshalb schnell
   zur Gewohnheit. Das tatsächlich passende Zeichen macht die Aussage präziser.
   Die Überarbeitung ergibt fast immer bessere technische Prosa, nicht bloß andere.

**Ersetzen.** Niemals blind gegen einen Bindestrich tauschen.
Die Beziehung der beiden Satzteile lesen und dann wählen:

| Bisherige Funktion | Ersatz | Beispiel |
|---|---|---|
| Bezeichnung mit Erläuterung | `:` | A &mdash; YouTube wird `A: YouTube` |
| Zwei unabhängige Aussagen | `.` | X works &mdash; Y does not wird `X works. Y does not.` |
| Eng verknüpfte Teilsätze | `;` | no admin rights &mdash; this differs wird `no admin rights; this differs` |
| Einschub innerhalb eines Satzes | `, ,` oder `( )` | X &mdash; and Y &mdash; is Z wird `X, and Y, is Z` |
| Fortsetzung oder Nachtrag | `,` | signed &mdash; not merely checksummed wird `signed, not merely checksummed` |
| Leere Tabellenzelle | `n/a` | Eine Zelle nur mit Gedankenstrich wird `n/a` |

Zwei Fallen, die in diesem Baum bereits aufgetreten sind:

- **YAML.** Ein `:` in einem nicht zitierten Skalar verändert die Dokumentstruktur.
  Ein Schritt aus `Guard`, langem Gedankenstrich und `all refs are pinned` muss
  zu `- name: "Guard: all refs are pinned"` mit Anführungszeichen werden oder
  stattdessen ein Komma verwenden.
- **Geprüfte Zeichenketten.** Eine Nachricht unter `cmd/`, die ein Test vergleicht,
  muss an beiden Stellen geändert werden. Beginnt ein Punkt einen neuen Satz,
  folgt Großschreibung. In testgebundenen Texten eher `;` oder `,` verwenden.

Der **Halbgeviertstrich** U+2013 ist nicht verboten. Zwischen Bereichsgrenzen wie
`10&ndash;19` und `Mon&ndash;Fri` ist er korrekt, als Satzzeichen nicht.
Die Prüfung zählt ihn, schlägt deshalb aber nie fehl.

**Ausnahme** aufgrund der Bytes, nicht der Prosa:

| Pfad | Grund |
|---|---|
| `pkg/skillctl/bodyscan/testdata/` | Der Korpus IST der getestete Input; `.expected.json` bindet Befundpositionen. |

`demo/kup-training/artifacts/` war eine zweite Ausnahme, solange dieser Baum eingecheckt war.
Er ist nicht mehr getrackt: Er enthielt drei private ed25519-Schlüssel, und Git erhält
Modus 0600 nicht, weshalb eine frische Kopie bei `skillctl sign` scheiterte.
`.gitignore` hält ihn aus der Liste geprüfter Dateien. Die Ausnahme hatte damit keinen Gegenstand mehr.

Eine zweite Ausnahme erfordert zuerst eine hier dokumentierte Begründung.

### Die Prüfung

```bash
./scripts/check-no-emdash.sh            # the gate, exit 1 on any hit
./scripts/check-no-emdash.sh --staged   # only what is staged, for a pre-commit hook
./scripts/check-no-emdash.sh --all      # include the exempt paths and list the en dashes
make check-emdash                       # same gate, wired into `make ci`
```

Sie läuft in CI als `prose-gate` in `ci.yml` und als Schritt des Release-`docs-gate`
in `release.yml` und `skillctl-release.yml`. Ein Release kann deshalb keine Prosa
ausliefern, die hier fehlschlägt.

### Die Agentenregel gilt schon beim Schreiben

Agenten wenden diese Regel während des Schreibens an.
[CLAUDE.md](CLAUDE.md) verweist für Repository-Sitzungen darauf.
Das eingecheckte [scripts/check-no-emdash.sh](scripts/check-no-emdash.sh)
erzwingt sie lokal und in CI. Lokale Agenten-Hooks werden nicht mit dem Repository verteilt.

---

## Konsistenz zwischen CLI, Handbuch und --help

`cmd/docaudit` ist das Release-Gate, das die **tatsächlich vorhandenen** Flags jeder CLI
mit ihrem Handbuch abgleicht, in **beiden** Richtungen:

- Flag im Code ohne Handbucheintrag → **UNDOCUMENTED**
- Handbucheintrag ohne Flag im Code → **PHANTOM**

Unabhängig davon prüft es die Selbstauskunft des Binarys:

- Aufgerufenes Verb ohne Zeile in `printUsage` → **UNLISTED**
- Zeile in `printUsage` für ein nie dispatchtes Verb → **USAGE-PHANTOM**

Jeder dieser vier Fälle lässt das Gate mit Exit `1` fehlschlagen;
`2` bezeichnet einen Aufruf- oder Ein-/Ausgabefehler. Ausführen mit:

```bash
go run ./cmd/docaudit -cli all                      # the gate
go run ./cmd/docaudit -cli skillctl -scaffold       # draft the missing entries
./scripts/check-docs.sh                             # section 4 runs the gate, blocking
```

### Ermittlung der tatsächlich vorhandenen Oberfläche

Unabhängig vom Mechanismus als **Vereinigung** dreier AST-Strategien,
weil die beiden CLIs unterschiedliche Muster nutzen:

1. **Registrierung über `flag.FlagSet`**: Der Name ist das erste Stringliteral in
   `fs.String` / `fs.BoolVar` / `fs.Var` / `fs.Func`(…) bei skillctl.
   Der Hilfetext steht direkt daneben und liefert deshalb auch die Vorlage für `-scaffold`.
2. **`"--flag"`-Stringliterale**: Ein handgeschriebener `case "--x":`-Switch registriert
   kein FlagSet. Seine Oberfläche ergibt sich aus den verglichenen Literalen mit
   zwei Bindestrichen, wie bei m3c-tools.
3. **Kurze Aliase neben ihrer Langform**: etwa `case "-f", "--force":` oder
   `if a == "--dry-run" || a == "-n"`. Ein *alleinstehendes* `-x` ist **kein** Flag,
   sondern meist ein Argument eines anderen Programms, etwa `open -a`, `stty -echo`
   oder `security -w`. Ein Literal mit einem Bindestrich zählt deshalb nur, wenn
   dieselbe Case-Liste oder `if`-Bedingung ein `--long`-Flag enthält. Dieses Nachbarliteral
   ist der Nachweis. Untersucht werden nur Case-Liste und Bedingung, niemals deren Rümpfe.

Namen werden auf die Form ohne Bindestriche vereinheitlicht, weil Gos Paket `flag`
`-x` und `--x` gleich behandelt und Handbücher beide Schreibweisen mischen.

### Ermittlung der dokumentierten Oberfläche

Zuerst werden abgegrenzte Codeblöcke entfernt: Ein kopierbares Beispiel ist keine
Flagdefinition. Danach trägt jede Inline-Codepassage die Flags bei, **mit denen sie beginnt**:

| Passage | Definiert |
|---|---|
| `` `--skill <dir>` `` | `--skill` |
| `` `-o, --output <path>` `` | `-o`, `--output` |
| `` `--author-intent green\|yellow\|red` `` | `--author-intent` |
| `` `skillctl report --input <scan.json>` `` | *Nichts*: eine Kommandozeile, keine Definition |
| `` `~/.claude/skills` `` | *Nichts* |

Die führende Position signalisiert die Definition. So erzwingt die Prüfung
"beschrieben" statt lediglich "erwähnt". Zwei Folgen:

- **Fremde** Flags innerhalb einer Kommandozeile nennen, ohne sie als eigene zu beanspruchen:
  `` `claude --dangerously-skip-permissions` `` statt `` `--dangerously-skip-permissions` ``.
- **Metaplatzhalter** nicht wie echte Flags schreiben: `` `--<flag> <value>` ``.

### Ermittlung der Selbstauskunft

Die dritte Frage betrifft nicht das Handbuch. Ein dort fehlendes Verb ist eine
Dokumentationslücke; ein in `--help` fehlendes Verb bleibt allen Nutzern verborgen,
die nie das Handbuch öffnen. Bei Einführung der Prüfung fehlten 33 der 54
Dispatcher-Literale von `skillctl`, darunter `pack`, Schritt 2 des beworbenen Lebenszyklus.

Beide Oberflächen werden per AST aus demselben Kommandopaket gelesen:

- **Dispatcht**: Die Stringliterale der Case-Zweige in `switch os.Args[1]`, einschließlich
  Aliasen. Ein nie im Switch genanntes Verb kann zur Laufzeit nicht aufgerufen werden.
- **Genannt**: Alle Stringliterale in `printUsage` des Pakets, ohne Anführungszeichen
  und in Zeilen aufgeteilt. Ein Rohstring bei m3c-tools und hundert `Fprintln`-Argumente
  bei skillctl werden damit gleich gelesen.

Eine Usage-Zeile **nennt** das Verb an ihrem Anfang, wenn sie mit **genau zwei Leerzeichen**
beginnt; weitere Aliase folgen kommasepariert:

```text
  help, --help, -h        Print this command list.     ← names help, --help, -h
  pack                    Build a .skb bundle.          ← names pack
                          ... continued, mentions seal  ← names nothing
Getting started                                         ← names nothing
```

Stärkere Einrückung bedeutet Fortsetzung, Spalte null einen Gruppentitel.
Prosa kann daher kein Verb versehentlich registrieren. Dieses Format bei Änderungen
an Usage-Texten einhalten.

Pakete ohne Dispatch über `os.Args[1]` werden übersprungen, weil sie dieses Muster nicht nutzen.
Ein Paket **mit** Dispatch, aber ohne `printUsage`, ist ein Fehler; Umbenennen kann die
Prüfung deshalb nicht abschalten. Es gibt bewusst **keine Ausnahmen**:
Jedes aufrufbare Verb muss von `--help` genannt werden.

Das unterscheidet sich von `cmd/verbaudit`, das denselben Dispatch mit dem
Allokationsregister `docs/v2/referenz/CLI-VERBS.md` abgleicht.
Registriert bedeutet nicht sichtbar: Alle Verben waren registriert, während 33 unsichtbar blieben.

### Ausnahmen

`docs/docaudit-ignore.txt` arbeitet fail-closed. Ein Flag gehört nur mit
**schriftlicher Begründung** hinein. Ein Eintrag kann auf eine CLI begrenzt werden,
etwa `skillctl:--force`. Bisher zulässige Kategorien: ausdrücklich als nicht vorhanden
dokumentierte Flags, verborgene erweiterte Flags außerhalb des normalen FlagSet und
Flags nie dispatchter Kommandos wie `invoke-replay`. Letztere entfallen mit dem toten Code.

"Der Extraktor erkennt es nicht" ist kein Ausnahmegrund. Erkennt die Prüfung ein
echtes Muster nicht, den Extraktor erweitern und einen Test ergänzen.

---

## Aktualität der Indizes

`docs/program-index.md` beansprucht, *jeden baubaren Einstiegspunkt* aufzuführen;
`docs/component-index.md` nennt die Bibliothekspakete samt Anzahl.
Eine Aussage über ein Verzeichnis lässt sich gegen dieses prüfen.
`scripts/check-index.sh` tut dies in beiden Richtungen:

- Baubares `cmd/<name>` fehlt im Programmindex → **Fehler**
- Im Programmindex genanntes `cmd/<name>` existiert nicht mehr → **Fehler**
- Go-Paket unter `pkg/` oder `internal/` fehlt im Komponentenindex → **Fehler**
- Genanntes Paket fehlt im Baum → **Fehler**
- Paketanzahl im Komponentenindex widerspricht dem Verzeichnis → **Fehler**

Gerade die Gegenrichtung ist wertvoll: Der Komponentenindex dokumentierte das nirgendwo
existierende Paket `skillimport`, während zwölf echte `pkg/skillctl`-Pakete fehlten.
Die Mengenprüfung ergänzt dies: Eine reine Listenprüfung lässt eine veraltete Anzahl
stehen. Ein 41. Paket MIT Indexzeile besteht die Liste, widerlegt aber still
"40 Unterpakete". Jeder Satz mit einer Anzahl muss genau einmal erkannt werden.
Ein Umformulieren aus dem Erkennungsmuster lässt deshalb die Prüfung fehlschlagen,
statt sie abzuschalten.

Die Prüfung läuft in Abschnitt 7 von `scripts/check-docs.sh` sowie, weil kein Workflow
dieses Skript aufruft, als eigener Schritt im Job `docs-gate` von `ci.yml`, `release.yml`
und `skillctl-release.yml`. Eine nie aufgerufene Prüfung ist lediglich ein Bericht.

Sie ist bewusst mechanisch: Geprüft werden **Vorhandensein** und **Arithmetik**,
niemals Prosa. Ein neues Paket braucht weiterhin eine menschlich verfasste
Verantwortungsbeschreibung. Das fehlschlagende Gate erinnert den Autor daran.
## Konsistenz des Exit-Code-Registers

`cmd/exitaudit` hält die **Zahlen** konsistent, so wie `docaudit` die Flags konsistent hält.
Gegenstand ist `pkg/skillctl/exitcode`. Anlass war AUDIT-0001: Ohne diese Prüfung bildete
`pull` seine fünf Gates auf `12/10/11/13/6` ab, das Handbuch nannte aber "0 ok, 2 usage"
und `docs/v2/referenz/CLI-VERBS.md` "0/1/2". `verify-sig` lieferte für ein verändertes Bundle
`10`, das kein Dokument erwähnte. Der Verweigerungsraum von verify-hook war im Code
`17/22/25/28`, im Handbuch `17/22` und im Verbregister `25/26/28`.
Zwölf der vierzehn Verben mit Exit-Angaben in beiden Dokumenten hatten verschiedene Angaben.

Fünf mögliche Fehler:

- Ein `Code` aus `exitcode.AllCodes()` fehlt als Zeile in der generierten
  Registertabelle des Handbuchs → **UNDOCUMENTED**
- Eine Tabellenzeile fehlt in `AllCodes()` → **NOT REGISTERED**
- Eine anderswo im Handbuch, in einer `Exit:`-Zeile pro Kommando oder in einer
  Exit-Code-Zelle von `docs/v2/referenz/CLI-VERBS.md` genannte Zahl wird weder vom
  Register noch von "Codes outside the register" erfasst → **UNACCOUNTED**
- `Exit:`-Zeile im Handbuch und Verbregisterzelle nennen verschiedene Mengen
  für dasselbe Verb → **PER-VERB DRIFT**
- `gateExit` aus `cmd/skillctl/pull_cmds.go`, per AST gelesen und über
  `pkg/skillctl/exitcode/registry.go` aufgelöst, liefert eine nicht in der `pull`-Zelle
  genannte Zahl oder die Zelle behauptet eine unmögliche Zahl → **PULL GATE DRIFT**

### Was nicht geprüft wird

Eine Prüfung mit versteckten Grenzen ist schlechter als keine. Deshalb nennt diese
Datei ebenso wie der Paketkommentar die Grenze; `exitaudit` gibt seinen Umfang in jedem Lauf aus.

- **Nur `pull` wird als Code gelesen.** Alle anderen Verbzellen werden gegen das HANDBUCH
  verglichen, niemals gegen ihren Handler. Ein direktes `return 13` in
  `cmd/skillctl/runbook_cmds.go` ist unsichtbar; dieser Fall wurde von Hand gefunden.
  Eine Ausweitung erfordert die Auflösung dateiübergreifender Helfer wie
  `verify.ExitCode`, direkter Literale und `os.Exit`-Aufrufe. Das ist sinnvoll und noch nicht umgesetzt.
- **Nur `Exit:`-Angaben und Exit-Code-Zellen werden nach Zahlen durchsucht.** Zahlen in
  gewöhnlicher Prosa und in der `refusal_code`-Tabelle von `verify-hook` nicht.
  Gemessen am 2026-09-07 ließen eine erfundene `77` in Prosa und `88` in jener Tabelle
  die Prüfung jeweils grün.
- **Verben ohne `Exit:`-Zeile im Handbuch fallen vollständig aus dem Vergleich pro Verb.**
  Das wird inzwischen gezählt und ausgegeben statt verschwiegen. Eine falsche
  `pin`-Zelle mit `0/1/2`, obwohl das Verb `3` liefert, überstand den ersten Release
  der Prüfung genau auf diese Weise.

```bash
go run ./cmd/exitaudit                 # the gate
go run ./cmd/exitaudit -write          # regenerate the manual's register table
go run ./cmd/exitaudit -scaffold       # print it instead of writing it
./scripts/check-docs.sh                # section 6 runs the gate, blocking
```

Die vier generierten Spalten Code, Label, Surface und Theme stammen aus dem Register.
Meaning ist Prosa, die `-write` übernimmt; Neugenerieren benötigt daher keine Textarbeit.
**Ausnahmen stehen im Handbuch, nicht in einer Nebendatei**: Zahlen außerhalb des Registers,
etwa `0/1/2`, `audit` mit `3` und das `skillgate`-Band `30`-`39`, gehören mit ihrer
verantwortlichen Datei in "Codes outside the register". Fehlt die Datei, schlägt das Gate fehl.
Eine Zahl ohne benennbaren Verantwortlichen sollte nicht dokumentiert werden.
