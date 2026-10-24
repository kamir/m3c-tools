# CODESTYLE.md: Qualitätsgrundlage des m3c-tools-Codes

[Deutsch](CODESTYLE.de.md) · [English](CODESTYLE.md)

Diese Datei begründet die maschinell erzwungenen Regeln. `.golangci.yml` bestimmt,
was CI ausführt; hier steht **warum** und ebenso ausdrücklich, was **noch nicht**
erzwungen wird. Eine Absicht darf nicht mit einer verbindlichen Prüfung verwechselt werden.

Ergänzende Werkzeuge: `/code-quality` führt die Baseline aus und behebt Befunde,
`/docs-consistency` prüft CLI und Handbuch wie unten beschrieben,
`/slop-check` prüft maschinell wirkende Prosa und überzogene Behauptungen.

---

## Die pragmatische Grundlage

Implementierungen bleiben einfach, Sicherheitsentscheidungen werden ausdrücklich
getroffen. Erst Fehler beheben, dann abstrahieren. Eine Regel wird nach Prüfung
ihrer tatsächlichen Befunde blockierend. Ausnahmen brauchen einen konkreten Grund
am jeweiligen Aufruf.

| Bereich | Regel | Durchsetzung |
|------|------|-------------|
| Format | Deterministische Go-Standardformatierung | `scripts/check-gofmt.sh` lokal und in CI |
| Korrektheit | Vet, statische Analyse, ungenutzter Code und geprüfte Fehler | `govet`, `staticcheck`, `unused`, `errcheck` in golangci-lint |
| Ressourcen | HTTP-Antwortkörper schließen; überflüssige Schleifenkopien und Konvertierungen entfernen | `bodyclose`, `copyloopvar`, `unconvert` in golangci-lint |
| Fehler | Relevante Ursachen mit `%w` erhalten und mit `errors.Is`/`errors.As` zuordnen; Fehlschläge nicht still zu Erfolg machen | Review, errcheck im dokumentierten Umfang und Regressionstests |
| Kommentare | Verträge, Invarianten und Gründe erklären; öffentliche APIs sinnvoll dokumentieren | Review; keine behauptete allgemeine Kommentarprüfung |
| Sicherheitsanalyse | Neue Befunde gegenüber der eingecheckten Baseline erkennen | Eigenständiges gosec und Diff-Gate |
| Abhängigkeiten | Erreichbare Schwachstellen, Geheimnisse und Modulkonsistenz prüfen | govulncheck, gitleaks und Tidy-Gate in CI |
| Coverage | Gemessene Untergrenzen der erfassten Vertrauenspakete schützen | `.testcoverage.yml`, einschließlich Gesamtuntergrenze 57 |
| CLI-Oberfläche | Echte Flags, Dokumentation und Hilfe konsistent halten | docaudit |
| Verzeichnisse und Exits | Programm-/Paketindizes und dokumentierte Exit-Codes konsistent halten | check-index, verbaudit und exitaudit |
| Release-Review | Befehlsfehler, fehlender Scanner oder unvollständiger Scan sperren das Review | code-review.sh und Negativ-Vertragstests |

### Die Ehrlichkeitsregel für Kommentare

Ein Kommentar beschreibt den vorhandenen Zustand. Grenzen und beabsichtigte
Fallbacks benennen. Geplanten Schutz nicht als implementiert darstellen.
Eine übersprungene Prüfung ist kein Erfolg, ein unlesbarer Halter kein geprüfter
Halter. Nachweise müssen ihren Geltungsbereich nennen.

## Einfach implementieren, Grenzen explizit machen

- Konkrete Typen und Standardbibliothek bevorzugen. Eine Abhängigkeit nur für einen
  belegten Bedarf ergänzen; Grund und Wartungskosten im PR erläutern.
- Kleine Schnittstellen bei den Verbrauchern definieren, wenn Austauschbarkeit
  gebraucht wird. Nicht für jeden Struct Interface, Factory oder Framework einführen.
- Funktionen zusammenhängend und Kontrollfluss direkt halten. Frühe Rückgaben machen
  den Normalpfad sichtbar. Versteckte Nebenwirkungen und vorsorgliche Verallgemeinerung vermeiden.
- Nicht vertrauenswürdige Pfade, Größen, Ursprünge und Formate an der Grenze prüfen.
  Autorisierung, Integrität, Widerruf und unvollständige Ergebnisse ausdrücklich behandeln.
- `context.Context` bei abbrechbarem I/O zuerst übergeben und bis zur Anfrage oder zum
  Unterprozess durchreichen. Reine Berechnungen benötigen keinen künstlichen Context.
- Lebensdauer von Goroutinen klären: Abbruch, Ende und wartender Besitzer.
  Ohne belegten Nutzen durch Nebenläufigkeit synchronen Code bevorzugen.
- Schreib-, Flush-, Sync-, Close- und Rename-Fehler beim Veröffentlichen dauerhafter
  oder geheimer Daten prüfen. Ignorierte Fehler beim Schließen einer Lesequelle lokal
  begründen. Ein defer-Schreibvorgang ersetzt keinen geprüften Veröffentlichungsschritt.
- Bewährte Kryptoprimitive und `crypto/rand` für Sicherheitswerte verwenden.
  Geheimnisbytes gehören weder in Fehler noch Prozessargumente oder Logs.
- Tests nutzen temporäre Benutzerverzeichnisse, Ordner und Stores. Für Nutzerpfade
  sowohl `HOME` als auch `USERPROFILE` setzen. Echte Dienste und Zugangsdaten erfordern
  ausdrückliches Opt-in; normale Tests verändern keine Entwicklerkonfiguration.
- Vertrauensentscheidungen und Persistenz mit gezielten Fehlerpfad-/Regressionstests
  absichern. Betroffene nebenläufige Pfade mit Race Detector prüfen. Aussagekräftige
  Assertions nicht durch pauschale Coverage-Ziele oder Tests des Implementierungstexts ersetzen.

Grundlagen sind die [Go-Reviewhinweise](https://go.dev/wiki/CodeReviewComments)
und die [Go-Sicherheitshinweise](https://go.dev/doc/security/).

## Was heute maschinell erzwungen wird

### Nachweise der Testausfuehrung

`ci-test-selection.json` legt die erfassten Testgruppen fest. Der erforderliche
Simulationsjob wartet auf deren Produzenten und prueft jeden erwarteten Rohbericht
mit Commit, Lauf, Versuch, Produzent, Auswahl und Datei-Hash. Fehlende Artefakte,
erfolglose Produzenten oder Berichte ohne bestandene Tests sperren diesen Job.
Deklarierte Ausnahmen fuer reine Dokumentationsaenderungen bleiben als kleinere
erwartete Testmenge sichtbar. Dies ist ein CI-Konsistenznachweis, keine unabhaengige
Attestierung oder Kundenabnahme.

Nach einem fehlgeschlagenen Versuch **Re-run all jobs** verwenden. Wer nur
fehlgeschlagene Jobs wiederholt, kann Nachweise erfolgreicher Produzenten aus
einem aelteren Versuch behalten; der Verbraucher weist diese absichtlich ab.
Auch Windows-/Linux-Paritaet benoetigt beide Produzenten desselben Versuchs.
Benoetigte Ausfuehrungsnachweise vor Ablauf der siebentaegigen CI-Aufbewahrung
sichern. Neue Testpakete brauchen eine Zuordnung; das Paketinventar beweist
keine Ausfuehrung jedes plattformspezifischen oder optionalen Tests.

Die Offline-E2E-Gruppe verlangt bestandene benannte CLI-Faelle und erlaubt nur
ihre deklarierten exakten optionalen Skips. Optionale macOS-App-Bundle-
Voraussetzungen werden vor dem Build geprueft. Eine gesonderte Packagingpruefung
muss `M3C_REQUIRE_APP_BUNDLE=1` setzen, damit fehlende Voraussetzungen fehlschlagen;
anschliessende Build- oder Ausfuehrungsfehler sind immer Fehler. Packaging- und
Live-Service-Skips gelten nicht als Kundenabnahme.

Der bestehende Job Lint & Vet führt die konfigurierte golangci-lint-Version nativ
für macOS und für die Linux-/Windows-Buildauswahl aus. Portable Auswahlen verwenden
`CGO_ENABLED=0`; dies sind statische Prüfungen, keine Ausführung auf den Zielplattformen.
Native Tests laufen getrennt. `make lint` verwendet das lokale Werkzeug; CI pinnt die Version.

Errcheck nimmt derzeit Testdateien, formatierte Ausgaben und defer-Aufrufe aus.
Diese Grenzen gelten tatsächlich: Nicht jede `_ =`-Zuweisung oder jedes Cleanup-
Ergebnis wird erzwungen. Review muss dauerhafte Zustandsoperationen trotzdem prüfen.
Eine begründete plattformspezifische Ausnahme nennt Regel und Grund direkt an der Zeile.

Separate CI-Jobs prüfen govulncheck, gitleaks, Tidy, Race-Tests,
Dokumentationskonsistenz und die erfasste Coverage. `make ci` führt die im Makefile
gewählten lokalen Prüfungen und Offline-E2E-Liste aus; es ist nicht die vollständige
CI-Paket-/Race-Suite. Das Release-Review wertet Exit-Status aus und startet Pakettests
einmal. Ein fehlender oder erfolgloser Vulnerability-Scanner sperrt dieses Review.

## Reviewregeln ohne pauschale Lint-Sperre

`gofumpt`, `gci`, `revive`, `gocritic`, `nilerr`, `errorlint`, `godot` und
`misspell` sind hier keine allgemeinen Sperren. gofmt erzwingt Formatierung.
Einige Befunde betreffen beabsichtigte Fallbacks oder sprachabhängige Prosa.
Mechanisches Ersetzen von `%v` durch `%w` verändert die sichtbare Fehler-API.
Vor Übernahme einer Regel deren tatsächliche Befunde prüfen und nie durch breitere
Ausnahmen verstecken. Gosec bleibt eigenständig, statt doppelt in golangci-lint zu laufen.
Coverage-Untergrenzen nicht über nachgewiesene Ergebnisse anheben und eine Baseline
nicht als Beweis fehlender Schwachstellen darstellen.

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

Ein vom Betreiber triagierter historischer Scanner-Fingerprint muss seinen
ursprünglichen Commit, Pfad, die Regel und Zeile behalten, um den Fund zuzuordnen.
Der Namen-Wächter nimmt nur den geprüften exakten Fingerprint in seiner
maschinenlesbaren Datei aus. Andere Zeilen, Dateien und Commits bleiben geprüft;
sechs Regressionen schützen diese Grenze.

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
etwa `skillctl:--force`. Aktuelle Kategorien sind ausdrücklich als nicht vorhanden
dokumentierte Flags und verborgene erweiterte Flags außerhalb des normalen FlagSet.
Ausnahmen für entfernten Code müssen mit diesem Code entfernt werden.

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
