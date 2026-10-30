# Anleitung: Entwicklungsumgebung, Build, Tests und Gates

Sprachen / Languages: [Deutsch](getting-started.de.md) | [English](getting-started.md)

Vom frischen Klon zum erfolgreichen lokalen CI-Lauf und die Gates, die eine
Änderung vor der menschlichen Prüfung beurteilen. Die Befehle wurden am
2026-09-16 aus `Makefile` und `scripts/check-docs.sh` gelesen; im
Repository-Wurzelverzeichnis des eigenen Worktrees ausführen.

Zielgruppe: Entwickler vor ihrer ersten Änderung. Die Architektur steht im
[Architekturüberblick](architecture.de.md); diese Seite behandelt den Ablauf
rund um eine Änderung.

Rolle: Entwickler · Sprache: DE · Stand: 2026-09-17

## Die Grundregel in einem Satz

**Im eigenen `git worktree` auf einem Branch namens `<prefix>/<name>` arbeiten,
den Pull Request gegen `master` öffnen und vor dem Push `make ci` ausführen:**
Im gemeinsamen Checkout arbeiten parallele Sitzungen, ein Pflicht-Check
prüft den Branchnamen, und CI führt dieselben lokal verfügbaren Gates aus.

Branch-Präfixe, Begründung und die eine Ausnahme stehen in
[README, "Branch & worktree workflow"](../../../README.md#branch--worktree-workflow).
Zwei in Reviews bereits aufgefallene Ergänzungen:

- **PR-Ziel ist `master`.** `origin/main` existiert, nimmt aber keine Arbeit
  auf: Gemessen am 2026-09-16 sind die jüngsten Pull Requests (#307, #309,
  #311) Merge-Commits auf `origin/master`, und `origin/master` liegt 554
  Commits vor dem gemeinsamen Vorfahren mit `origin/main`. Tools, die
  "main" als Vorgabe erraten, liegen hier falsch.
- **Der Worktree-Befehl.** Das vorgesehene Target lautet
  `make worktree SPEC=spec-XXXX STEP=name BRANCH=feat/name [BASE=origin/master]`
  (erstellt `../wt/<SPEC>/<STEP>`; fehlende Argumente zeigen die Verwendung).
  Direktes git funktioniert ebenfalls:

  ```bash
  git worktree add ../wt/my-change -b fix/my-change origin/master
  ```

- **Eine Abhängigkeit von einem anderen PR steht im Beschreibungstext.**
  Muss ein PR nach einem anderen landen, `Depends-on: #316` in den
  PR-BESCHREIBUNGSTEXT schreiben (mehrere solche Zeilen oder
  `Depends-on: #316, #317` sind zulässig; Groß-/Kleinschreibung ist egal).
  Der Workflow `.github/workflows/pr-deps-gate.yml` führt bei jeder
  Textänderung und Branch-Bewegung `scripts/check-pr-deps.sh` aus: Der Check
  "PR dependencies (DAG gate)" ist rot, solange ein genannter PR OPEN ist,
  rot bei nicht auflösbaren Referenzen (Tippfehler zählen nie als erfüllt)
  und grün, wenn alle genannten PRs MERGED oder CLOSED sind. Solange er
  blockiert ist, trägt der PR das Label `blocked-by-dependency`; dadurch
  zeigt die PR-Liste die Merge-Reihenfolge. Ein Kommentar "merge #316 first"
  bewirkt nichts davon; der Beschreibungstext ist der Vertrag, ein Kommentar
  ist Gespräch.

## Teil A: Build

Die zwei CLIs haben unterschiedliche Build-Voraussetzungen, die leichtere zuerst:

```bash
make build-skillctl     # the trust CLI; plain `go build`, no extra tools needed
make build              # main CLI -> ./build/m3c-tools; gated by check-deps (below)
make build-all          # every command in cmd/, a set the check-make-targets gate pins
make vet                # go vet ./...
```

**`make build` verweigert ohne Capture-Werkzeuge.** Das Target hängt von
`check-deps` (Makefile) ab, das mit Exit 1 endet, wenn nicht alle Werkzeuge
`pkg-config`, `ffmpeg` und `whisper` im PATH liegen; `make deps` installiert
sie. Dies sperrt die Haupt-CLI, obwohl die genannten Werkzeuge zur
Capture-Laufzeit gehören; nur `build-skillctl` ist davon frei.
`make build-all` baut zusätzlich `poc-recorder`, das PortAudio über cgo
importiert und daher zusätzlich `brew install portaudio` benötigt.
Plattformdetails: [Voraussetzungen](../nutzer/prerequisites.de.md).

## Teil B: Tests

Alle Tests liegen unter `e2e/`. Die Suiten sind nach Voraussetzungen geteilt;
kein Offline-Pfad benötigt `.env` oder ER1-Konfiguration:

```bash
make test-unit          # offline only: no network, no hardware
make test-network       # needs internet
make test-er1           # needs a running ER1 server
make test-whisper       # needs the whisper binary in PATH
make test-recorder      # needs PortAudio + a microphone
make e2e                # all of the above
```

`make test-unit` ist ein einzelner längerer `go test`-Lauf: Gemessen am
2026-09-16 auf einer Maschine mit warmen Caches:
`ok github.com/kamir/m3c-tools/e2e 39.601s`, Exit 0; `make ci` führt dieselbe
Suite im Testschritt erneut aus.

Ein einzelner Offline-Test:
`go test -v -count=1 ./e2e/ -run TestRetryQueueInsertAndQuery` (Teil der
`test-unit`-Auswahl). Eigene `-run`-Muster sorgfältig wählen: Einige Tests in
`e2e/` nutzen das Netz, und nicht alle schützen sich mit `SkipIfNoYTCalls`
(`TestTranscriptFetch` in `e2e/transcript_test.go` ruft YouTube ungeschützt
auf). Außerdem die in [CODESTYLE.md](../../../CODESTYLE.de.md) dokumentierte
Falle beachten: Ein `-run`-Muster ohne Treffer endet mit 0;
`scripts/require-tests-ran.sh` existiert genau dafür.

## Teil C: Gates und die geprüften Dateien

`make ci` führt in dieser Reihenfolge aus (aus dem Makefile-Target `ci`):
`vet lint check-emdash check-gofmt check-redirect-guard check-required-checks
check-docpages test-unit build`.

**Ein Tool wird nicht automatisch installiert: `golangci-lint`.** Der
`lint`-Schritt ruft unmittelbar `golangci-lint run` auf (Makefile); fehlt es,
stoppt `make ci` beim zweiten Schritt. Das Stage-2-Skript
(`scripts/skillctl-enterprise-test.sh`, beschrieben unter
[Voraussetzungen](../nutzer/prerequisites.de.md)) installiert die in CI
festgelegte Version; manuelle Installation geht ebenfalls. Die verbindliche
Konfiguration ist `.golangci.yml`.

**`make ci` braucht auch PyYAML.** Der Schritt `check-required-checks` endet mit `3` und
`this gate needs python3 with PyYAML`, wenn `import yaml` scheitert. Führen Sie
`python3 -m pip install pyyaml` aus. `make qa-all` braucht zusätzlich `pytest` und `ruff`.

**Tests mit Abhängigkeits-Fixture werden ohne Fixture übersprungen.** Tests, die ein Python mit
`packaging` brauchen, laufen nur, wenn `M3C_DEPENDENCY_TEST_PYTHON` dessen absoluten Pfad enthält,
und werden sonst übersprungen. Die CI setzt die Variable immer.

Die Dokumentations-Gates liegen in `./scripts/check-docs.sh` und blockieren Releases:

| Gate | Binary | Prüft |
|---|---|---|
| CLI ↔ Manual ↔ `--help` | `cmd/docaudit` | [manual-m3c-tools](../referenz/manual-m3c-tools.de.md), [manual-skillctl](../referenz/manual-skillctl.de.md), Ausnahmen in [docaudit-ignore.txt](../../docaudit-ignore.txt) |
| Verb-Register | `cmd/verbaudit` | [CLI-VERBS](../referenz/CLI-VERBS.de.md): Verb VOR der Implementierung registrieren |
| Exit-Code-Register | `cmd/exitaudit` | `Exit:`-Zeilen des Manuals, Registerspalte, `pkg/skillctl/exitcode` |
| Tutorial-Kette | `scripts/tutorial-smoke.sh` | `docs/v2/nutzer/tutorial-szenario-0*.de.md`, ausgeführt gegen ein Wegwerf-Registry (ein bloßes `local://`-Git-Registry in einem temporären HOME, je Lauf angelegt und entfernt) |
| Indexaktualität | `scripts/check-index.sh` | [program-index](../../program-index.de.md), [component-index](../../component-index.de.md), beide Richtungen und Anzahlen |
| Docpage-Abweichungen | `scripts/check-docpages.sh` | Jede im `REGISTER`-Block registrierte Seite, byteweise mit ihrer Markdown-Quelle verglichen |

Prosa-Regeln stehen in [CODESTYLE.md](../../../CODESTYLE.de.md): keine
Geviertstriche, und Kommentare beschreiben implementiertes Verhalten.

Formatierungs- und Commit-Konventionen über `gofmt` hinaus (gofumpt,
`gci`-Importgruppen, die `-race`-Testregeln) stehen in
[CONTRIBUTING.md](../../../CONTRIBUTING.de.md); `.golangci.yml` wird geprüft,
und [CODESTYLE.md](../../../CODESTYLE.de.md) enthält die Begründung.

## Teil D: Bugs und Features melden

Reproduzierbare Fehler und Feature-Wünsche unter
[GitHub Issues](https://github.com/kamir/m3c-tools/issues) melden. Version,
Plattform, erwartetes Verhalten und eine minimale Reproduktion angeben.
Für Schwachstellen den privaten
[Sicherheitsmeldeweg](../../../SECURITY.de.md) nutzen.

## Teil E: Releases

Releases werden durch Tags ausgelöst; Produktlinie (`vX.Y.Z`) und
skillctl-Linie (`skillctl/vX.Y.Z`) werden unabhängig veröffentlicht.
Build-, Signatur- und Veröffentlichungsschritte definieren der
[Produkt-Release-Workflow](../../../.github/workflows/release.yml) und
[skillctl-Release-Workflow](../../../.github/workflows/skillctl-release.yml).
Die Downloadprüfung steht in [SECURITY.md](../../../SECURITY.de.md).
