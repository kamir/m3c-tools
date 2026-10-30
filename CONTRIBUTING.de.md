# Beiträge leisten

Sprachen / Languages: [Deutsch](CONTRIBUTING.de.md) | [English](CONTRIBUTING.md)

Danke für Beiträge zu **m3c-tools** und **skillctl**. Diese Anleitung beschreibt die lokale
Einrichtung, CI-Prüfungen und Konventionen, die beide Werkzeuge veröffentlichbar halten.

## Voraussetzungen

- **Go 1.26.10+**.
- Nur für die macOS-Menüleisten-GUI: `portaudio` und `ffmpeg` (cgo).
  Die CLIs einschließlich `skillctl` benötigen beides nicht.
- Für `make ci`: `golangci-lint` und `python3` mit PyYAML (`python3 -m pip install pyyaml`). Der
  Schritt `check-required-checks` endet ohne PyYAML mit `3`.
- Für `make qa-all` zusätzlich `pytest` und `ruff`.

```bash
git clone https://github.com/kamir/m3c-tools.git && cd m3c-tools
make build                                  # → ./build/m3c-tools
go build -o build/skillctl ./cmd/skillctl   # skillctl
```

## Vor einem PR dieselben Prüfungen wie CI ausführen

```bash
make ci            # vet · lint · prose · gofmt · redirect-guard · required-checks · docpages · unit tests · build
make code-review   # build, vet, tests, secret scan, dead code, deps
make check-docs    # documentation ↔ implementation consistency
```

- **Formatierung ist verbindlich.** `gofumpt -w .` ausführen und Imports mit `gci`
  gruppieren: Standardbibliothek, externe Pakete, `github.com/kamir/m3c-tools`.
  `.golangci.yml` enthält die erzwungene Konfiguration.
- **Tests erkennen Fehler.** Tests mit der Änderung ergänzen; die Suite läuft mit `-race`.
  Offline-Tests stehen unter `make test-unit`, Netzwerk-, ER1- und whisper-Suites
  werden ausdrücklich mit `make test-*` aktiviert.
- **CLI-Flags dokumentieren.** Jedes echte Flag muss im Handbuch beschrieben sein:
  `docs/v2/referenz/manual-m3c-tools.md` beziehungsweise `docs/v2/referenz/manual-skillctl.md`.
  Nicht implementierte Flags dürfen nicht dokumentiert sein. Fehlende oder erfundene
  Flags gelten als Fehler.

Der macOS-Keychain-Roundtrip ist ein ausdrücklicher Integrationstest. Nur mit
`M3C_TEST_KEYCHAIN=1` auf einem Testkonto aktivieren, dessen Schlüsselbund geändert
werden darf. Der Test nutzt ein eindeutiges synthetisches Konto und entfernt
seinen Eintrag. Temporäre Werte für `HOME`/`USERPROFILE` und `M3C_TOKEN_STORE=file`
isolieren dieses native Backend nicht. Ohne Aktivierung wird der Roundtrip
übersprungen; die übrigen Credential-Store-Tests laufen weiterhin.

## Commit-Nachrichten: Conventional Commits

Die Release-Versionsanhebung wird **aus den Commits abgeleitet**. Deshalb ist das Präfix
entscheidend: siehe [`scripts/derive-bump.sh`](scripts/derive-bump.sh).

| Präfix | Bedeutung | Release-Auswirkung |
|--------|---------|----------------|
| `feat:` | neue Funktion | **minor** |
| `fix:` | Fehlerkorrektur | **patch** |
| `feat!:` / `fix!:` / `BREAKING CHANGE:`-Trailer | inkompatible Änderung für Aufrufer | **major**, niemals automatisch |
| `chore:` / `docs:` / `refactor:` / `test:` | keine Änderung des Nutzerverhaltens | **patch** |

Die Zeilenzahl entscheidet nicht: Eine einzeilige Funktion ist `feat:`, ein umfangreiches
Refactoring ohne Verhaltensänderung nicht.

## Branches und PRs

- Von `master` abzweigen; PR gegen `master` eröffnen.
- Die Pflichtprüfung `Validate branch name` verlangt `<prefix>/<name>` mit genau einem
  Schrägstrich. Präfixliste und Begründung stehen im englischen README unter
  „Branch & worktree workflow“. Neue Präfixe müssen im selben PR dort ergänzt werden.
  Arbeite in einem eigenen `git worktree`.
- Die **einzige Ausnahme** sind von `dependabot[bot]` erstellte PRs (E1). Sie aktivieren
  Auto-Merge selbst (E2), sodass grüne Abhängigkeitsupdates ohne menschlichen Merge
  landen. Das Label `hold` hält sie zurück. Details stehen im README unter
  „The one exception: Dependabot“.
- PRs fokussiert halten; ein grünes `make ci` ist die Grundlage für das Review.
- Änderungen an `.github/workflows/**` benötigen zum Push ein **SSH**-Remote.
  Dem HTTPS-OAuth-Token fehlt der Scope `workflow`.

## Wo Inhalte liegen

- **Code** liegt in diesem Repository.
- **Pläne, SPECs und Entwurfsdokumente** gehören ins separate private Maintenance-Repository.
  [`tools/boundary-gate.sh`](tools/boundary-gate.sh) prüft diese Grenze.
  Beim Code bleiben aktuelle Nutzer-, API-, Sicherheits- und Beitragsdokumente.
  Vor dem Entfernen veralteter oder interner Dokumente die Originalbytes unter `Archiv`
  im privaten Repository sichern, mit Originalpfad, Quellcommit und SHA-256.
  Öffentliche Links und generierte Seiten im selben Schritt aktualisieren.
  Test-Fixtures, Schemas und Abhängigkeitsmanifeste bleiben Bestandteil des Codes.
  Beitrags- und Release-Werkzeuge finden den Maintenance-Bereich über
  `M3C_MAINTENANCE_DIR`; siehe README.

## Releases

Tags lösen Releases aus; CI signiert sie. Siehe Release-Ziele im [Makefile](Makefile)
und den [Release-Workflow](.github/workflows/release.yml).
Interne Freigaben und Abnahmen bleiben im Maintenance-Bereich.

## Sicherheit

Sicherheitslücken vertraulich melden: siehe [SECURITY.de.md](SECURITY.de.md).

## Lizenz

Mit einem Beitrag stimmst du dessen Veröffentlichung unter **Apache-2.0** zu:
siehe [LICENSE](LICENSE).

## Dokumentationssprachen

Veröffentlichte Dokumentation muss auf Deutsch und Englisch mit demselben fachlichen
Inhalt vorliegen. Jede Fassung verlinkt die Gegenfassung. CLI-Befehle, Flags, Beispiele
und maschinenlesbare Verträge bleiben unverändert. Bei fachlichen Änderungen beide
Fassungen prüfen; eine Zusammenfassung ist keine Übersetzung. Geprüfte Sprachpaare
stehen in `docs/languages.json`.
