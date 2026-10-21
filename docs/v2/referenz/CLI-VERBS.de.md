# skillctl: CLI-Befehlsregister

[Deutsch](CLI-VERBS.de.md) | [English](CLI-VERBS.md)

Diese Datei ist die Zuordnungstabelle für die obersten `skillctl`-Befehle, analog
zur SPEC-Platzzuordnung, die FR-0104 für SPEC-Nummern eingeführt hat. Sie macht
die Befehlszuordnung von einem **Lesevorgang** zu einem **Schreibvorgang**: Vor
FR-0113 musste man `cmd/skillctl/main.go` lesen, um freie Befehlsnamen zu finden.
Zwei Personen, die zu unterschiedlichen Zeiten lasen, erhielten dieselbe Antwort;
innerhalb von zwei Tagen entstanden zwei Kollisionen (`audit` gegenüber `auditlog`
und `capability` gegenüber den Referenzbindungen von SPEC-0401). Der Eintrag hier
zeigt der zweiten Person, dass der Name bereits vergeben ist.

Quelle: SPEC-0404 §7-K3 (REQ-7.8 .. REQ-7.10), entschieden am 2026-09-04.

## Spalten

- **Verb**: der kanonische, vom Dispatcher aufgerufene Befehl. Aliasse für denselben
  Handler stehen danach in Klammern, etwa `version` (`--version`, `-v`).
- **Owning SPEC**: die Spezifikation und gegebenenfalls der im Code genannte
  Abschnitt, die die Bedeutung des Befehls festlegen. `built-in` kennzeichnet
  Befehle ohne eigene SPEC (Ausgabe von Aufrufhilfe und Version). Ein abschließendes
  `(?)` bezeichnet einen im Code nicht eindeutig festgelegten Wert: die bestmöglich
  belegte Zuordnung, keine erfundene Tatsache.
- **Exit-Code space**: die Menge der Prozess-Exit-Codes, die der Handler liefern
  kann. Diese Spalte ist **verpflichtend** (REQ-7.9): Beide bekannten Kollisionen
  betrafen sie. `skillctl audit` verwendet `0/2/3` (SPEC-0189 §14, Zustandsurteile).
  Ein Skript, das auf Exit `2` verzweigt, darf deshalb keinen gleichlautenden Code
  mit einer anderen Bedeutung erhalten. Die Vertrauenskette verwendet `0` und
  `10..17` (SPEC-0188 §11). Ein reines Namensregister hätte die Mehrdeutigkeit von
  `audit status` erkannt, aber nicht das eigentliche Risiko: Ein Skript, das heute
  auf `2` verzweigt, erhält morgen eine falsche Antwort. Seit AUDIT-0001 wird die
  Zelle auch **geprüft**: `cmd/exitaudit` vergleicht sie mit der `Exit:`-Angabe
  desselben Befehls im [Handbuch](manual-skillctl.md#exit-codes) und mit
  `pkg/skillctl/exitcode`. Die Dokumente können daher nicht mehr unbemerkt
  voneinander abweichen (bei zwölf von vierzehn Befehlen war das der Fall).

Notation: `0/1/2` ist der gemeinsame Basisbereich (`exitOK`=0, `exitGeneric`=1,
`exitUsage`=2 aus `cmd/skillctl/signing_cmds.go`). `10..17` ist ein einschließlich
beider Grenzen geltender Zahlenbereich aus `pkg/skillctl/exitcode`. Ein als
`(NN in refusal_code)` angegebener Code steht im signierten Entscheidungs-JSON;
der **Prozess** endet weiterhin mit `2`, um den PreToolUse-Aufruf zu blockieren
(Konvention von verify-hook / enforce / guard-path). Es ist kein eigener Prozess-Exit.

## Einen Befehl hinzufügen

1. **Zuerst registrieren.** Ergänzen Sie unten eine Zeile mit dem kanonischen
   Namen, der zuständigen SPEC und dem Exit-Code-Bereich. Wählen Sie einen noch
   nicht vergebenen Namen. Vereinbarte, aber noch nicht implementierte Befehle
   gehören zunächst in den Abschnitt **Reserved**.
2. **Danach implementieren.** Ergänzen Sie `case "<verb>":` im obersten
   Dispatch-Switch in `cmd/skillctl/main.go` und den zugehörigen Handler.
3. **Danach den Exit-Bereich an beiden Stellen angeben.** Die Tabellenzelle hier
   und die `Exit:`-Zeile im Handbuch müssen dieselben Zahlen nennen. Zahlen
   außerhalb von `0/1/2` müssen in `pkg/skillctl/exitcode` registriert oder in der
   Handbuchtabelle „Codes outside the register“ als Ausnahme dokumentiert sein.
   `go run ./cmd/exitaudit` zeigt fehlende Einträge an.

Ein ausgelieferter Befehl **ohne** Registerzeile lässt CI **fehlschlagen**
(REQ-7.10). Das wird technisch durchgesetzt, nicht nur vereinbart.
`cmd/verbaudit` liest den Dispatch-Switch `switch os.Args[1]` über den AST und
prüft diese Datei. Nicht registrierte Befehle und leere Exit-Code-Zellen in der
Haupttabelle sind Fehler. Die Prüfung ist in `scripts/check-docs.sh` und im
CI-Job `docs-gate` verbindlich eingebunden, analog zur Flag-Prüfung durch
`cmd/docaudit`. `cmd/exitaudit` prüft den **Inhalt** der Exit-Code-Spalte gegen
das Code-Register und das Handbuch.

## Befehlsregister

| Verb | Owning SPEC | Exit-Code space |
| --- | --- | --- |
| `login` | FR-0043 | 0/1/2 |
| `version` (`--version`, `-v`) | built-in | 0 |
| `doctor` | SPEC-0406 D1 | 0/1/2 |
| `token` (`set`, `list`, `rm`) | FR-0117 | 0/1/2 |
| `pack` | SPEC-0188 (Phase 1 PoC) | 0/1/2, 18 |
| `keygen` | SPEC-0188 §11 | 0/1/2 |
| `sign` | SPEC-0188 §11 | 0/1/2 |
| `verify-sig` | SPEC-0188 §11 | 0/1/2, 10, 11 |
| `trust` (`list`, `add`, `add-author`, `fingerprint`, `remove`) | SPEC-0188 (S7), `add-author`/`fingerprint` SPEC-0406 §3.2 | 0/1/2 |
| `peer` | SPEC-0359 (D2) | 0/1/2 |
| `cross-sign` | SPEC-0359 (D3) | 0/1/2 |
| `attest` | SPEC-0188 (S9) | 0/1/2 |
| `revoke` | SPEC-0188 §4.5 | 0/1/2, 15, 22 |
| `audit` | SPEC-0189 §14 | 0/1/2/3 |
| `envreport` | SPEC-0428 | 0/1/2 |
| `trust-freeze` | SPEC-0466 (with SPEC-0467..SPEC-0471) | 0/1/2 |
| `propose` | SPEC-0194 | 0/1/2 |
| `install` | SPEC-0188 §11 (S8) | 0/1/2, 10..17, 20, 22 |
| `verify` | SPEC-0188 §11 (S8) | 0/1/2, 10..17, 20, 22 |
| `export-bundle` | SPEC-0406 Phase 2 | 0/1/2, 10..17, 20 |
| `export-verification-kit` | SPEC-0276 R4.3 | 0/1/2, 10..17, 20 |
| `compliance` | SPEC-0276 R5 | 0/1/2 |
| `verify-hook` | SPEC-0247 P0.1 | 0/2 (17/22/25/28 in refusal_code) |
| `enforce` | SPEC-0317 P0 | 0/2 (26 in refusal_code) |
| `guard-path` | SPEC-0317 R-6 | 0/2 (27 in refusal_code) |
| `agentid` | SPEC-0277 P0+P1 | 0/1/2, 11/12/17/20/21/22 |
| `gate-stats` | SPEC-0255 | 0/1/2 |
| `auditlog` | SPEC-0403 §8 | 0/1/2 |
| `pin` | SPEC-0247 §7.3 | 0/1/2, 3 |
| `session-baseline` | SPEC-0317 R-7 | 0/1 |
| `scan` | SPEC-0189 (S0a) | 0/1/2 |
| `report` | SPEC-0189 (S0a) | 0/1 |
| `diff` | SPEC-0189 (S0a) | 0/1 |
| `seal` | SPEC-0189 (S0a) | 0/1 |
| `import` | SPEC-0189 (S0a) | 0/1 |
| `menubar` | SPEC-0189 (S0a) | 0/1 |
| `review` | SPEC-0189 (S0a) (?) | 0/1 |
| `browse` | SPEC-0189 (S0a) (?) | 0/1 |
| `consolidate` | SPEC-0189 (S0a) (?) | 0/1 |
| `drift` | SPEC-0432 (FR-0278) | 0/1/2 |
| `sync-usage` | SPEC-0189 (S0a) | 0/1 |
| `sync` | SPEC-0317 R-5, SPEC-0455 REQ-5.1a | 0/1/2, 29, 40 |
| `awareness` | SPEC-0195 (S2 M1) | 0/1/2, 19 |
| `intent` | SPEC-0195 (S2 M2) | 0/1/2, 18 |
| `translog` | SPEC-0278 P5 | 0/1/2, 23/24/25 |
| `project` | SPEC-0214 | 0/1/2 |
| `session` | SPEC-0213 | 0/1/2 |
| `publish` | SPEC-0225 P1 | 0/1/2 |
| `pull` | SPEC-0225 P2 | 0/1/2, 6, 7, 10..13 |
| `registry` | SPEC-0225 P2 | 0/1/2 |
| `runbook` | SPEC-0272 | 0/1/2, 13 |
| `room` | SPEC-0246 §7 | 0/1/2 |
| `help` (`--help`, `-h`) | built-in | 0 |

Hinweise zur Herkunft:

- `review`, `browse` und `consolidate` bestanden vor SPEC-0189 und wurden beim
  Merge der Scanner-Familie S0a zugeordnet (Kopfkommentar von
  `cmd/skillctl/scanner_cmds.go`: „pre-SPEC-0189 behaviour preserved“). Ihre
  Zuständigkeit ist deshalb mit `(?)` markiert: S0a ist der Ort ihrer Ausführung
  und Dokumentation, nicht zwingend ihr Ursprung.
- `revoke` auf Autorenseite liefert `0/1/2` sowie `15`, wenn die Registry `404`
  (nicht zugelassen) oder `409` (bereits widerrufen) antwortet. Das wurde am
  Programm gegen einen lokalen Registry-Stub und gegen
  `cmd/skillctl/revoke_cmds.go`, Zeilen 267 und 270, geprüft. Es liefert auch
  `22`: `revoke feed --refresh` verweigert auf einem MANAGED-Rechner bei nicht
  verfügbarem Widerrufsabruf mit derselben Nummer `revocation_stale`, die auch
  Hook und Sweep verwenden (`cmd/skillctl/revoke_feed_cmds.go:79`). Gemessen
  wurde dies mit vorhandener, aber nicht ladbarer `~/.claude/trust-roots.yaml`.
  Die Nummer wird geteilt, ihre Bedeutung nicht: Im Register gehört `15` zu
  `verify`/`blob_missing`. Skripte müssen `15` befehlsbezogen auswerten. Der
  Verifier-Exit `identity_revoked` mit `17` (`pkg/skillctl/exitcode`, Ebene 4)
  erscheint bei `verify` / `install`, nicht bei `revoke` selbst.
- `pin` liefert `3`, wenn `pin install` als unprivilegierter Nutzer die Datei
  vorbereitet und die sudo-Anleitung ausgibt (`pinExitNeedPrivMsg`,
  `cmd/skillctl/pin_cmds.go`). `3` ist unter `pin`/`need_priv_msg` registriert
  und hat nicht die Bedeutung von `audit`-Exit `3`.
- `audit` liefert zusätzlich zu `0/2/3` auch `1`. Die Skala `0/2/3` beschreibt
  den **Zustand** (`exitCodeFor`, `pkg/skillctl/audit/audit.go`); `1` ist ein
  interner Fehler. Er entsteht an drei Stellen: Inventarscan fehlgeschlagen
  (`cmd/skillctl/audit_cmds.go:138`), Cleanup-Token nicht erzeugbar (`:236`)
  oder teilweise fehlgeschlagene Löschungen mit `--confirm-delete` (`:304`).
  Am Programm geprüft: confirm-delete in einem schreibgeschützten Skills-Verzeichnis
  endet mit `1`.
- `install` und `verify` erreichen `23` **nicht**. Die Nummer ist als
  `log_inclusion_missing` registriert und in `verify.ExitCode` zugeordnet.
  `verify.CheckLogInclusion`, die einzige Funktion, die `ErrLogInclusionMissing`
  auslöst, wird außerhalb ihrer Tests jedoch nicht aufgerufen. Daher kann kein
  Lauf der Vertrauenskette diesen Code erzeugen. Aktuell ist `23` nur über
  `translog verify` erreichbar (`exitTranslogNotIncluded`).
- `runbook publish` liefert `13`, wenn ein Geräte-Token fehlt oder der Katalog
  `401`/`403` antwortet (`cmd/skillctl/runbook_cmds.go`, Zeilen 96 und 123).
  Wieder dieselbe Nummer mit anderer Bedeutung: Das Register ordnet `13` auch
  `verify`/`governance_below_min` zu.
- `session-baseline` liefert ausschließlich `0/1`. Der Befehl liest nur und
  sperrt keine Aktion. Auch ein Fehler beim Flag-Parsing ergibt `1`, nicht `2`
  (`cmd/skillctl/session_baseline_cmds.go`).
- `auditlog` liefert ein Gesundheitsurteil `0/1` und bei Aufruf- oder
  Flag-Fehlern `2` (`auditlogExitUsage`, `cmd/skillctl/auditlog_cmds.go`). Der
  Gesundheitsbereich darf nicht mit der Zustandsbewertung von `audit` verwechselt
  werden; der Aufruffehler verwendet den gewöhnlichen Code.
- `export-bundle` und `export-verification-kit` reichen Fehler von
  `verify.Verify` an `verify.ExitCode` weiter. Ihr Exit-Bereich ist daher
  `0/1/2` plus `10`..`17` und `20`. Sie erreichen weder `18`/`19` (diese werden
  durch intent und awareness ausgelöst, nicht durch die Kette) noch `22`/`23`
  (Aktualitäts- und Log-Inklusionsprüfungen, die `install` und `verify` um die
  Kette herum durchführen; diese beiden Exportbefehle tun das nicht).
- `trust-freeze` bündelt sechs Unterbefehle: `doctor`, `capture`, `baseline approve`,
  `verify`, `diff` und `report`. Dies sind Unterbefehle, keine Aliasse. Deshalb
  nennt die Verb-Zelle nur den kanonischen Befehl. Als Alias-Spannen würden sie
  die eigenständigen obersten Befehle `diff`, `report`, `verify` und `doctor`
  ein zweites Mal registrieren. Der Exit-Bereich bleibt `0/1/2`; es wird keine
  neue Nummer vergeben. Die Bedeutung von Exit `1` (`execution_error`,
  `verification_failure`, `drift_threshold_exceeded` oder `incomplete_capture`)
  steht stattdessen im JSON-Feld `result_class`
  (`cmd/skillctl/trustfreeze_cmds.go`). Dies unterscheidet sich von `drift`,
  `envreport` und `audit`, deren Bedeutungen erhalten bleiben.
- `import` bezeichnet hier den Scanner-Import von SPEC-0189 S0a mit Exit `0/1`.
  Er unterscheidet sich von `import-public` mit Exit `4/5/17/18/19`, das im
  aktuellen Dispatcher kein oberster Befehl ist.

## Reserviert (vor der Implementierung registriert)

Diese Namen sind vergeben, werden aber in `main.go` noch nicht ausgeführt.
Der Prüfer beanstandet reservierte Einträge ohne Dispatch ausdrücklich nicht;
das ist der Zweck einer Reservierung. Sobald der `case` implementiert ist,
wird die Zeile in die Haupttabelle verschoben.

| Verb | Owning SPEC | Exit-Code space |
| --- | --- | --- |
| `capability` | SPEC-0378 | 0/1 |

`capability` ist die zweite bekannte Kollision. SPEC-0378 definiert die
Capability-Bindung (normatives P0); SPEC-0401 §3 beschreibt Referenzbindungen
unter demselben Namen. Die Reservierung klärt die Zuständigkeit, bevor eine
der beiden Implementierungen einen `case` ergänzt.
