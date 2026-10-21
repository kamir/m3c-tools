# Referenz: secretctl, der Lebenszyklus eines gemeinsamen Service-Secrets

Sprachen / Languages: [Deutsch](secretctl.de.md) | [English](secretctl.md)

Wer ein gemeinsames Service-Secret hält, ob jede Ablage den aktuellen Wert
enthält und ob ein Dienst ihn noch akzeptiert: `cmd/secretctl` (SPEC-0438)
beantwortet genau diese drei Fragen. Alles Folgende wurde am 2026-09-16 aus
`cmd/secretctl/main.go`, `registry.go`, `read.go`, `secret.go`,
`inventory.go` und `verify.go` am Commit `bd00a6f` gelesen (dem Stand, den
PR #319 in master übernimmt). Jede hier zitierte Befehlsausgabe und jeder
Exit-Code wurden offline mit einem aus genau diesem Stand gebauten Binary
(`go build ./cmd/secretctl`) gemessen; reine Codewiedergaben sind als solche markiert.
Diese historischen Ausgaben bleiben unten erhalten. Die aktuellen Regeln für
unvollständige Ergebnisse im Exit-Code-Abschnitt ersetzen den damaligen Erfolgs-Exit
bei unlesbarer Quelle. Synthetische Regressionstests decken sie ab, kein neuer
Lauf gegen einen produktiven Dienst.

Zielgruppe: Entwickler und Betreiber, die vor einer Rotation den Bestand
aufnehmen oder den Abschluss einer Rotation nachweisen müssen. Der
Build-Eintrag steht im [Program-Index](../../program-index.de.md), sobald #319
gelandet ist; die allgemeinen Gates für Änderungen beschreibt die
[Einstiegsseite für Entwickler](getting-started.de.md).

Rolle: Entwickler · Sprache: DE · Stand: 2026-09-16

## Die Grundregel in einem Satz

**Das Tool liest und vergleicht; es gibt niemals einen Secret-Wert aus.** Im
Code laufen Werte als Typ `Secret` (`cmd/secretctl/secret.go`), der über
`String`, `GoString`, `MarshalJSON` und `MarshalYAML` als `<redacted>`
ausgegeben wird; jeder Bericht und Vergleich arbeitet mit `Fingerprint()`.
Der einzige Weg zum Rohwert ist das bewusst auffällige `Reveal()`.
Gemessen: Ein in einer Dateiablage platzierter Testwert
(`super-test-value-123`) erscheint in keiner erfassten Ausgabe von `inventory`
oder `verify`, während dasselbe `grep`-Muster ihn in der Quelldatei findet.

## Verben und Flags

Der Dispatch in `cmd/secretctl/main.go`:

| Verb | Funktion | Stand |
|---|---|---|
| `inventory <name>` | Wer hält dieses Secret, und ist jede Kopie aktuell? | implementiert |
| `verify <name>` | Je Ablage beim Dienst prüfen, ob ihr Wert akzeptiert wird | implementiert |
| `verify --old <name>` | Stattdessen Ablehnung erwarten: Nachweis einer abgeschlossenen Rotation | implementiert |
| `new`, `stage`, `distribute`, `retire` | Der schreibende Teil von SPEC-0438 | verweigert mit Exit `2`, "not built yet" |
| `help`, `-h`, `--help` | Verwendung ausgeben | Exit `0` |

Ein gemeinsames Flag, verdrahtet durch `registryFlag` in `main.go`:

| Flag | Bedeutung | Vorgabe |
|---|---|---|
| `--registry <path>` | Pfad zum Secret-Register | `$SECRETCTL_REGISTRY`, sonst `~/.config/m3c/secrets.yaml` (`DefaultRegistryPath`, `registry.go`) |

**Flags stehen vor dem Namen.** Gos `flag`-Parser stoppt am ersten
Positionsargument; deshalb gibt `secretctl verify demo --old` die Verwendung
aus und endet mit `2` (gemessen). Die funktionierende Form ist
`secretctl verify --old demo`.

## Welches Verb wann

| Gesuchte Auskunft | Ausführen | Grün bedeutet |
|---|---|---|
| Wer das Secret hält, bevor etwas verändert wird | `inventory <name>` | Jede genannte Ablage enthält den aktuellen Wert |
| Ob der neue Wert überall aktiv ist | `verify <name>` | Jede geprüfte Ablage wird akzeptiert |
| Ob die Rotation tatsächlich abgeschlossen ist | `verify --old <name>` | Jede Ablage mit dem alten Wert wird abgelehnt |

`verify` kann `cloud-run`-Ablagen nicht anhand ihres Werts prüfen. Es meldet
`NICHT PRUEFBAR (cloud-run)` und endet mit `1`, auch bei `--old` und wenn
andere Ablagen bestanden. Null erfolgreich befragte Ablagen sind niemals Erfolg.

## Die Registerdatei

Das Register enthält Ablageorte, niemals Werte. Deshalb darf es in git
liegen (`cmd/secretctl/registry.go`). Schema-Kennung:
`m3c-secret-registry/v1`; der Loader verweigert jede andere. Struktur gemäß
den Structs in `registry.go`:

```yaml
schema: m3c-secret-registry/v1
secrets:
  - name: er1-api-key
    summary: what this secret is
    prefix: m3cer1_          # optional, SPEC-0438 §5
    source:                  # where the authoritative value lives
      kind: gcp-secret-manager
      project: my-project
      secret: er1-api-key
    roles:                   # what breaks when the value turns
      - id: service-clients
        was: authenticates service clients
        bei_rotation: clients need the new value at next start
    holders:                 # every place that carries a copy, named one by one
      - id: laptop-keychain
        kind: macos-keychain
        service: aims-core-er1
      - id: laptop-env
        kind: file
        path: ~/.m3c-tools.env
        key: ER1_API_KEY
    probe:                   # how to ask the service whether a value counts
      kind: http
      url: https://example.org/api/health
      header: X-API-KEY
      expect_ok: 200
      expect_revoked: 401
```

Ablagearten und ihre Pflichtfelder (`Holder.validate`, `registry.go`):

| Art | Pflichtfelder | Leseweg (`read.go`) |
|---|---|---|
| `macos-keychain` | `service` | `security find-generic-password`, lokal oder über ssh (`host`) |
| `file` | `path`, `key` | `grep -m1 '^KEY='`, niemals `cat`: Die gesamte Datei darf nicht übertragen werden |
| `cloud-scheduler` | `project`, `region`, `job`, `header` | `gcloud scheduler jobs describe`, Header aus der Jobdefinition |
| `docker` | `container`, `env` | `docker inspect` auf die Umgebung des laufenden Containers |
| `cloud-run` | `project`, `region`, `service_name`, `env` | Kein Lesen des Werts; stattdessen wird die GEBUNDENE SECRET-VERSION gemeldet (`BoundVersion`) |

`Validate` in `registry.go` verweigert Register, die keine vollständige
Rotation abbilden können: Secrets ohne Ablagen oder Rollen; Rollen ohne
`id`, `was` oder `bei_rotation`; doppelte Secret- oder Ablage-IDs sowie
Ablagen mit Sammelbezeichnungen in ID oder Pfad (`*`, `alle`, `all `,
`usw`, `...`). Jede Ablage wird einzeln benannt, weil eine Rotation an der
nicht erfassten Kopie scheitert.

**Probes müssen https verwenden.** `Probe.validate` (`registry.go`) lehnt
`http://`-Probe-URLs ab, sofern der Host nicht `localhost`, `127.0.0.1`
oder `::1` ist. Die Probe sendet den aktuellen Wert im Request-Header;
Klartext würde ihn bei jedem verify erneut offenlegen. Mit dem gebauten
Binary gemessen: Ein Register mit `url: http://example.com/api/health`
lässt `inventory` mit `1` enden und meldet:

```
... probe url "http://example.com/api/health" would send the live value over plaintext http; use https (http is allowed only for localhost)
```

## Sicherheitseigenschaften mit Quellen

Aus dem Code gelesen, mit Datei und Bezeichner; die zwei markierten Punkte
wurden zusätzlich mit dem gebauten Binary gemessen:

- **Kein Wert in irgendeiner Ausgabe.** Typ `Secret` mit `<redacted>`-Darstellung
  und auffindbarem `Reveal()` (`secret.go`). Gemessen: Suche nach dem
  eingebrachten Testwert über alle Ausgaben, siehe Grundregel oben.
- **Verglichen und ausgegeben werden Fingerprints, keine Werte.**
  PBKDF2-HMAC-SHA256, `600_000` Iterationen, öffentlicher fester Salt
  `m3c-secretctl-fingerprint/v1`, die ersten 12 Hexzeichen
  (`Secret.Fingerprint`, `secret.go`). Der Salt ist bewusst öffentlich,
  damit zwei Maschinen denselben Tag berechnen; die Rechenkosten schützen.
  Gemessen: Zwei getrennte Läufe lieferten für denselben Wert denselben
  Fingerprint mit 12 Hexzeichen.
- **Die Probe folgt keinen Redirects.** `Probe.Ask` (`read.go`) setzt
  `CheckRedirect` auf `http.ErrUseLastResponse`; so gelangt der
  Credential-Header weder an einen anderen Host noch über ein
  herabgestuftes Schema. Die 30x-Antwort selbst ist das Ergebnis.
- **Die Probe verwendet HTTP im Prozess, nicht curl.** Ein curl als Header
  übergebener Wert steht im argv des Prozesses und ist über jedes `ps`
  lesbar; `Probe.Ask` hält ihn im Prozess (Kommentar und Code, `read.go`).
- **Entfernte Argumente werden für die Shell gequotet.** ssh verbindet die
  Argumente zu einem String für die entfernte Login-Shell. Deshalb quotet
  `capture` (`read.go`) jedes entfernte Argument mit
  `shellQuote`/`shellQuoteRemote`; nur das bewusste Präfix `$HOME/` bleibt
  expandierbar.
- **Dateischlüssel passieren vor ihrer Verwendung als Muster eine
  Positivliste.** `readFile` (`read.go`) verweigert alle Schlüssel, die
  nicht `^[A-Za-z0-9_]+$` entsprechen (`envKeyShape`), statt sie in das
  `grep`-Muster zu escapen.
- **Unerreichbar wird niemals als fehlend gemeldet.** `ErrUnreachable` und
  `ErrAbsent` sind unterschiedliche Typen (`read.go`); ssh-Exit `255`
  kennzeichnet einen Transportfehler, grep `1`/`2` sind echte Antworten.
  Eine Bestandsaufnahme mit unerreichbarer Ablage bezeichnet sich als
  INCOMPLETE und endet mit `1` (`inventory.go`).

## Exit-Codes

Aus den `return`-Anweisungen in `main.go`, `inventory.go` und `verify.go`
gelesen. Die historischen Messläufe unten liegen vor den aktuellen Prüfungen
unvollständiger Ergebnisse; diese deckt `cmd/secretctl/incomplete_test.go` ab:

| Code | Bedeutung |
|---|---|
| `0` | Hilfe; oder lesbare Quelle und keine veralteten, fehlenden, unlesbaren oder unerreichbaren Ablagen (`inventory`); oder jede konfigurierte Ablage wurde befragt und antwortete wie erwartet, mit mindestens einer erfolgreichen Probe (`verify`) |
| `1` | Befund oder Betriebsfehler: Register fehlt oder ist ungültig, unbekannter Secret-Name, `verify` ohne konfigurierte Probe, unlesbare Quelle, veraltete oder wertlose oder unlesbare oder unerreichbare Ablagen, nicht prüfbare Ablage oder null erfolgreich befragte Ablagen, unerwartete Probe-Antwort |
| `2` | Usage: kein Verb, unbekanntes Verb, eines der nicht implementierten Schreibverben, falsche Argumentzahl, nicht auswertbares Flag |

Historische Messläufe aus `bd00a6f`, insgesamt 12: `-h` endet mit `0`;
fünf Läufe enden mit `2` (kein Verb, unbekanntes Verb, `new`, `inventory`
ohne Namen, Flag hinter dem Positionsnamen); fünf mit `1` (fehlende
Registerdatei, unbekannter Secret-Name, Register wegen Klartext-Probe-URL
verweigert, `verify` für einen Eintrag ohne Probe, fehlgeschlagene
Loopback-Probe); die folgende Offline-Bestandsaufnahme endete damals mit `0`.
Der aktuelle Code liefert für deren unlesbare Quelle stattdessen `1`.

## Praxis, offline gemessen

Beide Teile liefen am 2026-09-16 gegen das aus `bd00a6f` gebaute Binary,
mit lokalem Register, lokaler Dateiablage und keinem Netzwerk außer
Loopback. `gcloud` lag nicht im `PATH`, damit das Lesen der Quelle sichtbar
scheitert; es wurde kein echtes System abgefragt und kein echtes Secret verwendet.

### Teil A: Wert prüfen

```bash
go build -o secretctl ./cmd/secretctl
./secretctl inventory --registry ./measure/reg.yaml demo
```

Gemessene Ausgabe (der Fingerprint ist der tatsächliche des eingebrachten
Testwerts):

```
Geheimnis:  demo
            offline measurement entry, file holder only
Quelle:     NICHT LESBAR (source none-project/demo: exec: "gcloud": executable file not found in $PATH)
            Ohne die Quelle ist kein Abgleich moeglich; die Spalte Stand bleibt leer.
...
ORT         ART   MASCHINE  FINGERABDRUCK  STAND
laptop-env  file  lokal     f9448d60fde5   ?

1 Orte gefuehrt.
```

Historischer Exit-Code: `0`. Dies war ein unvollständiges Inventar, kein
Nachweis einer aktuellen Ablage: Die unlesbare Quelle ließ STAND auf `?`,
der Wert erschien nur als Fingerprint mit 12 Hexzeichen. Der aktuelle Code
markiert diesen Fall `UNVOLLSTAENDIG` und endet mit `1`. Auch eine unlesbare
Ablage macht das Inventar unvollständig. Bei lesbarer Quelle zeigt STAND
`aktuell` oder `veraltet`; `veraltet`, `fehlt`, `unlesbar` und `unerreichbar`
führen alle zu Exit `1`. Das aktuelle Verhalten wird mit synthetischen
Quellen-/Ablage-Fixtures in `cmd/secretctl/incomplete_test.go` geprüft;
eine neue Messung gegen einen produktiven Dienst wird hier nicht behauptet.

### Teil B: Rotation prüfen

```bash
./secretctl verify --registry ./measure/reg.yaml --old demo-probe
```

Gemessene Ausgabe gegen eine Loopback-Probe-URL ohne laufenden Listener:

```
Geheimnis:  demo-probe
Probe:      http://127.0.0.1:9/api/health, erwartet 401 (abgewiesen)

ORT         FINGERABDRUCK  ANTWORT  URTEIL
laptop-env  f9448d60fde5   n/a      PROBE FEHLGESCHLAGEN

0 Orte befragt, 1 nicht wie erwartet.
Solange ein alter Wert noch angenommen wird, hat die Rotation nichts bewirkt.
```

Exit-Code: `1`. Bei einem laufenden Dienst enthält ANTWORT den HTTP-Status
je Ablage; `--old` kehrt die Erwartung zu `expect_revoked` um: Eine
Rotation gilt erst als abgeschlossen, wenn jede Ablage, die noch den alten
Wert hält, abgewiesen wird (`verify.go`; der Live-Pfad wurde aus dem Code
gelesen und hier nicht gemessen).

Eine vor dem Skripting wichtige, gemessene Verweigerung:
`verify` auf einem Eintrag ohne `probe:`-Block gibt
`verify: "demo" has no probe; without one there is nothing to ask` aus und
endet mit `1`.

## Wo der Rest liegt

- Die Spezifikation: SPEC-0438 auf der privaten Maintenance-Ebene, per ID
  referenziert (SPEC-0358: Dateien der öffentlichen Ebene enthalten keine
  Pfade in die private).
- Der schreibende Teil (`new`, `stage`, `distribute`, `retire`) ist bewusst
  nicht in diesem Build; die Verben existieren im Dispatch und verweigern
  mit Exit `2` (`main.go`).
- Die erzeugte druckbare Fassung dieser Seite:
  [Doku-Seite](../pages/entwickler-secretctl.html), geprüft durch
  `scripts/check-docpages.sh`.
