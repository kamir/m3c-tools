# Test Ride: die Skill-Vertrauenskette selbst nachweisen

[Deutsch](TUTORIAL.de.md) · [English](TUTORIAL.md)

**Für wen:** Alle, die Agent-Skills mit `skillctl` veröffentlichen, prüfen, installieren
oder ausführen werden. Keine Vorkenntnisse erforderlich. Sie lesen nicht nur über
Vertrauen, sondern beschädigen ein Bundle und beobachten seine Ablehnung.

**Dauer:** Etwa 20 Minuten offline, zusätzlich 10 Minuten für den Online-Teil.

**Abgrenzung:** Dies ist nicht die technische Abnahme. Diese fragt, ob die MASCHINE
funktioniert, also Build, Tests und CI-Prüfungen. Sie wird mit einem Einzeiler gestartet:

```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-test.sh | bash             # stage 1: builds + tests
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-enterprise-test.sh | bash  # stage 2: the CI gates
```

Unter Windows existieren dieselben zwei Skripte als `.ps1`, siehe
[Quickstart: skillctl](../../docs/v2/nutzer/quickstart-skillctl.md#1b-optional-prove-it-on-your-own-machine-source-self-test).
Zuerst diese ausführen. Sind sie grün, funktioniert die Maschine; offen bleibt,
ob **Sie** das Werkzeug bedienen können. Das ist dieser Test Ride.

---

## Vor dem Start

| Voraussetzung | Grund | Prüfung |
|---|---|---|
| `git`, Go 1.25+ | Die Demo baut `skillctl` aus diesem Checkout | `go version` |
| `bash`, `curl`, `tar`, `shasum` | Skripte der einzelnen Schritte | Auf macOS und Linux vorhanden; unter Windows Bestandteil von Git for Windows, siehe unten |
| Etwa 200 MB frei | Build-Cache und Artefakte | n/a |
| **Nur für den Online-Teil** | ER1-Konto, `ER1_API_KEY`, erreichbares aims-core | Siehe [Teil 3](TUTORIAL.md#part-3-the-online-half-scan-use-decay) |

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools/demo/kup-training
```

**Unter Windows.** PowerShell führt diese POSIX-Shellskripte nicht aus. Git for
Windows liefert die nötige bash, nimmt `bash.exe` bei empfohlener Installation
aber nicht in PATH auf. Deshalb über den Pfad aufrufen:

```powershell
& "$env:ProgramFiles\Git\bin\bash.exe" run-all.sh --offline-only --no-pdf --no-release
```

Alternativ **Git Bash** im Startmenü verwenden und die folgenden Befehle unverändert
ausführen. Fehlen git oder Go, enthält
[docs/v2/nutzer/prerequisites.md](../../docs/v2/nutzer/prerequisites.de.md) je eine
`winget`-Zeile sowie den Weg ohne Administratorrechte.

Alle Schreibvorgänge landen unter dem von Git ignorierten
`demo/kup-training/artifacts/`. Ihr echtes `~/.claude/` bleibt unberührt:
Alice erhält ein künstliches Home unter `artifacts/alice-home/`.
Nach `rm -rf artifacts/` bleibt davon nichts zurück.

---

## Teil 1: der gültige Ablauf (etwa 10 Minuten)

Die Offline-Kette vollständig ausführen:

```bash
./run-all.sh --offline-only --no-pdf --no-release
```

Pro Schritt erscheint ein Ausgabeblock. Beim Durchlauf lesen; dies ist die Übung,
nicht nur ein Build.

| Schritt | Ablauf | Nachweis |
|---|---|---|
| `00` preflight | Baut `skillctl` aus dem Checkout nach `artifacts/bin/` | Geprüft wird der vorliegende Code |
| `01` Bob als Autor | `keygen`, `pack`, `sign`, `verify-sig` | Skill wird versiegeltes Bundle mit abgetrennter Signatur. Die Zeile **"determinism: two packs of the same input are byte-identical"** zeigt: Das Siegel bindet Inhalt, keinen Zeitpunkt |
| `02` Bob veröffentlicht | Offline sauber übersprungen | Registry ist Speicher, keine Vertrauensquelle |
| `03` Reviewer attestiert | Schreibt `attestation.json` mit level green | Urteil einer zweiten Person ist ein separates Artefakt neben der Autorsignatur |
| `04` Alice pinnt Vertrauen | `trust add` schreibt `artifacts/alice-home/.claude/skill-trust-roots.yaml` | Alice trifft lokal eine Entscheidung über einen Schlüssel in ihrer eigenen Datei |
| `05` Alice installiert und führt aus | Prüfen, entpacken, ausführen | `artifacts/alice-home/output/hello.txt` existiert **nur**, wenn die gesamte Kette gehalten hat |

Die letzte Datei ansehen. Sie ist das Ziel der Übung:

```bash
cat artifacts/alice-home/output/hello.txt
```

Diese Datei hätte bei einem gebrochenen Glied nicht entstehen können.
Jetzt einige Glieder brechen.

---

## Teil 2: die vier Ablehnungen

Schritte `06` bis `09` übergeben `skillctl` jeweils einen ungültigen Skill und prüfen
die Ablehnung. `run-all.sh` hat sie bereits ausgeführt. Einen Schritt von Hand
wiederholen und die Ausgabe aufmerksam lesen:

```bash
./06-invalid-tampered.sh
```

| Schritt | Angriff | Ablehnung |
|---|---|---|
| `06` | Ein Bundle-Byte geändert, ursprüngliche Signatur behalten | Exit **11**, Signatur ungültig |
| `07` | Angreifer signiert eigenes Bundle und behauptet Bobs Identität | Exit **11** gegen Bobs Pin, Exit 0 gegen eigenen Schlüssel. Die Signatur stimmt, die IDENTITÄT nicht |
| `08` | Bundle kommt ganz ohne Signatur | Fehlercode, niemals Fail-open |
| `09` | Installierte Datei nachträglich editiert | `CHECKSUMS`-Vergleich erkennt die Änderung, Reparatur aus dem signierten Bundle |

**Die Lektion aus `07`.** Eine gültige Signatur bedeutet nicht "ungefährlich",
sondern "genau dies hat der Inhaber dieses Schlüssels versiegelt".
Alles Weitere ist Ihre Entscheidung über den Schlüssel, und diese fällt in Schritt `04`.

**Exit-Codes sind das Vokabular.** `0` angenommen, `10` Digest-Abweichung,
`11` ungültige Autorsignatur, `17` widerrufen, `2` nicht erzwingbare Governance-Aktion.
Die vollständige Tabelle steht im
[skillctl-Handbuch](../../docs/v2/referenz/manual-skillctl.md#exit-codes).

---

## Teil 3: der Online-Teil mit SCAN, USE und DECAY

Teil 1 und 2 belegen die ANGEBOTSSEITE und brauchen keinen Server.
Schritte `10` bis `12` schließen den Kreis zur NUTZUNG: Was ist installiert,
wer nutzt es und was verfällt ohne Nutzung? Sie sind **nicht** Teil von `run-all.sh`.
Von Hand ausführen; ein laufendes aims-core ist erforderlich.

```bash
export ER1_API_KEY=...                          # or store it once in the macOS keychain:
                                                #   security add-generic-password -s aims-core-er1 -a "$USER" -w
export REGISTRY_URL=https://127.0.0.1:8081      # default; point it at your instance
```

Jeder Schritt prüft zuerst die Erreichbarkeit: `GET $REGISTRY_URL/api/skills/health`
muss mit 200 antworten. Fehlt Server oder Schlüssel, **überspringt er sich mit Warnung**.
Ausführen ohne Server ist deshalb sicher, belegt aber nichts.

| Schritt | Ablauf | Nachweis |
|---|---|---|
| `10-scan-and-sync.sh` | Liest Alices installierte Skills und importiert sie in ihr Profil | Die Flottenansicht stammt aus tatsächlichem Platteninhalt statt Behauptungen |
| `11-use-skill.sh` | Schreibt fünf Nutzungsereignisse für `kup-hello` | Beherrschung entsteht durch Nutzung, jede Nutzung ist ein Ereignis |
| `12-decay.sh` | Berechnet Beherrschung aller Profile neu | Ungenutzte Skills verfallen; ungeübte Fähigkeit ist keine belastbare Fähigkeit |

`12-decay.sh` ruft eine Admin-Route auf, und `ER1_API_KEY` ist nie Admin. Nötig ist die
Browser-Sitzung eines Admins in `AIMS_ADMIN_COOKIE`; ohne sie überspringt sich der Schritt
und erklärt, wie man sie bekommt. Dasselbe gilt für das Registrieren der Demo-Identitäten
vor einem Online-Lauf von `run-and-prove.sh`: siehe
[README.de.md](README.de.md#admin-routen-brauchen-eine-admin-sitzung).

`10` bietet außerdem `--operator`. Dabei wird Ihr ECHTES `~/.claude/skills/`
statt des Demo-Homes gelesen. Vorher das Skript lesen: Dies ist der einzige
Befehl dieses Durchlaufs, der die Sandbox verlässt.

---

## Was Sie gerade nachgewiesen haben

1. Ein Skill lässt sich versiegeln, sodass jede spätere Änderung erkennbar ist: `01`, `06`.
2. Das Siegel benennt einen Schlüssel, keine Person; dessen Pin ist eine lokale Entscheidung: `04`, `07`.
3. Eine zweite Prüfung ist ein separates, prüfbares Artefakt: `03`.
4. Auf Alices Maschine läuft nichts, was nicht die gesamte Kette bestanden hat: `05`.
5. Ablehnung ist der Standard; kein ungültiges Bundle wird still angenommen: `06` bis `09`.
6. Tatsächliche Teamfähigkeit wird aus installierten Skills und echter Nutzung gemessen
   und verfällt ohne Übung: `10` bis `12`.

## Nachweise statt Gefühl hinterlassen

Nicht "Schulung gemacht" melden, sondern das Artefakt erzeugen:

```bash
./run-and-prove.sh --skip-online --chain-only --json ride-report.json
```

`run-and-prove.sh` führt dieselbe Kette aus und prüft pro Schritt die wesentliche
Ausgabe statt nur den Exit-Code. Erwartet: `Pass: 24, Warn: 2, Fail: 0`, Exit 0.
Die beiden Warnungen betreffen Maintainer-Prüfungen, die `--chain-only` überspringt:
PDF-Erzeugung mit einer nicht vorhandenen Dokumentquelle und plattformübergreifender
Release-Build. Der JSON-Bericht benennt Host, Schritte und Ergebnisse.
Ihn dem Onboarding-Ticket beifügen. Die Nachweisregel dieses Werkzeugs gilt auch
für die eigene Aussage: Eine Behauptung ist so viel wert wie ihr Beleg.

## Danach weiterüben

Ein Durchlauf vermittelt den Aufbau, noch keine Routine. Schritte `06` bis `09`
wurden hier FÜR Sie ausgeführt. Der Übungsmodus macht dieselben Befehle zu fünf
wiederholbaren Übungen; jeder Fortschritt beruht auf einem echten Exit-Code:

```bash
skillctl-demo --mode kata      # K1 seal, K2 tamper, K3 govern, K4 trust roots, K5 revoke
skillctl-demo --kata-list      # the board, and your progress
```

Siehe [Quickstart: skillctl-demo](../../docs/v2/nutzer/quickstart-skillctl-demo.md#5-training-mode-kata-shipped).

---

## Wenn etwas schiefgeht

| Symptom | Ursache | Abhilfe |
|---|---|---|
| `private key ... has insecure mode 0644` | Schlüsseldatei mit falschen Berechtigungen angekommen | `chmod 600 artifacts/keys/*.priv`. Preflight erledigt das inzwischen. Tritt es auf, melden: Der Schlüssel kam aus einer ungeeigneten Quelle |
| `01` scheitert, danach `05`, `06`, `09` | Ohne Signatur kann kein Folgeschritt prüfen | Zuerst `01` beheben; die anderen Fehler sind Folgen, keine vier unabhängigen Bugs |
| `online mode not available: skipping` | Kein `ER1_API_KEY` oder Registry antwortet nicht mit 200 | Siehe [Teil 3](TUTORIAL.md#part-3-the-online-half-scan-use-decay). Teil 1 und 2 benötigen dies nicht |
| `admin routes need an admin's browser session` (P0 rot oder `12-decay.sh` überspringt sich) | Admin-Route ohne Admin-Sitzung aufgerufen; `ER1_API_KEY` ist nie Admin | Den ausgegebenen Anmeldeschritten folgen oder [README.de.md](README.de.md#admin-routen-brauchen-eine-admin-sitzung) lesen. `--skip-online` braucht das nicht |
| `make-pdf.sh` findet Handbuch nicht | Dokumentquelle stammt aus privatem Maintenance-Checkout | `run-all.sh --no-pdf`, `run-and-prove.sh --chain-only`; Maintainer-Prüfung, kein Teil der Übung |
| Neu beginnen gewünscht | | `rm -rf artifacts/`, dann erneut starten. Schlüssel werden neu erzeugt |

## Weitere Dokumente

- Jeder Befehl, jedes Flag, jeder Exit-Code: [skillctl-Handbuch](../../docs/v2/referenz/manual-skillctl.de.md)
- In fünf Minuten installieren, erstellen, signieren und prüfen: [Quickstart: skillctl](../../docs/v2/nutzer/quickstart-skillctl.de.md)
- Signierten Skill veröffentlichen und installieren: [Tutorial zum signierten Skill](../../docs/v2/nutzer/tutorial-szenario-02-erster-signierter-skill.de.md)
- Zweck dieses Verzeichnisses für Maintainer und seine vier Release-Prüfungen:
  [README.de.md](README.de.md)
