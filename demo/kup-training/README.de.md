# KuP Skill-Manager-Schulung: durchgängige Demo

[Deutsch](README.de.md) · [English](README.md)

> **Zum Tutorial geht es hier: [TUTORIAL.de.md](TUTORIAL.de.md).**
> Dieses Verzeichnis dient zwei Zielgruppen mit unterschiedlichen Anliegen.
> **Lernende:** Sie suchen den geführten 20-Minuten-Durchlauf, an dessen Ende Sie ein
> Bundle beschädigt und dessen Ablehnung beobachtet haben. Dafür ist `TUTORIAL.md` da.
> **Maintainer:** Sie benötigen das unten beschriebene Release-Gate, das vor einer
> Kohortenschulung die vier verbindlichen Ergebnisse prüft. Dafür ist diese Datei da.

Jede Aussage im Skill-Manager-USER-MANUAL auf der privaten Maintenance-Ebene wird hier
durch ein ausführbares Shellskript belegt. Der Orchestrator `run-all.sh` ist das
**Release-Gate** und prüft die vier vertraglich erforderlichen Ergebnisse.

## Punkte des Release-Gates

| # | Prüfung | Nachweis |
|---|---|---|
| **G1** | Nutzerhandbuch als PDF ausgeben | `make-pdf.sh` → `artifacts/{USER-MANUAL,SKILLCTL-MANUAL,KuP-skill-manager-handbook}.pdf` |
| **G2** | skillctl über GitHub-Download und Installer ausliefern | `build-release.sh` → `artifacts/release/{skillctl-*,SHA256SUMS,install.sh,RELEASE_NOTES.md,gh-release-create.sh}` |
| **G3** | Skill von Bob über aims an Alice übertragen | Schritte `01–05`; `05` endet mit `artifacts/alice-home/output/hello.txt`, erzeugt durch Alices Ausführung eines anhand der Vertrauenskette geprüften Skills |
| **G4** | Gültiger Skill funktioniert bei Alice, ungültiger scheitert | `05` gültig ✓, dazu `06`/`07`/`08`/`09`: vier unterschiedliche ungültige Fälle mit jeweils geprüftem erwartetem Fehlercode |

## Schnellstart

```bash
cd demo/kup-training             # from the repository root
./run-all.sh                    # full demo + PDF + release build
./run-all.sh --offline-only     # skip aims-core round-trip (chain proof still runs)
./run-all.sh --no-pdf           # skip PDF render
./run-all.sh --no-release       # skip cross-platform binary build
```

Der Orchestrator gibt abschließend einen Bericht aus, der jeden Prüfpunkt seinem
Nachweisartefakt zuordnet.

`run-and-prove.sh` ist das Gegenstück mit einzelnen Zusicherungen: Es führt dieselbe
Kette aus und prüft pro Schritt das wesentliche Artefakt, nicht nur den Exit-Code.

```bash
./run-and-prove.sh                                  # full chain, fail-fast
./run-and-prove.sh --skip-online --chain-only       # trust chain only: skips G1 (PDF) + G2 (release)
./run-and-prove.sh --keep-going --json out.json     # run everything, emit a summary
```

`--chain-only` ist für den Test Ride gedacht. G1 rendert ein Handbuch aus der privaten
Maintenance-Ebene. Ohne diesen Checkout brach früher der gesamte Nachweis mit rc=1 ab,
obwohl alle Vertrauensprüfungen bestanden waren.

## Schritte in Reihenfolge

| Datei | Ablauf | Prüfung |
|---|---|---|
| `00-preflight.sh` | Baut skillctl aus Quellcode nach `artifacts/bin/`, prüft das Online-Registry und bereinigt den Arbeitsbereich. | Werkzeuge vorhanden, Binary baut fehlerfrei |
| `01-bob-author.sh` | Bob: `keygen` → `pack` → `sign` → lokales `verify-sig`. Prüft Determinismus durch zwei bytegleiche Pakete. | Verify-sig Exit 0, deterministische Bundle-Bytes |
| `02-bob-publish.sh` | Bob: `skillctl publish --registry self` über den ER1-Transport, online nach Möglichkeit, Ziel standardmäßig `local`. | Online "published to ER1 self"; ein gescheitertes Veröffentlichen warnt, der Schritt endet trotzdem mit Exit 0. Offline sauber übersprungen |
| `03-reviewer-attest.sh` | Reviewer: `skillctl attest <digest> --level green`. Schreibt offline eine lokale `attestation.json`. | Online nimmt das Registry an, offline ist attestation.json mit level=green vorhanden |
| `04-alice-trust-root.sh` | Alice pinnt Bobs öffentlichen Schlüssel mit `skillctl trust add`. | `~/.claude/skill-trust-roots.yaml` enthält den gepinnten Schlüssel |
| `05-alice-install-and-run.sh` | **Alice installiert, prüft mit verify-sig, entpackt und führt aus.** Online zuerst Versuch mit `skillctl install`; der Offline-Pfad läuft immer als tragender Kettennachweis. | `output/hello.txt` erzeugt ✓ |
| `06-invalid-tampered.sh` | Ändert ein Byte im Bundle und behält die ursprüngliche Signatur. | `verify-sig` Exit **11**, Signatur ungültig |
| `07-invalid-wrong-key.sh` | Angreifer signiert ein paralleles Bundle mit eigenem Schlüssel und behauptet Bobs Identität. | Gegen Bobs Pin `verify-sig` Exit **11**; Kontrollprüfung desselben Bundles mit Angreiferschlüssel Exit 0 |
| `08-invalid-no-signature.sh` | Bundle ohne passende `<digest>.author.sig` geliefert. | `verify-sig` verweigert mit Fehlercode, kein Fail-open |
| `09-invalid-edited-install.sh` | Ändert eine installierte Datei und vergleicht gegen `CHECKSUMS`. | Abweichung erkannt, Reparatur aus dem signierten Bundle |

### Schritte 10 bis 12: Nutzungsseite, NICHT von run-all.sh ausgeführt

`run-all.sh` endet nach `09`. Die folgenden drei Schritte schließen den Kreis von
Angebot und Nutzung gegen ein laufendes aims-core. Sie werden von Hand ausgeführt,
prüfen zuerst `GET $REGISTRY_URL/api/skills/health` und überspringen sich mit Warnung,
wenn Registry oder `ER1_API_KEY` fehlen.

| Datei | Ablauf | Prüfung |
|---|---|---|
| `10-scan-and-sync.sh` | Phase SCAN: Projiziert installierte Skills über `/api/v2/skills/profile/import` nach `_user_skill_profiles`. `--operator` liest das ECHTE `~/.claude/skills/` des Trainers statt des Demo-Homes. | Profil entspricht der tatsächlichen Installation |
| `11-use-skill.sh` | Phase USE: Schreibt fünf Nutzungsereignisse nach `/api/v2/skills/usage`. Benötigt `ER1_CONTEXT_ID` aus `~/.m3c-tools.env`. | `use_count` steigt, `last_used` gesetzt, Beherrschung wechselt aware -> practiced |
| `12-decay.sh` | Phase DECAY: `POST /api/v2/skills/profile/recalculate-all`. | Ungeübte Fähigkeit verfällt. Admin-Route: braucht eine [Admin-Sitzung](#admin-routen-brauchen-eine-admin-sitzung), überspringt sich ohne sie |

### Arbeitsbereich erzeugen statt einchecken

`artifacts/` wird von Git ignoriert; jede Datei darin entsteht durch einen Lauf.
Früher war der Bereich samt `keys/{bob,reviewer,attacker}.priv` eingecheckt.
Git erhält Modus `0600` nicht. Jede frische Kopie enthielt deshalb einen allgemein
lesbaren privaten Schlüssel. `skillctl sign` verweigerte fail-closed mit
"insecure mode 0644"; Schritt `01` scheiterte und zog `05`, `06` und `09` mit.
Die Demo war damit überall außer auf der ursprünglichen Erzeugermaschine defekt.
Heute entstehen die Schlüssel je Maschine neu, `00-preflight.sh` erzwingt `0600`,
und das alte eingecheckte Paar ist außer Betrieb. Für ein signiertes Demo-Bundle
die Demo ausführen und das Ergebnis aus `artifacts/bundles/` verwenden.

## Welche Bereiche verändert werden

Die Demo ist **isoliert**. Sie schreibt ausschließlich unter `artifacts/`, relativ
zu diesem Verzeichnis. `artifacts/alice-home/` dient für `skillctl trust add` und
Installation als künstliches `$HOME`. Ihr echtes `~/.claude/` bleibt unverändert.

## Online und offline

| Fähigkeit | Offline, immer verfügbar | Online, benötigt ER1_API_KEY und erreichbares aims-core |
|---|---|---|
| keygen, pack, sign | ✓ | ✓ |
| Lokales verify-sig als Wurzel der Kette | ✓ | ✓ |
| Dateibasierte Trust Roots | ✓ | ✓ |
| Bundle über Registry installieren | Übersprungen, ersetzt durch verify-sig und Entpacken | ✓ mit `skillctl install` |
| Attestierung übertragen | Übersprungen, stattdessen lokale attestation.json | ✓ mit `skillctl attest` |
| Identität registrieren | Übersprungen | ✓ mit `POST /api/skills/identities` in einer [Admin-Sitzung](#admin-routen-brauchen-eine-admin-sitzung) |

Der kryptografische Nachweis ist in beiden Modi gleich. Das Registry ist Speicher,
keine Vertrauensquelle. Die Demo betont dies bewusst, damit die Lektion auch bei
Netzausfall während einer Schulung erhalten bleibt.

### Admin-Routen brauchen eine Admin-Sitzung

Zwei Aufrufe dieser Demo sind Admin-Routen von aims-core: das Registrieren einer
Identität (`POST /api/skills/identities`, P0 in `run-and-prove.sh` und
`register-identity.sh`) und `12-decay.sh` (`POST /api/v2/skills/profile/recalculate-all`).
Sie brauchen die angemeldete Browser-Sitzung eines Benutzers, der laut RBAC Admin ist.
Der gemeinsame `ER1_API_KEY` ist nie Admin, gleich welche `X-User-ID` mitgeschickt wird;
mit ihm lässt sich keine Identität registrieren.

Die beiden Demo-Identitäten einmal vor dem Online-Lauf registrieren. Ihre Schlüssel
müssen zuerst existieren: Die Offline-Kette erzeugt sie, und `00-preflight.sh` behält
sie über Läufe hinweg:

```bash
./run-and-prove.sh --skip-online --chain-only           # generates artifacts/keys/{bob,reviewer}.pub
read -rs AIMS_ADMIN_COOKIE && export AIMS_ADMIN_COOKIE  # paste an admin session's Cookie header, then Enter
./register-identity.sh id:bob@m3c      artifacts/keys/bob.pub      "Bob (KuP demo author)"
./register-identity.sh id:reviewer@m3c artifacts/keys/reviewer.pub "Reviewer (KuP demo)"
unset AIMS_ADMIN_COOKIE
./run-and-prove.sh                                      # P0 confirms both with a read: no admin session needed
```

Zum Cookie: `$REGISTRY_URL/v2/skills/admin` im Browser öffnen und als Admin anmelden,
dann in den Entwicklerwerkzeugen im Netzwerk-Tab bei einer beliebigen Anfrage an das
Registry den Wert des `Cookie`-Request-Headers kopieren. `read -rs` hält ihn vom
Bildschirm und aus der Shell-History fern. Die Skripte geben ihn curl über stdin, nie
als Argument, und schicken weder `X-API-KEY` noch einen `Origin`-Header mit:
`skill_registry_bp` ist CSRF-befreit, hinter einer Origin-Prüfung.

Eine Identität bleibt registriert, spätere Läufe brauchen deshalb keine Admin-Sitzung:
`register-identity.sh` liest `GET /api/skills/identities/<id>` und vergleicht den
registrierten Schlüssel mit dem lokalen. Ebenso möglich: `AIMS_ADMIN_COOKIE` vor
`./run-and-prove.sh` exportieren. P0 registriert dann, was fehlt, sobald die Schritte
01 und 03 die Schlüssel erzeugt haben.

| Exit von `register-identity.sh` | P0-Urteil | Bedeutung |
|---|---|---|
| 0 | grün | mit dem lokalen Schlüssel registriert, gerade eben oder früher |
| 3 | rot, Anmeldeschritte ausgegeben | nicht registriert (oder vom Lesezugriff nicht bestätigt) und keine Admin-Sitzung: `AIMS_ADMIN_COOKIE` fehlt oder ist keine Admin-Sitzung |
| 4 | rot | mit einem anderen oder widerrufenen Schlüssel registriert. Erneutes Registrieren ändert das nicht: das Schlüsselpaar wiederherstellen, das das Registry kennt (`00-preflight.sh --reset-all` löscht `artifacts/keys/`) |
| sonst | gelb | Registry nicht erreichbar oder Serverfehler, siehe `artifacts/logs/run-and-prove.log` |

`--skip-online` führt kein P0 aus und braucht nichts davon. `12-decay.sh` ohne
`AIMS_ADMIN_COOKIE` überspringt sich und gibt dieselben Anmeldeschritte aus.

## Ausgaben

Nach `./run-all.sh`:

```
artifacts/
├── bin/skillctl                              # the binary (matches release/skillctl-*)
├── keys/{bob,reviewer,attacker}.{priv,pub} # ed25519 keypairs
├── bundles/
│   ├── kup-hello-0.1.0.skb                   # the deterministic bundle
│   ├── kup-hello-0.1.0.skb.<digest>.author.sig
│   ├── tampered.skb (+sig)                   # step 06
│   ├── attacker-kup-hello-0.1.0.skb (+sig)   # step 07
│   ├── no-sig/kup-hello-0.1.0.skb            # step 08 (no sig sidecar)
│   └── src/kup-hello/                        # the staged source
├── trust-roots/                              # (handed to Alice in step 04)
├── alice-home/
│   ├── .claude/skill-trust-roots.yaml        # pinned by step 04
│   ├── .claude/skills/kup-hello/             # installed by step 05
│   └── output/hello.txt                      # produced by step 05 ✓
├── attestation.json                          # offline reviewer verdict
├── digest.txt                                # the bundle's sha256:...
├── logs/full.log                             # every captured stderr
├── USER-MANUAL.pdf
├── SKILLCTL-MANUAL.pdf
├── KuP-skill-manager-handbook.pdf
└── release/
    ├── skillctl-darwin-arm64
    ├── skillctl-darwin-amd64
    ├── skillctl-linux-amd64
    ├── skillctl-linux-arm64
    ├── skillctl-windows-amd64.exe
    ├── SHA256SUMS
    ├── install.sh
    ├── RELEASE_NOTES.md
    ├── release-tag.txt
    └── gh-release-create.sh                  # run manually to publish (DRAFT)
```

## Aufräumen

```bash
rm -rf artifacts/
```

Die Demo greift auf nichts außerhalb dieses Verzeichnisses zu.

## Nächste Erweiterungspunkte

- Sobald SPEC-0194 `propose` im Dispatcher verfügbar ist, den manuellen Multipart-POST in Schritt 02 durch `skillctl propose` ersetzen.
- Sobald SPEC-0201 `import-public` verfügbar ist, `11-airlock-import.sh` zur Aufnahme fremder Bundles ergänzen.
- Sobald SPEC-0202 `run` verfügbar ist, die direkte bash-Ausführung in Schritt 05b durch `skillctl run` ersetzen und `12-envelope-violation.sh` ergänzen, das gezielt Exit 32 wegen gesperrtem Egress auslöst.
