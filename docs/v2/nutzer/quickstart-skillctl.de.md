---
layout: default
title: "Schnellstart: skillctl"
---

# Schnellstart: skillctl

[Deutsch](quickstart-skillctl.de.md) · [English](quickstart-skillctl.md)

Den ersten Agent-Skill in etwa fünf Minuten paketieren, signieren und prüfen:
vollständig offline, ohne Server. Anschließend denselben Bundle-Lebenszyklus
von admit über install bis revoke nachvollziehen.

> **Was ist skillctl?** Die Trust- und Governance-CLI für Agent-Skills. Sie gibt jedem
> Skill eine prüfbare Identität und den vollständigen Lebenszyklus **author → pack →
> sign → admit → attest → verify / install → use → audit → revoke**, damit Agenten
> keine unautorisierten oder unbelegbaren Skills ausführen. Die Vertrauenskette ist
> **offline prüfbar**, ohne gehostete CA im Prüfpfad. Alle Befehle und Flags stehen im
> [skillctl-Handbuch](../referenz/manual-skillctl.de.md).

---

## 1. Installieren

`skillctl` ist ein einzelnes CLI-Binary in jedem
[Release](https://github.com/kamir/m3c-tools/releases/latest). Es läuft auf macOS,
Linux und Windows gleich.

Die **Einzeilen-Installer** laden das passende Binary, **prüfen cosign-Provenance
über GitHub OIDC und den SHA-256-Integritätsdigest** und installieren dann in ein
**nutzerbezogenes** Binary-Verzeichnis, ohne Administratorrechte.

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/kamir/m3c-tools/953dd07dfe440309f5702f296346b5e85bc5c1e1/tools/skillctl-install.ps1 | iex
```

Installiert nach `%LOCALAPPDATA%\Programs\skillctl`, nach Prüfung von cosign-Provenance
und SHA-256. Zielverzeichnis oder Release lassen sich vor dem Start mit `$env:INSTALL_DIR`
und `$env:RELEASE_BASE` überschreiben. Dieser **leichte, nutzerbezogene Weg ohne Adminrechte**
unterscheidet sich vom maschinenweiten Installer `M3C-Tools-Setup.exe`. **Eine der beiden
Varianten** verwenden, damit nicht zwei `skillctl.exe` in Ihrem `PATH` liegen.

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/953dd07dfe440309f5702f296346b5e85bc5c1e1/tools/skillctl-install.sh | bash
```

Zielverzeichnis oder Release mit `INSTALL_DIR=…` beziehungsweise `RELEASE_BASE=…` überschreiben.

**Integrität des Bootstraps.** Die Einzeiler-URLs sind auf den **unveränderlichen Commit
`953dd07`** gepinnt, statt auf den veränderlichen Branch `master`, auf dem eine Umschreibung
Bootstrap-Skript und alle darin enthaltenen Pins gleichzeitig austauschen könnte.
Die heruntergeladenen Bytes vor dem Vertrauen unabhängig prüfen. Erwartete SHA-256:
`tools/skillctl-install.ps1` → `a85f73ba04d279033d1bfad348f71931297df06511c75c9313bde1eb2883ed2b`;
`tools/skillctl-install.sh` → `a013791fbe2ae90a109e98c26cca88874348e3aa7d4164832dc8d52bddf5a2b8`.
Der [Installationsabschnitt der README](../../../README.md#install) enthält eine kopierbare
Anleitung zum Prüfen vor Ausführung. Bei jedem neuen signierten Release gepinnten
Commit **und** diese Hashwerte gemeinsam aktualisieren.

**Manuelle Installation eines signierten Release-Binarys:** Der **einzige** skillctl-Vertriebskanal
ist die signierte Release-Linie `skillctl/v*`, mit cosign/OIDC, SLSA-Provenance und gepinntem
ed25519-Fallback. Die früher im Produktrelease `v*` enthaltenen unsignierten skillctl-Dateien
je Architektur wurden **eingestellt**. Dort nicht mehr danach suchen. Zur manuellen
Installation Binary und `SHA256SUMS` aus dem signierten Release laden und die Integrität
**vor** dem Verschieben in `PATH` prüfen:
```bash
BASE="https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.6.2"
curl -sLO "$BASE/skillctl-darwin-arm64"     # or darwin-amd64 / linux-amd64 / linux-arm64 / windows-amd64.exe
curl -sLO "$BASE/SHA256SUMS"
grep ' skillctl-darwin-arm64$' SHA256SUMS | shasum -a 256 -c -     # integrity gate. Fails closed on mismatch
sudo install skillctl-darwin-arm64 /usr/local/bin/skillctl
```

Für vollständige Provenance-Prüfung, also cosign-Bundle oder ed25519-Signatur, die Einzeiler
oben bevorzugen. Sie übernehmen die Prüfung. Alternativ aus Quellcode bauen:
`go build -o build/skillctl ./cmd/skillctl`.

```bash
skillctl version
skillctl help        # the full command map, grouped by capability
```

---

## 1b. Optional: auf dem eigenen Rechner nachweisen (Quellcode-Selbsttest)

Bevor Sie einem fremdgebauten Binary vertrauen, können Sie es selbst bauen und die Tests
lokal ausführen. Je ein Befehl pro Plattform klont das Repository nach `~/m3c-tools` oder
aktualisiert es per Fast-forward, prüft Toolchain und Modulprüfsummen, baut `skillctl`, führt
dessen Tests aus, mit Race Detector bei verfügbarer C-Toolchain, prüft die CLI mit einem
Smoke-Test und gibt eine PASS/FAIL-Tabelle aus.

**Windows (PowerShell):**
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
irm https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-test.ps1 | iex
```

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-test.sh | bash
```

Voraussetzungen: **git** und **Go 1.26.10+** in `PATH`, sonst nichts. Fehlt eines davon oder
ist Windows frisch eingerichtet, helfen die [Voraussetzungen](prerequisites.de.md): je eine
`winget`-Zeile, PATH neu laden für das bereits offene Fenster und eine Variante ohne
Administratorrechte. Die Skripte verändern keine Trust Roots, schreiben nicht außerhalb
des Checkouts und enden bei jedem fehlgeschlagenen Schritt mit einem Fehlercode.

Vorher den Quelltext lesen? Die Skripte sind
[`scripts/skillctl-test.ps1`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-test.ps1)
und [`scripts/skillctl-test.sh`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-test.sh).
Erst klonen, dann die lokale Kopie ausführen:

```bash
git clone https://github.com/kamir/m3c-tools.git && cd m3c-tools
./scripts/skillctl-test.sh --repo-dir "$PWD"
```

Nützliche Flags, auf beiden Plattformen entsprechend:

| Zweck | PowerShell | bash |
|---|---|---|
| Anderes Checkout-Verzeichnis | `-RepoDir C:\src\m3c-tools` | `--repo-dir ~/src/m3c-tools` |
| Anderen Branch prüfen | `-Ref my-branch` | `--ref my-branch` |
| Gesamtes Modul statt nur skillctl | `-Full` | `--full` |
| Race Detector überspringen | `-NoRace` | `--no-race` |

Zwei Punkte: Standardmäßig werden dieselben Pakete wie im Release-Gate geprüft,
`./cmd/skillctl/... ./pkg/skillctl/...`. Ein einfaches `go test ./...` baut auch Pakete,
die Netzwerk, ER1-Server, Whisper oder Mikrofon benötigen; deren Fehler sagen nichts
über skillctl aus. Der Race Detector benötigt außerdem cgo und einen C-Compiler:
mingw-w64 unter Windows, `xcode-select --install` unter macOS, gcc unter Linux.
Ohne Compiler laufen die Tests trotzdem; die Race-Zeile meldet `SKIP` statt einen
nicht ausgeführten Test als bestanden auszugeben.

Dies ist bewusst Stage 1: reproduzierbarer Build und Testsuite, **nicht** das Trust- und
Release-Gate. Lint, `govulncheck`, gosec, Coverage-, Boundary-Gate und Windows-E2E-Smoke
laufen in [CI](https://github.com/kamir/m3c-tools/actions) sowie unter `make ci` und
`make release-skillctl`. Den Windows-Lebenszyklus belegt
[`scripts/skillctl-quickstart-windows.ps1`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-quickstart-windows.ps1).

---

## 1c. Stage 2: CI auf dem eigenen Rechner ausführen (Enterprise-Gate)

Ist Stage 1 grün, folgt die Frage: **Würde dieser Stand die Prüfungen bestehen, auf denen
Merge und Release beruhen?** Stage 2 führt jede sinnvoll auf einem Laptop ausführbare
CI-Prüfung aus, bricht nicht beim ersten Fehler ab und endet mit einem
**Vertrauensbericht** aus PASS, FAIL und SKIP.

**Windows (PowerShell):**
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
irm https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-enterprise-test.ps1 | iex
```

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-enterprise-test.sh | bash
```

| Prüfung | Nachweis | Gegenstück in CI |
|---|---|---|
| `stage1` | Build erfolgreich, Tests bestanden, CLI antwortet | Voriger Abschnitt |
| `vet` | Keine `go vet`-Befunde | `ci.yml` Lint & Vet |
| `lint` | golangci-lint sauber, gepinnt auf v2.13.2 | `ci.yml` Lint & Vet |
| `mod-tidy` | `go mod tidy` verändert nichts | `ci.yml` CD-T4 |
| `docaudit` | Jedes echte CLI-Flag dokumentiert, jedes dokumentierte Flag vorhanden | `ci.yml` docs-gate |
| `prose` | Kein U+2014 im getrackten Baum | `ci.yml` prose-gate |
| `pins` | Jeder gepinnte Installations-Einzeiler auflösbar, Digests stimmen | `pin-guard` und BUG-0215 |
| `boundary` | Grenze zwischen öffentlicher und privater Ebene eingehalten | `boundary-gate.yml` |
| `coverage` | Coverage-Untergrenzen aus `.testcoverage.yml` für die Vertrauensschicht | `coverage-gate.yml` |
| `govulncheck` | Keine aus dem Code erreichbare CVE, gepinnt auf v1.7.0 | `ci.yml` govulncheck |
| `gosec` | Keine **neuen** SAST-Befunde gegenüber der eingecheckten Baseline | `gosec-diff-gate.yml` |
| `gitleaks` | Keine Secrets in der vollständigen Historie | `ci.yml` gitleaks |
| `trust-surface` | Gesamte Vertrauensschicht, ganze Pakete, keine Allowlist | `windows-gate.yml` |
| `lifecycle` | Erstellen, signieren, prüfen, vertrauen und manipuliertes Bundle **abweisen** | `skillctl-windows-smoke.yml` |

Unter Windows brauchen `pins`, `boundary` und `gosec` eine POSIX-Shell. Git for Windows
enthält sie bereits. Das Skript findet sie neben `git.exe`, auch wenn die empfohlene
Installation `bash.exe` nicht in PATH aufnimmt. Die [Voraussetzungen](prerequisites.de.md)
erklären diese Falle und warum eine in PATH gefundene `bash` häufig WSL und damit die falsche ist.

Flags: `--full` / `-Full` erweitert die Go-Prüfungen von der skillctl-Vertrauensschicht
auf `./...`. `--no-install` / `-NoInstall` verbietet die Installation fehlender Werkzeuge.
`--strict` / `-Strict` lässt übersprungene Prüfungen den Lauf fehlschlagen.
`--skip-stage1` / `-SkipStage1` überspringt Build und Tests.

**Drei bewusste Grenzen dieses Berichts.**

*Keine unangekündigte Werkzeuginstallation.* golangci-lint, gosec und go-test-coverage
werden in den von CI gepinnten Versionen nach `$(go env GOPATH)/bin` geladen, und der Lauf
meldet das. gitleaks wird nie automatisch installiert: CI prüft dessen Release-Archiv
vor Ausführung gegen einen gepinnten SHA-256; ein Komfortskript darf dies nicht vortäuschen.
Fehlt ein Werkzeug, lautet das Ergebnis `SKIP`.

*Übersprungen zählt nicht als bestanden.* Eine nicht ausführbare Prüfung meldet `SKIP`,
das Gesamtergebnis `PASS with N skipped`. Mit `--strict` wird der Bericht als strenger
Nachweis verwendbar.

*Der Bericht ist kein Release.* SLSA-Provenance, cosign/OIDC-Signierung, Übernahme in
Code Scanning und die Cross-Compile-Matrix existieren nur serverseitig. Ein grüner Bericht
hier ersetzt keine grüne PR.

**Ein Windows-Detail.** Ein ausgeliefertes Windows-Binary ignoriert `$HOME` für Trust-Root-Pfade
absichtlich, weil Angreifer diese Umgebungsvariable setzen können. Isolierte Trust-Tests
injizieren `$HOME` und laufen unter Windows deshalb nur mit `-tags allow_home_override_test`
tatsächlich. Stage 1 prüft ohne Tag das ausgelieferte Verhalten. Das `trust-surface`-Gate
prüft mit Tag, und `lifecycle` baut sein Sandbox-Binary ebenfalls damit, damit der Nachweis
niemals Ihr echtes `%USERPROFILE%\.claude` berührt. macOS und Linux benötigen keinen Tag,
weil sie `$HOME` berücksichtigen. Ihr Lebenszyklusnachweis ist
[`scripts/skillctl-quickstart-unix.sh`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-quickstart-unix.sh),
das Gegenstück zu
[`scripts/skillctl-quickstart-windows.ps1`](https://github.com/kamir/m3c-tools/blob/master/scripts/skillctl-quickstart-windows.ps1).

---

## 1d. Der menschliche Teil: Test Ride

Stage 1 und 2 prüfen die Maschine. Ob **Sie** das Werkzeug bedienen können, zeigen sie
nicht. Das übernimmt der Test Ride: etwa zwanzig Minuten, in denen Sie einen Skill
versiegeln, einen Schlüssel pinnen, als andere Person installieren und ihn anschließend
auf vier Arten beschädigen. Jeder Versuch wird abgewiesen.

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools/demo/kup-training && ./run-all.sh --offline-only --no-pdf --no-release
```

Unter Windows die Demoskripte mit Gits bash ausführen:
`& "$env:ProgramFiles\Git\bin\bash.exe" run-all.sh --offline-only --no-pdf --no-release`
oder über Git Bash im Startmenü. Siehe [Voraussetzungen](prerequisites.de.md).

Die Anleitung ist
[`demo/kup-training/TUTORIAL.md`](https://github.com/kamir/m3c-tools/blob/master/demo/kup-training/TUTORIAL.md):
was jeder Schritt belegt, was die Exit-Codes bedeuten und welche Lektion häufig missverstanden
wird. Eine gültige Signatur bedeutet "Das hat dieser Schlüssel versiegelt", niemals
"Das ist ungefährlich". Alles läuft offline unter `demo/kup-training/artifacts/` mit
einem künstlichen Home; Ihr echtes `~/.claude/` bleibt unberührt. Drei weitere Schritte
führen bei vorhandenem ER1-Konto durch SCAN / USE / DECAY.

Mit einem Nachweis abschließen:
`./run-and-prove.sh --skip-online --chain-only --json ride-report.json`.

Danach mit [`skillctl-demo --mode kata`](quickstart-skillctl-demo.md#5-training-mode-kata-shipped)
weiterüben: fünf Übungen, bei denen jeder Fortschritt ein echter Exit-Code ist.

---

## 2. Autoridentität anlegen

Einem Skill wird wegen seiner **Signatur** vertraut. Einmal ein ed25519-Schlüsselpaar erzeugen:

```bash
skillctl keygen --out ~/.config/m3c/skill-keys/mykey
```

Dabei entstehen:

- `~/.config/m3c/skill-keys/mykey.priv`: Ihr **privater** Schlüssel, Modus `0600`, geheim halten.
- `~/.config/m3c/skill-keys/mykey.pub`: Ihr **öffentlicher** Schlüssel, zum Prüfen an andere weitergeben.

Beide sind PEM-verpacktes ed25519, PKCS#8 beziehungsweise SPKI.

---

## 3. Einen Skill als versiegeltes Bundle paketieren

Ein Skill-Verzeichnis benötigt nur `SKILL.md`. Mit Manifest in ein `.skb`-Bundle packen:

```bash
skillctl pack \
  --skill ./my-skill \
  -o my-skill.skb \
  --name my-skill \
  --version 1.0.0 \
  --summary "What this skill does"
```

Nützliche optionale Manifestfelder:

| Flag | Zweck |
|---|---|
| `--source-repo` / `--source-commit` / `--source-path` | Provenance: Herkunft des Skills |
| `--depends-on kind:name:constraint` | Abhängigkeiten deklarieren, etwa `python:requests:>=2.31`; wiederholbar |
| `--author-intent green\|yellow\|red` | Beratender Governance-Hinweis; der Verifier ignoriert ihn. Signierte **Attestierungen** sind verbindlich. |
| `--data-scopes <json>` | Vom Autor signierter Datenumfang, im Bundle gebunden |

---

## 4. Signieren

```bash
skillctl sign --key ~/.config/m3c/skill-keys/mykey.priv my-skill.skb
```

Berechnet den SHA-256-Digest des Bundles, signiert ihn mit ed25519 und schreibt eine
**abgetrennte** Signatur daneben: `my-skill.skb.<digest>.author.sig`.

---

## 5. Offline prüfen

```bash
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/mykey.pub my-skill.skb
```

Berechnet den Digest erneut, findet die passende Signatur und prüft sie.
**Kein Netzwerk, keine CA.**

```
Exit codes:  0 ok  ·  11 signature invalid  ·  1 other error  ·  2 usage
```

Das ist der Kernablauf: **Jeder mit Ihrem öffentlichen Schlüssel kann Echtheit und
Unverändertheit des Bundles allein mit den beiden vorliegenden Dateien nachweisen.**

---

## 6. In ein lokales Registry veröffentlichen, pinnen, installieren

Ein Registry auf der Platte braucht keinen Server. Es nutzt denselben Codepfad wie ein Git-Registry auf GitHub oder GitLab. Die Reihenfolge zählt: erst veröffentlichen und attestieren, dann pinnen, dann installieren.

```bash
K=~/.config/m3c/skill-keys
REG="local://$HOME/skill-registry.git"
DIGEST="sha256:$(skillctl sign --key "$K/mykey.priv" my-skill.skb | awk '/^digest:/ {print $2}')"

skillctl registry init --registry "$REG"
skillctl publish my-skill@1.0.0 --bundle my-skill.skb --version 1.0.0 \
  --registry "$REG" --key "$K/mykey.priv" --identity id:me@local --yes
skillctl publish --attest my-skill@1.0.0 --digest "$DIGEST" --level green --rationale "reviewed" \
  --registry "$REG" --key "$K/mykey.priv" --identity id:me@local --yes

skillctl peer add mine "$REG" \
  --pubkey "$(skillctl trust fingerprint --b64 "$K/mykey.pub")" \
  --pin "$(skillctl trust fingerprint "$K/mykey.pub")"

skillctl pull --registry "$REG" --skill my-skill --install --trust-mode --dry-run-install --no-checkpoint
```

Der letzte Befehl gibt einen Plan und ein fünf Minuten gültiges Token aus. Lesen Sie den Plan und bestätigen Sie:

```bash
skillctl pull --registry "$REG" --skill my-skill --install --trust-mode \
  --confirm-install --dry-run-install-token <TOKEN> --no-checkpoint
skillctl verify my-skill
skillctl verify --all
```

Der Skill liegt jetzt unter `~/.claude/skills/my-skill/`. `verify` endet mit `0`.

Der Prüfer liefert nummerierte Exit-Codes, damit Automatisierung gezielt verzweigen kann:

| Code | Bedeutung | Code | Bedeutung |
|-----:|---------|-----:|---------|
| `0` | in Ordnung | `13` | Governance unter dem Minimum |
| `10` | Digest stimmt nicht | `14` | `depends_on` nicht erfüllt |
| `11` | Autorensignatur ungültig | `15` | Blob fehlt |
| `12` | Registry nicht in den Trust-Roots | `16` | Tenant gesperrt (CISO-Urteil) |
| `17` | widerrufen | | |

Die Installation aus einem HTTP-Registry mit `skillctl trust add` und `skillctl install` steht im [Handbuch](../referenz/manual-skillctl.de.md). Dieser Weg hat keine Client-Authentifizierung.

---

## 7. Veröffentlichen, attestieren und widerrufen

Mit einem eigenen Registry über ER1 erweitert sich der Lebenszyklus:

```bash
skillctl login                                     # device-pair against ER1 (browser)
skillctl publish my-skill --bundle my-skill.skb    # admit the bundle to your `self` registry
skillctl publish --attest my-skill --level green --rationale "reviewed"   # governance attestation
skillctl pull                                      # run the 5-gate gauntlet; stage verified bundles
skillctl registry ls                               # list admitted bundles
skillctl publish --revoke my-skill --digest sha256:… --reason "superseded"   # revoke on demand
skillctl audit  <name>                             # inspect a skill's trust timeline
```

Widerruf ist **signiert und offline prüfbar**. Frischeverträge nach dem Fail-closed-Prinzip
weisen veraltete oder zurückgerollte Widerrufslisten ab, statt ihnen still zu vertrauen.

---

## 8. Claude-Code-Trust-Gate einbinden (optional)

`skillctl` kann jeden Skill-Aufruf in Claude Code **fail-closed** prüfen:

```bash
# As a PreToolUse(Skill) hook: reads the hook event on stdin, verifies the chain,
# and emits allow/deny. Wire it in settings, don't run it by hand:
skillctl verify-hook

skillctl gate-stats --since 168h        # decisions, top blocks, cache-hit rate
```

Das Gate verweigert danach einen verwalteten Skill, der die Vertrauenskette nicht besteht oder widerrufen ist. Skills, die `skillctl` nicht verwaltet, etwa Plugin-Skills und eine von Hand abgelegte `SKILL.md`, lässt es standardmäßig weiter zu. Um auch diese zu verweigern, setzen Sie `unmanaged_skills: deny` in `~/.claude/skillctl/gate-policy.yaml`.

---

## Zusätzlich: einem Agenten eine prüfbare Identität geben

```bash
skillctl agentid issue --owner <you> --owner-key mykey.priv \
                       --for-agent <agent-id> --skills my-skill --intents summarize
skillctl agentid show agentid.json          # owner, grant, expiry, fingerprints
```

Eine **AgentID** ist ein vom Eigentümer signiertes Mandat: *Dieser Agent darf diese Skills
für diese Absichten einsetzen*. Sie ist offline prüfbar, ohne Autorität im Prüfpfad.

---

## Nächste Schritte

- **Jedes Kommando, Flag und jeder Exit-Code:** [skillctl-Handbuch](../referenz/manual-skillctl.de.md)
- **Selbst bauen und Tests ausführen:** die Einzeiler zum [Quellcode-Selbsttest](quickstart-skillctl.md#1b-optional-prove-it-on-your-own-machine-source-self-test) oben.
- **CI auf dem eigenen Rechner ausführen:** das [Enterprise-Gate](quickstart-skillctl.md#1c-stage-2-run-our-ci-on-your-own-machine-enterprise-gate) mit Vertrauensbericht.
- **Bedienfähigkeit statt nur Build nachweisen:** der [Test Ride](quickstart-skillctl.md#1d-the-human-half-the-test-ride).
- **Erinnerungen erfassen, mit denen Ihre Agenten arbeiten:** [Schnellstart: m3c-tools](quickstart-m3c-tools.de.md)
- **Das vollständige Lebenszyklus- und Governance-Modell** zeigt `skillctl help`, nach
  Fähigkeiten gruppiert: Signieren, Trust Roots, Installation, Agentenidentität,
  Registry, Transparenzlog, Sitzungen und PLM-Projektkontext.
