---
layout: default
title: "Tutorial, Szenario 02: der erste signierte Skill, mit Prüfung durch einen Zweiten"
---

# Tutorial, Szenario 02: der erste signierte Skill

**Für wen:** Sie haben mit Claude Code lokal einen Skill gebaut und wollen ihn erstmals
signieren und veröffentlichen. Ihr Vorgesetzter oder eine Kollegin prüft ihn vorher.
In diesem Text heißen die drei Rollen **Mitarbeiter** (Autor), **Eric** (Reviewer und
Herausgeber) und **Konsument** (jemand, der den Skill danach installiert).

**Was Sie am Ende haben:** einen signierten Skill mit einer Attestierung, die **eine andere
Person** unterschrieben hat, und einen Konsumenten, der ihn installieren kann, weil die
Prüfung stattgefunden hat, nicht weil ihm jemand gesagt hat, sie habe stattgefunden.

**Dauer:** Teil 1 (Trockenlauf, offline, ohne Server) etwa 15 Minuten. Teil 2 (der echte
Vorgang) etwa eine Stunde beim ersten Mal, danach Minuten.

**Verwandte Dokumente:** [Szenario 01](tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md)
(eine Person, mehrere Maschinen), [Runbook Zwei-Personen-Austausch](runbook-two-person-er1-exchange.md)
(derselbe Vorgang als Abnahmeprozedur), [Manual](manual-skillctl.md).

---

## Die Regel, aus der alles Weitere folgt

**Niemand darf seinen eigenen Skill freigeben.** Der Autor versiegelt, ein Zweiter
bescheinigt. Deshalb hat der Vorgang zwei Schlüssel in zwei Händen und nicht einen in einer.
Alles Umständliche an diesem Tutorial kommt aus dieser einen Regel, und sie ist der Grund,
warum das Ergebnis etwas wert ist.

Zwei Begriffe, die man nicht verwechseln darf:

- **Autorenabsicht** (`--author-intent green`) ist ein Hinweis des Autors. Der Verifier
  **ignoriert** sie. Sie kostet nichts und beweist nichts.
- **Attestierung** (`skillctl publish --attest` über ER1, `skillctl attest` gegen ein
  HTTP-Registry) ist ein signiertes Urteil eines Prüfers über einen bestimmten Digest. Sie ist
  bindend. Fehlt sie, scheitert jede Installation mit Exit `13`.

---

## Teil 0: was VOR dem ersten Signieren erledigt sein muss

Sieben Punkte. Die ersten drei sind offensichtlich, die anderen vier sind der Grund, warum
der erste Versuch sonst an einer unverständlichen Fehlermeldung endet.

| # | Punkt | Prüfen mit | Wer |
|---|---|---|---|
| 1 | `skillctl` aus einem **signierten Release**, nicht aus einem Quellbaum-Build, und auf allen beteiligten Maschinen **dieselbe** Version | `skillctl version` zeigt `skillctl/vX.Y.Z`, nicht `dev` | alle |
| 2 | Ein eigenes Schlüsselpaar, privater Teil mit Modus `0600` | `skillctl keygen --out <pfad>` | Mitarbeiter, Eric |
| 3 | Eine Identitäts-ID der Form `id:<name>@<org>`, die in jede Signatur eingestempelt wird und später nicht folgenlos wechselt | Absprache | Mitarbeiter, Eric |
| 4 | Ein **Registry, in das geschrieben werden darf**: bei Git ein leeres Repository plus ein Project Access Token für den Herausgeber (kein Deploy Token), beim HTTP-Registry zusätzlich eine serverseitig registrierte Identität, sonst `19 identity_mismatch` | `skillctl registry ls --registry <locator>` antwortet | Registry-Betreiber |
| 5 | Der Reviewer ist **nicht** der Autor und hat einen **eigenen** Schlüssel | Absprache, siehe die Regel oben | Eric |
| 6 | Beim Git-Weg: der Locator und die Token-Variablen sind gesetzt. Beim ER1-Weg: Anmeldung und eine serverseitig eingerichtete Raum-Mitgliedschaft (dafür gibt es **kein** `skillctl`-Verb) | `echo $REG`, `skillctl login --status` | alle |
| 7 | Jede Seite hat den Fingerprint der anderen über einen **zweiten Kanal** bestätigt | Telefon, Videocall, persönlich | Mitarbeiter, Eric, Konsument |

Zu Punkt 7, weil er der am leichtesten übersprungene ist: ein öffentlicher Schlüssel, der
zusammen mit dem Bundle ankommt, beweist nichts. Er kam über denselben ungeprüften Weg wie
das Bundle. Erst der vorherige, über einen zweiten Kanal bestätigte Pin macht den Satz „ich
muss dem Transportweg nicht vertrauen" wahr. Ein Pin ohne Kanalwechsel ist kein Pin.

Und ein Punkt, der **nicht** in der Liste steht: Ihr Skill muss nicht perfekt sein. Er muss
prüfbar sein.

---

## Teil 1: der Trockenlauf (offline, ohne Server, 15 Minuten)

Dieser Teil braucht kein Registry, keine Anmeldung, kein Netz. Er spielt die Mechanik einmal
durch, damit Sie im echten Vorgang wissen, wie eine Ablehnung aussieht. Alles passiert in
einem Arbeitsverzeichnis; Ihr echtes `~/.claude/` wird nicht angefasst.

### 1.1 Arbeitsverzeichnis und ein winziger Skill

```bash
export WS="$HOME/skillctl-uebung"
rm -rf "$WS" && mkdir -p "$WS"/{keys,src/hello-kup/scripts} && cd "$WS"

cat > src/hello-kup/SKILL.md <<'MD'
---
name: hello-kup
version: 0.1.0
description: Minimaler Uebungsskill fuer die Publisher-Kette, schreibt eine Datei nach ./out.
---

# hello-kup

Schreibt einen Gruss nach ./out/hello.txt. Kein Netzwerk, keine Secrets.
MD

cat > src/hello-kup/scripts/hello.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p ./out
echo "hello from hello-kup" > ./out/hello.txt
cat ./out/hello.txt
SH
chmod +x src/hello-kup/scripts/hello.sh
```

### 1.2 Zwei Schlüssel, zwei Rollen

```bash
skillctl keygen --out "$WS/keys/mitarbeiter"
skillctl keygen --out "$WS/keys/eric-reviewer"
ls -l "$WS/keys"
```

Erwartet: vier Dateien, die `.priv` mit Modus `-rw-------`. Ist ein `.priv` offener, verweigert
`sign` später den Dienst, absichtlich.

> Geben Sie absolute Pfade an. Bei einem relativen Pfad warnt `keygen` („relative path;
> resolving against CWD"), und Sie finden den Schlüssel später an einer anderen Stelle, als
> Sie denken.

### 1.3 Packen und signieren

```bash
skillctl pack \
  --skill ./src/hello-kup \
  -o hello-kup@0.1.0.skb \
  --name hello-kup \
  --version 0.1.0 \
  --summary "Uebungsskill" \
  --author-intent green \
  --author-intent-rationale "kein Netzwerk; schreibt nur ./out"

SIGN_OUT=$(skillctl sign \
  --key "$WS/keys/mitarbeiter.priv" \
  --identity-id id:mitarbeiter@kup \
  hello-kup@0.1.0.skb)
echo "$SIGN_OUT"

DIGEST="sha256:$(echo "$SIGN_OUT" | awk '/^digest:/ {print $2}')"
echo "DIGEST=$DIGEST"
```

> **Die Falle, die jeder einmal erlebt.** `pack` gibt `bundle_digest: sha256:…` aus, `sign`
> gibt `digest: …` aus, und **die beiden Werte sind verschieden**. Der Wert, den Sie ab jetzt
> überall brauchen (Signaturdateiname, das Argument von `attest`, `--digest` bei `publish`
> und `revoke`), ist **der von `sign`**. Der von `pack` ist der Manifest-Digest, nicht der
> Digest der Bundle-Bytes.

### 1.4 Der Autor prüft sich selbst

```bash
skillctl verify-sig --pubkey "$WS/keys/mitarbeiter.pub" hello-kup@0.1.0.skb
echo "rc=$?"
```

Erwartet: `OK: signature verified`, `rc=0`.

### 1.5 Die Reproduzierbarkeitsprobe

Zweimal packen muss byteidentisch sein. Ist es das nicht, enthält Ihr Skill etwas
Zeitabhängiges, und dann ist keine Signatur der Welt eine Aussage über den Inhalt.

```bash
skillctl pack --skill ./src/hello-kup -o probe.skb --name hello-kup --version 0.1.0 \
  --summary "Uebungsskill" --author-intent green \
  --author-intent-rationale "kein Netzwerk; schreibt nur ./out" >/dev/null
shasum -a 256 hello-kup@0.1.0.skb probe.skb
rm -f probe.skb
```

Erwartet: zweimal derselbe Hash.

### 1.6 Das Freigabe-Tor des Autors

Bevor Sie jemandem etwas vorlegen, lassen Sie die Selbstprüfung laufen. Sie braucht den Skill
an seinem normalen Ort:

```bash
mkdir -p "$WS/home/.claude/skills/hello-kup"
tar -xzf hello-kup@0.1.0.skb -C "$WS/home/.claude/skills/hello-kup"
HOME="$WS/home" skillctl propose hello-kup --dry-run --intent green
```

Ausgabe: eine Tabelle mit elf Prüfungen. In diesem Übungsskill schlägt `#9 smoke-test marker`
fehl, weil es kein `tests/smoke.sh` gibt. Das ist der beabsichtigte Anblick: das Tor sagt
Ihnen, was fehlt, bevor ein Mensch seine Zeit darauf verwendet.

> Zwei Dinge dazu. Mit `--dry-run` ist der Prozess-Exit **immer** `0`, lesen Sie die Tabelle,
> nicht den Exit-Code; ohne `--dry-run` bedeutet `2`, dass das Tor gehalten hat.
> Und `tar -xzf` ist hier nur ein Übungsgriff: ein von Hand entpackter Skill ist danach für
> `skillctl verify` unsichtbar (siehe Teil 3.3).

### 1.7 Die beiden Ablehnungen, die Sie kennen müssen

Zuerst der Unfall: jemand ändert das Bundle nach dem Signieren.

```bash
cp hello-kup@0.1.0.skb kaputt.skb
printf '\xff' | dd of=kaputt.skb bs=1 seek=200 count=1 conv=notrunc 2>/dev/null
skillctl verify-sig --pubkey "$WS/keys/mitarbeiter.pub" kaputt.skb
echo "rc=$?"
```

Erwartet: `signature file not found …`, `rc=1`. Die Begründung ist wörtlich zu nehmen: der
Name der Signaturdatei enthält den Digest, und zu diesen neuen Bytes existiert schlicht keine
Signatur.

Jetzt der Angriff: derselbe Byte-Tausch, aber der Angreifer benennt die Originalsignatur so
um, dass sie zu den neuen Bytes zu gehören scheint.

```bash
cp hello-kup@0.1.0.skb boese.skb
SIZE=$(wc -c < boese.skb | tr -d ' ')
printf '\xff' | dd of=boese.skb bs=1 seek=$((SIZE / 2)) count=1 conv=notrunc 2>/dev/null
BOESE_DIGEST=$(shasum -a 256 boese.skb | awk '{print $1}')
cp "hello-kup@0.1.0.skb.${DIGEST#sha256:}.author.sig" "boese.skb.${BOESE_DIGEST}.author.sig"

skillctl verify-sig --pubkey "$WS/keys/mitarbeiter.pub" boese.skb
echo "rc=$?"
```

Erwartet: `signature is invalid …`, `rc=11`. Das ist der Fall, für den die Kryptografie da
ist: eine Signatur, die behauptet, zu diesen Bytes zu gehören, und es nicht tut.

**Der Unterschied ist wichtig.** `1` heißt „zu diesen Bytes gibt es keine Signatur", `11`
heißt „die vorgelegte Signatur ist falsch". Beide sind korrekte Verweigerungen, sie begründen
nur Verschiedenes. Wer für einen Nachweis nur `verify-sig` gegen ein verändertes Bundle
laufen lässt, bekommt in der Regel `1` und dokumentiert damit etwas anderes, als er glaubt.

### 1.9 Kür: die ganze Kette offline, mit echtem Registry

Der Trockenlauf oben endet bei der Signatur. Wenn Sie zehn Minuten mehr haben, bauen Sie das
komplette Registry auf der Platte: **derselbe Code-Pfad wie GitLab**, nur ohne Remote. Damit
haben Sie den Produktivablauf einmal ganz gesehen, bevor Sie ihn gegen einen Server fahren.

```bash
cd "$WS"
skillctl keygen --out "$WS/keys/eric-herausgeber"
skillctl registry init --registry "local://$WS/registry.git"

# Eric nimmt das Bundle des Mitarbeiters auf:
skillctl publish hello-kup@0.1.0 --bundle hello-kup@0.1.0.skb --version 0.1.0 \
  --registry "local://$WS/registry.git" \
  --key "$WS/keys/eric-herausgeber.priv" --identity id:eric@kup --yes

# Eric attestiert, mit dem ANDEREN Schlüssel:
skillctl publish --attest hello-kup@0.1.0 --digest "$DIGEST" --level green \
  --rationale "geprueft im Trockenlauf" \
  --registry "local://$WS/registry.git" \
  --identity id:eric-reviewer@kup --key "$WS/keys/eric-reviewer.priv" --yes

skillctl registry ls --registry "local://$WS/registry.git"
```

Erwartet: eine Zeile `hello-kup  0.1.0  sha256:…  green  ok`.

Jetzt die Konsumentenseite, in einem eigenen Zuhause:

```bash
mkdir -p "$WS/kunde/.claude"
cat > "$WS/kunde/.claude/trust-roots.yaml" <<YAML
registry: local://$WS/registry.git
pubkey_b64: $(openssl pkey -pubin -in "$WS/keys/eric-herausgeber.pub" -outform DER | tail -c 32 | base64)
fingerprint: sha256:$(openssl pkey -pubin -in "$WS/keys/eric-herausgeber.pub" -outform DER | tail -c 32 | shasum -a 256 | awk '{print $1}')
governance_minimum: green
governance_quorum: 1
signers:
  - reviewer_id: id:eric-reviewer@kup
    pubkey_b64: $(openssl pkey -pubin -in "$WS/keys/eric-reviewer.pub" -outform DER | tail -c 32 | base64)
YAML

HOME="$WS/kunde" skillctl pull --registry "local://$WS/registry.git" --skill hello-kup \
  --install --trust-mode --dry-run-install --no-checkpoint
```

Erwartet: `✅ hello-kup@0.1.0 … gov=green` und ein Token mit fünf Minuten Gültigkeit.
Mit `--confirm-install --dry-run-install-token <TOK>` landet der Skill unter
`$WS/kunde/.claude/skills/hello-kup/`, mit `.m3c-provenance.json` und `.skillctl-attest.json`.

**Und jetzt die lehrreiche Variante.** Löschen Sie den `signers:`-Block aus der
`trust-roots.yaml` und wiederholen Sie den Pull:

```
❌ hello-kup@0.1.0  [gate 4: no attestation at or above the trust-roots governance_minimum]
```

Die Attestierung liegt im Repository, sie ist gültig, und sie zählt trotzdem nicht: der
Konsument hat diesen Reviewer nicht gepinnt. Das ist keine Panne, das ist die Aussage des
Systems. Vertrauen entsteht beim Empfänger, nicht beim Sender.

### 1.8 Aufräumen

```bash
cd ~ && rm -rf "$WS"
```

(Damit ist auch das Übungs-Registry weg. Es lag ausschliesslich unter `$WS`.)

Damit ist der Trockenlauf abgeschlossen. Sie haben eine Versiegelung erzeugt, sie geprüft,
und zwei Arten von Ablehnung mit echten Exit-Codes gesehen.

---

## Teil 2: der echte Vorgang (Produktion: das Git-Registry)

Drei Bahnen: Mitarbeiter, Eric, Konsument. **Produktiv ist das Registry ein Git-Repository.**
Die Kommandos unten benutzen `github://<owner>/<repo>`, weil das der Locator ist, der heute
belastbar läuft. Die interne GitLab-Instanz (`gitlab://<host>/<gruppe>/<projekt>`) ist
dieselbe Mechanik und derselbe Backend-Kern; sobald deren Sync steht, ändert sich genau zwei
Dinge: der `--registry`-Wert und der Name der Token-Variable. Der ER1-Weg steht in Anhang A
und ist der **Testpfad**.

Warum ein Git-Repository ein gutes Registry ist: das Layout ist lesbar und reviewbar, jede
Aufnahme und jedes Urteil ist ein Commit, und die Historie ist genau das Audit-Log, das
sonst gebaut werden müsste.

```
skills/<name>/<version>/bundle.skb     das versiegelte Bundle (sha256 == Digest)
skills/<name>/<version>/bundle.json    das entpackte Manifest, zum Nachlesen im Merge Request
events/<digesthex>/<seq>-<kind>.json   die signierten Ereignisse: admit, attest, revoke
```

Die Rollenteilung ist die, die auch organisatorisch gilt:

| Rolle | Wer | Was er tut | Sein Schlüssel |
|---|---|---|---|
| **Autor** | der Mitarbeiter | packt und versiegelt | eigener Autorenschlüssel |
| **Freigeber und Herausgeber** | Eric | prüft, nimmt auf, attestiert | Herausgeberschlüssel und Reviewer-Schlüssel |
| **Konsument** | Dritte | zieht und installiert | kein Schlüssel, nur ein Pin auf das Registry |

Der Mitarbeiter publiziert **nicht selbst**, und er braucht keinen Schreibzugriff auf das
Repository. Das ist keine Einschränkung, sondern der Punkt.

### Vorbereitung: das Registry und der Token

Das Repository legt ein Mensch an: leer, **privat** (es wird das Audit-Log), Default-Branch
geschützt. Schreibrecht auf den Default-Branch hat nur der Herausgeber.

```bash
# Schreibtoken, nur der Herausgeber braucht ihn (GitHub: PAT mit repo-Schreibrecht):
export M3C_GITHUB_TOKEN="<personal access token>"

# Optional, empfohlen: ein getrennter Lesetoken für Konsumenten,
# damit ein Pull nie den Schreibtoken überträgt.
export M3C_GITHUB_RO_TOKEN="<read token>"

export REG="github://<owner>/<repo>"
```

Auf macOS gehen beide auch in die Keychain, unter den Dienstnamen `m3c-skillctl-github` und
`m3c-skillctl-github-ro`; `skillctl` liest die Umgebungsvariable zuerst, dann die Keychain.

> **Für die interne GitLab-Instanz**, sobald deren Sync steht: `export
> REG="gitlab://<host>/<gruppe>/<projekt>"` und die Variablen heissen `M3C_GITLAB_TOKEN` /
> `M3C_GITLAB_RO_TOKEN` (Keychain: `m3c-skillctl-gitlab[-ro]`). Dort braucht der Schreibpfad
> ein **Project Access Token** oder einen PAT, **kein Deploy Token**: GitLab kennt
> `write_repository` als Deploy-Token-Scope nicht. Eine selbstgehostete Instanz ohne TLS im
> LAN erreichen Sie mit `M3C_GIT_HTTP=1`. Alles andere in diesem Tutorial bleibt Wort für
> Wort gleich.

### Bahn 1: der Mitarbeiter (Autor)

```bash
# M1. Einmalig: Schlüssel. Der private Teil verlässt diese Maschine nie.
mkdir -p ~/.config/m3c/skill-keys
skillctl keygen --out ~/.config/m3c/skill-keys/mitarbeiter

# M2. Fingerprint und Rohschlüssel, für Punkt 7 aus Teil 0.
openssl pkey -pubin -in ~/.config/m3c/skill-keys/mitarbeiter.pub -outform DER \
  | tail -c 32 | base64
openssl pkey -pubin -in ~/.config/m3c/skill-keys/mitarbeiter.pub -outform DER \
  | tail -c 32 | shasum -a 256

# M3. Selbstprüfung, bevor Eric Zeit investiert.
skillctl propose <skill-name> --intent green
#   Exit 0: das Tor hält. Exit 2: es hat gegriffen, die FAIL-Zeilen abarbeiten.

# M4. Packen und signieren.
skillctl pack --skill ~/.claude/skills/<skill-name> \
  -o <skill-name>@<version>.skb \
  --name <skill-name> --version <version> \
  --summary "<ein Satz>" \
  --author-intent green --author-intent-rationale "<warum harmlos>"

SIGN_OUT=$(skillctl sign --key ~/.config/m3c/skill-keys/mitarbeiter.priv \
  --identity-id id:mitarbeiter@kup <skill-name>@<version>.skb)
DIGEST="sha256:$(echo "$SIGN_OUT" | awk '/^digest:/ {print $2}')"
echo "$DIGEST"

# M5. Selbst gegenprüfen.
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/mitarbeiter.pub \
  <skill-name>@<version>.skb        # -> 0
```

**Was Sie Eric übergeben, und auf welchem Weg:**

| Was | Weg | Warum |
|---|---|---|
| `<skill-name>@<version>.skb` **und** die `.author.sig` daneben | beliebig (Mail, Freigabe, Ticket, Merge Request) | der Transportweg muss nicht vertrauenswürdig sein, beide Dateien werden gebraucht |
| Der Digest aus M4 | derselbe Weg, aber **zusätzlich vorgelesen** | Eric muss prüfen, worüber er urteilt |
| Ihr Fingerprint aus M2 | **anderer Kanal**, einmalig | siehe Teil 0, Punkt 7 |
| Was der Skill tut, welche Daten er anfasst, was er ins Netz schickt | Text, Ticket, Merge Request | das ist der Gegenstand der Prüfung, nicht die Signatur |

### Bahn 2: Eric (Freigeber und Herausgeber)

```bash
# E1. Einmalig: zwei Schlüssel mit zwei Aufgaben.
skillctl keygen --out ~/.config/m3c/skill-keys/eric-herausgeber
skillctl keygen --out ~/.config/m3c/skill-keys/eric-reviewer

# E2. Die Autorensignatur des Mitarbeiters prüfen. Vorher muss der Fingerprint
#     aus M2 über den zweiten Kanal bestätigt sein.
skillctl verify-sig --pubkey ./mitarbeiter.pub <skill-name>@<version>.skb
echo "rc=$?"        # 0, sonst hier abbrechen und nichts aufnehmen

# E3. Über denselben Digest urteilen, den der Mitarbeiter genannt hat.
shasum -a 256 <skill-name>@<version>.skb
```

**E4, die eigentliche Prüfung.** Nicht automatisierbar, und der Punkt der Übung:

```bash
mkdir -p /tmp/review-<skill-name>
tar -xzf <skill-name>@<version>.skb -C /tmp/review-<skill-name>
ls -R /tmp/review-<skill-name>
cat /tmp/review-<skill-name>/SKILL.md
```

Worauf zu achten ist: Was liest der Skill, was schreibt er, wohin schickt er etwas? Steht in
`SKILL.md` etwas anderes, als die Skripte tun? Enthält das Bundle Zugangsdaten, Tokens,
Kundendaten? Passen die deklarierten Abhängigkeiten zu dem, was aufgerufen wird? Und die
Frage, die keine Signatur beantwortet: **wollen wir, dass dieser Skill im Unternehmen läuft?**

**E5. Aufnehmen (Admit).** Erst jetzt, und nur wenn E2 und E4 sauber waren:

```bash
skillctl publish <skill-name>@<version> \
  --bundle <skill-name>@<version>.skb \
  --version <version> \
  --registry "$REG" \
  --key ~/.config/m3c/skill-keys/eric-herausgeber.priv \
  --identity id:eric@kup \
  --yes
```

Erwartete Ausgabe: `==> admitted: <name>/v<version>  transport=git  registry=<REG>`. Im
Repository stehen danach ein Commit mit dem Bundle und einer unter `events/<digesthex>/`.

**E6. Attestieren, mit dem Reviewer-Schlüssel:**

```bash
skillctl publish --attest <skill-name>@<version> \
  --digest "$DIGEST" \
  --level green \
  --rationale "geprüft am <datum>; Autorensignatur id:mitarbeiter@kup verifiziert; kein Netzwerkzugriff; schreibt nur unter ./out" \
  --registry "$REG" \
  --identity id:eric-reviewer@kup \
  --key ~/.config/m3c/skill-keys/eric-reviewer.priv \
  --yes
```

**E7. Kontrollieren, was im Registry steht:**

```bash
skillctl registry ls --registry "$REG"
skillctl registry show <skill-name> --registry "$REG"
```

`registry ls` muss den Skill mit `gov=green` und `status=ok` zeigen. Steht dort `gov=` leer
oder `status` anders, fehlt die Attestierung, und kein Konsument wird installieren können.

Die drei Stufen bedeuten: **green** freigegeben, **yellow** mit Auflagen, **red** abgelehnt.
Ein `red` ist kein Scheitern des Vorgangs, es ist sein Funktionieren.

### Bahn 3: der Konsument

Der Konsument pinnt **das Registry**, und zwar von Hand, in `~/.claude/trust-roots.yaml`:

```yaml
registry: github://<owner>/<repo>
pubkey_b64: <Erics Herausgeberschlüssel, roh, base64>
fingerprint: sha256:<über den zweiten Kanal bestätigt>
governance_minimum: green
governance_quorum: 1
signers:
  - reviewer_id: id:eric-reviewer@kup
    pubkey_b64: <Erics Reviewer-Schlüssel, roh, base64>
```

> **Warum von Hand und nicht mit `skillctl peer add`.** `peer add` erzwingt den
> Out-of-Band-Pin (es verweigert, wenn `--pin` nicht zum `--pubkey` passt) und wäre die
> schönere Form. Es kann heute aber **keinen Reviewer-Schlüssel ausdrücken**: ein gepinnter
> Peer trägt genau einen Schlüssel, und der Pull weist die Attestierung dann mit
> `gate 4: no attestation at or above the trust-roots governance_minimum` ab, obwohl sie im
> Repository liegt (nachgemessen, Prozess-Exit `1`). Solange das so ist, ist die
> handgeschriebene Datei der Weg, und der Fingerprint-Vergleich ist Ihre Aufgabe, nicht die
> des Werkzeugs. Wer Herausgeber und Reviewer bewusst mit **einem** Schlüssel fährt, kann
> `peer add` benutzen und `signers` weglassen.

```bash
# K1. Nur Lesetoken setzen. Ein Konsument braucht keinen Schreibzugriff.
export M3C_GITHUB_RO_TOKEN="<read token>"
export REG="github://<owner>/<repo>"

# K2. Plan ansehen (G-23, Schritt 1).
skillctl pull --registry "$REG" --skill <skill-name> \
  --install --trust-mode --dry-run-install --no-checkpoint
#   -> "✅ <name>@<version> … gov=green" und
#      "dry-run-install token (5-minute TTL): <TOK>"

# K3. Bestätigen (G-23, Schritt 2). Kein --key, kein --emit-installed.
skillctl pull --registry "$REG" --skill <skill-name> \
  --install --trust-mode \
  --confirm-install --dry-run-install-token <TOK> --no-checkpoint
```

Installiert wird unter `~/.claude/skills/<name>/`, mit `.m3c-provenance.json` und
`.skillctl-attest.json` daneben: die signierten Ereignisse werden mitgelegt, damit das
Laufzeit-Tor später auch offline gegen den gepinnten Schlüssel nachrechnen kann.

Dabei laufen fünf Tore: Envelope-Signatur, nicht widerrufen, Governance-Schwelle, Digest,
Bundle-Signaturen. Was eine Ablehnung bedeutet:

| Zeile bzw. Code | Bedeutung | Wer ist am Zug |
|---|---|---|
| `✅ … gov=green` | alle Tore bestanden | n/a |
| `gate 1: envelope` | Ereignis nicht vom gepinnten Schlüssel signiert | falscher Pin, oder das Repository ist nicht das, für das Sie es halten |
| `gate 4: no attestation …` | keine gültige Attestierung ≥ Schwelle | E6 fehlt, oder der Reviewer-Schlüssel steht nicht unter `signers:` |
| `gate 5: revoked` | widerrufen | nicht installieren |
| `gate 2/3: digest` bzw. `bundle sigs` | Bytes oder Signatur passen nicht | Bundle neu beziehen, nicht weitermachen |

**Achtung beim Skripten:** ein Pull, der alle Bundles verwirft, endet mit Prozess-Exit `1`
und der Zeile `NOT installing: N bundle(s) were skipped`. Ein Pull, der **nichts** zu tun
findet, endet mit `0`. Prüfen Sie in Automatisierungen die `✅`-Zeilen, nicht nur den Code.

### Der Weg ohne Netz: erst lokal, dann hochschieben

Sie können das gesamte Registry offline aufbauen und später nach GitLab spiegeln. Der
Code-Pfad ist derselbe, nur der Locator ändert sich:

```bash
skillctl registry init --registry local://$HOME/skill-registry.git
skillctl publish <name>@<ver> --bundle <name>@<ver>.skb --version <ver> \
  --registry local://$HOME/skill-registry.git --key <herausgeber.priv> --identity id:eric@kup --yes
# ... admit + attest wie oben ...

git -C "$HOME/skill-registry.git" push --mirror https://github.com/<owner>/<repo>.git
```

Für eine Übergabe ohne jeden Server gibt es zusätzlich
`skillctl registry export --registry local://<pfad> --out <datei.bundle>`: eine einzige
Datei, aus der ein Empfänger mit `pull --registry local://<datei.bundle>` zieht, mit
demselben Torlauf.

### Was der Konsument dabei prüft, und was nicht

Sagen Sie es genau, sonst verspricht die Kette mehr, als sie hält:

- **Geprüft:** dass Eric dieses Bundle aufgenommen hat (Herausgebersignatur über den Digest),
  dass ein gepinnter Reviewer-Schlüssel grün attestiert hat, dass die Bytes unverändert sind,
  dass zu diesem Digest kein Widerruf im Repository liegt.
- **Nicht geprüft:** die Autorensignatur des **Mitarbeiters**. Der Herausgeber signiert beide
  Rollen (Autor und Registry) mit seinem Schlüssel, und die losgelöste `.author.sig` des
  Mitarbeiters reist nicht mit ins Repository. Die Urheberangabe steht im Bundle und ist
  durch Erics Signatur gegen Veränderung geschützt, aber **wer den Skill wirklich geschrieben
  hat, hat Eric in E2 geprüft, nicht der Konsument.**

Genau deshalb ist E2 kein Formalismus. Der Konsument vertraut Eric; Eric vertraut niemandem,
sondern rechnet nach.

### Nach der Installation, heute noch eine Baustelle

Zwei Dinge, die Sie wissen müssen, bevor Sie den Betrieb darauf aufsetzen:

- `skillctl verify <name>` prüft einen aus dem Git-Registry installierten Skill jetzt selbst:
  es bindet den Inhalt auf der Platte an das signierte Bundle und rechnet die Attestierung
  gegen den gepinnten Schlüssel nach. Erwartet ist `0` plus eine Zeile, die nennt, worauf der
  Skill verankert ist. Eine nachträglich veränderte Datei ergibt `10`. Zwei Dinge dazu: der
  Pfad braucht die Beilagen aus dem verwalteten Install (ein von Hand entpackter Skill bleibt
  stumm, siehe 3.3), und er verlangt, dass Sie den Herausgeber gepinnt haben, in der
  `trust-roots.yaml` oder über `peer add`.
- `skillctl verify --all` fällt unter verwalteten Trust-Roots ohne erreichbare
  Revocation-Quelle **fail-closed** und würde installierte Skills quarantänisieren. Bevor der
  Sweep in den Alltag geht, muss der Widerrufskanal stehen; bis dahin ohne `--quarantine`
  laufen lassen und die Ausgabe lesen.

## Teil 3: drei Dinge, die dieses Tutorial nicht verschweigt

### 3.1 Eine Signatur ist keine Unbedenklichkeitsbescheinigung

Sie sagt: „diese Bytes hat dieser Schlüssel versiegelt". Sie sagt nicht, dass der Inhalt
harmlos ist. Ein perfekt signierter Skill kann Daten abziehen. Genau deshalb steht in Bahn 2
ein Mensch mit einer Attestierung, und deshalb ist E5 der Teil, den man nicht abkürzen darf.

### 3.2 Der Weg „signiertes .skb per Mail" ist ein Notweg

Die vollständige Kette prüft mehr als die Autorensignatur: Registry-Signatur, Bundle-Status,
Governance-Level, Tenant-Scope. Offline und ohne Registry können Sie davon nur die
Autorensignatur prüfen. Der dafür vorgesehene portable Weg (`skillctl verify --bundle` mit
einer `BundleMeta`-Hülle, oder ein `export-verification-kit`) setzt voraus, dass das Bundle
einmal durch ein Registry gelaufen ist: die Hülle `<name>.skbmeta.json` entsteht beim Admit.
Ein frisch gepacktes, sauber signiertes Bundle lässt sich heute nicht in ein solches Kit
verwandeln.

### 3.3 Von Hand entpackte Skills sind stumm

`tar -xzf` funktioniert, aber danach antwortet `skillctl verify <name>` mit „no .skb found …
(was this skill installed by skillctl install?)", und `verify --offline <name>` findet keine
hinterlegten Metadaten. Damit fällt der Skill aus dem Sweep `verify --all` und aus dem Gate
heraus. Für die Prüfung in E5 ist Entpacken richtig, für eine Installation nicht.

---

## Teil 4: die Abnahme

Der Vorgang gilt als bestanden, wenn diese vier Punkte belegt sind, jeder mit einer Ausgabe,
nicht mit einer Einschätzung:

| # | Kriterium | Beleg |
|---|---|---|
| 1 | Der Mitarbeiter hat authentisch versiegelt | M5 und E2 `verify-sig` rc=0, und der Digest aus M4 ist derselbe, über den Eric in E6 geurteilt hat |
| 2 | Ein Zweiter hat geprüft | E2 rc=0 (Eric hat die Autorensignatur selbst verifiziert), E6 angenommen mit einer `--identity` ungleich der aus M4, und E7 zeigt `gov=green status=ok` |
| 3 | Ein Dritter kann installieren | K2 zeigt `✅ … gov=green`, K3 installiert mit Provenienz-Datei |
| 4 | Ein manipuliertes Bundle wird abgelehnt | Trockenlauf 1.7, rc=11 mit umbenannter Signatur |

Die Evidenz in eine Datei, die man in sechs Monaten noch lesen kann:

```bash
{
  echo "Datum:      $(date -u +%FT%TZ)"
  echo "Host:       $(hostname)"
  skillctl version
  echo "Autor:      id:mitarbeiter@kup"
  echo "Registry:   $REG"
  echo "Herausgeber: id:eric@kup"
  echo "Reviewer:   id:eric-reviewer@kup"
  echo "Digest:     $DIGEST"
  echo "Fingerprint bestätigt über: <Telefon / Videocall / persönlich>, am <datum>"
  skillctl trust list
} | tee ~/szenario-02-evidenz.txt
```

Der Fingerprint-Kanal gehört ins Protokoll. Ein Pin, bei dem nicht steht, **wie** er bestätigt
wurde, ist kein Pin, sondern Vertrauen beim ersten Anblick mit besserer Presse.

---

## Anhang A: derselbe Vorgang über ER1 `self` (der Testpfad)

ER1 `self` ist der Weg zum **Testen** und für Einzelnutzer ohne Git-Registry. Die Rollen, die
Prüfung und die Trust-Roots-Datei bleiben identisch; es ändern sich nur drei Kommandos und
die Adressierung des Registry.

```bash
# Einmalig auf jeder beteiligten Maschine:
skillctl login --base-url https://onboarding.guide
skillctl login --status

# E5 (Admit) und E6 (Attest) laufen gegen den eigenen ER1-Kontext:
skillctl publish <skill-name>@<version> --bundle <skill-name>@<version>.skb \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-keys/eric-herausgeber.priv --identity id:eric@kup --yes

skillctl publish --attest <skill-name>@<version> --digest "$DIGEST" --level green \
  --rationale "geprüft am <datum>" \
  --registry self --er1-target prod --er1-context skills \
  --identity id:eric-reviewer@kup --key ~/.config/m3c/skill-keys/eric-reviewer.priv --yes

# Sichtbar machen, damit der Konsument es findet:
skillctl room share <skill-name> --room <raum-label> --yes

# K2/K3 beim Konsumenten, aus ERICS Kontext:
skillctl pull --registry self --er1-target prod --er1-context <eric-sub>___skills \
  --skill <skill-name> --install --trust-mode --dry-run-install --no-checkpoint
```

In der `trust-roots.yaml` steht dann `registry: self` statt des Git-Locators; der
`signers:`-Block bleibt unverändert nötig, wenn Herausgeber und Reviewer verschiedene
Schlüssel benutzen.

Drei Eigenheiten dieses Pfades, die auf Git nicht existieren: `publish` schreibt **immer** in
den eigenen Kontext (ein Publish in einen fremden endet mit `403`), die Raum-Mitgliedschaft
wird serverseitig in der Konsole eingerichtet (es gibt kein `skillctl`-Verb dafür), und der
Kontextname des Herausgebers muss dem Konsumenten exakt bekannt sein. Der ausführliche
Zwei-Personen-Ablauf steht im
[Runbook Zwei-Personen-Austausch](runbook-two-person-er1-exchange.md).

## Anhang B: das HTTP-Registry `/api/skills`, und warum es hier nicht der Hauptweg ist

Neben dem ER1-`self`-Registry (Memory-Layer, `publish` / `pull`) hat aims-core ein zweites
Registry-Gesicht: das Modul `skill_registry` unter `<base>/api/skills`. Das ist **kein
zweiter Server**, es ist eine zweite API auf demselben Dienst, und sie läuft in Produktion:
`GET https://onboarding.guide/api/skills/health` antwortet mit
`{"module":"skill_registry","status":"healthy"}`. Für dieses Gesicht gelten die Kommandos
`skillctl trust add`, `install`, `attest` und die Datei `~/.claude/skill-trust-roots.yaml`.

Trotzdem steht in Teil 2 der ER1-Weg, und zwar aus einem messbaren Grund: **`skillctl` kann
sich an `/api/skills` heute nicht anmelden.** Die Produktivinstanz antwortet auf
`/api/skills/bundles`, `/identities` und `/attestations` mit `401 AUTH_REQUIRED`, während der
Registry-Client (`pkg/skillctl/registry/client.go`) und `skillctl attest`
(`cmd/skillctl/attest_cmds.go`) ausschließlich `Content-Type`, `Accept` und `User-Agent`
senden. Es gibt keinen Header und keine Umgebungsvariable für ein Token. Der Weg funktioniert
deshalb heute nur gegen eine Instanz, die diese Endpunkte ohne Client-Auth bedient, etwa die
lokale Docker-Instanz aus `demo/kup-training/`.

Wo dieser Weg läuft, ist er die sauberere Form von Teil 2, weil der Reviewer dort **selbst**
postet und der Umweg über Eric als Herausgeber entfällt:

```bash
# Reviewer, gegen eine Instanz, die den Endpunkt ohne Client-Auth bedient:
skillctl attest "$DIGEST" --level green \
  --rationale "geprüft am <datum>" \
  --reviewer-id id:eric@kup --author-id id:mitarbeiter@kup \
  --key ~/.config/m3c/skill-keys/eric-reviewer.priv \
  --registry https://<host>/api/skills

# Konsument:
skillctl trust add --registry https://<host>/api/skills --pubkey ./registry.pub
skillctl install <skill-name>@<version>
```

`--author-id` ist dabei nicht Kosmetik: damit greift die Prüfung „Reviewer ist nicht Autor"
auch dann, wenn der Admit-Datensatz gerade nicht erreichbar ist. Antwortet das Registry mit
`19 identity_mismatch`, ist Punkt 4 aus Teil 0 offen: die Reviewer-Identität ist dort noch
nicht registriert (`POST /api/skills/identities`, Vorlage
`demo/kup-training/register-identity.sh`).

## Anhang C: Windows

- Pfade: `%USERPROFILE%\.claude\skill-trust-roots.yaml` statt `~/.claude/…`.
- Ein ausgelieferter Windows-Build ignoriert `$HOME` für sicherheitsrelevante Pfade
  absichtlich und liest `%USERPROFILE%`. Der Sandkasten aus Teil 1 muss dort über
  `$env:USERPROFILE` gebaut werden.
- Statt `shasum -a 256` nehmen Sie `Get-FileHash -Algorithm SHA256`.
- Installation über die PowerShell-Einzeile aus [Quickstart §1](quickstart-skillctl.md#1-install).

---

## Wie es weitergeht

- Eigene Skills auf mehreren Maschinen: [Szenario 01](tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md)
- Üben, bis es sitzt: [Katas und Test Ride](tutorial-katas-und-test-ride.de.md)
- Jedes Kommando, jedes Flag, jeder Exit-Code: [Manual](manual-skillctl.md)
