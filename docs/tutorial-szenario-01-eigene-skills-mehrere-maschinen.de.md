---
layout: default
title: "Tutorial, Szenario 01: eigene Skills auf mehreren Maschinen"
---

# Tutorial, Szenario 01: eigene Skills auf mehreren Maschinen

**Für wen:** Sie nutzen Ihre eigenen Skills auf mehr als einem Rechner (Laptop, Desktop,
Windows-Maschine) und wollen zusätzlich fremde, bereits signierte Skills einsetzen.
Sie sind der einzige Autor Ihrer eigenen Skills.

**Was Sie am Ende haben:** einen Signierschlüssel, der genau eine Maschine nie verlässt,
Ihre eigenen Skills auf allen anderen Maschinen **verwaltet installiert** (also dauerhaft
nachprüfbar), einen fremden Schlüssel korrekt gepinnt, und ein Gate, das einen manipulierten
Skill blockiert, bevor der Agent ihn lädt.

**Dauer:** etwa 45 Minuten für den ersten Durchlauf, danach Minuten pro Skill.

**Verwandte Dokumente:** [Quickstart skillctl](quickstart-skillctl.md) (Installation und
Grundbegriffe), [Manual](manual-skillctl.md) (jedes Kommando, jedes Flag),
[Szenario 02](tutorial-szenario-02-erster-signierter-skill.de.md) (zwei Personen, eine
Freigabe).

---

## Das Modell in vier Sätzen

Ein Skill ist vertrauenswürdig, weil er **signiert** ist, nicht weil er von einem bestimmten
Server kam. Deshalb ist es auch zweitrangig, ob Ihr Registry ein Git-Repository oder ein ER1-
Kontext ist: produktiv nehmen wir **Git** (intern GitLab, beim Kunden dessen eigene Instanz),
ER1 ist der Testpfad, und die Kommandos unterscheiden sich nur im `--registry`-Wert. Das Registry ist Transport und Audit-Fläche, es steht **nicht** im
kryptografischen Prüfpfad. Sie vertrauen genau den öffentlichen Schlüsseln, die Sie selbst
gepinnt haben. Und eine gültige Signatur sagt „das hat dieser Schlüssel versiegelt", sie sagt
niemals „das ist ungefährlich".

---

## Teil 0: die Entscheidung vor dem ersten Kommando

**Legen Sie eine Signierstation fest.** Genau eine Maschine hält Ihren privaten Schlüssel.
Alle anderen Maschinen sind reine Konsumenten. Der Grund ist unromantisch: jede weitere Kopie
eines `.priv` vervielfacht die Angriffsfläche, und der Dateimodus `0600`, auf den `skillctl
sign` fail-closed besteht, überlebt weder Git noch die meisten Sync-Dienste. Ein Schlüssel,
der über einen Sync-Ordner reist, kommt irgendwann als `0644` an, und dann verweigert `sign`
den Dienst, zu Recht.

Prüfen Sie zuerst, dass überall dasselbe, echte Release läuft:

```bash
skillctl version        # muss skillctl/vX.Y.Z zeigen, nicht "dev"
```

Zeigt das `dev`, haben Sie einen Build aus dem Quellbaum vor sich und keinen signierten
Release. Installation: siehe [Quickstart §1](quickstart-skillctl.md#1-install).

---

## Teil A: die Signierstation einrichten (einmalig)

### A1. Schlüsselpaar erzeugen

```bash
mkdir -p ~/.config/m3c/skill-keys
skillctl keygen --out ~/.config/m3c/skill-keys/eric
```

Erwartete Ausgabe:

```
wrote ~/.config/m3c/skill-keys/eric.priv (mode 0600)
wrote ~/.config/m3c/skill-keys/eric.pub  (mode 0644)
```

`eric.priv` bleibt auf dieser Maschine. `eric.pub` darf überall hin.

### A2. Den eigenen Fingerprint festhalten

Sie brauchen ihn auf jeder weiteren Maschine, und Sie brauchen ihn in einer Form, die Sie
vorlesen können:

```bash
openssl pkey -pubin -in ~/.config/m3c/skill-keys/eric.pub -outform DER | tail -c 32 | base64
openssl pkey -pubin -in ~/.config/m3c/skill-keys/eric.pub -outform DER | tail -c 32 | shasum -a 256
```

Die erste Zeile ist der rohe Schlüssel in Base64 (der Wert `pubkey_b64`), die zweite der
Fingerprint. Notieren Sie beide.

### A3. Einen Skill packen und signieren

Nehmen wir einen Skill, den Sie lokal gebaut haben, unter `~/.claude/skills/mein-skill`.
Er braucht mindestens eine `SKILL.md`.

```bash
cd ~/skills-workbench                       # ein Arbeitsverzeichnis, egal welches

skillctl pack \
  --skill ~/.claude/skills/mein-skill \
  -o mein-skill@1.0.0.skb \
  --name mein-skill \
  --version 1.0.0 \
  --summary "was der Skill tut" \
  --author-intent green \
  --author-intent-rationale "kein Netzwerk; schreibt nur ./out"

SIGN_OUT=$(skillctl sign \
  --key ~/.config/m3c/skill-keys/eric.priv \
  --identity-id id:eric@kup \
  mein-skill@1.0.0.skb)
echo "$SIGN_OUT"

DIGEST="sha256:$(echo "$SIGN_OUT" | awk '/^digest:/ {print $2}')"
echo "$DIGEST"
```

> **Falle, die Sie einmal erleben und nie vergessen.** `pack` gibt eine Zeile
> `bundle_digest: sha256:…` aus, `sign` gibt eine Zeile `digest: …` aus, und **das sind zwei
> verschiedene Werte**. Der Digest, den Sie ab jetzt brauchen (Signaturdateiname,
> `--digest` bei `publish` und `revoke`, das Argument von `attest`), ist **der von `sign`**.
> Der von `pack` ist der Manifest-Digest.

Die Variable `$DIGEST` oben hält genau diesen Wert fest, und `sign` ist idempotent: ein
zweiter Lauf über dieselben Bytes schreibt dieselbe Signatur, Sie können den Block also
gefahrlos wiederholen.

### A4. Sofort selbst gegenprüfen

```bash
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/eric.pub mein-skill@1.0.0.skb
echo "rc=$?"          # 0 = OK: signature verified
```

Exit `0` heißt: diese Bytes wurden von diesem Schlüssel versiegelt. Exit `11` heißt: die
Signatur passt nicht zu den Bytes. Exit `10` heißt: die Datei hasht jetzt anders, als die
Signatur daneben deckt, sie wurde also nach dem Signieren verändert; die Meldung nennt beide
Digests, damit Sie den Unterschied sehen. Exit `1` heißt: es liegt überhaupt keine Signatur
neben der Datei, sie wurde hier vermutlich nie signiert.

### A5. Publizieren und attestieren

Ab hier brauchen Sie eine ER1-Anmeldung. Der Skill wandert in Ihr persönliches
`self`-Registry, aus dem Ihre anderen Maschinen ziehen.

```bash
skillctl login --base-url https://onboarding.guide
skillctl login --status

skillctl publish mein-skill@1.0.0 \
  --bundle mein-skill@1.0.0.skb \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-keys/eric.priv \
  --identity id:eric@kup \
  --yes
```

Jetzt der Schritt, den fast jeder beim ersten Mal auslässt und dann eine Stunde sucht:
**ohne eine grüne Attestierung schlägt Ihr eigener Pull auf der zweiten Maschine mit
Exit `13` (`governance_below_min`) fehl.** Die Governance-Schwelle ist Teil der Kette, und
`--author-intent green` aus A3 ist ausdrücklich **nur ein Hinweis**, den der Verifier
ignoriert. Bindend ist eine signierte Attestierung.

Für eigene Skills auf eigenen Maschinen erzeugen Sie dafür einen zweiten Schlüssel, den
Reviewer-Schlüssel:

```bash
skillctl keygen --out ~/.config/m3c/skill-keys/eric-reviewer

skillctl publish --attest mein-skill@1.0.0 \
  --level green \
  --rationale "eigener Skill; kein Netzwerk; Datenpfade geprüft" \
  --registry self --er1-target prod --er1-context skills \
  --identity id:eric-reviewer@kup \
  --key ~/.config/m3c/skill-keys/eric-reviewer.priv \
  --yes
```

> **Was das ist und was es nicht ist.** Zwei Schlüssel einer Person sind eine
> **Schlüsseltrennung**, keine Gewaltenteilung. Für Ihre eigenen Skills auf Ihren eigenen
> Maschinen ist das angemessen: es gibt niemanden, den Sie täuschen könnten außer sich
> selbst. Sobald ein Skill an Dritte geht, ist es das nicht mehr, und dann gilt
> [Szenario 02](tutorial-szenario-02-erster-signierter-skill.de.md).

---

## Teil A6: Variante für den Produktivbetrieb, ein Git-Registry statt ER1

Alles aus A1 bis A4 bleibt unverändert. Es ändern sich nur die beiden Kommandos aus A5 und
später der Pull, und zwar ausschliesslich im `--registry`-Wert.

Einmalig: ein leeres, **privates** Repository anlegen (es wird das Audit-Log) und ein Token
mit Schreibrecht erzeugen.

```bash
export M3C_GITHUB_TOKEN="<personal access token>"
export REG="github://<owner>/<repo>"                # gitlab://<host>/<gruppe>/<projekt>, sobald der Sync steht

skillctl publish mein-skill@1.0.0 --bundle mein-skill@1.0.0.skb --version 1.0.0 \
  --registry "$REG" --key ~/.config/m3c/skill-keys/eric.priv --identity id:eric@kup --yes

skillctl publish --attest mein-skill@1.0.0 --digest "$DIGEST" --level green \
  --rationale "eigener Skill; kein Netzwerk; Datenpfade geprüft" \
  --registry "$REG" --identity id:eric-reviewer@kup \
  --key ~/.config/m3c/skill-keys/eric-reviewer.priv --yes

skillctl registry ls --registry "$REG"      # muss gov=green status=ok zeigen
```

Auf den Konsumentenmaschinen steht dann im `trust-roots.yaml` aus B2 statt `registry: self`
der Locator (`registry: gitlab://…`), und der Pull heisst
`skillctl pull --registry "$REG" --skill mein-skill --install --trust-mode …`, sonst identisch.
Dort genügt ein **Lesetoken** (`M3C_GITHUB_RO_TOKEN`, für GitLab `M3C_GITLAB_RO_TOKEN`), der
Schreibtoken bleibt auf der Signierstation.

Zwei Vorzüge gegenüber ER1, die den Aufwand rechtfertigen: das Repository ist lesbar
(`skills/<name>/<version>/bundle.json` liest sich im Browser, jedes Urteil ist ein Commit),
und die zweite Maschine braucht keine ER1-Anmeldung, nur einen Lesetoken.

Und ein Weg, der ganz ohne Server auskommt: `skillctl registry init --registry
local://$HOME/skill-registry.git` legt ein bares Repo auf der Platte an, in das Sie genauso
publizieren; `git -C ~/skill-registry.git push --mirror https://github.com/<owner>/<repo>.git` schiebt es
später hoch.

---

## Teil B: die zweite (und dritte) Maschine

Auf jeder weiteren Maschine, **ohne** privaten Schlüssel.

### B1. Anmelden

```bash
skillctl login --base-url https://onboarding.guide
skillctl login --status
```

### B2. Den eigenen Schlüssel pinnen

Für den ER1-`self`-Weg wird die Trust-Roots-Datei **von Hand** geschrieben. Das ist Absicht:
der Pin ist der Moment, in dem Sie Vertrauen aussprechen, und der soll nicht nebenbei
passieren.

```bash
cat > ~/.claude/trust-roots.yaml <<'YAML'
registry: self
pubkey_b64: <der Base64-Wert aus Schritt A2, Ihr Signierschlüssel>
fingerprint: sha256:<der Fingerprint aus Schritt A2>
governance_minimum: green
governance_quorum: 1
signers:
  - reviewer_id: id:eric-reviewer@kup
    pubkey_b64: <der Base64-Wert Ihres REVIEWER-Schlüssels aus A5>
YAML
```

Der Block `signers:` ist nicht optional, wenn Sie in A5 mit einem **zweiten** Schlüssel
attestiert haben: die Attestierung wird gegen die gepinnten Signer geprüft, und ohne diesen
Eintrag gilt implizit nur der Signierschlüssel als zulässiger Attestierer. Der Pull würde
sonst abbrechen, obwohl die Attestierung existiert. Wer beide Rollen mit demselben Schlüssel
fährt, lässt `governance_quorum` und `signers` weg.

Für ein Git-Registry geht dasselbe kürzer und sicherer, weil `peer add` den
Fingerprint-Abgleich erzwingt statt ihn Ihnen zu überlassen:

```bash
skillctl peer add meins "$REG" \
  --pubkey <Signierschlüssel-b64> --pin sha256:<Fingerprint> \
  --signer id:eric-reviewer@kup:<Reviewer-Schlüssel-b64> --quorum 1
```

> **Die zwei Dateien, die man verwechselt.** `~/.claude/trust-roots.yaml` (flach, von Hand)
> gilt für den ER1-`self`-Weg und wird von `pull` gelesen.
> `~/.claude/skill-trust-roots.yaml` gilt für HTTP-Registries, wird von
> `skillctl trust add --registry <URL> --pubkey <datei>` geschrieben und von `install`,
> `verify` und `audit` gelesen. Die falsche Datei zu füllen ist der häufigste
> Einrichtungsfehler und äußert sich als Exit `12` (`registry_not_trusted`).

### B3. Ziehen und installieren (zweistufig)

Das Installieren ist ein G-23-Zweischritt: erst ein Plan mit einem kurzlebigen Token, dann
die Bestätigung, die den Plan gegen den **aktuellen** Zustand neu prüft.

```bash
skillctl pull --registry self --er1-target prod --er1-context skills \
  --skill mein-skill --install --trust-mode --dry-run-install --no-checkpoint
```

Die Ausgabe zeigt, was angelegt und was überschrieben würde, und endet mit
`dry-run-install token (5-minute TTL): <TOK>`. Lesen Sie den Plan. Dann:

```bash
skillctl pull --registry self --er1-target prod --er1-context skills \
  --skill mein-skill --install --trust-mode \
  --confirm-install --dry-run-install-token <TOK> --no-checkpoint
```

Dabei laufen fünf Tore: Envelope-Signatur, nicht widerrufen, Governance-Schwelle, Digest,
Bundle-Signaturen. Der Skill landet unter `~/.claude/skills/mein-skill/` mit einer
Provenienz-Datei `.m3c-provenance.json` daneben.

### B4. Nachprüfen

```bash
skillctl verify mein-skill
echo "rc=$?"        # 0
skillctl verify --all
```

> **Warum nicht einfach entpacken?** Ein `.skb` ist ein tar.gz, und `tar -xzf` funktioniert.
> Aber ein von Hand entpackter Skill ist danach **stumm**: `skillctl verify <name>` antwortet
> „no .skb found … (was this skill installed by skillctl install?)", und auch
> `verify --offline <name>` findet keine hinterlegten Metadaten. Damit fällt er aus dem
> Sweep `verify --all` und aus dem Gate heraus. Von Hand entpacken ist ein Notweg für den
> Fall ohne Registry (Teil C2), kein Installationsweg.

---

## Teil C: fremde, bereits signierte Skills einsetzen

Jetzt kommen Skills ins Spiel, die jemand anderes signiert hat, im Folgenden „Mirko".

**Die Regel vorweg, sie spart Ihnen später Ärger.** Pinnen Sie nicht mehrere Registries
nebeneinander. Ein fremder Skill wird geprüft und **in Ihr eigenes Registry aufgenommen**
(Re-Admit), genau wie ein Artefakt-Mirror im Unternehmen. Dann pinnt jede Ihrer Maschinen
weiterhin genau einen Schlüssel, einen Locator und eine Schwelle. Der Grund ist nicht
Ordnungsliebe: `trust-roots.yaml` trägt genau einen Registry-Eintrag, und die Alternative
(eine Datei je Herkunft, beim Pull mit `--trust-roots` mitgegeben) verlagert eine
Sicherheitsentscheidung in die Kommandozeile, wo sie irgendwann falsch getippt wird.

### C0. Zuerst der Pin, dann das Artefakt

Ein öffentlicher Schlüssel, der **zusammen mit dem Bundle** ankommt, beweist nichts: er kam
über denselben ungeprüften Weg wie das Bundle selbst. Lassen Sie sich den Fingerprint über
einen **zweiten Kanal** vorlesen (Telefon, Videocall, persönlich) und vergleichen Sie ihn
Zeichen für Zeichen. Erst danach stimmt der Satz „ich muss dem Transportweg nicht vertrauen".

### C1. Weg 1: Re-Admit in Ihr eigenes Registry (Regelweg)

Sie sind hier in genau der Rolle, die in [Szenario 02](tutorial-szenario-02-erster-signierter-skill.de.md)
Eric hat: Sie sind Freigeber für einen Skill, den jemand anderes geschrieben hat.

```bash
# 1. Mirkos Bundle und seine .author.sig entgegennehmen, Fingerprint vorher
#    über den zweiten Kanal bestätigt haben (C0).
skillctl verify-sig --pubkey ./mirko.pub mirko-skill@1.0.0.skb
echo "rc=$?"        # 0, sonst hier abbrechen

# 2. Ansehen, worüber Sie urteilen.
mkdir -p /tmp/review-mirko && tar -xzf mirko-skill@1.0.0.skb -C /tmp/review-mirko
cat /tmp/review-mirko/SKILL.md && ls -R /tmp/review-mirko

# 3. In Ihr Registry aufnehmen und attestieren.
skillctl publish mirko-skill@1.0.0 --bundle mirko-skill@1.0.0.skb --version 1.0.0 \
  --registry "$REG" --key ~/.config/m3c/skill-keys/eric.priv --identity id:eric@kup --yes

skillctl publish --attest mirko-skill@1.0.0 --digest "<Digest aus Mirkos sign-Ausgabe>" \
  --level green --rationale "Upstream id:mirko@m3c; Signatur verifiziert; Inhalt geprüft am <datum>" \
  --registry "$REG" --identity id:eric-reviewer@kup \
  --key ~/.config/m3c/skill-keys/eric-reviewer.priv --yes
```

Danach zieht **jede** Ihrer Maschinen den Skill mit demselben Kommando und demselben Pin wie
Ihre eigenen Skills:

```bash
skillctl pull --registry "$REG" --skill mirko-skill --install --trust-mode \
  --dry-run-install --no-checkpoint
```

Was Sie damit gewonnen haben: eine Quelle, ein Pin, und in `registry show mirko-skill` steht,
**wer** wann geurteilt hat, nämlich Sie. Mirkos Autorenschaft bleibt im Bundle sichtbar, aber
die Verantwortung für „das läuft bei uns" liegt sichtbar dort, wo sie hingehört.

> **Ausnahme, kein Regelweg.** Auf einer einzelnen Maschine, für einen einmaligen Versuch,
> können Sie ein fremdes Registry auch direkt pinnen: eine zweite Trust-Roots-Datei anlegen und
> beim Pull `--trust-roots <datei>` mitgeben. Machen Sie das nicht auf mehreren Maschinen und
> nicht dauerhaft.

### C2. Weg 2: über einen ER1-Raum (Testpfad)

Mirko publiziert in **seinen** Kontext und teilt den Skill in einen gemeinsamen Raum. Sie
werden serverseitig Mitglied dieses Raums (dafür gibt es kein `skillctl`-Verb, das passiert
in der onboarding.guide-Konsole). Dann ziehen Sie aus **seinem** Kontext:

```bash
# Trust-Roots-Datei für Mirkos Schlüssel, gleiche Form wie in B2
skillctl pull --registry self --er1-target prod --er1-context <mirko-sub>___skills \
  --skill mirko-skill --install --trust-mode --dry-run-install --no-checkpoint
# ... Plan lesen, dann mit --confirm-install und dem Token bestätigen
```

Wichtig: **kein** `--key` und **kein** `--emit-installed`. Sie sind hier reiner Konsument,
und nichts von Ihnen soll in Mirkos Registry zurückgeschrieben werden.

Der ausführliche Zwei-Personen-Ablauf mit allen Feldern steht im
[Runbook Zwei-Personen-Austausch](runbook-two-person-er1-exchange.md).

### C3. Weg 3: über ein HTTP-Registry (heute nur gegen eine Instanz ohne Client-Auth)

> **Vorher lesen.** `/api/skills` ist das aims-core-Modul `skill_registry`, dieselbe Maschine
> wie ER1, andere API. Es läuft in Produktion (`GET /api/skills/health` antwortet `healthy`),
> aber `skillctl` sendet an diese API **keinen Auth-Header**, und die Produktivinstanz
> verlangt einen: `/api/skills/bundles` antwortet mit `401 AUTH_REQUIRED`. Dieser Weg
> funktioniert deshalb heute gegen eine Instanz, die die Endpunkte ohne Client-Auth bedient
> (etwa die lokale Docker-Instanz aus `demo/kup-training/`), nicht gegen prod. Für den
> Produktivbetrieb nehmen Sie Weg 2.

```bash
skillctl trust add \
  --registry https://<registry-host>/api/skills \
  --pubkey ./mirko.pub \
  --id mirko-2026

skillctl trust list
```

`trust list` gibt den gepinnten Schlüssel als Base64 aus. Vergleichen Sie ihn mit dem, was
Mirko Ihnen am Telefon vorgelesen hat. Dann:

```bash
skillctl install mirko-skill@1.0.0
echo "rc=$?"                     # 0 = installiert
skillctl verify mirko-skill
```

Schlägt es fehl, sagt der Exit-Code, woran:

| Code | Bedeutung | Was zu tun ist |
|---|---|---|
| `10` | Digest passt nicht | Bundle neu beziehen, nicht weitermachen |
| `11` | Autorensignatur ungültig | Bundle neu beziehen, nicht weitermachen |
| `12` | Registry nicht in den Trust-Roots | falsche Datei oder falscher Schlüssel gepinnt (siehe B2) |
| `13` | Governance unter der Schwelle | es fehlt eine grüne Attestierung; beim Herausgeber nachfragen |
| `14` | `depends_on` nicht erfüllt | die deklarierte Abhängigkeit bereitstellen |
| `17` | widerrufen | der Skill wurde zurückgezogen; nicht installieren |

### C4. Weg 4: ohne Registry, per Datei

Wenn Sie nur ein `.skb` und die Signaturdatei bekommen, ist die einzige Aussage, die Sie
offline prüfen können, die **Autorensignatur**:

```bash
skillctl verify-sig --pubkey ./mirko.pub mirko-skill@1.0.0.skb
echo "rc=$?"        # 0 = von diesem Schlüssel versiegelt
```

Erst wenn das `0` ist, entpacken Sie:

```bash
mkdir -p ~/.claude/skills/mirko-skill
tar -xzf mirko-skill@1.0.0.skb -C ~/.claude/skills/mirko-skill
```

Seien Sie ehrlich darüber, was Sie damit **nicht** haben: kein Governance-Level, keine
Widerrufsprüfung, keinen Tenant-Scope, und keine spätere Nachprüfbarkeit (siehe B4).
Das ist ein Notweg, kein Regelweg. Der dafür vorgesehene portable Weg,
`skillctl verify --bundle` mit einer `BundleMeta`-Hülle, setzt voraus, dass das Bundle einmal
durch ein Registry gelaufen ist: die Hülle `<name>.skbmeta.json` entsteht beim Admit, und
`export-verification-kit` kann sie nicht erzeugen, es baut das Kit nur um sie herum. Das
Kommando sagt das inzwischen selbst und nennt `skillctl registry show <digest>` als Bezugsquelle.

---

## Teil D: das Gate scharfschalten (auf jeder Maschine)

Bis hierhin haben Sie geprüft, wenn Sie daran gedacht haben. Das Gate prüft, wenn Sie es
vergessen. Es hängt als `PreToolUse(Skill)`-Hook in Claude Code, verifiziert die Kette,
**bevor** ein Skill geladen wird, und verweigert im Zweifel (fail-closed).

In der Claude-Code-Konfiguration (`settings.json`):

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Skill", "hooks": [ { "type": "command", "command": "skillctl verify-hook" } ] } ] } }
```

`verify-hook` wird **nicht von Hand aufgerufen**. Es liest das Hook-Ereignis von der
Standardeingabe; ruft man es interaktiv auf, gibt es folgerichtig eine Ablehnung aus
(„unreadable hook event on stdin (fail-closed)") und endet mit `2`. Das ist kein Fehler,
das ist das Verhalten im Zweifel.

Danach kann ein Agent einen Skill, der die Kette nicht besteht, nicht mehr laden, auch dann
nicht, wenn er es versucht. Was das Tor entschieden hat, sehen Sie hier:

```bash
skillctl gate-stats --since 168h     # Entscheidungen der letzten Woche
```

Regelmäßig, und nach jedem Verdacht:

```bash
skillctl verify --all
skillctl audit --source all --minimum-governance green
```

> **Eine Grenze, gemessen, bevor Sie das in einen Cronjob schreiben.** `verify --all` fällt
> unter verwalteten Trust-Roots **fail-closed**, wenn keine Widerrufsquelle erreichbar ist,
> und würde mit `--quarantine` frisch installierte Skills verschieben. Lassen Sie den Sweep
> deshalb erst ohne `--quarantine` laufen und lesen Sie die Ausgabe, bis der Widerrufskanal
> steht. Das Nachprüfen eines **einzelnen** Skills (`skillctl verify <name>`) funktioniert
> dagegen auch für einen aus dem Git-Registry installierten Skill: es bindet den Inhalt an
> das signierte Bundle und rechnet die Attestierung gegen den gepinnten Schlüssel nach.

`audit` hat eine eigene Skala: `0` alles in Ordnung, `2` mindestens ein Skill unbestätigt
oder unter der Schwelle, `3` mindestens ein Skill defekt.

---

## Teil E: Widerruf

Wenn ein eigener Skill zurückgezogen werden muss:

```bash
skillctl publish --revoke mein-skill \
  --digest "$DIGEST" \
  --reason superseded \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-keys/eric.priv --identity id:eric@kup --yes
```

Gegen ein Git-Registry heisst dasselbe Kommando `--registry "$REG"` statt
`--registry self --er1-target …`; der Widerruf wird als weiteres signiertes Ereignis unter
`events/<digesthex>/` abgelegt und beim nächsten Pull als `gate 5: revoked` wirksam.

Auf den anderen Maschinen greift der Widerruf beim nächsten `verify --all` (Exit `17`).
Der Widerruf ist signiert und offline prüfbar, und eine veraltete oder zurückgedrehte
Widerrufsliste wird zurückgewiesen statt stillschweigend geglaubt (Exit `22`).

---

## Abschluss: die Evidenz, die Sie aufheben

Nicht „hat funktioniert", sondern Zahlen:

```bash
{
  echo "Datum:        $(date -u +%FT%TZ)"
  echo "Host:         $(hostname)"
  skillctl version
  echo "Fingerprint:  $(openssl pkey -pubin -in ~/.config/m3c/skill-keys/eric.pub \
                        -outform DER | tail -c 32 | shasum -a 256 | awk '{print $1}')"
  echo "Digest:       $DIGEST"
  skillctl trust list
  skillctl verify --all
  echo "verify --all rc=$?"
} | tee ~/szenario-01-evidenz.txt
```

Diese Datei beantwortet in sechs Monaten die Frage, was an diesem Tag tatsächlich galt.

---

## Windows

Alles oben gilt, mit drei Unterschieden:

- Pfade: `%USERPROFILE%\.claude\trust-roots.yaml` und
  `%USERPROFILE%\.claude\skill-trust-roots.yaml`.
- Ein ausgelieferter Windows-Build ignoriert `$HOME` für alle sicherheitsrelevanten Pfade
  absichtlich, weil eine Umgebungsvariable von einem Angreifer setzbar ist. Er liest
  `%USERPROFILE%`. Sandkasten-Tricks über `$HOME` funktionieren dort also nicht.
- Installation über die PowerShell-Einzeile aus [Quickstart §1](quickstart-skillctl.md#1-install),
  und entweder diese **oder** den maschinenweiten Installer, nicht beide.

---

## Wenn etwas klemmt

| Symptom | Bedeutung | Abhilfe |
|---|---|---|
| `sign`: „insecure mode 0644" | der private Schlüssel ist zu offen | `chmod 600 <key>.priv`; wenn er über einen Sync-Ordner kam, ist die Signierstation aus Teil 0 die eigentliche Antwort |
| `pull` Exit `12` | falsche Trust-Roots-Datei oder falscher Schlüssel | B2 lesen: `trust-roots.yaml` für `self`, `skill-trust-roots.yaml` für HTTP |
| `pull` Exit `13` | keine grüne Attestierung | A5 zweiter Block |
| `publish` HTTP 403 | Publish in einen fremden Kontext | nur in den **eigenen** `--er1-context skills` publizieren |
| `verify <name>`: „no .skb found" | der Skill wurde von Hand entpackt | über `pull --install` oder `install` neu installieren |
| `verify-sig` Exit `10`, „bundle bytes changed after signing" | die Bytes wurden nach dem Signieren verändert | Bundle neu beziehen |
| `verify-sig` Exit `1`, „no signature found" | es liegt keine Signatur daneben, vermutlich nie signiert | beim Absender nach der `.sig` fragen |

---

## Wie es weitergeht

- Zwei Personen, eine Freigabe: [Szenario 02](tutorial-szenario-02-erster-signierter-skill.de.md)
- Üben, bis es sitzt: [Katas und Test Ride](tutorial-katas-und-test-ride.de.md)
- Jedes Kommando, jedes Flag: [Manual](manual-skillctl.md)
