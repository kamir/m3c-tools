# Ops-Runbook: kompromittierter Schlüssel, kompromittiertes Registry

Was zu tun ist, wenn ein Autorenschlüssel, ein Registry-Schlüssel oder das
Registry selbst in fremde Hände geraten ist.

Zielgruppe: die Person, die das Registry betreibt, und die Person, deren
Schlüssel betroffen ist. Wer nur eine Maschine betreibt, liest Abschnitt 5.

**Wie weit dieses Runbook gemessen ist.** Jeder Block, der mit "Gemessen"
angekündigt ist, ist am 2026-09-07 gegen das Binary gelaufen, gegen ein
Wegwerf-Registry unter `local://` und ein Wegwerf-`$HOME`. Gekürzt sind Pfade
(`/…/`) sowie Digests und Fingerabdrücke (`…` am Ende); wird eine Ausgabe
darüber hinaus gekürzt, steht an der Stelle eine Zeile `[…]`. Die Kommandos
gegen ein HTTP-Registry (`https://…/api/skills`) sind nur so weit gemessen, wie
sie ohne erreichbare Gegenstelle laufen, also bis zur Argument-, Datei- und
Namensprüfung; eine Instanz stand nicht zur Verfügung. Diese Einschränkung steht
auch an den betroffenen Stellen. Eine Zusage im Kopf eines Dokuments ist eine
Behauptung wie jede andere: was hier steht, ist der geprüfte Umfang, nicht mehr.

Das Schwesterdokument [Ops-Routine: Zugangstoken](ops-registry-tokens.de.md)
behandelt **Token**. Dieses Runbook behandelt **Schlüssel**. Der Unterschied ist
der Kern der ganzen Sache:

> **Der Token entscheidet, wer die Bytes bewegen darf. Der Schlüssel entscheidet,
> wem sie zugerechnet werden.**

Ein gestohlener Token erlaubt Schreiben unter fremder Flagge, bis GitLab ihn
widerruft. Ein gestohlener **Schlüssel** erlaubt, Bundles zu erzeugen, die jede
Maschine der Flotte als echt annimmt, und der Widerruf des Tokens ändert daran
nichts. Deshalb sind das zwei getrennte Abläufe.

## 0. Die drei Fälle in einem Satz

| Fall | Was der Angreifer kann | Was ihn stoppt |
|---|---|---|
| **Autorenschlüssel** (`author.key`, `*.priv`) | Bundles signieren, die als von dieser Autorin stammend gelten | Widerruf der betroffenen Digests, dann Schlüsselwechsel und neues Pinnen bei jedem Konsumenten |
| **Registry-Schlüssel** (der Schlüssel, gegen den `trust-roots` pinnt) | Admit-, Attest- und Revoke-Ereignisse fälschen; ein Widerruf ist damit unterdrückbar | Überlappungsfenster mit neuem Schlüssel, dann alte Pinnung entfernen |
| **Registry selbst** (Projekt, Token, Server) | Inhalte ersetzen, Ereignisse löschen | Neuaufbau aus der Sicherung, danach Nachweis über die Signaturen |

Die mittlere Zeile ist die schlimmste. Ein kompromittierter Registry-Schlüssel
kann einen Widerruf verschweigen, also greift der Widerruf des Autorenschlüssels
allein nicht: dann muss auch der Registry-Schlüssel rotieren.

## 1. Erkennen

Erst feststellen, was tatsächlich im Registry steht. Alle drei Kommandos sind
lesend, keines verändert etwas.

```bash
# Was ist admittiert, was ist schon widerrufen?
skillctl registry ls --registry <locator>

# Die volle Zeitleiste eines Bundles: admit, attest, revoke, install
skillctl registry show <name> --registry <locator>
```

Gemessene Ausgabe von `registry show` nach einem Widerruf, vollständig, gekürzt
nur an Pfad und Digest:

```
skill:           demo-skill
registry:        local:///…/probe/skills.git
latest digest:   ?
latest gov:      green
status:          REVOKED

events (newest first):
--------------------------------------------------------------------------------
  2026-09-07T20:48:35Z  revoked    sha256:22a21798c283…
    rationale:  Autorenschluessel kompromittiert, Probe
  2026-09-07T20:48:13Z  attested   sha256:22a21798c283…
    governance: green
    rationale:  Probe
  2026-09-07T20:48:07Z  admitted   sha256:22a21798c283…
```

Zwei Zeilen dieses Kopfes lesen sich falsch, und beide sind so gemessen:

* **`latest digest:   ?`** heisst nicht "Digest unbekannt", sondern "es gibt keine
  nicht widerrufene Version mehr". Die Namensauflösung überspringt widerrufene
  Versionen und findet dann nichts; aus demselben Grund fällt die Zeile
  `latest version:` ganz weg. Vor dem Widerruf stand dort `latest version:  1.0.0`
  samt vollem Digest.
* **`latest gov:      green`** ist die Attestierung von vorher. Der Kopf filtert
  die Ereignisse auf den aufgelösten Digest; weil keiner mehr aufgelöst wird,
  entfällt der Filter, und das neueste `attested` gewinnt, ganz gleich zu welcher
  Version es gehörte. Ohne jede Attestierung steht in dieser Zeile ein
  Doppelpunkt als Platzhalter, gemessen an einem zweiten Wegwerf-Registry mit
  Aufnahme und Widerruf, aber ohne Urteil:

```
latest digest:   ?
latest gov:      :
status:          REVOKED
```

Der Platzhalter ist wörtlich ein Doppelpunkt und ein Leerzeichen; wer die Zeile
maschinell liest, prüft auf genau diesen Wert und nicht auf "leer".

Massgeblich ist `status:` und die Ereignisliste darunter, nicht der Kopf.

Auf der betroffenen Maschine dazu die lokale Seite:

```bash
skillctl gate-stats --since 168h     # was hat das Tor in der letzten Woche geblockt
skillctl auditlog status             # schreibt das Audit-Subsystem überhaupt noch
skillctl doctor                      # Pinnungen, Schlüssel, Verzeichnisse
```

**Was hier NICHT geht.** Es gibt keine Abfrage "welche Maschine hat dieses Bundle
installiert". `emit-installed` schreibt ein `BundleInstalledEvent`, aber nur wenn
der Konsument es beim Pull ausdrücklich angefordert hat. Die Reichweite eines
Vorfalls ist also eine Frage an das Token-Register und an die Menschen, nicht an
das Werkzeug.

## 2. Widerrufen

**Zuerst widerrufen, dann rotieren.** Ein Widerruf, den man nach dem
Schlüsselwechsel nachholen will, braucht den alten Schlüssel, den man gerade
gelöscht hat.

### Git-gestütztes Registry (`local://`, `gitlab://`, `github://`)

```bash
skillctl publish <name> --revoke \
  --digest sha256:<hex> \
  --reason key_compromise \
  --rationale "Autorenschlüssel am <datum> kompromittiert" \
  --version <v> \
  --registry <locator> \
  --key <schlüssel>.priv \
  --identity id:<du>@m3c \
  --yes
```

Gemessene Ausgabe:

```
==> publish --revoke demo-skill@1.0.0
    digest:    sha256:5b998c48a366…
    reason:    key_compromise
    rationale: Autorenschluessel kompromittiert, Probe
==> revoked: demo-skill/v1.0.0  transport=git  registry=local:///…/skills.git
```

Danach steht in `registry ls` in der Spalte `status` das Wort `REVOKED`.

### HTTP-Registry (`https://…/api/skills`)

Ein eigenes Verb mit eigenem Rollenmodell:

```bash
skillctl revoke sha256:<hex> \
  --reason key_compromise \
  --role original_author \
  --registry https://<host>/api/skills
```

| Rolle | Wer | Was gebraucht wird |
|---|---|---|
| `original_author` (Vorgabe) | die Autorin selbst | eigener Schlüssel, Vorgabe `~/.claude/skillctl-keys/author.key` |
| `governance_reviewer` | die freigebende Person | `--actor-identity` und `--key` |
| `registry_operator` | der Betreiber | unsigniert, die Registry-Seite authentifiziert per HTTP |

### Die Falle bei `--reason`

Die beiden Wege prüfen den Grund **unterschiedlich**. `skillctl revoke` erzwingt
das geschlossene Vokabular:

```
$ skillctl revoke sha256:… --reason kaputt --registry https://…/api/skills
skillctl revoke: invalid --reason "kaputt" (want one of: key_compromise|vulnerability|governance_retraction|author_request|duplicate)
```

`publish --revoke` nimmt dagegen jede Zeichenkette an; gemessen wurde ein
Widerruf mit `--reason kaputt`, der ohne Warnung durchging. Wer später
auswerten will, welche Widerrufe eine Kompromittierung waren, schreibt deshalb
auch auf dem git-Weg von Hand `key_compromise` und nichts anderes.

## 3. Rotieren

Nie abrupt tauschen, wo ein Fenster möglich ist. Die Herleitung steht im
[Manual, Abschnitt "Rotate the registry key"](manual-skillctl.md#rotate-the-registry-key-overlap-publish-window);
hier steht der Ablauf im Vorfall, und der hängt am Backend.

Er hängt daran, weil die Vertrauenswurzeln in **drei verschiedenen Dateien**
liegen. Das ist der häufigste Fehlgriff in diesem Runbook, deshalb zuerst die
Tabelle:

| Registry | Wo die Pinnung liegt | Womit sie gesetzt wird |
|---|---|---|
| `https://…/api/skills` | `~/.claude/skill-trust-roots.yaml` | `skillctl trust add`, `trust remove` |
| `local://`, `gitlab://`, `github://` | `~/.claude/skill-peers.yaml` | `skillctl peer add`, `peer rm` |
| dieselben, ohne Peer-Pin | `~/.claude/trust-roots.yaml`, flach | von Hand geschrieben |
| `self` (ER1) | `~/.claude/trust-roots.yaml`, flach | von Hand geschrieben |

Die flache `~/.claude/trust-roots.yaml` in Zeile 3 und 4 hat eine zweite,
weniger offensichtliche Wirkung: ihre blosse **Anwesenheit** macht die Maschine
zu einer *verwalteten*, und davon hängt ab, ob der Widerruf-Abgleich zuschliesst
oder still durchwinkt. Die Messung dazu steht in Abschnitt 5.

`trust add` nimmt **ausschliesslich** `https://` an, `http://` nur für Loopback
und RFC1918. Gemessen:

```
$ skillctl trust add --registry gitlab://<host>/<gruppe>/skill-registry \
    --pubkey reg-v2.pub --id kup-v2
trust-roots: registry_url "gitlab://<host>/<gruppe>/skill-registry" must use https:// (or http:// for loopback / RFC1918 only)
$ echo $?
1
```

`local://` und `github://` scheitern mit derselben Zeile, gemessen. Für ein
git-gestütztes Registry, und genau darum geht es bei der KuP-Einrichtung, ist
`trust add` also kein Weg.

Wie sauber die beiden Dateien getrennt sind, zeigt `trust list` in einem `$HOME`,
in dem **nur** die flache `trust-roots.yaml` liegt. Gemessen:

```
$ ls ~/.claude/
trust-roots.yaml
$ skillctl trust list
trust roots: /…/.claude/skill-trust-roots.yaml (does not exist yet)
no trust roots configured
configure one with: skillctl trust add --registry <url> --pubkey <path>
$ echo $?
0
```

Es liegt eine gültige, benutzte Vertrauenswurzel im Verzeichnis, und `trust list`
sagt "no trust roots configured" und zeigt auf eine andere Datei. Wer den Zustand
einer Maschine über `trust list` prüft, prüft auf dem git-Weg das Falsche.

### git-gestütztes Registry (`local://`, `gitlab://`, `github://`)

```bash
# 1) neues Schlüsselpaar beim Betreiber
skillctl keygen --out ~/.config/m3c/skill-registry-v2

# 2) im Fenster jedes noch gültige Bundle unter dem NEUEN Schlüssel neu
#    aufnehmen und neu attestieren
skillctl publish <name>@<v> --bundle <name>@<v>.skb --version <v> \
  --registry gitlab://<host>/<gruppe>/skill-registry \
  --key ~/.config/m3c/skill-registry-v2.priv \
  --identity id:<betrieb>@<org> --yes

# 3) jede Maschine zieht das Pin nach: Abschnitt 4
```

**Für den Registry-Schlüssel gibt es hier kein Überlappungsfenster.** Ein Locator
trägt genau einen Pin. Gemessen:

```
$ skillctl peer add kup-registry-v2 gitlab://<host>/<gruppe>/skill-registry \
    --pubkey <neu-b64> --pin sha256:<neu>
peer add: peers: locator "gitlab://<host>/<gruppe>/skill-registry" is already pinned
$ echo $?
1
```

Auch derselbe Name ein zweites Mal wird abgewiesen, mit einer anderen Zeile.
Gemessen, damit die beiden Fehlschläge nicht verwechselt werden:

```
$ skillctl peer add kup-registry gitlab://<host>/<gruppe>/skill-registry \
    --pubkey <b64> --pin sha256:<hex>
peer add: peers: a peer named "kup-registry" already exists
$ echo $?
1
```

Der Weg ist deshalb `peer rm <name>`, dann `peer add` mit dem neuen Schlüssel.
Überlappung heisst auf diesem Weg also: kurz zwei Registries nebeneinander, oder
ein eng terminierter Umstieg, bei dem der neue Fingerabdruck **vorher** über den
zweiten Kanal zugestellt ist.

**Für den Reviewer-Schlüssel gibt es eines.** `--signer` ist wiederholbar, und das
Quorum bleibt bei 1, solange es niemand hochsetzt. Gemessen:

```
$ skillctl peer add probe local:///…/probe/skills.git \
    --pubkey <reg-b64> --pin sha256:3b2dc6afd3fa… \
    --signer id:reviewer@probe:<alt-b64> --signer id:reviewer-v2@probe:<neu-b64>
pinned peer "probe" → local:///…/probe/skills.git
  fingerprint: sha256:3b2dc6afd3fa… (matched)
  signer:      id:reviewer@probe
  signer:      id:reviewer-v2@probe
  quorum:      1 of 2 pinned signer(s)
  pull with:   skillctl pull --registry local:///…/probe/skills.git
$ echo $?
0
```

In diesem Fenster zählen Attestierungen beider Reviewer-Schlüssel; danach fliegt
der alte aus dem Aufruf.

### HTTP-Registry (`https://…/api/skills`)

Hier trägt eine Registry-Zeile mehrere Schlüssel, also gibt es das Fenster:

```bash
# 1) neues Schlüsselpaar
skillctl keygen --out ~/.config/m3c/skill-registry-v2

# 2) das neue Pin ZUSÄTZLICH setzen, das alte bleibt vorerst stehen
skillctl trust add --registry https://<host>/api/skills \
  --pubkey ~/.config/m3c/skill-registry-v2.pub --id <registry>-v2

# 3) im Fenster alle noch gültigen Bundles unter dem neuen Schlüssel neu admittieren

# 4) nach dem Umstieg: Eintrag entfernen und NUR das neue Pin wieder setzen
skillctl trust remove --registry https://<host>/api/skills
skillctl trust add --registry https://<host>/api/skills \
  --pubkey ~/.config/m3c/skill-registry-v2.pub --id <registry>-v2
```

**Schritt 4 ist kein Tippfehler.** `trust remove` entfernt den ganzen
Registry-Eintrag samt allen Schlüsseln, seine Hilfe sagt das auch
("Remove a pinned registry (including all its keys)"). Ein einzelnes Pin lässt
sich nicht wegnehmen; das alte Pin verschwindet nur, indem der Eintrag neu
aufgebaut wird. Gemessen, zwei Schlüssel gepinnt, dann entfernt und neu gesetzt:

```
$ skillctl trust list
trust roots: /…/.claude/skill-trust-roots.yaml

registry: https://beispiel.invalid/api/skills
  identity_keys_authorized: from-registry
  governance_minimum:       green
  registry_keys:
    - id: reg-v1   issued: 2026-09-07
      pubkey (b64): jUndusQ7uIdfHjFbhY3pNMc8Y/oMDoMjDZyGXo94dWg=
    - id: reg-v2   issued: 2026-09-07
      pubkey (b64): LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs=

$ skillctl trust remove --registry https://beispiel.invalid/api/skills
removed registry https://beispiel.invalid/api/skills from /…/.claude/skill-trust-roots.yaml
$ skillctl trust add --registry https://beispiel.invalid/api/skills \
    --pubkey skill-registry-v2.pub --id reg-v2
added registry https://beispiel.invalid/api/skills to /…/.claude/skill-trust-roots.yaml
$ skillctl trust list
trust roots: /…/.claude/skill-trust-roots.yaml

registry: https://beispiel.invalid/api/skills
  identity_keys_authorized: from-registry
  governance_minimum:       green
  registry_keys:
    - id: reg-v2   issued: 2026-09-07
      pubkey (b64): LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs=
```

Dass **zwei** Schlüssel gleichzeitig unter einer Registry-Zeile stehen können,
ist genau das Überlappungsfenster; auf dem git-Weg gibt es diese Liste nicht.

`trust add`, `trust list` und `trust remove` schreiben und lesen nur die lokale
Datei; sie sind deshalb auch ohne erreichbare Instanz gemessen. Das
Neu-Admittieren in Schritt 3 ist es **nicht**.

Im Vorfall ist das Fenster **so kurz wie möglich**: der Sinn der Überlappung ist,
den Betrieb nicht zu unterbrechen, nicht, dem alten Schlüssel Gnadenfrist zu
geben. Ein kompromittierter Schlüssel bleibt so lange gültig, wie er gepinnt ist.

### ER1-Registry `self`

Kein Mehrschlüssel-Pinning: die flache `~/.claude/trust-roots.yaml` hält genau ein
`pubkey_b64`. Dort heisst Überlappung: unter dem neuen Schlüssel neu
veröffentlichen, jeder Konsumentin den neuen Fingerabdruck **über einen zweiten
Kanal** zustellen, erst dann den alten zurückziehen.

## 4. Neu pinnen

Was jede Maschine der Flotte tun muss, nachdem der Betreiber rotiert hat. Auch
das je Backend, aus demselben Grund wie oben.

### git-gestütztes Registry: `peer add`

Aus dem öffentlichen Schlüssel des Betreibers kommen zwei Werte, und der zweite
kommt **über einen anderen Kanal als der erste**:

```bash
openssl pkey -pubin -in skill-registry-v2.pub -outform DER | tail -c 32 | base64 | tr -d '\n'
skillctl trust fingerprint skill-registry-v2.pub
```

Gemessen:

```
$ openssl pkey -pubin -in reg-v2.pub -outform DER | tail -c 32 | base64 | tr -d '\n'
LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs=
$ skillctl trust fingerprint reg-v2.pub
sha256:9c37af1780c90f4104d9598d6680a45a95c0606a142220430c1aad44e3650b27
```

Der Fingerabdruck ist der SHA-256 über genau die 32 rohen Schlüsselbytes, die
auch `--pubkey` bekommt. Gemessen, damit klar ist, dass die zwei Kanäle
denselben Schlüssel meinen:

```
$ openssl pkey -pubin -in reg.pub -outform DER | tail -c 32 | shasum -a 256
3b2dc6afd3fa2901346a6f0683814babb99144d07cfa53db5a80c53eada1e218  -
$ skillctl trust fingerprint reg.pub
sha256:3b2dc6afd3fa2901346a6f0683814babb99144d07cfa53db5a80c53eada1e218
```

Dann auf jeder Maschine:

```bash
skillctl peer ls                              # was ist heute gepinnt
skillctl peer rm <name>                       # das alte Pin weg
skillctl peer add <name> gitlab://<host>/<gruppe>/skill-registry \
  --pubkey <raw-b64> --pin sha256:<hex> \
  --signer id:<reviewer>@<org>:<reviewer-raw-b64>
skillctl peer verify <name>                   # Trockenlauf, installiert nichts
```

Gemessen, mit einem `gitlab://`-Locator:

```
$ skillctl peer add kup-registry gitlab://<host>/<gruppe>/skill-registry \
    --pubkey LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs= \
    --pin sha256:9c37af1780c90f4104d9598d6680a45a95c0606a142220430c1aad44e3650b27
pinned peer "kup-registry" → gitlab://<host>/<gruppe>/skill-registry
  fingerprint: sha256:9c37af1780c90f4104d9598d6680a45a95c0606a142220430c1aad44e3650b27 (matched)
  signer:      (none pinned: only this registry key may attest)
  pull with:   skillctl pull --registry gitlab://<host>/<gruppe>/skill-registry
$ echo $?
0
```

Das `(matched)` ist der Sinn des zweiten Kanals: der Fingerabdruck wird geprüft,
nicht bloss protokolliert. Gemessen mit einem falschen Pin:

```
$ skillctl peer add wrong gitlab://<host>/<gruppe>/anderes-registry \
    --pubkey LBjJv2++fb1i86rHWE9v13ngtfuBNlniTSB3SZI04Cs= \
    --pin sha256:0000000000000000000000000000000000000000000000000000000000000000
peer add: fingerprint mismatch (pinned sha256:0000…, key hashes to sha256:9c37af1780…)
$ echo $?
1
```

**`--signer` ist nicht optional, sobald Herausgeber und Reviewer verschiedene
Schlüssel haben.** Sonst liegt die Attestierung im Repository und zählt trotzdem
nicht. Gemessen, derselbe Peer einmal ohne und einmal mit gepinntem Reviewer:

```
$ skillctl peer verify live            # ohne --signer gepinnt
peer "live" (local:///…/probe/live.git)  gov-min=green  fp=sha256:3b2dc6afd3fa…
  would-verify (pass §7 gauntlet): 0
  rejected: 1
    ✗ demo-skill@1.0.0  gate 4: no attestation at or above the trust-roots governance_minimum: no signed attestation found for this digest
$ echo $?
1

$ skillctl peer verify live            # mit --signer id:reviewer@probe:<raw-b64>
peer "live" (local:///…/probe/live.git)  gov-min=green  fp=sha256:3b2dc6afd3fa…
  would-verify (pass §7 gauntlet): 1
    ✓ demo-skill@1.0.0  gov=green
$ echo $?
0
```

Der Exit-Code taugt damit als Torwächter in einem Skript: `peer verify` endet
mit 1, sobald auch nur ein Bundle abgelehnt wird.

### git-gestütztes Registry ohne Peer-Pin: die flache `trust-roots.yaml`

Ist der Locator nicht als Peer gepinnt, liest `pull` die **flache**
`~/.claude/trust-roots.yaml`. Das ist nicht die Datei, die `trust add` schreibt,
und `trust list` zeigt sie nicht an. Gemessen ist dieser Inhalt, mit dem ein Pull
durchläuft:

```yaml
registry: local:///…/probe/live.git
pubkey_b64: jUndusQ7uIdfHjFbhY3pNMc8Y/oMDoMjDZyGXo94dWg=
fingerprint: sha256:3b2dc6afd3fa…
governance_minimum: green
governance_quorum: 1
signers:
  - reviewer_id: id:reviewer@probe
    pubkey_b64: qbCDIlwrx8jhGKNbiHjNHrdUxILfnD2hYjlnvr8NBlY=
```

Mit genau dieser Datei endet der Pull auf `staged=1  skipped=0` und Exit 0;
die Messung steht in
[Ops-Runbook: Sicherung](ops-registry-backup-restore.de.md#prüfung-4-braucht-eine-voraussetzung-sonst-misst-sie-den-prüfenden).

Fehlt die Datei und ist auch kein Peer gepinnt, bricht `pull` mit Exit 2 ab,
bevor irgendein Tor läuft:

```
$ skillctl pull --registry local:///…/skills.git --skill demo-skill \
    --install --trust-mode --dry-run-install
pull: load trust-roots: trust-roots: open /…/.claude/trust-roots.yaml: open /…/.claude/trust-roots.yaml: no such file or directory
       Carry ~/.claude/trust-roots.yaml from machine 1 (10-keygen-and-trustroots.sh), or pin the peer with `skillctl peer add`.
$ echo $?
2
```

Der Pfad steht in dieser Zeile zweimal, das ist so gemessen und kein Abschreibfehler.

### HTTP-Registry: `trust add`

```bash
skillctl trust list                      # was ist heute gepinnt
skillctl trust add --registry https://<host>/api/skills --pubkey <neu>.pub --id <registry>-v2
skillctl trust remove --registry https://<host>/api/skills   # entfernt ALLE Schlüssel, siehe Abschnitt 3
skillctl trust fingerprint <datei>.pub   # Abgleich über den zweiten Kanal
```

**Der Fingerabdruck kommt nie über denselben Kanal wie der Schlüssel.** Wer den
neuen Schlüssel per E-Mail schickt und den Fingerabdruck in derselben Mail, hat
den Angreifer, der die Mail schreiben konnte, nicht ausgeschlossen.

## 5. Flotte prüfen

Auf jeder betroffenen Maschine, in dieser Reihenfolge:

```bash
# 1) Widerrufe abholen (HTTP-Registry mit signiertem Widerruf-HEAD)
skillctl revoke feed --registry https://<host>/api/skills          # Zustand: das ist die Vorgabe
skillctl revoke feed --refresh --registry https://<host>/api/skills

# 1b) dezentral: signierte Widerrufe der gepinnten Peers einsammeln
skillctl revoke feed --gossip

# 2) alle installierten Skills gegen die neue Vertrauenslage prüfen
skillctl verify --all --json

# 3) erst wenn Schritt 2 verstanden ist: Nichtbestehende aussortieren
skillctl verify --all --quarantine
```

**`--status` gibt es nicht, obwohl die Hilfe es aufführt.** Gemessen, Ausgabe
bis zur Flag-Liste, danach `[…]`:

```
$ skillctl revoke feed --status --registry https://<host>/api/skills
flag provided but not defined: -status
Usage: skillctl revoke feed [--status] [--refresh] [--registry URL] [--tenant T]

Inspect or refresh the signed revocation HEAD: the G5 kill-switch feed (FR-0045).
  --status  (default) fetch + verify the HEAD against the pinned registry key
  --refresh sweep now: adopt the HEAD into the local cache + freshness anchor
[…]
$ echo $?
2
```

Der Hilfetext nennt `--status` also zweimal und der Parser kennt es nicht. Er
sagt zugleich, was stattdessen gilt: der Zustandsabruf **ist** die Vorgabe, also
`revoke feed --registry <url>` ohne weiteres Flag. Der Fehler liegt im Werkzeug,
nicht im Aufruf.

**Der Zustandsabruf endet bei einer unerreichbaren Gegenstelle mit Exit 1.**
Gemessen gegen einen Namen, den es nicht gibt:

```
$ skillctl revoke feed --registry https://<unerreichbar>/api/skills
skillctl revoke feed: fetch failed: Get "https://<unerreichbar>/api/skills/revocations/head": dial tcp: lookup <unerreichbar>: no such host
$ echo $?
1
```

**Der Refresh antwortet je nach Zustand der Maschine verschieden, und das ist
der Punkt, an dem eine Überwachung falsch gebaut wird.** Entscheidend ist, ob die
flache `~/.claude/trust-roots.yaml` vorhanden ist: sie ist es, die eine Maschine
zu einer *verwalteten* macht. Beide Fälle gemessen, gegen denselben
unerreichbaren Namen:

```
$ ls ~/.claude/trust-roots.yaml            # Datei FEHLT: unverwaltet
ls: /…/.claude/trust-roots.yaml: No such file or directory
$ skillctl revoke feed --refresh --registry https://<unerreichbar>/api/skills
refreshed: 0 revoked digest(s), epoch=0 issued_at="" online=false
$ echo $?
0
```

```
$ ls ~/.claude/trust-roots.yaml            # Datei DA: verwaltet
/…/.claude/trust-roots.yaml
$ skillctl revoke feed --refresh --registry https://<unerreichbar>/api/skills
refreshed: 0 revoked digest(s), epoch=0 issued_at="" online=false
skillctl revoke feed --refresh: revocation unavailable under managed trust roots (fail-closed, exit 22): revoked-set unavailable under managed trust roots and no fresh cache (fail-closed)
$ echo $?
22
```

Auf der **unverwalteten** Maschine meldet der Refresh Erfolg, obwohl er nichts
erreicht hat; die ganze Auskunft steckt dann in `online=false`, und eine
Überwachung, die nur den Exit-Code liest, sieht nichts. Auf der **verwalteten**
Maschine schliesst das Werkzeug zu und sagt es mit Exit 22, sobald kein frischer
Cache die Alterung mehr begrenzt; innerhalb dieses Gnadenfensters bleibt es bei
Exit 0 mit `online=false`.

Daraus die Regel für eine Überwachung: auf `online=false` **und** auf Exit 22
alarmieren, nicht auf den Exit-Code allein, und für die Frage "ist mein
Widerruf-Kopf frisch" den Zustandsabruf nehmen, dessen Exit 1 unabhängig von der
Verwaltungslage kommt.

`verify --all` gibt mit `--json` einen stabilen Bericht aus. Gemessen auf einer
Maschine ohne installierte Skills, vollständig, samt der Vorspannzeile:

```
$ skillctl verify --all --json
skillctl verify --all: no installed skills at /…/.claude/skills (nothing to sweep)
{
  "skills_dir": "/…/.claude/skills",
  "total": 0,
  "verified": 0,
  "quarantined": 0,
  "unverified": 0,
  "skipped": 0,
  "entries": null
}
$ echo $?
0
```

Die Vorspannzeile geht auf **stdout**, nicht auf stderr, gemessen mit
`2>/dev/null`. Ein Auswerter schneidet deshalb ab der ersten `{`-Zeile; die
Einzelheiten stehen in [Monitoring und Alarmierung](ops-monitoring.de.md).

`--quarantine` verschiebt nur **verwaltete** Skills, die im Vertrauenspfad
durchfallen, in das Quarantäneverzeichnis. Der Lauf hat ein Zeitbudget
(`--budget`, Vorgabe 60s); was er nicht erreicht, gilt als `unverified` und wird
**nie** in Quarantäne verschoben. Ein Bericht mit `unverified > 0` ist deshalb
kein Freispruch, sondern eine unbeantwortete Frage.

**Was hier NICHT geht.** Es gibt keinen Push an die Flotte. Kein Kommando dieses
Werkzeugs erreicht eine andere Maschine. Jede Maschine muss `revoke feed
--refresh` und `verify --all` selbst laufen lassen, per Hook, per launchd, per
cron oder per Mensch. Wer eine Aussage über die Flotte braucht, sammelt die
`--json`-Ausgaben ein; siehe [Monitoring und Alarmierung](ops-monitoring.de.md).

## 6. Token, nicht Schlüssel

Wenn zusätzlich ein **Token** betroffen ist, gilt der andere Ablauf:

1. In GitLab widerrufen. Das wirkt sofort und ohne Zutun der Maschine. Es ist
   die einzige Stelle, die wirklich zählt.
2. `skillctl token rm --backend gitlab --host <host>` auf jeder Maschine, die
   ihn hatte. Das ist Hygiene, keine Sicherheitsmassnahme.
3. Die Zeile im Token-Register in der Spalte "Widerrufen am" füllen
   ([Teil C](ops-registry-tokens.de.md#teil-c-das-token-register)).
4. Neuen Token nach Teil A beziehungsweise Teil B ausstellen.

`skillctl token list --host <host>` zeigt danach, was auf der Maschine noch
hinterlegt ist, **ohne** einen Token auszugeben. Die interessante Spalte ist die
Quelle: eine gesetzte Umgebungsvariable schlägt den geschützten Speicher, und
ein vergessenes `export` überlebt jedes `token rm`.

## 7. Reihenfolge, zum Abhaken

| # | Schritt | Kommando |
|---|---|---|
| 1 | Umfang feststellen | `registry ls`, `registry show`, `gate-stats --since 168h` |
| 2 | Betroffene Digests widerrufen | `publish --revoke …` oder `revoke <digest> …` |
| 3 | Widerruf gegenprüfen | `registry ls` zeigt `REVOKED` |
| 4 | Neues Schlüsselpaar | `keygen --out …` |
| 5 | Neu pinnen | https: `trust add …`, das alte Pin bleibt im Fenster stehen · git: erst `peer rm …`, dann `peer add …`, in dieser Reihenfolge |
| 6 | Im Fenster neu admittieren | `publish …` (https; git kennt kein Fenster für den Registry-Schlüssel) |
| 7 | Altes Pin entfernen | https: `trust remove …`, dann das neue Pin erneut setzen · git: mit Schritt 5 erledigt |
| 8 | Fingerabdruck über zweiten Kanal | `trust fingerprint …`, für beide Backends dasselbe Kommando |
| 9 | Flotte nachziehen | `revoke feed --refresh` (Exit 22 auf verwalteten Maschinen ist ein Befund, kein Fehlaufruf), `verify --all` |
| 10 | Aussortieren | `verify --all --quarantine` |
| 11 | Token-Register nachführen | `OPS/token-register.md` |

## 8. Was dieses Runbook nicht löst

**Keine Flottensicht.** Es gibt keine Liste "wer hat was installiert", solange
die Konsumenten nicht mit `pull --emit-installed` gepullt haben. Der Umfang
eines Vorfalls ist eine organisatorische Frage.

**Kein Alarm.** Nichts meldet von selbst, dass ein Widerruf eingetroffen ist.
Der `revoke feed` muss abgeholt werden. Siehe
[Monitoring und Alarmierung](ops-monitoring.de.md).

**Keine Ablaufwarnung.** Weder GitLab noch `skillctl` warnen vor dem Ablauf
eines Tokens; das Ablaufdatum steht in keinem Token. Dafür gibt es das Register.

**Kein Zurückholen.** Ein Widerruf ist ein neues, signiertes Ereignis, keine
Löschung. Das ist Absicht: eine Zeitleiste, aus der etwas verschwinden kann, ist
als Nachweis wertlos. Ein irrtümlicher Widerruf wird durch ein neues Admit unter
einer neuen Version geheilt, nicht durch Zurücknehmen.

## Verwandte Runbooks

| Runbook | Wofür |
|---|---|
| [Ops-Routine: Zugangstoken](ops-registry-tokens.de.md) | wer welchen Token besorgt und was beim Ausscheiden passiert |
| [Registry-Backup und Restore](ops-registry-backup-restore.de.md) | Sicherung je Backend, mit Wiederherstellungsprobe |
| [Monitoring und Alarmierung](ops-monitoring.de.md) | was heute beobachtbar ist, und was nicht |
