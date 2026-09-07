# Ops-Runbook: kompromittierter Schlüssel, kompromittiertes Registry

Was zu tun ist, wenn ein Autorenschlüssel, ein Registry-Schlüssel oder das
Registry selbst in fremde Hände geraten ist. Copy-paste-fertig, jede Zeile am
Binary geprüft.

Zielgruppe: die Person, die das Registry betreibt, und die Person, deren
Schlüssel betroffen ist. Wer nur eine Maschine betreibt, liest Abschnitt 5.

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

Gemessene Ausgabe von `registry show` nach einem Widerruf:

```
skill:           demo-skill
registry:        local:///…/skills.git
status:          REVOKED

events (newest first):
--------------------------------------------------------------------------------
  2026-09-07T09:47:20Z  revoked    sha256:5b998c48a366…
    rationale:  Autorenschluessel kompromittiert, Probe
  2026-09-07T09:46:22Z  admitted   sha256:5b998c48a366…
```

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

Nie abrupt tauschen. Es gilt ein **Überlappungsfenster**, in dem beide Schlüssel
akzeptiert werden. Die Herleitung steht im
[Manual, Abschnitt "Rotate the registry key"](manual-skillctl.md#rotate-the-registry-key-overlap-publish-window);
hier steht nur der Ablauf im Vorfall.

```bash
# 1) neues Schlüsselpaar
skillctl keygen --out ~/.config/m3c/skill-registry-v2

# 2) das neue Pin ZUSÄTZLICH setzen, das alte bleibt vorerst stehen
skillctl trust add --registry https://<host>/api/skills \
  --pubkey ~/.config/m3c/skill-registry-v2.pub --id <registry>-v2

# 3) im Fenster alle noch gültigen Bundles unter dem neuen Schlüssel neu admittieren

# 4) nach dem Umstieg das alte Pin entfernen
skillctl trust remove --registry https://<host>/api/skills
```

Im Vorfall ist das Fenster **so kurz wie möglich**: der Sinn der Überlappung ist,
den Betrieb nicht zu unterbrechen, nicht, dem alten Schlüssel Gnadenfrist zu
geben. Ein kompromittierter Schlüssel bleibt so lange gültig, wie er gepinnt ist.

Für das ER1-Registry `self` gibt es kein Mehrschlüssel-Pinning: die flache
`~/.claude/trust-roots.yaml` hält genau ein `pubkey_b64`. Dort heisst
Überlappung: unter dem neuen Schlüssel neu veröffentlichen, jeder Konsumentin
den neuen Fingerabdruck **über einen zweiten Kanal** zustellen, erst dann den
alten zurückziehen.

## 4. Neu pinnen

Was jede Maschine der Flotte tun muss, nachdem der Betreiber rotiert hat:

```bash
skillctl trust list                 # was ist heute gepinnt
skillctl trust add --registry <url> --pubkey <neu>.pub --id <registry>-v2
skillctl trust remove --registry <url>   # nach dem Umstieg: das alte Pin weg
skillctl trust fingerprint <datei>.pub   # Abgleich über den zweiten Kanal
```

Sind Peers gepinnt (dezentrale Registries), gehören sie zur selben Runde:

```bash
skillctl peer ls
skillctl peer rm <name>
```

**Der Fingerabdruck kommt nie über denselben Kanal wie der Schlüssel.** Wer den
neuen Schlüssel per E-Mail schickt und den Fingerabdruck in derselben Mail, hat
den Angreifer, der die Mail schreiben konnte, nicht ausgeschlossen.

## 5. Flotte prüfen

Auf jeder betroffenen Maschine, in dieser Reihenfolge:

```bash
# 1) Widerrufe abholen (HTTP-Registry mit signiertem Widerruf-HEAD)
skillctl revoke feed --status --registry https://<host>/api/skills
skillctl revoke feed --refresh --registry https://<host>/api/skills

# 1b) dezentral: signierte Widerrufe der gepinnten Peers einsammeln
skillctl revoke feed --gossip

# 2) alle installierten Skills gegen die neue Vertrauenslage prüfen
skillctl verify --all --json

# 3) erst wenn Schritt 2 verstanden ist: Nichtbestehende aussortieren
skillctl verify --all --quarantine
```

`verify --all` gibt mit `--json` einen stabilen Bericht aus (gemessen):

```json
{
  "skills_dir": "/…/.claude/skills",
  "total": 0,
  "verified": 0,
  "quarantined": 0,
  "unverified": 0,
  "skipped": 0,
  "entries": null
}
```

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
| 5 | Neu pinnen, alt noch gepinnt | `trust add …` |
| 6 | Im Fenster neu admittieren | `publish …` |
| 7 | Altes Pin entfernen | `trust remove …` |
| 8 | Fingerabdruck über zweiten Kanal | `trust fingerprint …` |
| 9 | Flotte nachziehen | `revoke feed --refresh`, `verify --all` |
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
