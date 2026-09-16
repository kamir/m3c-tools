# Ops-Runbook: Registry-Backup und Restore

Wie ein Skill-Registry gesichert und wiederhergestellt wird, je Backend, mit
einer Probe, die den Restore prüfbar macht, und mit der Voraussetzung, ohne die
sie statt des Restores den Prüfenden misst.

Zielgruppe: die Person, die das Registry betreibt.

**Wie weit dieses Runbook gemessen ist.** Die Blöcke, die mit "Gemessen"
angekündigt sind, sind am 2026-09-07 gegen das Binary gelaufen, gegen ein
Wegwerf-Registry unter `local://` und ein Wegwerf-`$HOME`. Gekürzt sind Pfade
(`/…/`) und Digests (`…` am Ende); wird darüber hinaus gekürzt, steht an der
Stelle eine Zeile `[…]`. Vom ER1-Registry `self` ist nur gemessen, was das
Werkzeug **ohne** erreichbare Instanz beantwortet, also die Verweigerungen in
Abschnitt 4; eine ER1-Instanz stand nicht zur Verfügung.

## Die Grundregel in einem Satz

**Ein git-gestütztes Registry ist ein bare-Repository. Die Sicherung ist ein
`git clone --mirror`, die Wiederherstellung ist derselbe Befehl rückwärts.**

Daraus folgt der ganze Rest: für `local://`, `gitlab://` und `github://` gibt es
eine vollständige, prüfbare Sicherung mit Bordmitteln. Für das ER1-Registry
`self` gibt es sie nicht, und Abschnitt 4 sagt, was stattdessen zu tun ist.

| Backend | Sicherung | Vollständig? |
|---|---|---|
| `local://<pfad>` | `git clone --mirror` | ja: Refs, Objekte, Tags, Signaturen |
| `gitlab://<host>/<gruppe>/<projekt>` | `git clone --mirror` **plus** die Projekt-Einstellungen von Hand | Inhalt ja, Einstellungen nein |
| `github://…` | wie GitLab | wie GitLab |
| `self` (ER1) | kein Registry-Export im Werkzeug, siehe Abschnitt 4 | nein |

## Warum nicht einfach das Verzeichnis kopieren

Ein `cp -r` über ein bare-Repo, in das gerade geschrieben wird, ergibt eine
Sicherung mit halb geschriebenen Objekten, und man merkt es erst beim Restore.
`git clone --mirror` liest über die git-Objektschicht und ist gegen einen
parallelen Push abgesichert. Zusätzlich prüft `git` beim Klonen die Prüfsummen
aller Objekte: eine Sicherung, die durchläuft, ist damit auch verifiziert.

## 1. Backend `local://`

### Sichern

```bash
git clone --mirror <registry>.git <backup>/<registry>-$(date +%F).git
```

Gemessen am 2026-09-07:

```
$ git clone --mirror /…/probe/skills.git /…/probe/backup-skills.git
Klone in Bare-Repository '/…/probe/backup-skills.git' ...
Fertig.
```

Eine bestehende Sicherung wird mit `git -C <backup>.git remote update` statt mit
einem neuen Klon aktualisiert; sie ist ein Mirror, also holt sie alle Refs.

### Wiederherstellen

```bash
git clone --mirror <backup>/<registry>-<datum>.git <registry>.git
```

### Der Fallstrick nach dem Restore

Der wiederhergestellte Klon zeigt auf die Sicherung zurück, und zwar als Mirror:

```
$ git -C <registry>.git config --get remote.origin.url
/…/probe/backup-skills.git
$ git -C <registry>.git config --get remote.origin.mirror
true
```

Ein `git push` in diesem Repo würde also den **Stand des produktiven Registry in
die Sicherung schreiben**. Das ist genau die falsche Richtung, wenn der Restore
unvollständig war. Deshalb gehört zum Restore der letzte Schritt:

```bash
git -C <registry>.git remote remove origin
```

### Zusätzlich: der einzeldateiige Schnappschuss

Für einen Transport ohne git-Server, für ein Air-Gap oder für eine Übergabe an
eine prüfende Person:

```bash
skillctl registry export --registry local://<registry>.git --out skills.bundle
```

Gemessen:

```
$ skillctl registry export --registry local:///…/probe/skills.git --out /…/probe/skills.bundle
exported registry snapshot: /…/probe/skills.bundle
  hand it to a peer; they review + verify with:
    skillctl registry ls --registry local:///…/probe/skills.bundle
    skillctl pull --registry local:///…/probe/skills.bundle   # §7 gauntlet verifies against THEIR trust roots
$ echo $?
0
```

Ein `.bundle` ist eine **lesbare** Momentaufnahme aller Refs in einer Datei; man
kann daraus lesen und pullen, aber nicht hineinveröffentlichen. Als Sicherung ist
es damit vollwertig und als Betriebsregistry unbrauchbar. Wiederherstellen:
`git clone --mirror skills.bundle <registry>.git`.

## 2. Backend `gitlab://` und `github://`

### Sichern

Der Inhalt geht genauso, nur mit einer URL statt eines Pfades:

```bash
git clone --mirror https://<host>/<gruppe>/skill-registry.git \
  <backup>/skill-registry-$(date +%F).git
```

Braucht der Klon einen Token, ist es der **Lesetoken** aus
[Teil A der Token-Routine](ops-registry-tokens.de.md#teil-a-eine-mitarbeiterin-richtet-ihre-maschine-ein-lesen).
Eine Sicherung ist ein Lesevorgang; es gibt keinen Grund, sie mit dem
Schreibtoken laufen zu lassen.

### Was der Klon NICHT mitnimmt

Das ist der Teil, den man im Ernstfall vermisst. Ein `--mirror`-Klon enthält
Refs und Objekte, sonst nichts. Diese Einstellungen sind beim Neuaufbau von Hand
zu setzen und gehören deshalb **schriftlich** neben die Sicherung:

| Einstellung | Warum sie zählt |
|---|---|
| **Standard-Branch** (`main`) | Ohne sie liest `skillctl` ein leeres Registry, ohne Fehler. Siehe unten. |
| Project Access Token (`skillctl-publish`, Maintainer, `write_repository`) | Ohne ihn kann niemand mehr veröffentlichen. Der Token selbst ist nicht sicherbar, er wird neu ausgestellt. |
| Mitglieder und Rollen | Wer lesen darf, entscheidet die Reichweite des Registry. |
| Branch-Schutz auf `main` | Verhindert, dass an der Historie vorbei geschrieben wird. |
| Sichtbarkeit (privat / intern) | Ein versehentlich öffentliches Registry ist ein eigener Vorfall. |

Die Zeilen zu den Token stehen ohnehin schon im Token-Register
([Teil C](ops-registry-tokens.de.md#teil-c-das-token-register)); die übrigen vier
gehören daneben.

### Wiederherstellen

```bash
# 1) leeres Projekt auf dem Server anlegen (ohne README, ohne Initialisierung)
# 2) Inhalt zurückspiegeln
git -C <backup>/skill-registry-<datum>.git push --mirror \
  https://<host>/<gruppe>/skill-registry.git
# 3) Standard-Branch im Projekt auf `main` setzen
# 4) Project Access Token neu ausstellen, Registerzeile schreiben
# 5) Mitglieder, Branch-Schutz, Sichtbarkeit nachziehen
```

**Schritt 3 ist nicht optional.** `git push --mirror` überträgt Refs, nicht
`HEAD`. Gemessen an einem lokalen Ziel, dessen Standard-Branch `master` hiess,
während das Registry auf `main` liegt:

```
$ git -C <quelle>.git push --mirror <ziel>.git
 * [new branch]      main -> main
 * [new tag]         demo-skill/v1.0.0 -> demo-skill/v1.0.0
$ skillctl registry ls --registry local://<ziel>.git
(no skills in registry)
$ echo $?
0
```

Die Daten sind vollständig angekommen, `skillctl` findet sie nur nicht, und der
Exit-Code ist 0. Nach `git -C <ziel>.git symbolic-ref HEAD refs/heads/main`
listet dasselbe Kommando das Bundle. In GitLab entspricht das
Projekt → Einstellungen → Repository → Standard-Branch.

**Gemessen ist hier der lokale Fall.** Der Klon und der Push über HTTPS gegen
eine echte GitLab-Instanz sind noch nicht gemessen; sie sind derselbe git-Befehl
mit einer anderen Gegenstelle, aber das ist eine Begründung und kein Nachweis.
Der Nachweis fällt mit dem Lauf D-8 in
[Teil D der Token-Routine](ops-registry-tokens.de.md#teil-d-der-nachweislauf-d-8).

## 3. Die Wiederherstellungsprobe

Eine Sicherung, die nie zurückgespielt wurde, ist eine Vermutung. Die Probe
läuft auf einer **Kopie**, nie auf dem produktiven Registry.

Gemessen am 2026-09-07 gegen ein Wegwerf-Registry mit einem admittierten und
attestierten Bundle:

```
$ git clone --mirror /…/probe/skills.git /…/probe/backup-skills.git
Klone in Bare-Repository '/…/probe/backup-skills.git' ...
Fertig.

$ rm -rf /…/probe/skills.git              # der Schadensfall

$ git clone --mirror /…/probe/backup-skills.git /…/probe/skills.git
Klone in Bare-Repository '/…/probe/skills.git' ...
Fertig.

$ skillctl registry ls --registry local:///…/probe/skills.git
skill                            version    latest digest                                                            gov      status
------------------------------------------------------------------------------------------------------------------------------------
demo-skill                       1.0.0      sha256:22a21798c2839aa9667cae701a95a1a5bbd76559e8f7ab2d7b4f69fa1a70a9b9  green    ok
$ echo $?
0

$ git -C /…/probe/skills.git config --get remote.origin.url
/…/probe/backup-skills.git
$ git -C /…/probe/skills.git remote remove origin
Hinweis: Ein Branch außerhalb der refs/remotes/ Hierachie wurde nicht gelöscht;
um diesen zu löschen, benutzen Sie:
  git branch -d master
$ git -C /…/probe/skills.git config --get remote.origin.url
$ echo $?
1
```

Der Digest ist in dieser Ausgabe **vollständig**, nicht gekürzt: `registry ls`
druckt ihn ungekürzt, und genau das braucht Prüfung 2.

Als Abnahmekriterien:

| # | Prüfung | Erwartet |
|---|---|---|
| 1 | `skillctl registry ls --registry <wiederhergestellt>` | dieselbe Zeilenzahl wie vor dem Schaden |
| 2 | Digest je Skill | **zeichengleich** mit dem Stand vor dem Schaden |
| 3 | `skillctl registry show <name> --registry <wiederhergestellt>` | dieselbe Ereignisfolge, Widerrufe eingeschlossen |
| 4 | `skillctl pull …` **mit den Vertrauenswurzeln von vor dem Schaden** (siehe unten) | derselbe Ausgang wie vor dem Schaden: `staged=1` je Skill, Exit 0, gleicher Digest |
| 5 | `git -C <wiederhergestellt> config --get remote.origin.url`, **nach** `remote remove origin` | keine Ausgabe, Exit 1; direkt nach dem Mirror-Klon steht dort noch die Sicherung, siehe der Fallstrick oben |

Prüfung 2 ist die eigentliche. Ein Restore, der die Bundles hat, aber andere
Digests, hat die Signaturen gebrochen, und jede Maschine der Flotte wird das
Registry ab dann ablehnen.

### Prüfung 4 braucht eine Voraussetzung, sonst misst sie den Prüfenden

Prüfung 4 läuft dieselben Tore wie eine Konsumentin, und genau deshalb hängt ihr
Ausgang **nicht nur am Registry**, sondern an den Vertrauenswurzeln der Maschine,
auf der sie läuft. Drei gemessene Ausgänge, alle drei gegen dasselbe, korrekt
wiederhergestellte Registry:

Alle drei Läufe sind derselbe Aufruf, nur das `$HOME` ist ein anderes:

```bash
skillctl pull --registry local://<wiederhergestellt> --skill demo-skill \
  --install --trust-mode --dry-run-install
```

```
# 1) HOME ohne trust-roots.yaml und ohne Peer-Pin
pull: load trust-roots: trust-roots: open /…/.claude/trust-roots.yaml: open /…/.claude/trust-roots.yaml: no such file or directory
       Carry ~/.claude/trust-roots.yaml from machine 1 (10-keygen-and-trustroots.sh), or pin the peer with `skillctl peer add`.
$ echo $?
2

# 2) ein FREMDER Schlüssel gepinnt
    ❌ demo-skill@1.0.0  digest=sha256:22a21798c283…  [gate 1: envelope_signature does not verify against trust-roots] registry: envelope_signature does not verify
==> done. staged=0  skipped=1
[…]
$ echo $?
12

# 3) die Wurzeln von vor dem Schaden
    ✅ demo-skill@1.0.0  digest=sha256:22a21798c283…  gov=green  →  /…/skill-bundles/22a21798c283…/bundle.skb
==> done. staged=1  skipped=0
$ echo $?
0
```

Der Digest ist in allen drei Läufen derselbe, auch im abgelehnten: Tor 1 prüft
die Signatur, nicht den Inhalt. Ein `❌` ist deshalb kein Beweis, dass der
Restore die Bytes verloren hat.

Nur der dritte Lauf sagt etwas über den Restore. Die ersten beiden sagen etwas
über die Maschine des Prüfenden. Prüfung 4 ist deshalb nur dann ein Nachweis,
wenn zwei Dinge gelten:

1. Sie läuft mit **derselben** `~/.claude/trust-roots.yaml` beziehungsweise
   demselben `skillctl peer add`-Pin wie vor dem Schaden. Ein frisches `$HOME`,
   ein anderer Rechner oder eine geliehene Maschine erfüllen das nicht.
2. Der Ausgang von **vor** dem Schaden ist notiert. "Die Tore laufen durch" ist
   ohne diesen Vergleichswert eine Erwartung, kein Nachweis; und ein Pull, der
   auch vorher schon an Tor 4 hängen blieb, tut es nachher genauso.

Wer die Probe auf einer Maschine ohne diese Wurzeln fahren muss, protokolliert
das Ergebnis von Prüfung 4 als **nicht erhoben** und stützt die Abnahme auf die
Prüfungen 1 bis 3 und 5. Das ist ehrlicher als eine grüne Zeile, die den
Prüfenden misst.

Ein sinnvoller Takt: die Probe bei jeder Rotation eines Registry-Schlüssels und
mindestens einmal je Quartal, protokolliert mit Datum und der Ausgabe von
Prüfung 1 und 2.

## 4. Backend `self` (ER1): was hier fehlt

**Es gibt keinen Registry-Export für `self`.** Gemessen am 2026-09-07:

```
$ skillctl registry export --registry self --out /tmp/x.bundle
registry export: --registry must be local://<path> (got "self")
$ echo $?
2

$ skillctl registry init --registry self
registry init: only local:// registries are created locally (got "self").
  For gitlab://github:// create the project on the server; for ER1 use the self tenant.
$ echo $?
2
```

`registry export` ist ausschliesslich `local://`. Für `self` gibt es damit
weder ein Anlegen noch eine Sicherung durch dieses Werkzeug. Wer ein
`self`-Registry sichern will, hat heute zwei Wege, und beide sind Teilwege:

**(a) Bundle für Bundle, mit `export-bundle`.** Das ist das, was das Werkzeug
kann. Es schreibt das versendbare Paar aus Artefakt und Umschlag, und es prüft
die Kette, bevor es schreibt:

```bash
skillctl registry ls --registry self          # die Liste, die gesichert werden soll
skillctl export-bundle <name>@<version> --out <backup>/
# schreibt <name>@<version>.skb + <name>@<version>.skbmeta.json
```

Das sichert die **Artefakte**. Es sichert **nicht** die Zeitleiste: Attestierungen
und Widerrufe sind eigene Ereignisse im ER1-Kontext und liegen nicht im Paar.
Ein Restore daraus ist ein Neuaufbau durch erneutes `publish`, keine
Wiederherstellung.

**(b) Auf der ER1-Seite sichern.** Das Registry `self` ist der Kontext
`<sub>___skills` der ER1-Anmeldung. Die vollständige Sicherung ist damit eine
Sicherung des ER1-Mandanten und gehört zum Betrieb von aims-core, nicht zu
`skillctl`. Dieses Runbook beschreibt sie nicht, weil sie hier nicht gemessen
werden konnte.

**Die ehrliche Empfehlung.** Wer eine Sicherung braucht, die im Ernstfall
zurückspielbar ist, betreibt das Registry git-gestützt. `self` ist für die
persönliche Nutzung und für kleine Teams gedacht und trägt dieses Merkmal an
dieser Stelle sichtbar.

## 5. Was dieses Runbook nicht löst

**Keine automatische Sicherung.** `skillctl` sichert nichts von selbst. Der
`git clone --mirror` gehört in eine geplante Aufgabe (launchd, cron, ein
CI-Job), und dass sie läuft, muss jemand prüfen; siehe
[Monitoring und Alarmierung](ops-monitoring.de.md).

**Keine Sicherung der Projekt-Einstellungen.** Die Tabelle in Abschnitt 2 ist
eine Handarbeitsliste. Nichts prüft nach, ob sie gepflegt ist.

**Keine Sicherung der Schlüssel.** Ein Registry ohne den zugehörigen privaten
Schlüssel ist lesbar, aber nicht mehr fortschreibbar. Die Schlüssel gehören
getrennt gesichert, offline, und ihr Verlust ist ein Rotationsfall, kein
Restore-Fall; siehe [Incident Response](ops-incident-response.de.md).

**Keine Sicherung für `self`.** Siehe Abschnitt 4. Das ist eine Lücke im
Werkzeug, kein Versäumnis des Betriebs.

## Verwandte Runbooks

| Runbook | Wofür |
|---|---|
| [Ops-Routine: Zugangstoken](ops-registry-tokens.de.md) | welcher Token die Sicherung ziehen darf |
| [Incident Response](ops-incident-response.de.md) | kompromittierter Schlüssel, kompromittiertes Registry |
| [Monitoring und Alarmierung](ops-monitoring.de.md) | woran sich eine Überwachung andocken kann |
