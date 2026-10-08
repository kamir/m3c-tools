# Ops-Runbook: ein Mensch-Agent-Team einrichten

Wie eine Führungskraft und eine Mitarbeiterin in einen Arbeitsmodus kommen, in
dem ein Agent mitarbeitet, und wie der erste selbstgebaute Skill von der einen
Maschine auf die andere gelangt, ohne dass irgendjemand dem Transportweg
vertrauen muss.

Zielgruppe: die Person, die das Team einrichtet. Die Mitarbeiterin, die danach
darin arbeitet, braucht dieses Dokument nicht. Das ist der Zweck.

**Zum Lesen und Drucken** gibt es dieselbe Anleitung als Doku-Seite:
[`docs/v2/pages/ops-human-agent-team.html`](../pages/ops-human-agent-team.html). Sie
hat eine Abschnittsschiene, einen Kopierknopf an jedem Kommando und einen
Druck-Flavor, der jede Farbfläche auflöst. Erzeugt wird sie aus dieser Datei
mit `tools/docpage.sh`; maßgeblich bleibt diese Datei.

**Wo anfangen.** Wer das zum ersten Mal macht, beginnt bei
[Abschnitt 0, Voraussetzungen](#0-voraussetzungen), und arbeitet die Liste in
0.6 ab, bevor er weiterliest. Jede Zeile dort hat ein Kommando und eine
erwartete Ausgabe. Wer die Werkzeuge schon hat, springt zu Abschnitt 1.

## Inhalt

| Abschnitt | Für wen, wann |
|---|---|
| [0. Voraussetzungen](#0-voraussetzungen) | einmal je Maschine, vor allem anderen |
| [1. Die Reihenfolge](#1-die-reihenfolge-an-der-alles-hängt) | einmal lesen, bevor jemand etwas installiert |
| [2. Der Arbeitsraum](#2-der-arbeitsraum-auf-einer-maschine) | einmal je Person |
| [3. Die Rubriken](#3-warum-die-rubriken-wörtlich-dastehen) | wer moderiert oder berichtet |
| [4. Der Lebenszyklus A nach B](#4-der-skill-lebenszyklus-von-mensch-a-zu-mensch-b) | jedes Mal, wenn ein Skill übergeben wird |
| [5. Das gemeinsame Repository](#5-das-gemeinsame-repository-vom-ordner-nach-gitlab) | sobald GitLab dazwischen liegt |
| [6. Drei Dateien heißen Trust-Roots](#6-die-falle-drei-dateien-heißen-trust-roots) | wenn ein Pin da ist und trotzdem nichts geht |
| [7. Der Takt](#7-der-takt-von-manuellen-schritten-zum-skill) | die Führungskraft, laufend |
| [8. Wenn etwas fehlschlägt](#8-wenn-etwas-fehlschlägt) | im Fehlerfall, nach Exit-Code |
| [9. Was offen bleibt](#9-was-offen-bleibt) | wer den Umfang einschätzen muss |

## Das Ziel, das dieses Runbook trägt

**Enablement der Führungskraft und der Mitarbeiterin für Mensch-Agent-Zusammenarbeit
im Compliance-Kontext.**

Das Ziel ist nicht, ein Werkzeug auszurollen. Es ist erreicht, wenn vier Sätze
zutreffen, und jeder von ihnen ist an etwas prüfbar, das auf einer Platte liegt:

| Kriterium | Woran es geprüft wird |
|---|---|
| Z1: Beide führen ein Arbeitslog, das ein Agent lesen kann | `contexts/*/wlog/` enthält datierte Dateien mit den vier Rubriken |
| Z2: Beide halten die Reflexion über die Arbeitsweise getrennt vom Inhalt | `contexts/*/reflections/` ist nicht leer und enthält keine Fachgeheimnisse |
| Z3: Aus drei Durchläufen ist ein Skill geworden, nicht eine Prompt-Sammlung | ein `.skb` existiert, gepackt aus dem, was in `reflections/` steht |
| Z4: Der Skill wechselt die Maschine mit prüfbarer Herkunft | `.m3c-provenance.json` auf der Zielmaschine nennt Fingerabdruck und Freigabestufe |

Z4 ist der Teil, den das Werkzeug erledigt. Z1 bis Z3 sind der Teil, an dem
Einführungen scheitern, und sie kommen zuerst.

## Was dieses Runbook ausdrücklich nicht behauptet

Es behauptet nicht, dass eine installierte Werkzeugkette jemanden befähigt.
Die Beobachtung, aus der dieses Dokument entstanden ist, war die umgekehrte:
ein Werkzeug auf der Maschine einer Person, die den Arbeitsmodus noch nicht
hat, ist ein zusätzlicher Schritt und damit ein Hindernis. Deshalb steht das
Werkzeug hier in Abschnitt 4 und nicht in Abschnitt 1.

Es behauptet auch nicht, eine Governance-Schicht zu beschreiben. Signieren,
Freigeben und Prüfen sind darin enthalten; die Anbindung an ein Policy-Gerüst,
an ein Datenschutz-Inventar und an ein SIEM ist es nicht. Abschnitt 9 sagt,
was offen ist.

## Wie weit dieses Runbook gemessen ist

Jeder Block, der mit "Gemessen" beginnt, ist am 2026-09-16 gelaufen. Das Binary
war ein lokaler Bau aus `origin/master` (`af9e1d5`), es meldet sich als
`skillctl dev (darwin/arm64, go1.26.6)`, und es ist **nicht** eine
veröffentlichte Fassung. Wer gegen ein Release prüft, prüft ein anderes Objekt;
dann gilt die Zeile, nicht die Erinnerung an sie.

Die Läufe fanden gegen zwei Wegwerf-`HOME`-Verzeichnisse und eine
Wegwerf-Registry im Dateisystem statt. Kein Netz, kein Server, keine echten
Schlüssel. Pfade sind mit `/…/` gekürzt, der Rechnername ist entfernt.

Die Besetzung ist die des Hauses: **Bob** baut und gibt heraus, **Alice**
bekommt. In einer echten Einführung ist Bob die Führungskraft, die ihre eigene
Arbeitsweise zuerst an sich selbst erprobt, und Alice die Person, an die sie
übergibt.

## 0. Voraussetzungen

Dieser Abschnitt ist für die Person geschrieben, die das noch nie gemacht hat.
Er nennt jede Voraussetzung, wer sie herstellt, und das Kommando, mit dem man
prüft, ob sie da ist. Wer alle Kästchen in 0.6 abhaken kann, kann bei
Abschnitt 1 anfangen.

### 0.1 Wer was tut

Drei Rollen, und sie können auf zwei Personen fallen. Die dritte ist oft
dieselbe Person wie die erste; sie ist trotzdem getrennt aufgeführt, weil sie
eine andere Entscheidung trifft.

| Rolle | Wer das typischerweise ist | Tut |
|---|---|---|
| **Autor** (A, im Text "Bob") | die Führungskraft, die ihre eigene Arbeitsweise zuerst selbst erprobt | Skill bauen, packen, signieren, aufnehmen |
| **Freigeber** | im Vier-Augen-Prinzip eine zweite Person | `publish --attest`: sagt, auf welcher Stufe der Skill benutzt werden darf |
| **Empfänger** (B, im Text "Alice") | die Mitarbeiterin | Schlüssel pinnen, ziehen, installieren, benutzen |

Zusätzlich, einmalig und außerhalb dieses Runbooks: **die IT** legt das
GitLab-Projekt an (0.3) und vergibt die Zugänge.

### 0.2 Was auf jeder Maschine liegen muss

| Was | Wofür | Prüfen mit | Erwartet |
|---|---|---|---|
| `git` | die Registry **ist** ein Git-Repository | `git --version` | eine Versionszeile |
| `curl` und `openssl` | der Installer holt und prüft | `curl --version`, `openssl version` | je eine Versionszeile |
| `skillctl` | alles in Abschnitt 4 | `skillctl version` | `skillctl/vX.Y.Z`, **nicht** `dev` |
| Claude Code | der Agent, der die Skills benutzt | `claude --version` | eine Versionszeile |
| Zugang zum GitLab-Projekt | ziehen und schieben | `git ls-remote <url>` | eine Liste von Refs, keine Passwortfrage ins Leere |

**skillctl installieren.** Eine Zeile, sie holt das Binary, prüft die Signatur
über `SHA256SUMS` und danach die Prüfsumme des Binaries selbst:

```bash
# macOS und Linux
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/6f517440e7edf64c74f0f625a46291769d086f98/tools/skillctl-install.sh | bash
```

```powershell
# Windows
irm https://raw.githubusercontent.com/kamir/m3c-tools/6f517440e7edf64c74f0f625a46291769d086f98/tools/skillctl-install.ps1 | iex
```

**Die Bytes, bevor man sie in eine Shell kippt.** Die URL ist auf den
unveränderlichen Commit `6f51744` gepinnt und nicht auf `master`, denn ein
Zweig lässt sich umschreiben. Wer die Datei erst herunterlädt und prüft, statt
sie durchzuleiten, erwartet diese SHA-256:

- `tools/skillctl-install.ps1` → `a00826f30599439718f5ea126f81b8a78b4c28aa96980e1b136db65396a34177`
- `tools/skillctl-install.sh` → `dea4b86b78d20eeff28524240034efcb0c96c35016238434a8e7c97c7278dabc`

Der [README-Abschnitt Install](../../../README.md#install) hat das Rezept dafür zum
Kopieren. Wer den Einzeiler durchleitet, verzichtet auf diese Probe; das ist
eine Entscheidung und kein Versehen.

**Danach unbedingt `skillctl version` aufrufen und den Wert mit dem
vergleichen, den das Team festgelegt hat.** Gemessen am 2026-09-16: der oben
gepinnte Commit installiert `skillctl/v0.4.0`. Dieselbe Datei auf `master`
trägt keine eingebackene Fassungsvorgabe mehr: sie löst zur Laufzeit die
neueste veröffentlichte `skillctl/v*`-Marke auf (über den Releases-Atom-Feed;
ohne Token, ohne Rate-Limit, und bewusst nicht über `/releases/latest`, denn
das liefert das neueste Release des ganzen Repositories, oft ein Produkt-`v*`
und kein skillctl). Schlägt diese Auflösung fehl, bricht der Installer ab und
verlangt eine ausdrückliche Fassung; auf eine ältere Marke fällt er nicht
still zurück. Der gepinnte Commit und die SHA-256 oben ändern sich damit nur
noch, wenn das Installer-Skript selbst sich ändert, nicht mehr bei jedem
Release. Der Pin-Prüfer des Repositories prüft, dass der Pin auflöst und die
Bytes stimmen, nicht welche Fassung dabei herauskommt. Wer eine bestimmte
Fassung braucht, gibt sie an:

```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/6f517440e7edf64c74f0f625a46291769d086f98/tools/skillctl-install.sh \
  | RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.5.1 bash
```

Der Installer warnt dann laut, dass `RELEASE_BASE` gesetzt wurde. Das ist
Absicht und kein Fehler: die Zeile verschiebt den Vertrauensanker, und
deswegen sagt sie es.

Wenn `skillctl version` nach der Installation nicht gefunden wird, liegt das
Binary in `~/.local/bin`, und dieses Verzeichnis fehlt im Suchpfad. Dann
einmalig in die Shell-Konfiguration:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 0.3 Das Skill-Repository anlegen

Die Registry ist ein Git-Repository. Für ein Team, das sie teilt, liegt sie
auf der internen GitLab-Instanz.

**Sie bekommt ein eigenes Projekt, und das Projekt ist leer.** Nicht ein
vorhandenes mitbenutzen, nicht einen Ordner in einem Projekt, das noch etwas
anderes tut. Der Grund steht im Kasten unten und ist nicht verhandelbar: der
erste Push ersetzt alles, was im Zielzweig liegt.

| Frage | Antwort |
|---|---|
| Wer legt es an | die IT oder wer im Namensraum Projekte anlegen darf |
| Wo | die interne GitLab-Instanz, in einer Gruppe, die beide Seiten sehen |
| Sichtbarkeit | privat |
| Standardzweig | `main` |
| Wer darf schreiben | nur der Autor. Alle anderen lesen |
| Wie es heißen sollte | ein Name, der sagt, dass es eine Registry ist, zum Beispiel `skill-registry` |
| Was es sonst enthält | **nichts.** Kein README, keine CI-Datei, keine Issues-Vorlage |

> **Das Projekt muss leer sein, ohne README und ohne CI-Datei.** Das ist keine
> Stilfrage. Der Weg vom lokalen Ordner nach GitLab ist `git push --mirror`,
> und `--mirror` bedeutet: der Zustand des Ziels wird durch den der Quelle
> **ersetzt**. Gemessen am 2026-09-16 gegen ein Projekt, das `README.md` und
> `.gitlab-ci.yml` auf `main` hatte: nach dem Push meldete git
> `+ ffbaeef...f0e85f1 main -> main (forced update)`, und beide Dateien waren
> weg. Wer beim Anlegen "README hinzufügen" ankreuzt, hat sich diese Falle
> gestellt.

**Beim Anlegen in GitLab konkret:** im Formular *New project* bleibt
"Initialize repository with a README" **ungekreuzt**, und die
Sicherheits-Häkchen (SAST und Verwandte) bleiben es ebenfalls, denn sie legen
eine `.gitlab-ci.yml` an. Sichtbarkeit privat, Standardzweig `main`. Das
Projekt soll nach dem Anlegen die Seite "The repository for this project is
empty" zeigen. Zeigt es stattdessen eine Dateiliste, ist es das falsche
Projekt für diesen Zweck.

Ist ein Projekt schon mit README oder CI angelegt worden, ist der saubere Weg
**ein zweites, leeres Projekt nur für die Registry**. Die vorhandenen Dateien
zu löschen funktioniert auch, verbraucht aber eine Entscheidung darüber, was
mit dem alten Projekt geschieht, und die vergisst man. Was **nicht**
funktioniert, ist zu hoffen, dass `--mirror` sie stehen lässt.

**Zwei Registries, und nur eine davon darf jemand abräumen.** Wer übt, übt
nicht auf der Ablage, aus der Maschinen installieren. Deshalb gibt es zwei
Projekte, und der Unterschied gehört in ihre Namen:

| Projekt | Rolle | Darf geleert werden |
|---|---|---|
| `<name>-test` | zum Üben und für automatische Läufe; wird aus Tests neu befüllt | **ja**, jederzeit, das ist ihr Zweck |
| `<name>` | der Betrieb; hieraus installieren die Maschinen | **nein** |

Die Gefahr kommt aus derselben Ecke wie oben: `push --mirror` ersetzt das Ziel.
Wer im Übungsordner steht und die Betriebs-URL angibt, ersetzt den Betrieb durch
seinen Übungsstand, und der Push meldet dabei Erfolg. Die Gegenmaßnahme steht in
5.1 und ist banal: die URL steht im Ordner, nicht in der Kommandozeile.

Eine Test-Registry zu leeren ist kein Unfall, sondern ein Arbeitsschritt. Sie
darf deshalb auch dann neu angelegt werden, wenn sie schon Inhalt hat: bei ihr
ist der `--mirror`-Ersatz genau das Gewünschte.

**Zugang.** Wer über HTTPS arbeitet, braucht ein Token; wer über SSH arbeitet,
einen hinterlegten Schlüssel. Welches Token, wer es besorgt, wo es liegt und was
beim Ausscheiden passiert, steht vollständig in
[Ops-Routine: Zugangstoken](ops-registry-tokens.de.md). Dieses Runbook wiederholt
es nicht.

Die Probe, dass der Zugang steht, vor allem anderen:

```bash
git ls-remote https://git.example.internal/gruppe/skill-registry.git
```

Für ein frisch angelegtes, leeres Projekt ist die erwartete Ausgabe
**gar keine**, bei Exit 0. Das ist zugleich die Probe aus 5.1: keine Ausgabe
heißt leer, und leer heißt, dass der erste Push nichts überschreiben kann. Eine
Fehlermeldung über Authentifizierung heißt: zurück zur Token-Routine, und nicht
weiter.

```
$ git ls-remote https://git.example.internal/gruppe/skill-registry.git
$ echo $?
0
```

### 0.4 Die Identitäten festlegen

Jede Person bekommt eine Identität in der Form `id:<name>@<organisation>`. Sie
ist kein Etikett, sondern der Wert, unter dem der Empfänger den Schlüssel pinnt
und den die Signaturzeile eines Bundles trägt. Stimmen beide nicht überein,
findet der Prüfer den Schlüssel nicht und lehnt ab.

Deshalb gilt: **die Identitäten werden einmal aufgeschrieben, bevor jemand
einen Schlüssel erzeugt**, und beide Seiten lesen dieselbe Zeile.

| Person | Identität | Wird gebraucht bei |
|---|---|---|
| Autor | `id:bob@example` | `sign --identity-id`, `publish --identity` |
| Empfänger | `id:alice@example` | nur, wenn auch sie veröffentlicht |

Ein Suffix, das die Zugehörigkeit sagt, ist eine gute Angewohnheit: wer als
externer Partner auftritt, sollte nicht aussehen wie eine interne Rolle.

### 0.5 Die Schlüssel erzeugen und den öffentlichen teilen

Das Einrichtungsskript aus Abschnitt 2 erzeugt das Schlüsselpaar mit; wer es
von Hand tun will, tut es so:

```bash
skillctl keygen --out ~/.config/m3c/mein-autorenschluessel
```

Zwei Dateien entstehen, und die Unterscheidung ist die wichtigste dieses
Abschnitts:

| Datei | Rechte | Was damit geschieht |
|---|---|---|
| `…priv` | 0600 | **bleibt auf der Maschine.** Niemals per Mail, Chat, Ticket oder in ein Repository |
| `…pub` | 0644 | **darf jeden Weg nehmen.** Genau dafür ist er da |

Die Übergabe läuft über **zwei Kanäle**, und das ist der Kern des Verfahrens:

1. **Kanal 1, bequem:** die `.pub`-Datei per Mail, Teams, geteiltem Ordner oder
   USB-Stick. Der Weg muss nicht sicher sein.
2. **Kanal 2, mündlich:** der Autor lässt sich den Fingerabdruck anzeigen und
   liest ihn am Telefon vor.

```bash
skillctl trust fingerprint ~/.config/m3c/mein-autorenschluessel.pub
sha256:8e19d51c27db47f6851d54a4d4e206c668fd95cf13b29569a6b5c57a2cc8b471
```

Der Empfänger lässt sich denselben Wert aus der Datei anzeigen, die bei ihm
angekommen ist, und vergleicht Zeichen für Zeichen.

> **Stimmt der Wert nicht überein, wird abgebrochen und nachgefragt, nicht
> "nochmal geschickt".** Eine Abweichung heißt, dass die Datei unterwegs eine
> andere geworden ist. Genau dagegen ist der zweite Kanal da, und deshalb nimmt
> `--pin` den Wert zwingend: es gibt kein Vertrauen beim ersten Kontakt.

Eine Zahl reicht für beide Pins. Nachgeprüft am 2026-09-16: derselbe
Fingerabdruck ging an `trust add-author --pin` und an `peer add --pin`, und
beide bestätigten ihn als `matched`. Am Telefon wird also eine Zeile
vorgelesen, nicht zwei.

**Was der Autor sonst noch tut:** den privaten Schlüssel sichern, an einem Ort,
der nicht dieselbe Platte ist. Geht er verloren, ist keine der bisherigen
Signaturen ungültig, aber es kann nichts Neues mehr unter dieser Identität
signiert werden, und der Empfänger muss einen neuen Schlüssel pinnen. Das ist
kein Notfall, aber es ist ein Telefonat.

### 0.6 Bereit, wenn

Beide Seiten haken einzeln ab. Jede Zeile hat ein Kommando, keine Meinung.

| # | Auf welcher Maschine | Prüfung | Erwartet |
|---|---|---|---|
| V1 | beide | `git --version` | eine Versionszeile |
| V2 | beide | `skillctl version` | die Fassung, die das Team festgelegt hat |
| V3 | beide | `skillctl doctor` | `USABLE`, offene Schritte sind erlaubt |
| V4 | beide | `git ls-remote <registry-url>` | Exit 0 |
| V5 | Autor | `ls -l …priv` | Modus `-rw-------` |
| V6 | Autor | `skillctl trust fingerprint …pub` | ein `sha256:`-Wert |
| V7 | Empfänger | derselbe Wert, am Telefon abgeglichen | zeichenweise gleich |
| V8 | beide | die Identitäten liegen aufgeschrieben vor | zwei Zeilen `id:…@…` |

`skillctl doctor` ist dabei der Freundlichste der acht: er sagt zu jeder Zeile,
was zu tun ist, und `todo` ist kein Fehler.

Das `dev` in der ersten Zeile gehört zum Messaufbau dieses Runbooks (Abschnitt
"Wie weit dieses Runbook gemessen ist") und ist auf einer eingerichteten
Maschine eine echte Fassungsnummer:

```
$ skillctl doctor
ok    version      skillctl dev (darwin/arm64, go1.26.6)
ok    home         /Users/… ($HOME)
todo  skills dir   /…/.claude/skills does not exist yet
                   -> it is created by the first `skillctl install`
ok    trust roots  /…/.claude/skill-trust-roots.yaml (1 registry/ies, 1 pinned, 0 from-registry)
todo  peers        no pinned peers
--------------------------------------------------------------
USABLE, 4 step(s) not done yet. Nothing here is broken.
```

## 1. Die Reihenfolge, an der alles hängt

Erst die Arbeitsweise, dann das Werkzeug. Die Begründung ist kein Geschmack:

Eine Person, die Agenten noch nicht benutzt hat, bekommt eine fachlich große
Aufgabe und dazu ein neues Werkzeug. Sie kann das Alte nicht mehr guten
Gewissens tun und das Neue noch nicht. Was dabei herauskommt, ist langsamer als
vorher, und die Schuld bekommt das Werkzeug.

Der Ausweg ist die kleinste mögliche Übung, die nichts mit der Fachaufgabe zu
tun hat: ein Arbeitslog führen, am Tagesende drei Fragen beantworten, und das
Ergebnis in eine Datei schreiben. Erst wenn das Routine ist, hat die Person die
Erfahrung, aus der später ein Skill wird.

**Die drei Ebenen, die getrennt bleiben müssen.** Ohne diese Trennung ist keine
Methodik übergebbar, weil der Inhalt es nicht ist:

| Ebene | Was es ist | Übergebbar |
|---|---|---|
| rot | der fachliche Inhalt, oft vertraulich | nein |
| grau | die Arbeitsweise, der Doku-Flow | **ja, das ist der Skill** |
| blau | die Prüfung: wurde der Zweck erreicht | ja, als Kriterium |

Wer die Einführung eines vertraulichen Verfahrens dokumentiert, dokumentiert
rot. Wer aufschreibt, welche Fragen er wem gestellt hat und in welcher
Reihenfolge, dokumentiert grau. Nur grau verlässt die Abteilung.

## 2. Der Arbeitsraum auf einer Maschine

Ein Skript legt ihn an, in einer von zwei Rollen. Es installiert `skillctl`
nicht, es geht nicht ins Netz, und es entscheidet nicht, was jemand darf.

```bash
tools/team-base-setup.sh author --id id:bob@example --contexts isms,cra,grc
tools/team-base-setup.sh member --author-id id:bob@example \
    --author-key bob.pub --pin sha256:<am-telefon-abgeglichen> \
    --peer-registry local:///pfad/zur/registry
tools/team-base-setup.sh check
```

Was entsteht, ist je Kontext ein Vierklang, und die vier Ordner sind die vier
Stationen der Schleife:

```
<arbeitsraum>/
  CLAUDE.md                      die Hausregeln, die der Agent jede Sitzung liest
  contexts/<kontext>/
    inbox/                       Rohmaterial: Transkripte, Notizen, Exporte
    wlog/                        ein Arbeitslog je Tag
    reports/                     die Aggregate, die der Agent schreibt
    reflections/                 was über die ARBEITSWEISE gelernt wurde
  skills/    bundles/    keys/   nur in der Rolle author
```

`reflections/` ist der Ordner, den alle auslassen, und der einzige, aus dem
später ein Skill wird. Ohne ihn bleibt das Arbeitslog ein Tagebuch.

**Gemessen, Rolle author.** Ein Lauf, gekürzt:

```
$ tools/team-base-setup.sh author --id id:bob@example --workspace /…/ws-bob --contexts isms,cra,grc
role: author, identity id:bob@example
  ok      context isms (inbox, wlog, reports, reflections)
  ok      context cra (inbox, wlog, reports, reflections)
  ok      context grc (inbox, wlog, reports, reflections)
  ok      CLAUDE.md (the house rules the agent reads on every session)
  ok      .gitignore (keys and bundles never reach a remote by accident)
  ok      skills/, bundles/, keys/ (keys/ mode 0700)
wrote /…/ws-bob/keys/author.priv (mode 0600)
wrote /…/ws-bob/keys/author.pub (mode 0644)

Read this fingerprint aloud on a call. It is what the other side pins:
sha256:8e19d51c27db47f6851d54a4d4e206c668fd95cf13b29569a6b5c57a2cc8b471
```

Ein zweiter Lauf erzeugt **kein** neues Schlüsselpaar. Das ist Absicht: ein
neuer Schlüssel macht jedes bereits signierte Bundle herrenlos.

**Gemessen, Rolle member.** Der Fingerabdruck oben ist der Wert, der am Telefon
vorgelesen wird, und `--pin` nimmt genau ihn:

```
$ tools/team-base-setup.sh member --workspace /…/ws-alice --contexts isms \
    --author-id id:bob@example --author-key /…/author.pub \
    --pin sha256:8e19d51c… --peer-registry local:///…/reg2
role: member
  ok      context isms (inbox, wlog, reports, reflections)
added registry https://author.example/api/skills to /…/.claude/skill-trust-roots.yaml
pinned author id:bob@example under https://author.example/api/skills
You can now verify and install bundles this author signed, offline.
pinned peer "bob@example" → local:///…/reg2
  fingerprint: sha256:8e19d51c… (matched)
  ok      peer pinned: pull works against local:///…/reg2
```

Zum Schluss fragt das Skript `skillctl doctor`, weil eine Einrichtung, die sich
selbst für gelungen erklärt, nichts belegt.

## 3. Warum die Rubriken wörtlich dastehen

Ein Bericht trägt vier Überschriften, und zwar diese Wörter, nicht ihre
Synonyme:

```
## Progress
## Plans
## Problems
## Proposals
```

Das ist kein Formalismus. Ein System, das die Rubrik raten muss, interpretiert;
ein System, das sie liest, extrahiert. Wer die Wörter weglässt, zwingt die
Maschine zur Spekulation und nennt das Ergebnis später Halluzination.

Dasselbe gilt für eine Besprechung mit Transkript: die Rubriken werden im
Gespräch **ausgesprochen**, sonst kann sie hinterher niemand trennen. Das ist
eine Aufgabe für die Moderation, nicht für die Nachbearbeitung.

Die vierte Rubrik, **Proposals**, fehlt in der geläufigen Dreierform. Sie wird
von Anfang an mitgeführt, weil die Person mit der Beobachtung meistens auch die
mit dem Vorschlag ist, und weil ein Vorschlag, der nirgends hingehört, nicht
aufgeschrieben wird.

## 4. Der Skill-Lebenszyklus von Mensch A zu Mensch B

Sechs Schritte. Der viertletzte ist der, an dem ein Mensch entscheidet, und der
letzte ist der, den ein Runbook gern vergisst.

| # | Schritt | Wer | Kommando | Was es beweist |
|---|---|---|---|---|
| 1 | bauen | Autor | (kein Kommando) | der Skill entsteht aus `reflections/`, nicht am Reißbrett |
| 2 | prüfen | Autor | `skillctl pack` zweimal | zwei Läufe, Byte für Byte gleich |
| 3 | bündeln | Autor | `skillctl sign`, `skillctl verify-sig` | die eigene Arbeit ist geprüft, bevor sie weggeht |
| 4 | herausgeben | Autor, dann Freigeber | `skillctl publish`, dann `publish --attest` | Aufnahme und Freigabe sind zwei Vorgänge |
| 5 | übernehmen | Empfänger | `skillctl pull --install` | Herkunft und Freigabestufe liegen neben dem Skill |
| 6 | benutzen | Empfänger | `/<name>` in Claude Code | der Skill läuft, statt nur auf der Platte zu liegen |

Alles darunter setzt Abschnitt 0 voraus. Wer hier anfängt, ohne V1 bis V8
abgehakt zu haben, scheitert an Schritt 3 oder an Schritt 5, und die Meldung
sagt dann etwas über Schlüssel, nicht über die Voraussetzung, die fehlt.

### 4.1 Bauen und prüfen

Der erste Skill ist klein. Er fasst die Woche zusammen, die im Arbeitslog
steht, und er tut nichts anderes.

**Gemessen.**

```
$ skillctl pack --skill /…/ws-bob/skills/wochenbericht -o /…/wochenbericht@1.0.0.skb \
    --name wochenbericht --version 1.0.0 --summary "…" \
    --author-intent green --author-intent-rationale "Liest lokale Dateien, schreibt eine lokale Datei. Kein Netz, kein Unterprozess."
bundle_digest: sha256:e48dc720…  (manifest digest; NOT the value attest/publish/revoke take)
output:        /…/ws-bob/bundles/wochenbericht@1.0.0.skb
exit=0
zweimal gepackt: byte-gleich
```

`--author-intent` ist die Selbstauskunft des Autors, nicht die Freigabe. Wer
hier `green` schreibt, sagt, was der Skill tut; wer in Abschnitt 4.3 `--level green`
schreibt, sagt, dass er ihn dafür freigibt. Zwei verschiedene Aussagen, und in
einem Audit zwei verschiedene Personen.

**Achtung, zwei Prüfsummen.** `pack` druckt eine Manifest-Prüfsumme, `sign`
druckt die Bundle-Prüfsumme. Nur die zweite geht in `--digest`. Das Werkzeug
sagt es in beiden Ausgaben dazu, weil die Verwechslung sonst erst bei `attest`
auffällt.

### 4.2 Signieren, und die eigene Arbeit prüfen

**Gemessen.**

```
$ skillctl sign --key /…/keys/author.priv --identity-id id:bob@example /…/wochenbericht@1.0.0.skb
digest: 6e86343a606ef95d9a8d6c60cd5f366de2815e9fc317c5745b9b53bc11b9fe43
        ^ bundle digest: use this for `attest`, `publish --digest` and `revoke --digest`
signature: /…/wochenbericht@1.0.0.skb.6e86343a….author.sig
exit=0

$ skillctl verify-sig --pubkey /…/keys/author.pub /…/wochenbericht@1.0.0.skb
OK: signature verified
exit=0
```

Der zweite Aufruf prüft die eigene Arbeit gegen den eigenen Schlüssel. Er
kostet eine Sekunde und trennt später zwei Fehlerbilder, die sonst gleich
aussehen: ein Fehler beim Packen und ein Fehler auf dem Transportweg.

### 4.3 Die Registry ist ein Ordner

Für zwei Menschen braucht es keinen Server. Ein Git-Repository genügt, und das
Werkzeug legt es an.

**Gemessen.**

```
$ skillctl registry init --registry local:///…/reg2
initialized local skill registry: /…/reg2
  publish:  skillctl publish <skill> --registry local:///…/reg2 ...
  pull:     skillctl pull --registry local:///…/reg2
  push up:  git -C /…/reg2 push --mirror <gitlab-or-github-url>
exit=0
```

Die letzte Zeile ist der Weg in den Betrieb: derselbe Ordner, auf eine interne
GitLab-Instanz gespiegelt, ist die Skill-Ablage des Unternehmens. Damit gilt
über Skills dieselbe Nachvollziehbarkeit wie über Quelltext, ohne dass dafür
etwas Neues gebaut werden muss.

Diese eine Zeile hat drei Fallen, und alle drei treffen den, der sie zum ersten
Mal ausführt. [Abschnitt 5](#5-das-gemeinsame-repository-vom-ordner-nach-gitlab)
fährt sie einzeln vor. Wer heute nur zu zweit auf einer Maschine übt, braucht
sie noch nicht.

**Aufnehmen und freigeben sind zwei Vorgänge.**

```
$ skillctl publish wochenbericht@1.0.0 --registry local:///…/reg2 \
    --bundle /…/wochenbericht@1.0.0.skb --key /…/author.priv \
    --identity id:bob@example --version 1.0.0 --yes
==> publish (admit) wochenbericht@1.0.0
    digest:    sha256:6e86343a…
    transport: git (in-repo blob)
    identity:  id:bob@example
==> admitted: wochenbericht/v1.0.0  transport=git  registry=local:///…/reg2
exit=0
```

`--identity` ist keine Formalie, und sie ist erforderlich: einen Vorgabewert
gibt es bewusst nicht. Ohne die Flagge bricht der Befehl mit Ausstieg 2 ab, und
die Meldung nennt die Flagge samt Beispiel. Eine Identität ist eine Behauptung
darüber, WER veröffentlicht, und die kann kein Werkzeug raten; ein plausibler
Vorgabewert hätte einen fremden Namen in ein signiertes Ereignis gestempelt,
und die Gegenseite hätte eine Ablehnung bekommen, die auf die falsche Stelle
zeigt.

**Was ohne Freigabe passiert.** Aufgenommen ist nicht freigegeben, und das Tor
sagt das auch:

```
$ skillctl pull --registry local:///…/reg2
==> pull (registry=local:///…/reg2, gov-min=green)
    trust-roots: /…/.claude/skill-peers.yaml  fp=sha256:8e19d51c…
    peer:        bob@example (pinned key)

    ❌ wochenbericht@1.0.0  digest=sha256:6e86343a…  [gate 4: no attestation at or
       above the trust-roots governance_minimum] no signed attestation found for this digest

==> done. staged=0  skipped=1  (context: skills)
exit=13
```

Exit 13 heißt "Governance unter dem Minimum". Nichts wurde gestaget, nichts
installiert. Das ist die Stelle, an der ein Mensch entscheidet:

```
$ skillctl publish --attest wochenbericht@1.0.0 --registry local:///…/reg2 \
    --digest sha256:6e86343a… --level green \
    --rationale "Liest lokale wlog-Dateien, schreibt einen Bericht. Kein Netz, kein Unterprozess." \
    --key /…/author.priv --identity id:bob@example --yes
==> publish --attest wochenbericht@1.0.0
    level:     green
    rationale: Liest lokale wlog-Dateien, schreibt einen Bericht. Kein Netz, kein Unterprozess.
==> attested: wochenbericht/v1.0.0  transport=git  registry=local:///…/reg2
exit=0
```

`--rationale` ist der einzige Satz, den später ein Prüfer liest. Er gehört
niemandem sonst; er beantwortet, warum diese Stufe gerechtfertigt war.

In einer Abteilung, die das Vier-Augen-Prinzip führt, signiert hier ein
**anderer** Schlüssel als in 4.2. Der Lauf oben zeigt beide Rollen auf einer
Person, weil er auf einer Maschine lief; die Herkunftsdatei in 4.4 macht das
sichtbar, indem sie zweimal denselben Fingerabdruck nennt.

### 4.4 Übernehmen, in zwei Schritten

**Gemessen.** Nach der Freigabe zieht dieselbe Anfrage grün:

```
$ skillctl pull --registry local:///…/reg2
    ✅ wochenbericht@1.0.0  digest=sha256:6e86343a…  gov=green  →  /…/.cache/m3c/skill-bundles/6e86343a…/bundle.skb
==> done. staged=1  skipped=0  (context: skills)
exit=0
```

Installieren ist absichtlich zweistufig. Schritt 1 druckt den Plan und einen
Token, Schritt 2 verbraucht ihn:

```
$ skillctl pull --registry local:///…/reg2 --install --trust-mode --dry-run-install
==> install plan: 1 create, 0 overwrite
    + wochenbericht@1.0.0  →  /…/.claude/skills/wochenbericht   (digest sha256:6e86343a…)
==> dry-run-install token (5-minute TTL): 1789562258.sx3Dd3s6…
    re-run with: --confirm-install --dry-run-install-token <above>

$ skillctl pull --registry local:///…/reg2 --install --trust-mode \
    --confirm-install --dry-run-install-token 1789562258.sx3Dd3s6…
    +  installed at /…/.claude/skills/wochenbericht  (provenance: …/.m3c-provenance.json)
exit=0
```

Der Token läuft nach fünf Minuten ab. Wer ihn in ein Skript schreibt, hat die
Zustimmung wegautomatisiert, die er darstellt.

Neben dem Skill liegt danach seine Herkunft, und sie ist der Beleg für Z4:

```json
{
  "skill": "wochenbericht",
  "version": "1.0.0",
  "bundle_digest": "sha256:6e86343a…",
  "registry": "local://<pfad-zur-registry>",
  "pulled_at": "2026-09-16T12:37:47Z",
  "trust_roots_fingerprint": "sha256:8e19d51c…",
  "signatures": [
    { "role": "author",   "identity_id": "id:bob@example", "pubkey_fingerprint": "sha256:8e19d51c…" },
    { "role": "registry", "identity_id": "id:bob@example", "pubkey_fingerprint": "sha256:8e19d51c…" }
  ],
  "governance_level": "green"
}
```

### 4.5 Und dann benutzen

Der Schritt, den kein Kommando abnimmt und den ein Runbook trotzdem nennen
muss, sonst endet es beim Installieren.

Nach dem Install liegt der Skill unter `~/.claude/skills/<name>/`. Was dort
liegt, ist der Skill plus seine Belege:

```
$ ls -a ~/.claude/skills/wochenbericht/
.m3c-provenance.json     woher er kommt, wer signiert hat, welche Stufe
.skillctl-attest.json    die Freigabe, signiert
CHECKSUMS                die Prüfsummen der Dateien
SKILL.md                 der Skill selbst
bundle.json              das Manifest
wochenbericht.skb        das Bundle, aus dem entpackt wurde
```

Benutzt wird er in Claude Code unter seinem Namen aus dem `name:`-Feld der
`SKILL.md`, also `/wochenbericht`. Claude Code liest die installierten Skills
beim Sitzungsstart; eine laufende Sitzung sieht einen frisch installierten
Skill also erst nach einem Neustart.

Damit schließt sich die Schleife aus Abschnitt 7: die Mitarbeiterin ruft das
auf, was aus ihrer eigenen dreimal gelaufenen Arbeitsweise geworden ist, und
was sie beim Aufrufen stört, ist der Inhalt der nächsten Reflexion.

## 5. Das gemeinsame Repository: vom Ordner nach GitLab

Abschnitt 4 lief auf einer Maschine. Sobald zwei Menschen dieselbe Registry
benutzen, kommt GitLab dazwischen, und dabei gibt es drei Stellen, an denen es
still schiefgeht. Alle drei sind am 2026-09-16 gemessen, gegen ein
nachgebautes GitLab-Projekt im Dateisystem.

### 5.1 Der Autor schiebt hoch

Der Ordner aus 4.3 wird zum ersten Mal gespiegelt. `registry init` druckt dafür
eine Zeile mit der URL darin. Genau die schreibt man **einmal** in den Ordner
und danach nie wieder in eine Kommandozeile:

```bash
git -C /pfad/zur/registry remote add origin https://git.example.internal/gruppe/skill-registry.git
git -C /pfad/zur/registry push --mirror origin
```

Warum der Umweg über `remote add`: es gibt zwei Registries (0.3), und ein
`--mirror` an die falsche URL ersetzt die andere. Steht die URL im Ordner, kann
man sie nicht verwechseln, und eine Zeile sagt jederzeit, welcher Ordner wohin
zeigt:

```bash
git -C /pfad/zur/registry remote -v
```

**Vor dem allerersten Push eine Zeile Vorsicht.** Sie kostet eine Sekunde und
verhindert den einzigen Schaden, den dieser Weg anrichten kann:

```bash
git ls-remote https://git.example.internal/gruppe/skill-registry.git
```

Keine Ausgabe heißt: das Ziel ist leer, der Push kann nichts zerstören.
Kommt eine Liste von Refs, ist das Projekt **nicht** leer, und dann wird nicht
gepusht, sondern 0.3 zu Ende gelesen. Für jeden weiteren Push entfällt die
Probe: ab dann ist der eigene Registry-Inhalt genau das, was dort stehen soll.

**Vor dem ersten `publish` geht der Push nicht.** Eine frisch angelegte Registry
hat null Refs, und git sagt dann `Perhaps you should specify a branch`. Das ist
kein Defekt, sondern die Reihenfolge: erst aufnehmen und freigeben, dann
spiegeln.

**`--mirror` ersetzt den Zustand des Ziels.** Wie das aussieht, wenn im Projekt
schon etwas lag, steht in 0.3, samt der Zeile, die git dabei druckt. Ist das
Projekt leer angelegt worden, ist der erste Push unauffällig, und jeder weitere
auch:

```
   107efa7..bfc3d5f  main -> main
 * [new tag]         wb/v1.2.0 -> wb/v1.2.0
```

Jede veröffentlichte Fassung bekommt ein eigenes Tag. Wer im GitLab-Web
nachsehen will, was aufgenommen wurde, sieht unter `skills/` die Bundles und
unter `events/` die signierten Ereignisse.

### 5.2 Der Empfänger holt sie: `--mirror`, nicht `--bare`

Der Empfänger braucht eine lokale Kopie der Registry. Es gibt zwei Arten, das
zu tun, sie sehen gleich aus, und nur eine funktioniert dauerhaft.

```bash
# richtig
git clone --mirror https://git.example.internal/gruppe/skill-registry.git ~/skill-registry
```

**Warum nicht `--bare`.** Gemessen: nach einem `git clone --bare` trägt der Klon
keinen `fetch`-Refspec. Ein späteres `git fetch` in diesem Klon aktualisiert
`refs/heads/main` deshalb **nicht**, es setzt nur `FETCH_HEAD`. Der Empfänger
sieht dann auf Dauer den Stand vom Tag des Klonens, und zwar ohne
Fehlermeldung: `pull` meldet fröhlich grün, nur eben die alte Fassung. Ein
`--mirror`-Klon trägt `+refs/*:refs/*`, und damit holt ein schlichtes
`git fetch` alles.

Nachgeprüft: Autor veröffentlicht `1.2.0` und schiebt hoch, Empfänger ruft nur
`git fetch` auf, danach zeigt `pull` drei Fassungen statt zwei.

```
$ git -C ~/skill-registry fetch
   107efa7..bfc3d5f  main       -> main
 * [neues Tag]       wb/v1.2.0  -> wb/v1.2.0

$ skillctl pull --registry local://$HOME/skill-registry
    ✅ wb@1.0.0  …  gov=green
    ✅ wb@1.1.0  …  gov=green
    ✅ wb@1.2.0  …  gov=green
==> done. staged=3  skipped=0  (context: skills)
```

**Die zweite stille Stelle: `HEAD` des Klons.** Die Registry liegt auf `main`.
Zeigt `HEAD` des Klons auf einen Zweig, den es nicht gibt, findet `skillctl`
nichts und sagt es deutlich:

```
pull: NULLTREFFER im Kontext "skills".
  Das ist kein Erfolg: ein leerer Lauf ist von einem Lauf ohne Arbeit
  nicht zu unterscheiden […]
```

Bei einem GitLab-Projekt mit Standardzweig `main` tritt das nicht auf, der Klon
übernimmt `HEAD` vom Server. Die Prüfung kostet trotzdem eine Zeile, und sie
beantwortet die Frage, die sonst eine halbe Stunde kostet:

```bash
git -C ~/skill-registry symbolic-ref HEAD      # erwartet: refs/heads/main
git -C ~/skill-registry symbolic-ref HEAD refs/heads/main   # falls nicht
```

### 5.3 Der Pin hängt am Pfad, nicht am Projekt

**Die dritte Stelle, und die überraschendste.** `peer add` pinnt einen
**Locator**, also genau die Zeichenkette `local:///pfad/zur/registry`. Ein
anderer Pfad auf derselben Maschine, der dasselbe GitLab-Projekt enthält, ist
für skillctl ein anderer Peer und ist **nicht** gepinnt. Gemessen: nach dem
Umziehen der Registry in einen zweiten Ordner brach `pull` mit der Meldung ab,
es fehle `~/.claude/trust-roots.yaml`, obwohl der Autor längst gepinnt war.

Daraus folgt die Reihenfolge, und sie ist der Grund, warum 0.3 nach einem Pfad
fragt, bevor irgendjemand pinnt:

1. Pfad festlegen und klonen. Ein Pfad, einmal, für immer.
2. **Dann** pinnen, auf genau diesen Pfad.

```bash
tools/team-base-setup.sh member --author-id id:bob@example \
    --author-key ~/bob.pub --pin sha256:<am-telefon-abgeglichen> \
    --peer-registry local://$HOME/skill-registry
```

Zieht die Registry doch einmal um, wird neu gepinnt. Das ist ein Kommando, kein
Drama, aber es passiert nicht von allein.

### 5.4 Die Runde, auf einen Blick

| # | Wer | Kommando |
|---|---|---|
| 0 | IT | **eigenes, leeres**, privates GitLab-Projekt, Standardzweig `main`, ohne README und ohne CI |
| 1 | Autor | `git ls-remote <url>` muss leer sein, bevor Schritt 4 kommt |
| 2 | Autor | `skillctl registry init --registry local://$HOME/skill-registry` |
| 3 | Autor | `publish`, dann `publish --attest` |
| 4 | Autor | einmal `git -C $HOME/skill-registry remote add origin <url>`, dann `git -C $HOME/skill-registry push --mirror origin` |
| 5 | Empfänger | `git clone --mirror <url> ~/skill-registry` |
| 6 | Empfänger | `team-base-setup.sh member … --peer-registry local://$HOME/skill-registry` |
| 7 | Empfänger | `skillctl pull --registry local://$HOME/skill-registry --install --trust-mode …` |
| später | Empfänger | `git -C ~/skill-registry fetch`, dann Schritt 7 erneut |

Schritt 4 und Schritt 5 sind derselbe Inhalt in zwei Richtungen. Ab Schritt 6
ist der Transportweg gleichgültig: gepinnt ist der Schlüssel, nicht GitLab.

## 6. Die Falle: drei Dateien heißen Trust-Roots

Gemessen am 2026-09-16, an drei Ausgaben desselben Binaries:

| Pfad | Wer schreibt | Wer liest |
|---|---|---|
| `~/.claude/skill-trust-roots.yaml` | `trust add`, `trust add-author` | `verify --bundle`, `install --bundle` |
| `~/.claude/skill-peers.yaml` | `peer add` | `pull --registry` |
| `~/.claude/trust-roots.yaml` | n/a | `pull` verlangt sie, wenn kein Peer gepinnt ist |

Die praktische Folge: **ein gepinnter Autor macht `pull` nicht arbeitsfähig, und
ein gepinnter Peer macht `install --bundle` nicht arbeitsfähig.** Wer nur einen
der beiden Wege braucht, pinnt einmal. Wer beide will, pinnt zweimal. Das Skript
aus Abschnitt 2 tut Letzteres, wenn `--peer-registry` gesetzt ist, und sagt es
sonst ausdrücklich dazu.

Der Fingerabdruck ist in beiden Fällen **derselbe Wert**: `skillctl trust
fingerprint <key.pub>` liefert ihn, `trust add-author --pin` und `peer add --pin`
nehmen ihn beide an. Nachgeprüft, indem derselbe Wert an beide Kommandos ging
und beide ihn als `matched` bestätigten. Es wird also nur eine Zahl am Telefon
vorgelesen, nicht zwei.

Die dritte Zeile der Tabelle ist die unangenehme: `pull` fordert einen Namen an,
den kein Kommando dieses Binaries schreibt. Wer diese Meldung sieht, hat keinen
Peer gepinnt; der Rat lautet dann `peer add`, nicht die Datei anzulegen.

## 7. Der Takt: von manuellen Schritten zum Skill

Ein Skill entsteht nicht dadurch, dass jemand einen schreibt. Er entsteht, weil
dieselbe Abfolge dreimal gelaufen ist und beim dritten Mal niemand mehr
nachdenkt.

| Durchlauf | Was getan wird | Was danach existiert |
|---|---|---|
| 1 | sammeln, von Hand: Transkripte und Notizen je Kontext in `inbox/` | ein gefüllter Ordner, mehr nicht |
| 2 | Prompts zur Extraktion der Rubriken in strukturierte Form | ein Format, das sich wiederholen lässt |
| 3 | Prompts für das Aggregat, und die Reflexion darüber nach `reflections/` | die Erkenntnis, welche Schritte tragen |
| danach | den Skill aus `reflections/` ableiten und packen | ein Aufruf statt einer Prompt-Folge |

Wer den Skill vor dem dritten Durchlauf schneidet, schneidet zu groß. Das ist der
häufigste Fehler: eine ganze Fachaufgabe wird "ein Skill" genannt. Ein Skill ist
kleiner als eine Aufgabe, und eine Aufgabe kombiniert mehrere davon.

**Der Takt braucht eine Erinnerung.** Ein Wochenbericht, der jeden Donnerstag
erwartet wird und für den niemand erinnert wird, kommt nicht. Der Kanal ist
zweitrangig und darf das Einfachste sein, was vorhanden ist; eine Serien-E-Mail
aus dem eigenen Postfach ist eine vollständige Lösung. Ein Takt ohne Erinnerung
ist eine Hoffnung, und die Auswertung beklagt später die Datenlage.

## 8. Wenn etwas fehlschlägt

| Exit | Bedeutung | Was zu tun ist |
|---|---|---|
| 10 | Prüfsumme stimmt nicht | die Bytes haben sich nach dem Signieren geändert. Neu beziehen, nicht neu signieren |
| 11 | Signatur ungültig | der falsche Schlüssel, oder ein fremder. Zurück zum Fingerabdruck-Abgleich |
| 12 | Registry nicht in den Trust-Roots | der Pin fehlt oder trägt einen anderen Namen als die Signaturzeile |
| 13 | Governance unter dem Minimum | `publish --attest` fehlt. Kein Fehler, sondern das Tor |
| 17 | Identität widerrufen | anhalten und fragen. Kein Versuch, es zu umgehen |

Ein `verify-sig`, das fehlschlägt, während der Fingerabdruck stimmt, ist fast
immer die Identität. Ein beim Aufnehmen vergessenes `--identity` ist dabei
keine stille Ursache mehr: `publish` bricht ohne die Flagge mit Ausstieg 2 ab,
bevor ein Bundle entsteht. Schlägt es trotzdem fehl, wurde eine andere
Identität angegeben als die gepinnte; die Signaturzeile mit dem Pin abgleichen.

## 9. Was offen bleibt

- **Audit.** Signieren und Freigeben erzeugen Ereignisse in der Registry. Eine
  Weiterleitung an ein SIEM ist damit nicht eingerichtet, und dieses Runbook
  richtet sie nicht ein.
- **Verteilung durch die IT.** Der Weg oben ist der von Hand. Eine Verteilung
  über die Geräteverwaltung ist eine Anforderung an die Infrastruktur, nicht an
  dieses Werkzeug, und sie setzt eine Gerätepolicy voraus, die sagt, wo auf
  einer Maschine Skills überhaupt liegen dürfen.
- **Beschaffung fremder Skills.** Für einen Skill aus dem Netz braucht es
  dasselbe Eingangsverfahren wie für eine fremde Bibliothek: beziehen, lesen,
  Datennutzung prüfen, intern neu packen, intern signieren. Beschrieben ist es
  hier nicht.
- **Kosten.** Wie viele Token eine Arbeitsweise verbraucht, ist eine
  Governance-Frage wie die Sicherheitsfragen, und sie wird von keinem Kommando
  in diesem Runbook beantwortet.

## Verwandte Dokumente

- [Ops-Runbook: Monitoring und Alarmierung](ops-monitoring.de.md): was an einem
  Betrieb beobachtbar ist, und was ausdrücklich nicht.
- [Ops-Runbook: Incident Response](ops-incident-response.de.md): was passiert,
  wenn ein Schlüssel kompromittiert ist.
- [Ops-Routine: Zugangstoken](ops-registry-tokens.de.md): wer welchen Token
  besorgt, und was beim Ausscheiden passiert.
- [Runbook: two-person ER1 exchange](runbook-two-person-er1-exchange.md): derselbe
  Austausch über eine ER1-Registry statt über einen Ordner.
