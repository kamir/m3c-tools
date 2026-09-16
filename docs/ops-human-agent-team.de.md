# Ops-Runbook: ein Mensch-Agent-Team einrichten

Wie eine Führungskraft und eine Mitarbeiterin in einen Arbeitsmodus kommen, in
dem ein Agent mitarbeitet, und wie der erste selbstgebaute Skill von der einen
Maschine auf die andere gelangt, ohne dass irgendjemand dem Transportweg
vertrauen muss.

Zielgruppe: die Person, die das Team einrichtet. Die Mitarbeiterin, die danach
darin arbeitet, braucht dieses Dokument nicht. Das ist der Zweck.

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
an ein Datenschutz-Inventar und an ein SIEM ist es nicht. Abschnitt 8 sagt,
was offen ist.

## 0. Wie weit dieses Runbook gemessen ist

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

Fünf Schritte. Der vorletzte ist der, an dem ein Mensch entscheidet.

| Schritt | Kommando | Was es beweist |
|---|---|---|
| bauen | (kein Kommando) | der Skill entsteht aus `reflections/`, nicht am Reißbrett |
| prüfen | `skillctl pack` zweimal | zwei Läufe, Byte für Byte gleich |
| bündeln | `skillctl sign`, `skillctl verify-sig` | die eigene Arbeit ist geprüft, bevor sie weggeht |
| herausgeben | `skillctl publish`, dann `publish --attest` | Aufnahme und Freigabe sind zwei Vorgänge |
| übernehmen | `skillctl pull --install` | Herkunft und Freigabestufe liegen neben dem Skill |

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

`--identity` ist keine Formalie. Der Vorgabewert nennt jemand anderen. Wer ihn
stehen lässt, gibt ein Bundle heraus, dessen Signaturzeile einen fremden Namen
trägt; die Gegenseite bekommt dann eine Ablehnung, die sagt, die Identität sei
nicht gepinnt, obwohl sie korrekt gepinnt ist. Der Fehler war, dass der Absender
nie gesagt hat, wer er ist.

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

## 5. Die Falle: drei Dateien heißen Trust-Roots

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

## 6. Der Takt: von manuellen Schritten zum Skill

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

## 7. Wenn etwas fehlschlägt

| Exit | Bedeutung | Was zu tun ist |
|---|---|---|
| 10 | Prüfsumme stimmt nicht | die Bytes haben sich nach dem Signieren geändert. Neu beziehen, nicht neu signieren |
| 11 | Signatur ungültig | der falsche Schlüssel, oder ein fremder. Zurück zum Fingerabdruck-Abgleich |
| 12 | Registry nicht in den Trust-Roots | der Pin fehlt oder trägt einen anderen Namen als die Signaturzeile |
| 13 | Governance unter dem Minimum | `publish --attest` fehlt. Kein Fehler, sondern das Tor |
| 17 | Identität widerrufen | anhalten und fragen. Kein Versuch, es zu umgehen |

Ein `verify-sig`, das fehlschlägt, während der Fingerabdruck stimmt, ist fast
immer die Identität: `--identity` beim Aufnehmen vergessen, Vorgabewert
stehengeblieben.

## 8. Was offen bleibt

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
