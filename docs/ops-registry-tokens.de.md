# Ops-Routine: Zugangstoken für Registry und Skill-Repository

Wer welchen Token besorgt, woher, wo er liegt, und was beim Ausscheiden passiert.
Gedacht für den echten Betrieb bei einem Kunden mit eigener GitLab-Instanz.

Zielgruppe: die Person, die eine Maschine einrichtet, und die Person, die das
Registry betreibt. Beide brauchen jeweils nur ihren eigenen Abschnitt.

**Die Instanz.** Entschieden am 2026-09-06: produktiv ist `git.kieback-peter.de`.
Der Registry-Locator lautet dort

```
gitlab://git.kieback-peter.de/<gruppe>/skill-registry
```

und `<gitlab-host>` in allen Kommandos unten ist entsprechend
`git.kieback-peter.de`. Die Instanz spricht HTTPS, also bleibt `M3C_GIT_HTTP`
ungesetzt; die Variable ist nur fuer eine LAN-Instanz ohne TLS gedacht.

## Die Grundregel in einem Satz

**Der Token entscheidet, wer die Bytes bewegen darf. Der Schlüssel entscheidet,
wem sie zugerechnet werden.** Die beiden sind getrennt, und deshalb ist es keine
Schwächung, wenn ein Token einem Projekt gehört statt einer Person.

Daraus folgt die ganze Routine:

| | Woher | Wem gehört er | Warum |
|---|---|---|---|
| **Lesen** (`pull`, `verify`, `install`) | GitLab-Konto der Mitarbeiterin | der Person | Beim Ausscheiden endet der Zugang von selbst |
| **Schreiben** (`publish`, `attest`) | Projekt-Einstellungen des Registry | dem Projekt | Das Registry überlebt einen Personalwechsel |

Die zweite Zeile ist die einzige Stelle, an der diese Routine von der nächstliegenden
Lösung abweicht, und der Grund steht unten unter "Warum Schreibtoken nicht persönlich sind".

## Teil A: eine Mitarbeiterin richtet ihre Maschine ein (Lesen)

Dauer: zwei Minuten. Kein Adminrecht nötig.

**1. Token im eigenen GitLab-Konto erzeugen.**

> Profil → Zugriffstoken (Access Tokens) → Neuen Token hinzufügen
> Name: `skillctl-lesen-<maschinenname>`
> Ablaufdatum: setzen, höchstens 12 Monate
> Bereiche (Scopes): **`read_api`** und **`read_repository`**, sonst nichts

Der Token wird **einmal** angezeigt. Danach nie wieder.

**2. Token ablegen.**

macOS und Windows, ein Kommando:

```bash
skillctl token set --backend gitlab --host git.kieback-peter.de --read-only
```

Danach den Token einfügen und mit Ctrl-D abschliessen. **Der Token wird von stdin
gelesen und steht nie in der Kommandozeile**, also nicht in `ps` und nicht in der
Shell-Historie. Er landet im Keychain (macOS) beziehungsweise DPAPI-verschlüsselt
je Benutzerkonto (Windows).

Für ein HTTP-Registry (`--registry https://…/api/skills`) lautet das Backend
`registry` statt `gitlab`.

Auf Linux gibt es keinen geschützten Speicher; das Kommando sagt das und nennt
die Umgebungsvariable, statt den Token irgendwohin ungeschützt zu schreiben. Für
CI ist die Variable ohnehin der Normalfall:

```bash
export M3C_GITLAB_RO_TOKEN='<token>'      # Git-Registry
export M3C_REGISTRY_RO_TOKEN='<token>'    # HTTP-Registry
```

Was wo liegt, zeigt `skillctl token list --host git.kieback-peter.de`, und zwar
**ohne den Token auszugeben**. Die interessante Spalte ist die Quelle: eine
gesetzte Umgebungsvariable schlägt den geschützten Speicher, und ein vergessenes
`export` erklärt einen Fehlschlag, den der abgelegte Token nicht verursacht hätte.

**3. Prüfen.**

```bash
skillctl pull --registry gitlab://<host>/<gruppe>/<projekt> --skill <name> --dry-run-install
```

Erwartet: die Tore laufen durch. Bei `401` sagt das Werkzeug seit FR-0117
ausdrücklich, ob **kein** Token gesendet wurde oder ob der gesendete **abgelehnt**
wurde. Das sind zwei verschiedene Fehler mit zwei verschiedenen nächsten Schritten.

**4. Eintrag ins Token-Register.** Eine Zeile, siehe Teil C.

## Teil B: das Registry wird eingerichtet (Schreiben)

Macht die Person, die das Registry betreibt. Einmal je Registry, nicht je Mensch.

**1. Projekt anlegen.** Ein leeres GitLab-Projekt, z. B. `<gruppe>/skill-registry`.
Kein Inhalt, kein README: `skillctl registry init` schreibt die Struktur.

**2. Project Access Token erzeugen.**

> Projekt → Einstellungen → Zugriffstoken → Neuen Token hinzufügen
> Name: `skillctl-publish`
> Rolle: **Maintainer**
> Bereiche: **`write_repository`**
> Ablaufdatum: setzen, höchstens 12 Monate

**Kein Deploy Token.** GitLab lässt `write_repository` als Deploy-Token-Bereich
nicht zu, und der Standard-Branch ist auf Maintainer-Ebene geschützt. Ein Deploy
Token scheitert beim Push, und die Fehlermeldung sagt nicht, warum.

**3. Ablegen wie in Teil A**, aber ohne `--read-only`, also im Schreib-Tier:

```bash
skillctl token set --backend gitlab --host git.kieback-peter.de
```

**4. Prüfen.**

```bash
skillctl registry init --registry gitlab://<host>/<gruppe>/skill-registry
skillctl publish <name>@<version> --bundle <datei>.skb --registry gitlab://… --yes
```

## Warum Schreibtoken nicht persönlich sind

Der naheliegende Weg wäre, auch das Schreiben über das persönliche Konto laufen
zu lassen. Er hat zwei Folgen, die erst später auffallen:

1. **Das Registry stirbt mit dem Konto.** Scheidet die Person aus, kann niemand
   mehr aufnehmen, bis jemand merkt, woran es liegt. Beim Lesen ist genau das
   erwünscht, beim Schreiben ist es ein Ausfall.
2. **Es sieht nach Zurechenbarkeit aus, ist aber keine.** Wer aufgenommen hat,
   steht in der **Signatur** des Admit-Ereignisses, nicht im Token. Ein
   persönlicher Schreibtoken fügt der Zurechnung nichts hinzu und nimmt der
   Verfügbarkeit etwas weg.

Die Trennung kostet nichts: die Aufnahme wird weiterhin mit dem persönlichen
Schlüssel signiert, und der Pull prüft genau diese Signatur.

## Was bei einem Personalwechsel passiert

| Fall | Zu tun |
|---|---|
| Mitarbeiterin scheidet aus | Nichts. Ihr Lesetoken endet mit ihrem Konto. |
| Maschine wird ersetzt | Neuen Lesetoken erzeugen, alten in GitLab widerrufen, Registerzeile ersetzen. |
| Registry-Betreiber wechselt | Project Access Token rotieren; das Projekt und alle Lesetoken bleiben. |
| Token abgelaufen | GitLab meldet es nicht vorab. Deshalb Teil C. |
| Token kompromittiert | In GitLab widerrufen. Das ist die einzige Stelle, die wirklich zählt; der lokale Eintrag ist danach nur noch Müll. |

Ein Widerruf in GitLab wirkt sofort und ohne Zutun der Maschine. Das lokale
Löschen (Keychain-Eintrag entfernen) ist Hygiene, keine Sicherheitsmassnahme.

## Teil C: das Token-Register

Ohne Register läuft ein Token ab, und niemand weiss, welcher es war. Eine Zeile
je ausgestelltem Token, im Wartungsrepo unter `OPS/token-register.md` (Pfad
entschieden am 2026-09-06):

| Registry | Zweck | Inhaber | Ausgestellt | Läuft ab | Widerrufen am |
|---|---|---|---|---|---|
| `gitlab://git.kieback-peter.de/<gruppe>/skill-registry` | lesen, Laptop Anna | Anna | 2026-09-06 | 2027-09-01 | n/a |
| `gitlab://git.kieback-peter.de/<gruppe>/skill-registry` | schreiben, publish | Projekt | 2026-09-06 | 2027-09-01 | n/a |

Kein Token im Register, nur die Tatsache seiner Existenz. Wer das Register liest,
soll wissen, **was abläuft**, nicht **womit man sich anmeldet**.

Erfüllt AC-14 aus SPEC-0407 und REQ-3.15.

## Reihenfolge, in der gesucht wird

Findet `skillctl` nichts, arbeitet es anonym weiter. Das ist Absicht: eine
öffentliche Instanz soll ohne Einrichtung funktionieren.

```
1. Umgebungsvariable      M3C_GITLAB_RO_TOKEN → M3C_GITLAB_TOKEN
                          M3C_REGISTRY_RO_TOKEN → M3C_REGISTRY_TOKEN
2. macOS-Keychain         m3c-skillctl-gitlab-ro → m3c-skillctl-gitlab
                          m3c-skillctl-registry-ro → m3c-skillctl-registry
3. Windows-Speicher       DPAPI, je Benutzerkonto
4. sonst                  anonym
```

Auf einem Lesepfad wird zuerst der Lesetoken gesucht und nur ersatzweise der
Schreibtoken genommen. Wer beide hinterlegt hat, schickt auf einem `pull` nie den
Schreibtoken über die Leitung.

## Teil D: der Nachweislauf D-8

Einmalig, und danach ist REQ-3.5 ausserhalb eines lokalen Repos bestaetigt. Bis
dahin ist jede Aussage ueber den produktiven Weg eine Aussage ueber `local://`.

Die Reihenfolge zaehlt: **erst der Token, dann die Datei.** Ein Projekt ohne
Schreibtoken laesst `registry init` an einer Stelle scheitern, die nach einem
Netzproblem aussieht.

| # | Wer | Was | Ergebnis |
|---|---|---|---|
| 1 | Registry-Betreiber | leeres Projekt `<gruppe>/skill-registry` auf `git.kieback-peter.de` | leeres Repo, kein README |
| 2 | Registry-Betreiber | Project Access Token, Maintainer, `write_repository`, Ablauf setzen | Teil B, Schritt 2 |
| 3 | Registry-Betreiber | Registerzeile schreiben, **bevor** der Token benutzt wird | `OPS/token-register.md` |
| 4 | Registry-Betreiber | `skillctl registry init --registry gitlab://git.kieback-peter.de/<gruppe>/skill-registry` | die Struktur liegt im Repo |
| 5 | Autor | `pack` + `sign` mit dem eigenen Schluessel | `.skb` und `.author.sig` |
| 6 | Herausgeber | `publish` (Admit) | `transport=git` |
| 7 | Freigeber | `publish --attest --level green` mit einem **anderen** Schluessel | AC-2 |
| 8 | Konsument, zweite Maschine | eigener Lesetoken nach Teil A, **kein** `.priv` auf dieser Maschine | AC-5 |
| 9 | Konsument | `pull --install --trust-mode` | fuenf Tore, `.m3c-provenance.json` und `.skillctl-attest.json` |
| 10 | Konsument | `signers:`-Eintrag entfernen, denselben Pull erneut | `gate 4`, Exit **13**, nichts installiert (AC-3) |
| 11 | alle | Evidenzblock schreiben | AC-7, siehe Tutorial Szenario 02 |

Schritt 10 ist die wichtigste Zeile. Ein Lauf, der nur den Erfolgsfall zeigt,
belegt, dass die Kette **durchlaesst**, und nicht, dass sie **haelt**. Der Exit
ist seit FR-0122 die 13 und nicht mehr die 1; wer noch eine 1 erwartet, prueft
gegen einen alten Stand.

Drei Prinzipale, drei Maschinen (P3). Zwei Prinzipale auf derselben Maschine sind
ein Trockenlauf und als solcher zu protokollieren, nicht als D-8.

## Windows

Seit `skillctl token set` existiert, ist Windows gleichwertig: der Token liegt
DPAPI-verschlüsselt je Benutzerkonto, nicht im Prozessumfeld. Vorher war die
Umgebungsvariable dort der einzige Weg, also ein schreibfähiger Token im Klartext,
vererbt an jeden Kindprozess. Bis zum 2026-09-06 stand hier deshalb die
Empfehlung, ein Registry nur von macOS oder Linux aus zu bedienen. Sie ist
hinfällig.

Der Lesepfad konnte den geschützten Speicher immer schon; was fehlte, war ein Weg,
ihn zu füllen. Das ist die Art Lücke, die von beiden Seiten aus vollständig
aussieht.

## Was diese Routine nicht löst

**Ablaufwarnungen.** GitLab warnt nicht vorab, und `skillctl` kennt das
Ablaufdatum nicht: es steht in keinem Token. Deshalb das Register in Teil C, und
deshalb ist die Zeile dort wichtiger, als sie aussieht.

**Widerruf.** `skillctl token rm` entfernt die lokale Kopie, und das ist Hygiene.
Wer einen Token wirklich stoppen will, widerruft ihn in GitLab. Das wirkt sofort
und ohne Zutun der betroffenen Maschine.
