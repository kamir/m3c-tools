---
layout: default
title: "Tutorial: Katas und Test Ride, üben statt zusehen"
---

# Tutorial: Katas und Test Ride

**Für wen:** Sie haben `skillctl` installiert und wollen es **können**, nicht nur darüber
gelesen haben. Oder Sie geben eine Schulung und brauchen einen Ablauf, der am Ende einen
Beleg produziert.

**Was Sie am Ende haben:** einen geführten Durchlauf, in dem Sie einen Skill versiegeln, einen
fremden Schlüssel pinnen, als jemand anderes installieren und den Skill dann auf vier
verschiedene Arten kaputt machen, wobei jeder Versuch verweigert wird. Danach fünf Übungen,
die Sie so lange wiederholen, bis der Griff sitzt.

**Der eine Satz, um den es geht:** in beiden Formaten ist ein „bestanden" **ein echter
Exit-Code**, nie eine Selbstauskunft.

---

## Die Landkarte: vier Stufen, zwei Beweise

Es gibt zwei verschiedene Fragen, und sie werden dauernd verwechselt.

| Stufe | Frage | Artefakt | Beweist |
|---|---|---|---|
| 1 | Baut es und laufen die Tests? | `scripts/skillctl-test.sh` bzw. `.ps1` | die Maschine |
| 2 | Würde dieser Stand unsere CI-Tore bestehen? | `scripts/skillctl-enterprise-test.sh` bzw. `.ps1` | die Maschine |
| 3 | Kann **ich** das Werkzeug bedienen? | `demo/kup-training/`, der **Test Ride** | den Menschen, einmal |
| 4 | Sitzt der Griff auch nächste Woche noch? | `skillctl-demo --mode kata`, die **Katas** | den Menschen, dauerhaft |

Stufen 1 und 2 stehen im [Quickstart](quickstart-skillctl.md#1b-optional-prove-it-on-your-own-machine-source-self-test).
Dieses Tutorial behandelt 3 und 4. Die Reihenfolge ist keine Empfehlung, sondern eine
Abhängigkeit: der Ride reitet auf dem, was Stufe 1 gebaut hat.

---

## Teil 1: der Test Ride (etwa 20 Minuten, offline)

### 1.1 Holen und starten

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools/demo/kup-training
./run-all.sh --offline-only --no-pdf --no-release
```

Die drei Flags sagen: kein Server, kein PDF-Satz, kein plattformübergreifender Release-Bau.
Übrig bleibt der Teil, der die Vertrauenskette beweist, und der läuft ohne Netz.

**Alles bleibt in diesem Verzeichnis.** Der Ride schreibt ausschließlich unter
`demo/kup-training/artifacts/` und benutzt `artifacts/eric-home/` als künstliches `$HOME`.
Ihr echtes `~/.claude/` wird nicht angefasst. Aufräumen ist ein `rm -rf artifacts/`.

### 1.2 Was dabei passiert

Zehn Schritte, in dieser Reihenfolge:

| Schritt | Rolle | Was er zeigt | Erwartetes Ergebnis |
|---|---|---|---|
| `00` | Werkzeug | baut `skillctl` aus der Quelle, prüft die Umgebung | Binary vorhanden |
| `01` | Mirko (Autor) | `keygen`, `pack`, `sign`, `verify-sig`; zweimal packen ist byteidentisch | Exit `0`, Determinismus belegt |
| `02` | Mirko | Identität und Bundle ins Registry (nur online) | offline sauber übersprungen |
| `03` | Reviewer | Attestierung `green` auf den Digest | Urteil liegt vor |
| `04` | Eric | pinnt Mirkos Schlüssel in seine Trust-Roots | Schlüssel steht in der Datei |
| `05` | Eric | prüft, installiert, **führt den Skill aus** | `output/hello.txt` entsteht |
| `06` | Angreifer | ein Byte im Bundle geändert, Signatur passend umbenannt | Exit **`11`**, Signatur ungültig |
| `07` | Angreifer | fremder Schlüssel, fremde Signatur, Mirkos Identität behauptet | Exit **`11`** gegen Mirkos Pin, `0` gegen den eigenen |
| `08` | Angreifer | Bundle ganz ohne Signatur | Verweigerung, kein Durchrutschen |
| `09` | Angreifer | installierte Datei nachträglich editiert | Abweichung erkannt, Reparatur aus dem Bundle |

Schritt `07` ist der lehrreichste: dasselbe Bundle wird gegen zwei verschiedene Schlüssel
geprüft und liefert zwei verschiedene Urteile. Nicht das Artefakt entscheidet, sondern **wessen
Schlüssel Sie gepinnt haben**.

### 1.3 Die Lektion, die die meisten falsch mitnehmen

Eine gültige Signatur sagt: **„das ist, was dieser Schlüssel versiegelt hat".** Sie sagt
niemals: „das ist ungefährlich". Schritt `07` beweist genau das: die Signatur des Angreifers
ist mathematisch einwandfrei, sie ist nur nicht von dem, dem Sie vertrauen.

### 1.4 Mit Beleg abschließen

```bash
./run-and-prove.sh --skip-online --chain-only --json ride-report.json
```

Das ist die Zwillingsvariante von `run-all.sh`: sie prüft nicht nur die Exit-Codes, sondern
auch, ob jeder Schritt sein tragendes Artefakt tatsächlich erzeugt hat, und schreibt eine
Zusammenfassung. `--chain-only` lässt die beiden Tore weg, die eine Handbuch-Quelle bzw. einen
Release-Bau brauchen; ohne das bricht der Lauf ab, nachdem alle Vertrauensprüfungen bereits
grün waren.

`ride-report.json` ist Ihr Nachweis. Heben Sie ihn zusammen mit `skillctl version` auf.

### 1.5 Die Online-Hälfte (optional)

Drei weitere Schritte schließen den Kreis zur Nutzungsseite. Sie werden von `run-all.sh`
**nicht** ausgeführt und brauchen ein erreichbares aims-core plus `ER1_API_KEY`:

```bash
./10-scan-and-sync.sh     # SCAN:  was ist installiert, ins Profil spiegeln
./11-use-skill.sh         # USE:   Nutzungsereignisse, Reifegrad steigt
./12-decay.sh             # DECAY: ungeübtes verfällt wieder
```

Jeder prüft zuerst die Erreichbarkeit und überspringt sich mit einer Warnung, wenn Server oder
Schlüssel fehlen. `10-scan-and-sync.sh --operator` liest das **echte** `~/.claude/skills/` des
Trainers statt des Demo-Homes; benutzen Sie das nur bewusst.

### 1.6 Wenn etwas klemmt

| Symptom | Ursache | Abhilfe |
|---|---|---|
| Schritt `01` bricht bei `sign` ab, „insecure mode 0644" | ein privater Schlüssel mit zu offenem Modus | `chmod 600 artifacts/keys/*.priv`, dann neu starten. Seit 2026-09-04 erzwingt `00-preflight.sh` das selbst |
| Der Lauf endet rot, obwohl alle Vertrauensprüfungen grün waren | ein Tor braucht eine Quelle, die nur auf der Wartungsebene liegt | `run-and-prove.sh --skip-online --chain-only` |
| Schritt `02`, `03` melden „skipped" | kein Registry erreichbar | erwartet und in Ordnung: der kryptografische Beweis ist offline derselbe |

---

## Teil 2: die Katas (fünf Übungen, dauerhaft)

Der Ride beweist einmal, dass Sie es können. Die Katas halten es. Sie sind bewusstes Üben mit
einem Coach, und der Coach ist das Werkzeug selbst.

### 2.1 Starten

```bash
# aus dem Repository, baut skillctl gleich mit:
make build-skillctl-demo

./build/skillctl-demo --kata-list        # das Brett anzeigen und beenden
./build/skillctl-demo --mode kata        # die Coach-Schleife starten
./build/skillctl-demo --kata K3          # direkt in eine Übung springen
```

Beim Start baut das Werkzeug einen abgeschotteten Sandkasten (eigenes `HOME`, eigene
Schlüssel, eigenes dateibasiertes Registry, eigene Trust-Roots), findet das echte `skillctl`,
öffnet einen Spiegel im Browser auf `127.0.0.1` und zeigt das Kata-Brett. Es ist offline, ohne
Installation, ohne Adminrechte.

### 2.2 Die fünf Übungen

| Kata | Sie können danach | Geübt mit | Grün, wenn |
|---|---|---|---|
| **K1 Seal & prove** | einen Skill versiegeln und die Urheberschaft offline beweisen | `keygen`, `pack`, `sign`, `verify --bundle` | 3 saubere Durchgänge mit Exit `0` |
| **K2 Detect tamper** | eine Manipulation erkennen, **bevor** der Skill geladen wird | Datei auf der Platte ändern, `verify --all --quarantine` | 3 Durchgänge mit Urteil `10` |
| **K3 Govern reversibly** | eine löschende Operation fahren, die sich nicht erzwingen lässt | `audit --cleanup --dry-run-cleanup`, dann Bestätigung auf einem veränderten Zustand | 3 Durchgänge mit Exit `2` |
| **K4 Trust roots & install** | ein Registry pinnen und nur Zugelassenes installieren | `trust add`, `verify --bundle` | 3 Durchgänge mit Exit `0` |
| **K5 Revoke & fail-closed** | einen widerrufenen Skill offline abweisen | `verify --bundle … --revocations <signierte Liste>` | 1 Durchgang mit Exit `17` |

K3 ist die Übung, die man unterschätzt: es gibt **kein** `--force`. Der Plan bekommt ein Token
mit fünf Minuten Gültigkeit, und die Bestätigung prüft den Zustand **erneut**. Hat er sich
zwischenzeitlich verändert, verweigert sie. Das ist kein Schutz gegen Angreifer, es ist
Schutz gegen Sie selbst um 23 Uhr.

### 2.3 Wie eine Runde abläuft

Fünf Fragen, jede Runde dieselben:

1. **Ziel.** Was sollen Sie zeigen können?
2. **Ist-Stand.** Wo stehen Sie? Führen Sie es aus und schauen Sie hin.
3. **Hindernis.** Was hat blockiert? Das Werkzeug übersetzt den echten Exit-Code (`10`, `2`,
   `17`) in ein Hindernis in Klartext.
4. **Nächstes Experiment und Erwartung.** **Sie sagen den Exit-Code voraus**, bevor Sie
   drücken.
5. **Hingehen und sehen.** Ausführen, das echte Ergebnis vergleichen, ein Beat wird gezählt.

Schritt 4 ist der Kern. Wer den Exit-Code vorhersagt, hat ein Modell; wer nur ausführt, sammelt
Anekdoten.

### 2.4 Reifegrad und Verfall

Drei Zustände, wie im CEW-Modell: **rot** (neu), **gelb** (in Übung), **grün** (sitzt). Ein
sauberer, eigenständiger Durchgang ist ein Beat, `N/3` führt zu grün. Wird eine Kata länger
nicht geübt, **rostet** sie zurück; das Fenster steuert `KATA_STALL_DAYS` (Standard `5`).

Der Fortschritt liegt lokal unter `~/.skillctl-demo/kata-progress.json`, der Browser zeigt
dasselbe als Brett, eine Karte je Kata, live.

Das heißt auch: fünf Katas an einem Nachmittag durchzuklicken ergibt **nicht** grün, sondern
`1/3` fünfmal. Das ist Absicht.

### 2.5 Für die CI, und für die Frage „läuft das überhaupt ehrlich?"

```bash
./build/skillctl-demo --selftest
```

Fährt die Live-Szenarien ohne Interaktion, vergleicht jeden beobachteten Exit-Code mit seiner
Erwartung, druckt eine PASS/FAIL-Tabelle und endet ungleich null, wenn eine Behauptung nicht
hält.

Dazu die Hausregel, die das Werkzeug an sich selbst anlegt: Szenarien, die **nichts
ausführen**, sind als `ROADMAP` oder `PARTIAL` gekennzeichnet und werden nie als echtes Urteil
ausgegeben. Bei K5 ist der Offline-Widerruf (Exit `17`) echt; was Konzept bleibt, ist die
flottenweite Ausbreitung, weil dieser Aufbau kein Registry hochfährt.

---

## Teil 3: für Trainerinnen und Trainer

Ein Kohorten-Nachmittag, der etwas hinterlässt:

1. **Vorher, allein, 30 Minuten.** Alle laufen Stufe 1 und 2
   ([Quickstart §1b/§1c](quickstart-skillctl.md#1b-optional-prove-it-on-your-own-machine-source-self-test)).
   Wer hier hängt, hängt an der Werkzeugkette, nicht am Stoff.
2. **Gemeinsam, 30 Minuten.** Der Test Ride bis Schritt `05`. Halten Sie bei `05` an und
   lassen Sie zeigen, dass die Datei entstanden ist.
3. **Gemeinsam, 30 Minuten.** Die Schritte `06` bis `09`, einer nach dem anderen, jeweils mit
   der Frage vorweg: „welchen Exit-Code erwarten Sie?"
4. **Abschluss, 10 Minuten.** `run-and-prove.sh --skip-online --chain-only --json` bei allen,
   die Berichte einsammeln.
5. **Danach, über zwei Wochen.** Die Katas, dreimal je Kata, verteilt über Tage. Das Brett ist
   der Fortschrittsbericht.

Für den Vorführmodus ohne Publikumsbeteiligung gibt es `--mode kiosk --kiosk-delay 5s`, eine
Endlosschleife für Messestand oder geteilten Bildschirm.

Ein Hinweis zu den Unterlagen: `make-pdf.sh` setzt drei PDFs, greift dafür aber auf eine
Quelle auf der privaten Wartungsebene zu. Wer die nicht hat, lässt `--no-pdf` stehen; am
Ride ändert das nichts.

---

## Welches Format wann

| Situation | Nehmen Sie |
|---|---|
| Neu im Werkzeug, will einmal alles gesehen haben | Test Ride, offline |
| Soll es morgen bei einem Kunden bedienen | Test Ride, dann K1 und K4 |
| Hat es vor zwei Monaten gemacht | `--kata-list`, was rot geworden ist, das üben |
| Muss belegen, dass die Kette hält | `run-and-prove.sh … --json` plus `skillctl-demo --selftest` |
| Will einem Entscheider fünf Minuten zeigen | `skillctl-demo` im Standardmodus, Szenarien S1 und S5 |

---

## Wie es weitergeht

- Eigene Skills auf mehreren Maschinen: [Szenario 01](tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md)
- Der erste signierte Skill mit Prüfung durch einen Zweiten: [Szenario 02](tutorial-szenario-02-erster-signierter-skill.de.md)
- Alle Modi, Flags und Szenarien des Demo-Werkzeugs: [Quickstart skillctl-demo](quickstart-skillctl-demo.md)
- Jedes Kommando, jedes Flag, jeder Exit-Code: [Manual](manual-skillctl.md)
