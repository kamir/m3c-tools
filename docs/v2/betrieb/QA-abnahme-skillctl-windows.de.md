# QA-Abnahme: skillctl auf Windows, zum Ausdrucken und Unterschreiben

Ein Protokoll fuer **einen** Lauf auf **einer** Maschine: installieren, den Offline-Lebenszyklus
pruefen, den Freeze zum ersten Mal auf Windows fahren, und jede Gegenprobe mitnehmen, die zeigt,
dass die Pruefung auch Nein sagen kann.

## Was dieses Protokoll ist, und was es nicht ist

Es ist die Aufzeichnung dessen, was auf dieser Maschine wirklich lief. Erst ein ausgefuelltes und
unterschriebenes Exemplar macht aus `cross-compiled` ein `real-platform-tested`, und auch das nur
fuer die Proben, die tatsaechlich liefen.

Es ist **nicht** die Abnahme nach SPEC-0406. Die braucht zwei Personen, jede mit ihren eigenen
Schluesseln, und steht in
[Acceptance und Handover](acceptance-skillctl-lifecycle.md) sowie im
[Runbook fuer den Zwei-Parteien-Austausch](runbook-two-person-er1-exchange.md). Ein Lauf, in dem
eine Person alle Schluessel haelt, zeigt ueber zwei Parteien nichts.

## Kopf, vor dem ersten Befehl auszufuellen

| Feld | Eintrag |
|---|---|
| Fassung unter Test (Tag) | `skillctl/v________` |
| Ausgabe von `skillctl version` | ________________________________ |
| Geraet, OS-Build (`winver`) | ________________________________ |
| Pruefer / Prueferin | ________________________________ |
| Datum, Uhrzeit Beginn | ________________________________ |

**Voraussetzung:** das Release ist **veroeffentlicht**, nicht mehr Entwurf. Die Assets eines
Entwurfs sind nicht oeffentlich abrufbar und antworten mit 404; der Installer sagt das dann auch so.

Es braucht **keine** Administratorrechte, und es wird **nichts** ausserhalb des Installationsordners
und des Arbeitsverzeichnisses geschrieben.

---

## Stufe A: Installation und Integritaet

### A1 Installieren

Der Einzeiler steht in der [README](../../../README.md) unter "Install skillctl". Nimm ihn von dort,
nicht aus diesem Protokoll: er zeigt auf einen festen Commit mit hinterlegter Pruefsumme, und dieser
Pin wandert mit jedem Release. Wer lieber erst prueft und dann ausfuehrt, findet in der README
direkt darunter die Form mit `Get-FileHash`.

- **PASS:** der Installer meldet die aufgeloeste Fassung, prueft SHA-256, prueft die cosign-Herkunft
  (oder sagt, dass cosign fehlt und die SHA-256 der Anker ist) und legt `skillctl.exe` unter
  `%LOCALAPPDATA%\Programs\skillctl` ab.
- **FAIL:** jeder Abbruch. Der Installer bricht absichtlich ab, statt auf eine aeltere Marke
  zurueckzufallen.

### A2 Die Fassung stimmt

```powershell
skillctl version
```

- **PASS:** die Ausgabe nennt den Tag unter Test. Steht dort `dev`, liegt eine aeltere Datei frueher
  im PATH; mit `Get-Command skillctl -All` findet man sie.
- Das Installationsverzeichnis haengt im laufenden Fenster schon im `$env:Path`, neue Fenster ziehen
  es aus dem Benutzer-PATH.

---

## Stufe B: der Offline-Lebenszyklus

Ohne Netz, ohne Anmeldung, ohne ER1.

### B1 Schluessel, Buendel, Signatur, Pruefung

```powershell
$W = Join-Path $env:TEMP "skillctl-abnahme"
New-Item -ItemType Directory -Force -Path $W | Out-Null
Set-Location $W

New-Item -ItemType Directory -Force -Path .\abnahme-skill | Out-Null
@"
---
name: abnahme
description: Abnahmelauf skillctl auf Windows.
---
# abnahme
"@ | Set-Content -Encoding utf8 .\abnahme-skill\SKILL.md

skillctl keygen --out .\ab
skillctl pack --skill .\abnahme-skill -o .\ab.skb --name abnahme --version 1.0.0
skillctl sign --key .\ab.priv .\ab.skb
skillctl verify-sig --pubkey .\ab.pub .\ab.skb
$LASTEXITCODE
```

- **PASS:** jeder Schritt laeuft durch, `verify-sig` endet auf `0`.
- Flags stehen **vor** dem Buendelnamen: die Auswertung haelt beim ersten Positionsargument an.

### B2 Gegenprobe: ein veraendertes Buendel wird abgelehnt

```powershell
Copy-Item .\ab.skb .\ab-manipuliert.skb
Get-ChildItem -Filter "ab.skb.*.author.sig" | ForEach-Object {
    Copy-Item $_.FullName (".\ab-manipuliert.skb." + $_.Name.Substring("ab.skb".Length + 1))
}
$b = [System.IO.File]::ReadAllBytes("$W\ab-manipuliert.skb")
$b[200] = $b[200] -bxor 0xFF
[System.IO.File]::WriteAllBytes("$W\ab-manipuliert.skb", $b)

skillctl verify-sig --pubkey .\ab.pub .\ab-manipuliert.skb
$LASTEXITCODE
```

- **PASS:** Ausgang `10`, und die Meldung nennt als Grund die Aenderung nach dem Signieren, nicht
  eine fehlende Datei.
- **FAIL des Tors:** Ausgang `0`. Ein Lauf, in dem das durchgeht, ist der einzige Befund, auf den es
  hier ankommt.

> **Der schnelle Weg statt B1 und B2.** Dieselbe Kette gibt es als Skript:
> `scripts/skillctl-quickstart-windows.ps1`, mit gepinnter URL und Pruefsumme in
> [Acceptance und Handover](acceptance-skillctl-lifecycle.md). Es faehrt keygen, pack, sign,
> verify-sig, trust add und den Manipulationsfall in einem Wegwerfordner unter `%TEMP%` und druckt
> je Schritt eine Zeile. Es ist dasselbe Skript, das die CI auf `windows-latest` faehrt.
>
> Ein Unterschied bei der Gegenprobe, damit die Zahl niemanden ueberrascht: das Skript haengt die
> Sidecar-Signatur auf den manipulierten Digest um, die Ablehnung kommt also aus der Kryptografie
> (**Ausgang 11**, Signatur ungueltig). B2 oben laesst die Signatur stehen, dann faellt schon der
> Digest auf (**Ausgang 10**, Bytes nach dem Signieren geaendert). Beide schliessen zu, 11 ist der
> staerkere Nachweis. Wer das Skript nimmt, kreuzt B1 und B2 nach dessen Zeilen an und notiert
> `11` statt `10`.

---

## Stufe C: Trust Freeze, der erste echte Lauf auf Windows

### C1 Was die Maschine hergibt

```powershell
skillctl trust-freeze doctor --output .\cap
```

- **PASS:** `doctor` endet auf `0`, nennt das Profil `walking-skeleton`, die Proben mit ihrem
  Zustand und die Pruefungen (`output_location`, `tools`, `claude_roots`).
- Erwartet und richtig: die `linux.*`-Proben stehen fuer `windows` auf `not_implemented`. Die
  Windows-Probenfamilien existieren in dieser Fassung nicht, und nichts behauptet das Gegenteil.

### C2 Erheben

```powershell
skillctl trust-freeze capture --profile walking-skeleton --output .\cap --actor abnahme-windows
```

- **PASS:** `completeness: complete`, die Probe `common.identity` steht auf `captured`, Ausgang `0`.
- **Festhalten:** `bundle_id` und `content_digest` aus der Ausgabe unten eintragen.

### C3 Freigeben, also aus Beobachtung eine Baseline machen

```powershell
skillctl keygen --out .\tf
skillctl trust-freeze baseline approve --capture .\cap --output .\base `
  --reviewer "NAME DER PRUEFERIN" --change-id ABNAHME-WIN --reason "Abnahme skillctl auf Windows" `
  --key .\tf.priv --self-approval allow
```

- **PASS:** die Baseline entsteht, Ausgang `0`.
- `--self-approval allow` ist hier richtig, weil eine Person auf einer Maschine prueft. Die Ausgabe
  vermerkt die Selbstfreigabe als Warnung, und genau so soll sie im Buendel stehen.

### C4 Pruefen, offline

```powershell
skillctl trust-freeze verify --bundle .\base --trusted-key .\tf.pub
$LASTEXITCODE
```

- **PASS:** `signature: valid`, der Schluessel ist `trusted`, Ausgang `0`.

### C5 Vergleichen

```powershell
skillctl trust-freeze diff --baseline .\base --current .\cap --trusted-key .\tf.pub
$LASTEXITCODE
```

- **PASS:** `changes: 0 (none)`, Ausgang `0`.
- **Festhalten:** den `diff_digest` unten eintragen.

### C6 Berichten

```powershell
skillctl trust-freeze report --input .\base --output .\bericht.json
```

- **PASS:** `bericht.json` entsteht und laesst sich lesen.

### C7 Gegenprobe: ein Schluessel, dem niemand vertraut

```powershell
skillctl trust-freeze verify --bundle .\base
$LASTEXITCODE
```

- **PASS:** Ausgang `1` mit `key_not_trusted`. Eine gueltige Signatur allein genuegt nicht; sie muss
  von einem Schluessel stammen, den die Pruefung kennt.

### C8 Gegenprobe: ein gekipptes Byte

Zuletzt, denn dieser Schritt macht die Baseline unbrauchbar.

```powershell
$p = ".\base\probes\common.identity.json"
$b = [System.IO.File]::ReadAllBytes((Resolve-Path $p))
$b[[int]($b.Length/2)] = $b[[int]($b.Length/2)] -bxor 0x01
[System.IO.File]::WriteAllBytes((Resolve-Path $p), $b)

skillctl trust-freeze verify --bundle .\base --trusted-key .\tf.pub
$LASTEXITCODE
```

- **PASS:** Ausgang `1`, und die Meldung nennt die Datei, deren Digest nicht mehr passt
  (`integrity digest_mismatch probes/common.identity.json`).
- Wer danach weitermachen will, faehrt C3 mit einem neuen Ausgabeordner erneut.

---

## Stufe D: Ehrlichkeit auf fremder Plattform

Das ist die Stufe, wegen der sich der Aufwand lohnt: ein Werkzeug, das auf einer Plattform ohne
eigene Proben trotzdem "alles in Ordnung" sagt, ist gefaehrlicher als keines.

```powershell
skillctl trust-freeze capture --profile ubuntu-bastion --output .\cap-bastion
$LASTEXITCODE
```

- **PASS:** Ausgang `1`. Jede `linux.*`-Probe steht mit `unsupported (platform_not_supported:
  windows)` da, und am Ende zaehlt der Lauf seine Luecken einzeln auf (`gap linux.sudo:
  not_captured` und so fort). Mit `--format json` traegt er `result_class: incomplete_capture` und
  `completeness.status: incomplete`.
- **FAIL des Tors:** `complete`, oder eine Probe, die etwas erhoben haben will. Beides waere eine
  Behauptung ueber einen Host, den diese Fassung nicht lesen kann.

---

## Stufe E: der Bericht, drei Formate

Neu in `skillctl/v0.6.1`. Der Bericht ist eine Projektion: er rechnet nichts nach, prueft keine
Signatur und liest keine Uhr. Er zeigt, was im Buendel steht, und nennt daneben das Kommando, mit dem
man es selbst nachprueft.

```powershell
New-Item -ItemType Directory -Force -Path .\ber | Out-Null
foreach ($f in 'json','yaml','html') {
    skillctl trust-freeze report --input .\base --output .\ber --format $f
    Write-Host "$f Ausgang $LASTEXITCODE"
}
Get-ChildItem .\ber | Select-Object Name, Length
```

- **E1 PASS:** drei Dateien, `report.json`, `report.yaml`, `report.html`, je Ausgang `0`.
- Merke fuer den Ausgabepfad: ein **vorhandener Ordner** ergibt `report.<endung>` darin. Ein Pfad, den
  es noch nicht gibt, wird als **Dateiname** genommen.

```powershell
(Select-String -Path .\ber\report.html -Pattern 'https?://').Count      # erwartet: 0
(Select-String -Path .\ber\report.html -Pattern 'src=|href=').Count     # erwartet: 0
```

- **E2 PASS:** beide Zaehlungen sind `0`. Die Seite laedt nichts von aussen, kein CDN, keine Schrift,
  kein Skript, und ist auf einem Rechner ohne Netz vollstaendig lesbar. Das Aussehen steckt als CSS in
  der Datei.

Die Seite im Browser oeffnen und drei Dinge pruefen:

- **E3 PASS:** ein Kennblatt mit den Hashes, je Hash die Herkunft und das Pruefkommando daneben.
- **E4 PASS:** ein Abschnitt "Anleitung fuer den Benutzer" (englisch), der zur Buendelart passt und
  sagt, was das Dokument **nicht** beantwortet. Bei einer Baseline muss dort stehen, dass die Seite
  **nicht** sagt, ob die Signatur gueltig ist. Steht dort "signed and valid" oder etwas in dieser
  Richtung, ist das der schwerste Befund dieses Blattes.
- **E5 PASS:** jede Probe mit ihrem Statuswort und dem Grund, ausgeschrieben. Kein gruener oder roter
  Punkt, der einen Grund verschluckt. Auf Windows heisst das insbesondere: die `linux.*`-Proben stehen
  mit `unsupported` und dem Grund da, nicht als Fehler.

```powershell
New-Item -ItemType Directory -Force -Path .\w1,.\w2 | Out-Null
skillctl trust-freeze report --input .\cap --output .\w1\report.html --format html
Start-Sleep -Seconds 3
skillctl trust-freeze report --input .\cap --output .\w2\report.html --format html
(Get-FileHash .\w1\report.html).Hash -eq (Get-FileHash .\w2\report.html).Hash
skillctl trust-freeze report --input .\cap --output .\w1\report.html --format html
Write-Host "zweiter Schreibversuch: Ausgang $LASTEXITCODE"
```

- **E6 PASS:** der Vergleich ergibt `True`, auch mit Abstand dazwischen. Zwei Laeufe ueber dasselbe
  Buendel ergeben dieselben Bytes; die Uhr geht nicht in den Bericht ein.
- **E7 PASS, Gegenprobe:** der zweite Schreibversuch auf dieselbe Datei endet auf `1` und schreibt
  nicht. Ein Bericht wird nie ueberschrieben.

---

## Was festzuhalten ist

| Feld | Woher | Eintrag |
|---|---|---|
| `bundle_id` der Erhebung | C2 | ______________________________ |
| `content_digest` der Erhebung | C2 | ______________________________ |
| `diff_digest` | C5 | ______________________________ |
| Zeile zur Plattformunterstuetzung | C1 | ______________________________ |
| Dauer des ganzen Laufs | Kopf bis Ende | ______________________________ |

---

## Abnahme, zum Ankreuzen

Pflichtzeilen muessen **PASS** sein, damit der Lauf als bestanden gilt. Eine Gegenprobe gilt als
PASS, wenn sie **abgelehnt** hat.

| Stufe | Pruefung | PASS | FAIL | Pflicht | Bemerkung |
|---|---|:---:|:---:|:---:|---|
| A1 | Installation laeuft durch, Integritaet geprueft | ☐ | ☐ | ja | |
| A2 | `version` nennt den Tag unter Test, nicht `dev` | ☐ | ☐ | ja | |
| B1 | keygen, pack, sign, verify-sig, Ausgang 0 | ☐ | ☐ | ja | |
| B2 | veraendertes Buendel abgelehnt, Ausgang 10 | ☐ | ☐ | ja | |
| C1 | `doctor` laeuft, `linux.*` als not_implemented | ☐ | ☐ | ja | |
| C2 | Erhebung `complete`, Ausgang 0 | ☐ | ☐ | ja | |
| C3 | Freigabe erzeugt die Baseline | ☐ | ☐ | ja | |
| C4 | `verify` gueltig und vertraut, Ausgang 0 | ☐ | ☐ | ja | |
| C5 | `diff` 0 Aenderungen, Ausgang 0 | ☐ | ☐ | ja | |
| C6 | Bericht entsteht | ☐ | ☐ | nein | |
| C7 | unvertrauter Schluessel, Ausgang 1 | ☐ | ☐ | ja | |
| C8 | gekipptes Byte, `verify` Ausgang 1 | ☐ | ☐ | ja | |
| D | fremdes Profil bleibt unvollstaendig und sagt es | ☐ | ☐ | ja | |
| E1 | drei Formate entstehen, je Ausgang 0 | ☐ | ☐ | ja | |
| E2 | keine externe Referenz in der Seite, beide Zaehlungen 0 | ☐ | ☐ | ja | |
| E3 | Kennblatt mit Hashes, Herkunft und Pruefkommando | ☐ | ☐ | ja | |
| E4 | Anleitung passt zur Art und nennt, was sie nicht beantwortet | ☐ | ☐ | ja | |
| E5 | jede Probe mit Statuswort und Grund, keine Farbe statt Grund | ☐ | ☐ | ja | |
| E6 | zwei Laeufe byteweise gleich | ☐ | ☐ | ja | |
| E7 | zweiter Schreibversuch abgelehnt, Ausgang 1 | ☐ | ☐ | ja | |

**Abgenommen von:** ______________________  **Unterschrift:** ______________________

**Geraet / OS-Build:** ______________________  **Datum:** ______________

**Gesamturteil:** ☐ ANGENOMMEN  ☐ ABGELEHNT

Bei ABGELEHNT: die fehlgeschlagene Zeile, die Ausgabe und den Ausgang notieren, das ist der
Fehlerbericht.

---

## Danach

Aufraeumen, wenn gewuenscht: das Arbeitsverzeichnis `%TEMP%\skillctl-abnahme` loeschen. Die
Installation selbst bleibt, bis sie jemand entfernt.

Das ausgefuellte Blatt gehoert zum Release. Wer daraus eine Aussage im Baum machen will, traegt eine
Runde in `tests/evidence/trust-freeze/release-matrix.json` ein, mit dem Commit, der Plattform
`windows/amd64` und `evidence_level: real-platform-tested` fuer genau die Proben, die liefen. Nur
dort wird ein echter Lauf behauptet, nie in einem Fliesstext daneben.

---

## Siehe auch

- [Acceptance und Handover: der skillctl-Lebenszyklus](acceptance-skillctl-lifecycle.md), die
  Zwei-Parteien-Abnahme nach SPEC-0406 mit eigener Checkliste.
- [Runbook: Zwei-Parteien-Austausch ueber ER1](runbook-two-person-er1-exchange.md).
- [QA Acceptance Track: m3c-tools](QA-target-device-setup.md), dasselbe fuer die Capture-CLI.
- [Manual: skillctl](../referenz/manual-skillctl.md), jedes Flag und jeder Ausgang.
