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
