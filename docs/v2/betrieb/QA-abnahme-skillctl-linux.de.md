# QA-Abnahme: skillctl auf Linux, zum Ausdrucken und Unterschreiben

Das Gegenstueck zu [QA-Abnahme: skillctl auf Windows](QA-abnahme-skillctl-windows.de.md), fuer
einen Host, auf dem die Linux-Proben wirklich existieren. Jede Erwartung in diesem Blatt wurde am
2026-09-25 auf einem Ubuntu 24.04.1 Host gefahren, nicht aus dem Kopf geschrieben.

## Der Unterschied zum Windows-Blatt, in einem Satz

Auf Windows sagt eine Linux-Probe `unsupported`, weil es sie nicht gibt. Hier existiert sie, also
sagt sie etwas ueber **den Benutzer und den Host**: `captured`, `partial` oder `permission_denied`,
je mit Grund. Darum hat dieses Blatt zwei Stufen mehr: A0 vor der Installation und E nach dem
Freeze.

## Kopf, vor dem ersten Befehl auszufuellen

| Feld | Eintrag |
|---|---|
| Fassung unter Test (Tag) | `skillctl/v________` |
| Ausgabe von `skillctl version` | ________________________________ |
| Host, Distribution, Kernel | ________________________________ |
| Benutzer, Gruppen (`id -nG`) | ________________________________ |
| Pruefer / Prueferin | ________________________________ |
| Datum, Uhrzeit Beginn | ________________________________ |

**Voraussetzungen.** Das Release ist veroeffentlicht, nicht Entwurf. Es braucht keine
Administratorrechte fuer die Stufen A bis D; Stufe E braucht `sudo`, und der Pruefer entscheidet, ob
er es auf diesem Host einsetzt. Geschrieben wird nur in ein Arbeitsverzeichnis unter `/tmp` und in
das Installationsziel.

---

## Stufe A: Installation und Integritaet

### A0 Der Installer verweigert, wenn er nichts pruefen kann

Diese Stufe gibt es nur auf Linux und macOS, und sie ist der Grund, warum sie zuerst kommt: der
**Shell**-Installer laedt cosign **nicht** selbst nach, anders als die PowerShell-Fassung. Ist cosign
nicht da und traegt das Release keine ed25519-Signatur, kann keine der beiden Herkunftsspuren
pruefen.

Auf einem Host ohne cosign den Einzeiler aus der [README](../../../README.md) laufen lassen.

- **PASS:** der Installer loest die neueste Fassung selbst auf, nennt beide Auswege
  (cosign installieren, oder den Betreiber um die ed25519-Signatur bitten) und **bricht ab**,
  Ausgang `1`. Es wird nichts installiert.
- **FAIL des Tors:** eine Installation. Ein Installer, der unverifizierte Binaries ablegt, ist der
  einzige Befund, auf den es hier ankommt.
- Ist cosign auf dem Host schon vorhanden, entfaellt diese Stufe. Das im Feld "Bemerkung"
  festhalten, nicht ankreuzen.

### A1 cosign, dann installieren

cosign wird gegen seine veroeffentlichte Pruefsumme geprueft, bevor es ausgefuehrt wird. Die Fassung,
auf die dieses Repository pinnt, steht in `tools/skillctl-install.ps1` als `$COSIGN_VERSION`.

```bash
V=v2.4.3   # die gepinnte Fassung, siehe tools/skillctl-install.ps1
cd "$(mktemp -d)"
curl -fsSL -o sums.txt "https://github.com/sigstore/cosign/releases/download/$V/cosign_checksums.txt"
want=$(grep ' cosign-linux-amd64$' sums.txt | awk '{print $1}')
curl -fsSL -o cosign "https://github.com/sigstore/cosign/releases/download/$V/cosign-linux-amd64"
got=$(sha256sum cosign | awk '{print $1}')
[ "$want" = "$got" ] || { echo "DIGEST PASST NICHT, nichts installieren"; exit 1; }
mkdir -p "$HOME/.local/bin" && chmod +x cosign && mv cosign "$HOME/.local/bin/cosign"
export PATH="$HOME/.local/bin:$PATH"
```

Danach den Einzeiler aus der README erneut.

- **PASS:** die Ausgabe nennt in dieser Reihenfolge: die aufgeloeste Fassung, `cosign keyless
  provenance verified (signed by the release workflow)`, dann `Verifying SHA-256 (integrity)` mit
  `OK` und dem Digest, dann `Installed:`. Ausgang `0`.
- **FAIL:** jeder Abbruch, und besonders ein `OK` bei cosign ohne die SHA-256-Zeile danach.

### A2 Die Fassung stimmt

```bash
export PATH="$HOME/.local/bin:$PATH"   # das Installationsziel liegt oft nicht im PATH
skillctl version
```

- **PASS:** die Ausgabe nennt den Tag unter Test. Steht dort `dev`, liegt eine aeltere Datei frueher
  im PATH; `command -v -a skillctl` findet sie.

---

## Stufe B: der Offline-Lebenszyklus

```bash
W=$(mktemp -d /tmp/qa-linux.XXXX); cd "$W"; echo "$W"
mkdir -p abnahme-skill
printf -- '---\nname: abnahme\ndescription: Abnahmelauf skillctl auf Linux.\n---\n# abnahme\n' \
  > abnahme-skill/SKILL.md
skillctl keygen --out ./ab
skillctl pack --skill ./abnahme-skill -o ./ab.skb --name abnahme --version 1.0.0
skillctl sign --key ./ab.priv ./ab.skb
skillctl verify-sig --pubkey ./ab.pub ./ab.skb; echo "Ausgang $?"
```

- **B1 PASS:** jeder Schritt laeuft durch, `verify-sig` endet auf `0`. Flags stehen **vor** dem
  Buendelnamen, die Auswertung haelt beim ersten Positionsargument an.

```bash
cp ab.skb ab-manipuliert.skb
for s in ab.skb.*.author.sig; do cp "$s" "ab-manipuliert.skb.${s#ab.skb.}"; done
python3 -c 'b=bytearray(open("ab-manipuliert.skb","rb").read()); b[200]^=0xFF; open("ab-manipuliert.skb","wb").write(bytes(b))'
skillctl verify-sig --pubkey ./ab.pub ./ab-manipuliert.skb; echo "Ausgang $?"
```

- **B2 PASS:** Ausgang `10`, und die Meldung nennt beide Digests und sagt, dass die Bytes nach dem
  Signieren geaendert wurden. Ein Ausgang `0` ist der Befund.

---

## Stufe C: Trust Freeze, der portable Teil

```bash
export HOME="$W/home"; mkdir -p "$HOME"     # Wegwerf-HOME, damit nichts Echtes angefasst wird
skillctl trust-freeze doctor --output ./cap;                                        echo "C1 $?"
skillctl trust-freeze capture --profile walking-skeleton --output ./cap --actor abnahme-linux; echo "C2 $?"
skillctl keygen --out ./tf
skillctl trust-freeze baseline approve --capture ./cap --output ./base \
  --reviewer "NAME" --change-id ABNAHME-LINUX --reason "QA-Durchlauf" \
  --key ./tf.priv --self-approval allow;                                            echo "C3 $?"
skillctl trust-freeze verify --bundle ./base --trusted-key ./tf.pub;                echo "C4 $?"
skillctl trust-freeze diff --baseline ./base --current ./cap --trusted-key ./tf.pub; echo "C5 $?"
skillctl trust-freeze report --input ./base --output ./bericht.json;                echo "C6 $?"
skillctl trust-freeze verify --bundle ./base;                                       echo "C7 $?"
```

- **C1 PASS:** Ausgang `0`. Auf Linux nennt `doctor` zusaetzlich `check file_roots`, also die
  Wurzeln, aus denen der eingeschraenkte Leser lesen darf. Das gibt es auf Windows nicht.
- **C2 PASS:** `completeness: complete`, `common.identity` steht auf `captured`, Ausgang `0`.
  `bundle_id` und `content_digest` unten eintragen.
- **C3 bis C6 PASS:** je Ausgang `0`. Bei C4 steht `signature: valid` und der Schluessel ist
  `trusted`; die Selbstfreigabe erscheint als Warnung, und genau so soll sie im Buendel stehen.
  Bei C5 `changes: 0 (none)`, den `diff_digest` unten eintragen.
- **C7 PASS:** Ausgang `1` mit `key_not_trusted`. Eine gueltige Signatur allein genuegt nicht.

```bash
python3 -c 'p="base/probes/common.identity.json"
b=bytearray(open(p,"rb").read()); i=len(b)//2; b[i]^=1; open(p,"wb").write(bytes(b))'
skillctl trust-freeze verify --bundle ./base --trusted-key ./tf.pub; echo "C8 $?"
```

- **C8 PASS:** Ausgang `1`, und die Meldung nennt die Datei:
  `integrity digest_mismatch probes/common.identity.json`. Zuletzt ausfuehren, dieser Schritt macht
  die Baseline unbrauchbar.

---

## Stufe D: die Linux-Proben, unprivilegiert

```bash
skillctl trust-freeze capture --profile ubuntu-bastion --output ./cap-bastion; echo "Ausgang $?"
```

- **PASS:** Ausgang `1`, `completeness: incomplete` mit der Zahl der Luecken, und **je Probe ein
  Zustand mit Grund**. Erwartet auf einem gewoehnlichen Host: `permission_denied` fuer
  `linux.firewall` (die Backends verweigern ohne Rechte), fuer `linux.ssh` (der effektive
  sshd-Zustand) und fuer `linux.sudo` (die sudoers-Dateien); `partial` dort, wo nur ein Teil
  beobachtbar war, mit Zahlen im Grund; `captured` fuer den Rest; `unsupported
  (not_implemented)` fuer `common.git` und `common.claude`, die es in dieser Fassung nicht gibt.
- **FAIL des Tors:** `complete`, oder eine Probe ohne Grund, oder eine leere Liste, die sich wie eine
  Antwort liest. Ein unprivilegierter Lauf, der behauptet, die Firewall gesehen zu haben, ist der
  Befund.
- Gemessenes Beispiel vom 2026-09-25: 8 erhoben, 2 teilweise, 3 verweigert, 2 nicht implementiert,
  5 Luecken. Die Zahlen gehoeren dem Host, nicht dem Werkzeug; abschreiben statt vergleichen.

---

## Stufe E: mit Rechten, und der Vergleich der beiden Tiefen

Nur fahren, wenn der Pruefer `sudo` auf diesem Host einsetzen darf. Das Werkzeug erhoeht sich
**nie** selbst; hier entscheidet der Mensch.

```bash
sudo -n env HOME="$W/home" "$(command -v skillctl)" trust-freeze capture \
  --profile ubuntu-bastion --output ./cap-root --actor abnahme-linux-root; echo "E1 $?"
sudo -n chown -R "$(id -u):$(id -g)" ./cap-root
```

- **E1 PASS:** deutlich mehr `captured` als in Stufe D, insbesondere `linux.firewall`,
  `linux.ssh` und `linux.sudo`. Bleibt eine Probe `partial`, muss jede Verweigerung mit Pfad und
  Grund dastehen. Gemessenes Beispiel: 12 erhoben, 1 teilweise, 2 nicht implementiert, in 12
  Sekunden.

```bash
skillctl trust-freeze baseline approve --capture ./cap-bastion --output ./base-unpriv \
  --reviewer "NAME" --change-id ABNAHME-LINUX-E --reason "unprivilegierter Stand" \
  --key ./tf.priv --self-approval allow
skillctl trust-freeze diff --baseline ./base-unpriv --current ./cap-root --trusted-key ./tf.pub
```

- **E2 PASS, und das ist die wichtigste Zeile dieses Blattes:** die Faehigkeiten, die nur auftauchen,
  weil der zweite Lauf mehr sehen konnte (sudo-Regeln, NOPASSWD, Schluessel in
  `authorized_keys`), erscheinen als **`coverage_increased` auf `info`**, jede mit der blinden Probe
  im Klartext ("not captured in the baseline: linux.sudo"). **Kein kritischer Befund behauptet neue
  Rechte.**
- Ein kritischer Befund der Art `collection_gap ... (required)` ist erlaubt und richtig: er sagt,
  dass eine Pflichtprobe nicht vollstaendig erhoben wurde. Er behauptet keine Rechteaenderung.
- **FAIL des Tors:** eine neue Faehigkeit als `capability_added` in `critical` oder `high`, obwohl die
  Baseline an dieser Stelle blind war. Das war der gemessene Defekt, den die Regel abstellt.
- Gemessenes Beispiel: 175 Aenderungen, davon 1 critical (die Pflichtluecke), 2 medium (die zwei
  nicht gebauten Proben), 7 info (`coverage_increased`), 165 low (neu sichtbare Artefakte).

---

## Was festzuhalten ist

| Feld | Woher | Eintrag |
|---|---|---|
| `bundle_id` der Erhebung | C2 | ______________________________ |
| `content_digest` der Erhebung | C2 | ______________________________ |
| `diff_digest` | C5 | ______________________________ |
| Probenzustaende unprivilegiert | D | ______________________________ |
| Probenzustaende mit Rechten | E1 | ______________________________ |
| Befunde je Schwere | E2 | ______________________________ |

---

## Abnahme, zum Ankreuzen

Pflichtzeilen muessen **PASS** sein. Eine Gegenprobe gilt als PASS, wenn sie **abgelehnt** hat.

| Stufe | Pruefung | PASS | FAIL | Pflicht | Bemerkung |
|---|---|:---:|:---:|:---:|---|
| A0 | ohne cosign wird nichts installiert, Ausgang 1 | ☐ | ☐ | ja | |
| A1 | cosign-Digest geprueft, dann Herkunft und SHA-256 | ☐ | ☐ | ja | |
| A2 | `version` nennt den Tag unter Test | ☐ | ☐ | ja | |
| B1 | keygen, pack, sign, verify-sig, Ausgang 0 | ☐ | ☐ | ja | |
| B2 | veraendertes Buendel abgelehnt, Ausgang 10 | ☐ | ☐ | ja | |
| C1 | `doctor` laeuft, nennt `check file_roots` | ☐ | ☐ | ja | |
| C2 | Erhebung `complete`, Ausgang 0 | ☐ | ☐ | ja | |
| C3 bis C6 | Freigabe, Pruefung, Vergleich, Bericht | ☐ | ☐ | ja | |
| C7 | unvertrauter Schluessel, Ausgang 1 | ☐ | ☐ | ja | |
| C8 | gekipptes Byte, Ausgang 1, Datei genannt | ☐ | ☐ | ja | |
| D | unprivilegiert: `incomplete`, jede Probe mit Grund | ☐ | ☐ | ja | |
| E1 | mit Rechten: mehr erhoben, Verweigerungen benannt | ☐ | ☐ | nein | |
| E2 | Sichtbarkeitsdifferenz als `info`, keine falsche Kritische | ☐ | ☐ | nein | |

**Abgenommen von:** ______________________  **Unterschrift:** ______________________

**Host / Distribution:** ______________________  **Datum:** ______________

**Gesamturteil:** ☐ ANGENOMMEN  ☐ ABGELEHNT

---

## Danach

Aufraeumen: das Arbeitsverzeichnis loeschen. Die Installation und cosign bleiben, bis sie jemand
entfernt.

Das ausgefuellte Blatt gehoert zum Release. Wer daraus eine Aussage im Baum machen will, traegt eine
Runde in `tests/evidence/trust-freeze/release-matrix.json` ein, mit dem Commit, der Plattform und
`evidence_level: real-platform-tested` fuer genau die Proben, die liefen. Nur dort wird ein echter
Lauf behauptet, nie in einem Fliesstext daneben.

## Siehe auch

- [QA-Abnahme: skillctl auf Windows](QA-abnahme-skillctl-windows.de.md), das Gegenstueck.
- [Acceptance und Handover: der skillctl-Lebenszyklus](acceptance-skillctl-lifecycle.md), die
  Zwei-Parteien-Abnahme nach SPEC-0406.
- [Manual: skillctl](../referenz/manual-skillctl.md), jedes Flag und jeder Ausgang.
- [Platform differences](../referenz/PLATFORM-DIFFERENCES.md), was je Plattform ueberhaupt
  behauptet wird.
