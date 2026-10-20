---
layout: default
title: "Schnellstart: skillctl-demo"
---

# Schnellstart: skillctl-demo

[Deutsch](quickstart-skillctl-demo.de.md) · [English](quickstart-skillctl-demo.md)

Einem CISO in etwa fünf Minuten zeigen, wie die Vertrauensschicht **einen echten Angriff
eindämmt**: ein manipuliertes Bundle wird mit Exit `10`, eine erzwungene Governance-Aktion
mit Exit `2` abgewiesen. Auf einem eingeschränkten **Offline**-Laptop, ohne Installation,
Administratorrechte oder Server.

> **Was ist skillctl-demo?** Ein eigenständiges Offline-Binary, das das **echte
> `skillctl` mitliefert** und echte Vertrauensszenarien in einer isolierten Sandbox
> ausführt. Jedes LIVE-Ergebnis ist ein **echter `skillctl`-Exit-Code**. Nichts ist
> simuliert. Ein Browser öffnet eine Live-Ansicht mit Szenariografiken und laufendem
> Terminal; die CLI führt dieselbe Präsentation aus. Alle zugrunde liegenden Befehle
> und Flags stehen im [skillctl-Handbuch](../referenz/manual-skillctl.de.md).

> **Verbindliche Ehrlichkeitsregel.** LIVE-Szenarien führen das echte `skillctl` aus
> und zeigen seinen echten Exit-Code. ROADMAP-/PARTIAL-Tafeln **führen nichts aus**
> und sind entsprechend markiert. Simulierte Ausgaben werden nicht als echte Ergebnisse dargestellt.

---

## 1. Starten

Die Demo wird als ZIP mit `skillctl-demo` und `skillctl` ausgeliefert, zusätzlich mit
eingebetteten Webressourcen. Sie läuft **offline, ohne Adminrechte und ohne Installation**:
Doppelklick oder Start über die CLI öffnet einen Browser.

```bash
./skillctl-demo
```

Beim Start entsteht eine isolierte Sandbox: ein temporäres `HOME` mit eigenen Schlüsseln,
Beispielskills, dateibasiertem Registry und gepinnten Trust Roots. Das echte `skillctl`
wird gesucht, eine Webansicht auf `127.0.0.1` gestartet und der Browser geöffnet.
Die Ausgabe nennt Sandbox-`HOME`, aufgelösten `skillctl`-Pfad und Web-URL.

### Flags

| Flag | Zweck |
|---|---|
| `--mode guided\|kiosk\|kata` | `guided`, der Standard: Enter schaltet weiter; nach einem Durchlauf bleibt die Webansicht offen. `kiosk`: zeitgesteuerte Schleife für Messestand oder Bildschirmfreigabe. `kata`: praktisches Training mit Coachingzyklus und Kata-Board, §5. Unbekannte Werte fallen auf `guided` zurück. |
| `--kiosk-delay <dur>` | Wartezeit vor dem automatischen Weiterschalten im Kioskmodus, Standard `3s`. |
| `--kata <K1..K5>` | Direkt zu einer Kata springen; aktiviert zugleich `--mode kata`. |
| `--kata-list` | Board mit fünf Katas ausgeben und beenden; impliziert `--mode kata`. |
| `--port <n>` | Port der Webansicht auf `127.0.0.1`, Standard `8765`. |
| `--no-browser` | Browser nicht automatisch öffnen, nur die URL ausgeben. |
| `--no-web` | Nur CLI, ohne Webansicht. |
| `--no-color` | ANSI-Farben im Terminal deaktivieren. |
| `--skillctl <path>` | Pfad zum echten `skillctl`. Suchfolge: `./build/skillctl` → neben diesem Binary → `$PATH`. |
| `--selftest` | LIVE-Szenarien ohne Interaktion ausführen und echte Exit-Codes prüfen, siehe §4. |

```bash
./skillctl-demo --mode kiosk --kiosk-delay 5s      # booth loop
./skillctl-demo --mode kata                         # hands-on training (§5)
./skillctl-demo --kata K3                            # jump straight to Kata K3
./skillctl-demo --kata-list                         # print the 5-Kata board and exit
./skillctl-demo --no-browser --port 9000           # headless / custom port
./skillctl-demo --skillctl /usr/local/bin/skillctl # point at a specific skillctl
```

---

## 2. LIVE-Szenarien mit echten Exit-Codes

Diese drei Szenarien führen das echte `skillctl` in der Sandbox aus. Beobachten Sie
den Wechsel der Exit-Code-Anzeige.

### S1: Manipuliertes Skript → die Signatur verhindert die Ausführung

Ein signiertes `.skb`-Skill-Bundle wird **offline** gegen einen gepinnten Schlüssel
geprüft. Ein Angreifer verändert ein Skript *im* Bundle, um `~/.ssh` auszuleiten,
und verteilt es erneut. Ein verändertes Byte bricht den signierten Digest.

```
verify --bundle  →  0 (clean)  →  10 (digest mismatch, refused)
```

Die Signatur *beschreibt* das Risiko nicht nur, sie **verhindert die Ausführung**.
Nichts wird nach `~/.claude/skills/` geschrieben.

### S2A: Manipulation nach Installation → erneute Prüfung erkennt sie

Ein installierter grüner Skill wird auf der Festplatte verändert, um eine Prompt-Injection
in `SKILL.md` einzuschleusen. Das Lade-Gate `PreToolUse(Skill)` prüft die Vertrauenskette
**vor** dem Laden durch Claude Code erneut; anschließend setzt ein Prüflauf den Skill in Quarantäne.

```
verify-hook  →  0 (allow)  →  2 (gate BLOCKS the tampered load)
verify --all →  per-skill verdict 10 (digest mismatch)  →  quarantined
```

### S5: Reversible Governance ohne Erzwingen bei Zustandsänderung

Eine destruktive Operation von `skillctl`, die Cachebereinigung, erfolgt als
**G-23-Zweischritt**: signierter Dry-Run-Plan mit kurzlebigem Token, dann Bestätigung
mit **erneuter Prüfung der aktuell betroffenen Menge**. Ändert sie sich vor der
Bestätigung, **wird die Bestätigung verweigert**.

```
audit --cleanup --dry-run-cleanup   →  0 (plan + signed 5-minute token)
audit --cleanup --confirm-delete …  →  2 (confirm REFUSES on drift)
```

Exit `2` ist eine Verweigerung wegen Aufruf oder Vorbedingung. Das Token passt nicht
mehr zur aktuellen Menge. **Es gibt kein `--force`**; Plan und Ablehnung sind auditierbar.

---

## 3. Roadmap-Tafeln ohne Ausführung

Die Präsentation zeigt außerdem drei Szenarien, die sie **nicht** ausführt.
Jedes erklärt seine Geschichte und die *nächstliegende bereits implementierte Funktion*,
ehrlich gekennzeichnet. Sie erscheinen nie als LIVE-Ergebnisse.

| Szenario | Stufe | Dokumentierter Exit | Grund für die fehlende Ausführung |
|---|---|---|---|
| **S2BC**: Laufzeitverletzung der Rechtehülle und Flottensperre | `ROADMAP` | `envelope 32 · revoke 17` | Die Go-native ausgehende Netzwerksperre auf Betriebssystemebene ist FR-0044 und offen; die Sperrstelle existiert nur als Python-Referenz in `pkg/skillgate`, SPEC-0202. Exit `32` ist Roadmap; kein `skillctl`-Unterbefehl liefert ihn heute. |
| **S3**: Flottenweiter Kill-Switch bei laufender Kompromittierung | `PARTIAL` | `17 (revoked) / 22 (offline fail-closed)` | Die **Offline-Sperre widerrufener Digests ist LIVE vorführbar**: Kata **K5** führt `verify --bundle … --revocations <signed-list>` aus und erhält für einen widerrufenen Digest echt `17`; gefälschte oder nicht vertrauenswürdige Listen werden fail-closed abgewiesen. Der Frischevertrag mit `--emergency`/`--checkpoint`, Exit `22` bei veraltetem Snapshot und riskanter Aktion, sowie FR-0045s signierter `RevocationHead`-Feed über `skillctl revoke feed` sind integriert. Roadmap bleibt hier die **laufende Verteilung über die Flotte**: Die Offline-Demo startet kein Registry und führt deshalb keine flottenweite Sperre live aus. Genaue Grenze: Der Kill-Switch schützt fail-closed gegen **kompromittierten Feed oder Transport**, also MITM, bösartigen Mirror, gekürzte Mengen, Epoch-Rollback, Replay und gefälschte Frische durch den gepinnten Registry-Schlüssel; nicht gegen einen kompromittierten Prozess mit derselben UID. |
| **S4**: Nicht vertrauenswürdiger Internetimport → Schleuse | `ROADMAP` | `1 (refused on critical-rule hit)` | Ein statischer Importscanner existiert in `import_public_cmds.go`, SPEC-0201. Der Schleusenablauf ist aber nicht mit der Offline-Demo verbunden; S4 bleibt eine gekennzeichnete Roadmap-Tafel. |

---

## 4. Nachweis in CI mit `--selftest`

`--selftest` führt die drei LIVE-Szenarien ohne Interaktion aus, vergleicht jeden
gemessenen Exit-Code mit der Erwartung, gibt eine PASS/FAIL-Tabelle aus und endet bei
jeder verletzten Prüfung mit einem Fehlercode. Dies ist der CI-taugliche Nachweis,
dass die implementierten Sperren greifen.

```bash
./skillctl-demo --selftest
```

```
──────── selftest summary ────────
  1. allowed  exit=0  expected=0   [PASS]
  2. blocked  exit=10 expected=10  [PASS]
  ...
  ✔ all N exit-code assertions passed (real skillctl).
```

---

## 5. Trainingsmodus Kata: **ausgeliefert**

> **Status: BUILT (`--mode kata`, `--kata K1..K5`, `--kata-list`).** Das Binary enthält
> `guided`, `kiosk` und `kata`. Der Kata-Modus führt das echte `skillctl` durch fünf
> praktische Übungen. **Jeder Fortschritt beruht auf einem echten `skillctl`-Exit-Code**, nie auf einem simulierten.

Während die Demomodi einen Käufer vom Nutzen überzeugen, dient **Kata** der Einarbeitung:
Aus "Demo gesehen" wird durch **gezieltes Üben mit einem Coach** die Fähigkeit,
`skillctl` zu bedienen. Es ist kein bloßes Durchklicken. Der Modus nutzt das CEW-Kata-Vokabular
wieder: SPEC-0303 mit Drei-Zustands-Automat, **N/3-Anzeige**, *sitzt* und *rust*.
Damit stärkt die Werkzeugeinführung dasselbe Coachingmodell. Nichts beruht auf
Selbstauskunft: **Bestanden bedeutet einen echten Exit-Code.**

```bash
./skillctl-demo --mode kata        # start the coach loop + Kata board
./skillctl-demo --kata K2          # jump straight to K2
./skillctl-demo --kata-list        # print the 5-Kata board and exit
```

**Die fünf Katas**: Zielzustand → Übung → grün, wenn:

| Kata | Die lernende Person kann ... | Geübt mit | Grün bei |
|---|---|---|---|
| **K1 Seal & prove** | Einen Skill versiegeln und Urheberschaft offline nachweisen | `keygen → pack → sign → verify --bundle` → Exit `0` | Drei unterschiedliche saubere Wiederholungen |
| **K2 Detect tamper** | Einen veränderten Skill vor Ausführung erkennen | Auf Festplatte ändern → `verify --all` → Exit `10` | Drei Wiederholungen |
| **K3 Govern reversibly** | Eine destruktive, nicht erzwingbare Operation ausführen | `audit --cleanup --dry-run-cleanup` → `--cleanup --confirm-delete` nach Mengenänderung → Exit `2` | Drei Wiederholungen |
| **K4 Trust roots & install** | Ein Registry pinnen und nur zugelassene Inhalte installieren | `trust add → install → verify` → Exit `0` | Drei Wiederholungen |
| **K5 Revoke & fail-closed** | Einen widerrufenen Skill offline und fail-closed verweigern | `verify --bundle … --revocations <signed-list>` → widerrufener Digest → Exit `17` | Drei Wiederholungen, zusätzlich S3 zur flottenweiten Verteilung lesen |

K5 ist eine **echte** Übung: Die Offline-Sperre `verify --bundle --revocations` mit
Exit `17` wird ausgeführt. Nur die **laufende flottenweite Verteilung** bleibt Roadmap,
da die Offline-Demo kein Registry startet, siehe S3 in §3.

**Der Coachingzyklus mit fünf Fragen; das Werkzeug übernimmt den Coach:**

1. **Ziel**: Die Fähigkeit, die Sie nachweisen sollen.
2. **Ist-Zustand**: "Wo stehen Sie? Ausführen und beobachten." Die lernende Person führt den echten Befehl aus.
3. **Hindernis**: "Was hat Sie aufgehalten?" Das Werkzeug ordnet echte Exit-Codes `10`/`2`/`17` verständlichen Hindernissen zu.
4. **Nächstes Experiment und Erwartung**: Den Exit-Code vorhersagen, dann handeln.
5. **Hingehen und sehen**: Ausführen; das Werkzeug zeigt das **echte** Ergebnis und erfasst einen *beat*.

**Beherrschung.** Eine saubere, unterschiedliche Wiederholung ist ein Schritt zu
**N/3 → *sitzt* (grün)**. Ohne Übung über das Zeitfenster `KATA_STALL_DAYS`, standardmäßig
`5`, setzt *rust* ein und die Kata bewegt sich zurück Richtung Rot, wie im
Drei-Zustands-Automaten von CEW. Der Fortschritt **bleibt lokal gespeichert** unter
`~/.skillctl-demo/kata-progress.json`. Im Browser zeigt ein **Kata-Board** je eine Karte
mit Rot/Gelb/Grün und N/3-Anzeige, laufend mit jedem erfassten Fortschritt aktualisiert.

---

## Nächste Schritte

- **Jeder `skillctl`-Befehl, jedes Flag und jeder Exit-Code:** [skillctl-Handbuch](../referenz/manual-skillctl.de.md)
- **Eigenen Skill in fünf Minuten erstellen, signieren und prüfen:** [Schnellstart: skillctl](quickstart-skillctl.de.md)
- **Exit-Code-Verträge der Szenarien**, `10` bei Digest-Abweichung, `2` bei G-23-Zustandsänderung,
  `17` bei Widerruf und `22` bei unzureichender Frische: [Exit-Code-Tabelle des Handbuchs](../referenz/manual-skillctl.md#exit-codes).
