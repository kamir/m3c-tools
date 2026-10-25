---
layout: default
title: 'Handbuch: skillctl'
---

# Handbuch: skillctl

[Deutsch](manual-skillctl.de.md) | [English](manual-skillctl.md)

`skillctl` ist die CLI für Vertrauen und Governance von Agenten-Skills. Jeder
Skill erhält eine überprüfbare Identität und einen vollständigen Lebenszyklus:
**author → pack → sign → admit → attest → verify / install → use → audit → revoke**.
So soll alles, was ein Agent ausführt, autorisiert und nachweisbar sein. Die
Vertrauenskette ist **offline überprüfbar; keine externe Autorität liegt im
Prüfpfad.** Eine gehostete Registry, ein Ledger oder ein Transparenz-Log ergänzt
die Prüfung, ist aber kein Erfordernis für den Echtheitsnachweis eines Bundles.

> **Neu hier?** Der [Schnellstart: skillctl](../nutzer/quickstart-skillctl.de.md)
> führt in etwa fünf Minuten durch den regulären Ablauf. Dieses Handbuch ist die
> vollständige Referenz: alle Befehle, Flags und Exit-Codes, abgeleitet aus
> `skillctl help` und der jeweiligen `--help`-Ausgabe.

`skillctl` wird im selben Repository wie `m3c-tools` ausgeliefert und verwendet
für Registry-Zugriffe dessen ER1-Geräteanmeldung (`skillctl login`).

---

## Installation

`skillctl` ist eine einzelne CLI-Binärdatei mit wenigen Abhängigkeiten und läuft
unter macOS, Linux und Windows gleich. Laden Sie die passende Plattformversion
aus einem [Release](https://github.com/kamir/m3c-tools/releases/latest) herunter
oder erstellen Sie sie aus dem Quellcode:

```bash
go build -o build/skillctl ./cmd/skillctl
```

Plattformspezifische Installations-Einzeiler stehen im
[Schnellstart](../nutzer/quickstart-skillctl.md#1-install).

```bash
skillctl version          # print the build version
skillctl help             # the full command map, grouped by capability
```

`skillctl help` gruppiert die Befehle nach der einführenden SPEC: **S1** Signieren,
**Geräteanmeldung**, **S7** Vertrauensanker, **S8** Installation/Prüfung,
**SPEC-0247** Claude-Code-Vertrauensprüfung, **SPEC-0277** AgentID, **SPEC-0195**
Awareness-Brücke, **SPEC-0214** PLM-Projektkontext, **SPEC-0225** persönliche Registry,
**SPEC-0213** Sitzungszustand und **SPEC-0278** L1-Transparenz-Log. Die Flags eines
Befehls zeigt dessen Aufruf mit `--help`.

---

## Begriffe

| Begriff | Bedeutung |
|------|---------|
| **`.skb`-Bundle** | Versiegeltes Skill-Bundle: ein Skill-Verzeichnis mit `SKILL.md`, gepackt mit signiertem Manifest (`bundle.json`). Sein SHA-256-Digest ist die stabile Identität des Bundles. |
| **Separate Autorensignatur** | Eine ed25519-Signatur über den 32-Byte-Digest des Bundles. Sie steht *neben* dem Bundle als `<bundle>.<digest_hex>.author.sig`. Jeder mit dem öffentlichen Autorenschlüssel kann sie offline prüfen. |
| **Vertrauensanker** | Die von *Ihnen* fest hinterlegten öffentlichen Registry-Schlüssel; nur diesen vertraut der Verifier. Es gibt **zwei Dateien, eine je Registry-Modell**: `~/.claude/skill-trust-roots.yaml` für HTTP-Registries, verwaltet mit `trust`, und die manuell erstellte `~/.claude/trust-roots.yaml` für die ER1-Registry `self`. Siehe [Vertrauensanker und Registries: welche Datei wann?](manual-skillctl.md#trust-roots--registries-which-file-when). |
| **Registry** | Speicherort zugelassener Bundles und ihrer Governance-Ereignisse; persönliche ER1-Registry `self` oder HTTP-Registry. Sie dient der *Verteilung und dem Audit* und liegt **nicht** im kryptografischen Prüfpfad. |
| **Admit / attest** | *Admit* veröffentlicht ein Bundle in einer Registry. *Attest* veröffentlicht ein signiertes Governance-Urteil über einen zugelassenen Digest. Attestierungen, nicht die Absicht des Autors, sind für Governance verbindlich. |
| **Governance-Stufe (green/yellow/red)** | Das Urteil einer Attestierung. Install/verify erzwingen ein einstellbares Minimum, standardmäßig green. Die *Absicht* des Autors ist nur ein Hinweis und wird vom Verifier ignoriert. |
| **Widerruf und Aktualität** | Eine signierte, offline überprüfbare Widerrufsliste. Aufrufwege mit Aktualitätsprüfung lehnen ungültige Signaturen und zurückgesetzte Stände ab; überalterte Snapshots folgen der Risikoregel der Aktion. Ein signierter Prüfpunkt kann die Aktualitätsfrist erneuern; eine signierte Notfall-Sperrliste sperrt einen benannten Digest. |
| **AgentID** | Ein vom Eigentümer signiertes *Mandat*, das einer bestimmten Agenteninstanz die Verwendung dieser Skills für diese Absichten erlaubt. Die Prüfung erfolgt **offline** gegen fest hinterlegte Eigentümer-/Genehmigerschlüssel, ohne Autorität im Prüfpfad. |
| **Transparenz-Log (translog)** | Lokales RFC-6962-Merkle-Log (SPEC-0278, „L1“). Macht widersprüchliche Logansichten und das Zurückhalten von Einträgen **erkennbar** und erzeugt offline prüfbare Inklusionsbelege. Es sperrt keine Installationen; L2 (BFT-Ledger) und L3 (öffentliche Verankerung) sind zurückgestellt. |
| **Verweigernde Prüfung bei Fehlern** | `verify-hook` ist ein Claude-Code-Hook `PreToolUse(Skill)`. Er prüft die Vertrauenskette vor jeder Skill-Ausführung und gibt allow/deny aus. Kann er nicht lesen oder prüfen, **verweigert** er die Aktion: fail-closed. |

---

Für lokal konfigurierte verwaltete Roots (`offline_policy.enterprise: true`) beträgt der Standard für `max_staleness` 24 Stunden; größere konfigurierte Werte werden abgelehnt, kürzere bleiben gültig. Das begrenzt den bestehenden Aktualitätsprüfer, nicht jeden Befehl: Fail-open für geringes Risiko bleibt erhalten, HTTP-Installation und neue Aufnahme/Attestierung besitzen noch keine verpflichtende gemeinsame Aktualitätsprüfung, und lokale Installation hängt von ihren Prüfoptionen ab. Diese Einstellung ist weder Organisations-Enrollment noch eine vollständige Enterprise-Abnahme.

Bundle- und AgentID-Widerrufslisten sowie Notfall-Sperrlisten müssen dieselbe nicht leere Registry wie der ausgewählte fest hinterlegte Vertrauensanker benennen, einschließlich Registry-Pfad. Äußere Leerzeichen und abschließende Schrägstriche folgen der Normalisierung des Signaturformats. Eine korrekt signierte Liste einer anderen Registry wird auch dann abgewiesen, wenn beide Registries denselben Schlüssel verwenden. Diese Bindung führt kein Organisations-Enrollment ein und macht die Listenauswahl nicht in jedem Befehl verpflichtend.

## Vertrauensanker und Registries: welche Datei wann?

skillctl hat **zwei** Vertrauensanker-Dateien, eine je Registry-Modell. Die falsche
Datei zu verwenden ist der häufigste Einrichtungsfehler; wählen Sie bewusst:

| Verwendete Registry | Vertrauensanker-Datei | Erstellt durch | Gelesen durch |
|----------------|------------------|------------|---------|
| **ER1 `self`** (`publish` / `pull --registry self`) | `~/.claude/trust-roots.yaml`, flach: `registry: self`, `pubkey_b64`, `fingerprint`, `governance_minimum` | **manuell / über separaten Kanal übertragen** | `pull` |
| **HTTP-Registry `/api/skills`** | `~/.claude/skill-trust-roots.yaml` | `skillctl trust add --registry <URL> --pubkey <path>` | `install`, `verify`, `audit` |

- `skillctl trust add --registry` erwartet eine **URL**, etwa
  `https://aims.example.com/api/skills`, **niemals** eine ER1-Kontext-ID.
  Der Befehl schreibt `skill-trust-roots.yaml`.
- Der Consumer-Pfad für ER1 `self` verwendet `trust add` **nicht**. Erstellen Sie
  `trust-roots.yaml` manuell und prüfen Sie ihren `fingerprint` vor dem ersten
  `pull` über einen unabhängigen Kanal.
- **Schlüssel:** `keygen --out P` schreibt `P.priv` und `P.pub`. Übergeben Sie
  den privaten Schlüssel ausdrücklich mit `--key P.priv` an `sign` / `publish`.
  Die `self`-Vorgabe `~/.config/m3c/skill-registry-self.key` gilt nur ohne `--key`.

Eine Anleitung mit getrennten Rollen für Autor, Reviewer und Consumer bietet das
**[Tutorial: der erste signierte Skill](../nutzer/tutorial-szenario-02-erster-signierter-skill.de.md)**.

---

## Exit-Codes

`install`, `verify`, `verify-sig`, `pull` und die Gates liefern **nummerierte**
Exit-Codes, damit Automatisierungen präzise verzweigen können. Es folgen zwei
Tabellen. `cmd/exitaudit` prüft beide bei jedem Aufruf von `scripts/check-docs.sh`
gegen `pkg/skillctl/exitcode`: Die erste ist das Register selbst; die zweite führt
außerhalb davon definierte Nummern auf.

Das Gate liest genau die `Exit:`-Angabe unter jedem folgenden Befehl sowie die
Exit-Code-Zellen in [docs/v2/referenz/CLI-VERBS.md](CLI-VERBS.de.md). Jede dort genannte
Nummer muss in einer der beiden Tabellen stehen; ein Code kann deshalb nicht
ohne Herkunftsangabe dokumentiert werden. Zahlen in gewöhnlichem Fließtext und
in der Tabelle `refusal_code` von `verify-hook` werden **nicht** untersucht.
Falsche Nummern an diesen Stellen lassen das Gate nicht fehlschlagen; beide Fälle
wurden am 2026-09-07 mit grünem Ergebnis gemessen. `cmd/exitaudit` nennt bei jedem
Lauf seinen Prüfumfang und die Anzahl von Befehlszeilen ohne `Exit:`-Angabe, die
daher nie mit dem Register verglichen werden.

Der **Basisbereich** gilt für jeden Befehl: `0` erfolgreich, `1` allgemeiner
Fehler einschließlich Netzwerkfehler und Nicht-2xx-Antworten, `2` Aufruf- oder
Flag-Fehler. Die drei `PreToolUse`-Gates (`verify-hook`, `enforce`, `guard-path`)
beenden den Prozess zum Blockieren eines Werkzeugaufrufs immer mit `2`. Ihre
spezifische Nummer steht ausschließlich im Entscheidungsfeld `refusal_code`.
Codes mit derselben Nummer teilen ein Thema (FR-0023); dadurch können Skripte
allein anhand der Nummer verzweigen.

### Das Register

<!-- Generated block: run `go run ./cmd/exitaudit -write` after changing the register. -->
Die Spalten Code, Label, Surface und Theme stammen aus `exitcode.AllCodes()`.
Nur Meaning wird manuell geschrieben und von `exitaudit -write` übernommen.
Manuelle Änderungen an den vier erzeugten Spalten lassen `check-docs.sh` fehlschlagen.

<!-- exitaudit:register:begin -->

| Code | Label | Surface | Theme | Meaning |
|-----:|-------|---------|-------|---------|
| `3` | `need_priv_msg` | `pin` | privileged write required | `pin install` hat die zusammengeführte managed-settings-Datei vorbereitet und eine Anleitung ausgegeben. Nichts wurde geschrieben; den ausgegebenen Befehl mit Administratorrechten wiederholen. |
| `4` | `pin_required` | `import-public` | input validation | Die Importquelle enthielt keinen Pin. Exakten Commit oder Digest festlegen und erneut versuchen. SPEC-0201; diese Funktion ist in diesem Quellbaum nicht implementiert. |
| `5` | `scanner_refuse` | `import-public` | scanner / policy | Der Scanner hat den importierten Skill abgelehnt. Befund lesen; ein unveränderter neuer Versuch hilft nicht. |
| `6` | `bundle_revoked` | `pull` | trust-chain revocation | Alle übersprungenen Bundles scheiterten an der Widerrufsprüfung: Für den Digest existiert ein `BundleRevokedEvent`. Niemals erneut versuchen. Mit `skillctl verify --all` aktualisieren und quarantänisieren. |
| `7` | `no_matches` | `pull` | query yielded nothing | TODO: Handlungsempfehlung für den Betreiber ergänzen. |
| `10` | `digest_mismatch` | `verify` | trust-chain digest | Die Bytes entsprechen nicht den signierten Bytes. Auch `verify-sig` liefert dies bei verändertem Bundle, ebenso `pull --install`, wenn `CHECKSUMS` den Inhalt nicht mehr beschreibt. Herausgeber um erneutes Packen und Signieren bitten; kein Transportfehler. |
| `11` | `sig_invalid` | `signing` | trust-chain signature | `verify-sig` konnte die separate Autorensignatur mit dem übergebenen Schlüssel nicht bestätigen. Prüfen, ob der öffentliche Schlüssel des AUTORS verwendet wurde. |
| `11` | `author_sig_invalid` | `verify` | trust-chain signature | Die Autorensignatur des Bundles ist ungültig. Dieselbe Ursache, diesmal über die Vertrauenskette aus §7 erreicht. |
| `12` | `registry_not_trusted` | `verify` | trust-chain registry-root | Der Registry-Schlüssel fehlt in den Vertrauensankern. Mit `trust add` für HTTP oder `trust-roots.yaml` für `self` fest hinterlegen. |
| `13` | `governance_below_min` | `verify` | policy governance | Keine Attestierung erfüllt die Governance-Mindeststufe. Grüne Attestierung veröffentlichen oder Mindeststufe bewusst absenken. |
| `14` | `deps_unsatisfied` | `verify` | policy dependency | Ein `depends_on`-Eintrag fehlt oder unterschreitet seine Mindeststufe. Zuerst die Abhängigkeit installieren. |
| `15` | `blob_missing` | `verify` | trust-chain blob | Die Registry listet das Bundle, aber dessen Blob lässt sich nicht abrufen. Transport- oder Registry-Fehler; ein neuer Versuch ist sinnvoll. |
| `16` | `tenant_blocked` | `verify` | policy tenant | Die CISO-Konsole hat dieses Bundle für Ihren Mandanten gesperrt. |
| `17` | `no_source_policy` | `import-public` | data-source / source-policy | Keine Quellrichtlinie lässt den Ursprung zu. SPEC-0201; diese Funktion ist in diesem Quellbaum nicht implementiert. |
| `17` | `identity_revoked` | `revoke` | data-source / source-policy | Die Autorenidentität wurde widerrufen; die Herkunftskette des Bundles wird abgelehnt (SPEC-0198 §11). Ausgabe durch `verify` und `install`, nicht durch `revoke` selbst. |
| `17` | `data_source_denied` | `verify` | data-source / source-policy | Eine deklarierte Datenquelle ist durch die Richtlinie gesperrt. Auch der `refusal_code` eines Gates bei widerrufenem Bundle oder einer Notfallsperre. |
| `18` | `intent_capped` | `import-public` | intent contradiction | Die deklarierte Absicht wurde beim Import begrenzt. SPEC-0201; diese Funktion ist in diesem Quellbaum nicht implementiert. |
| `18` | `intent_inconsistent` | `verify` | intent contradiction | Die deklarierte Absicht widerspricht `data_dependencies` (SPEC-0196 §3.3). Ausgabe durch `intent declare` und `pack`. |
| `19` | `source_blocked` | `import-public` | identity / source-block | Die Importquelle ist gesperrt. SPEC-0201; diese Funktion ist in diesem Quellbaum nicht implementiert. |
| `19` | `identity_mismatch` | `verify` | identity / source-block | `client_identity` entspricht nicht `admitted_by_identity`; die Verweigerung von `awareness reset`. |
| `20` | `self_attested` | `verify-chain` | attestation reviewer-independence | Reviewer und Autor der Attestierung sind identisch (`reviewer_id` gleich `author_id`); die Mindeststufe ist damit nicht unabhängig bestätigt (SPEC-0246 §5.2). |
| `21` | `agentid_expired` | `agentid` | agent-identity expiry | Das AgentID-Mandat ist abgelaufen. Neu ausstellen. |
| `22` | `revocation_stale` | `verify-chain` | revocation freshness | Der Widerrufssnapshot ist für diese Aktion zu alt, daher wird verweigert (SPEC-0279 R3, FR-0045 D4). `skillctl revoke feed --refresh` ausführen. |
| `23` | `not_included` | `translog` | log inclusion | `translog verify`: Der Beleg lässt sich nicht gegen den Logkopf bestätigen. |
| `23` | `inclusion_missing` | `verify-chain` | log inclusion | Die Kette enthält keinen Inklusionsnachweis des Transparenz-Logs (SPEC-0278 L1). |
| `24` | `split_view` | `translog` | log equivocation | `translog witness` hat zwei signierte Baumköpfe gefunden, die nicht beide wahr sein können. |
| `25` | `offline_unverifiable_managed` | `state-machine` | offline / no-policy-basis | Ein `refusal_code`, kein Prozess-Exit. Ältere verwaltete Installation ohne Offline-Metadaten; `offline_policy` beschränkt den Online-Ausweichpfad anhand des Zustands. Mit `skillctl install <skill>` die Metadaten speichern. Teilt `25` mit `translog_rewrite` von `translog` unter anderem Thema: die einzige tolerierte historische Kollision, da beide Varianten bereits ausgeliefert sind (siehe `TestCodes_KnownLegacyCollision25`). |
| `25` | `translog_rewrite` | `translog` | log rewrite | `translog consistency`: Verletzung der Append-only-Eigenschaft; das Log wurde umgeschrieben. |
| `26` | `local_audit_unavailable` | `enforce` | evidence / audit-durability | Ein `refusal_code`. `require_local_audit` ist gesetzt und eine Erlaubnis konnte nicht dauerhaft protokolliert werden; das Gate verweigert daher (SPEC-0317 R-8.2). |
| `27` | `sidechannel_denied` | `guard-path` | side-channel / path-guard | Ein `refusal_code`. Die ausdrücklich aktivierte `guard-path`-Prüfung sperrt einen Seitenkanalzugriff auf ein Skill-Verzeichnis (SPEC-0317 R-6). |
| `28` | `offline_locked` | `state-machine` | offline / no-policy-basis | Ein `refusal_code`. Der Rechner ist managed-enterprise und hat keinerlei Vertrauensbasis; `offline_policy` verweigert jeden verwalteten Skill außerhalb der Freigabeliste. Vertrauensanker oder signierten Offline-Prüfpunkt wiederherstellen. |
| `29` | `ingest_rejected` | `sync` | egress / ingest | Der Ingest-Endpunkt hat den Batch wegen Authentifizierung oder Validierung mit 4xx abgelehnt. Unverändert nicht wiederholbar. |
| `40` | `audit_backend_config` | `sync` | egress / config | Die Backend-Auswahl für den Audit-Export wurde abgelehnt (SPEC-0455): Endpunkt ohne Backend-Namen (mit `SKILLCTL_AUDIT_BACKEND=er1` setzen), unbekanntes Backend oder unvollständige Konfiguration. |

<!-- exitaudit:register:end -->

### Codes außerhalb des Registers

Nicht jede Exit-Nummer ist ein registrierter Code; auch die übrigen müssen jedoch
dokumentiert werden. `bundle_revoked` beanspruchte kurzzeitig `20`, obwohl
`verify.ExitSelfAttested` diesen Code bereits seit Wochen lieferte, weil zuvor
nur das Register abgeglichen wurde. Jede Zeile nennt die Quelldatei der Nummer;
`cmd/exitaudit` schlägt fehl, wenn diese Datei nicht mehr vorhanden ist.

<!-- exitaudit:outside:begin -->

| Code | Surface | Source | Why it is not in the register |
|-----:|---------|--------|-------------------------------|
| `0` | all | `cmd/skillctl/signing_cmds.go` | Erfolgreich. Das Register vergibt Fehlercodes; `0` gehört keinem Code und wird vom Invariantentest übersprungen. |
| `1` | all | `cmd/skillctl/signing_cmds.go` | Bewusst unspezifischer allgemeiner Fehler. `pull` liefert ihn auch, wenn Bundles aus UNTERSCHIEDLICHEN Gründen übersprungen wurden: Eine Zahl kann keine zwei Ursachen beschreiben; die Prüfung steht je Bundle in dessen Ausgabezeile. |
| `2` | all | `cmd/skillctl/signing_cmds.go` | Aufruf- oder Flag-Fehler. Auch der Prozess-Exit eines `PreToolUse`-Gates zum BLOCKIEREN eines Werkzeugaufrufs (`exitHookBlock`); spezifische Verweigerungen stehen deshalb in `refusal_code`. |
| `3` | `audit` | `pkg/skillctl/audit/audit.go` | Das Zustandsurteil „mindestens ein Skill ist BROKEN“ (SPEC-0189 §14.2). Darf nicht ins Register: Dort belegt `need_priv_msg` von `pin` die `3` unter anderem Thema. Die Zuordnung von Nummer zu Thema macht das Register verlässlich. Beide Funktionen laufen nie innerhalb desselben Befehls. |
| `6` | `import-public` | `(unimplemented)` | SPEC-0201 §11 ordnet `6` einer bodyscan-Verweigerung zu. Diesen Befehl gibt es hier nicht; `6` gehört inzwischen `bundle_revoked` von `pull`. Ein zukünftiges `import-public` muss eine freie Nummer wählen. |
| `32` | `skillgate` | `pkg/skillgate/gate.go` | Der Laufzeitbereich für Capability-Hüllen `30`-`39` (SPEC-0202 §8.2) ist ein Bibliotheks-Konstantenbereich im Python-Referenzgateway. **Kein `skillctl`-Unterbefehl gibt ihn aus**; die native Go-Isolation auf Betriebssystemebene ist FR-0044 und noch ausstehend. Die Nummer erscheint ausschließlich im ROADMAP-Szenario der Demo. |

<!-- exitaudit:outside:end -->

`audit` verwendet eine eigene Skala: `0` alles OK, `2` mindestens ein
`UNVERIFIED`/`BELOW_MIN` oder eine G-23-Verweigerung der confirm-delete-Vorbedingung
bei Drift, `3` mindestens ein `BROKEN`. `propose` verwendet `0` bestanden und `2`
Gate fehlgeschlagen. `auditlog` hat ein eigenes Gesundheitsurteil `0/1`
(SPEC-0403 §8). Ein Gesundheitsbefund darf deshalb nicht als Zustandsurteil
interpretiert werden. Sein `2` ist der gewöhnliche Aufruffehler und kein Teil des
Gesundheitsurteils.

> Einige Befehle geben Flags in ihrer eigenen Hilfe mit **einem Bindestrich** aus,
> etwa `-key` und `-out`. Sowohl `-<flag>` als auch `--<flag>` werden akzeptiert.
> Dieses Handbuch übernimmt die Flag-Namen aus der Befehlsausgabe; Beispiele
> verwenden die übliche Form `--<flag>`.
---

## Befehlsreferenz

### Lebenszyklus im Überblick

```
keygen → pack → sign → verify-sig      # author, locally, fully offline
  → publish (admit) → attest           # governed distribution (registry)
  → trust add → install / verify       # consumer: pin, pull, verify offline
  → verify-hook (gate) → use           # runtime enforcement
  → audit → revoke                     # ongoing governance
```

---

### Begrenztes Entpacken von Bundles

Der gemeinsame gzip/tar-Reader begrenzt entpackte Nutzdaten und Namen standardmäßig
auf 100 MiB und 10.000 sichtbare Einträge. Eine eigene Streamgrenze zählt auch
versteckte PAX-Metadaten, Header, Padding und nachfolgende entpackte Bytes, bevor
der tar-Parser sie verarbeiten kann. Mit den Standardwerten beträgt sie `100 MiB +
10.000 * 1.024 Bytes + 1 MiB`. Eine überschrittene Grenze oder eine ungültige
gzip-Prüfsumme führt zur Ablehnung. Die bisherigen Nutzdaten- und Pfadprüfungen
gelten weiterhin. Diese Grenzen beschränken Decoder-Ressourcen; sie belegen weder
die Authentizität eines Bundles noch isolieren sie dessen Ausführung.

### `runtime fingerprint`: einen Runtime-Baum beobachten

```bash
skillctl runtime fingerprint --json --path /absolute/reviewed-site
skillctl runtime fingerprint --path /absolute/reviewed-site
```

Liest ein ausdrücklich gewähltes Verzeichnis und gibt seinen Baum-Fingerabdruck
aus. Der Befehl führt keinen Interpreter oder Systembefehl aus, ändert kein Profil
oder Trust-Protokoll und genehmigt keine Baseline automatisch. Er ermittelt kein
Standardziel aus Arbeitsverzeichnis, HOME, PATH oder Enterprise-Profil. Der gewählte
Baum muss während der Beobachtung stabil bleiben; der begrenzte Verzeichnislauf
ist kein atomarer Dateisystem-Snapshot und garantiert keine spätere Unveränderlichkeit.

| Flag | Zweck |
|------|-------|
| `--path <absolute-tree>` | Pflichtangabe: ausdrückliches absolutes Verzeichnis mit höchstens 4096 UTF-8-Bytes, ohne NUL, CR oder LF. Relative Pfade und zusätzliche Operanden sind Aufruffehler. |
| `--json` | Gibt ein Ergebnisobjekt aus. Das Flag muss vor fehlerhaften Argumenten stehen, damit deren Fehlerergebnis als JSON erscheint. |
| `--help` | Zeigt Aufruf und Flags des Fingerabdrucks. `skillctl runtime --help` zeigt die Hilfe der Befehlsfamilie. |

Ein erfolgreiches JSON-Ergebnis verwendet das Schema
`m3c.skillctl.runtime-tree-observation/v1`, Operation `runtime_fingerprint`,
`ok: true`, `exit_code: 0`, `complete: true` und `approved: false`. Es enthält den
kanonischen `path`, den kleingeschriebenen SHA-256-`digest`,
`algorithm: "m3c.python-site-tree/v1"` und die durchgesetzten `limits`. Bei einem
Beobachtungsfehler wird kein erfolgreicher Digest ausgegeben. Ein fehlschlagender
Ausgabekanal liefert einen Fehlercode; Teilausgabe ist kein erfolgreiches Ergebnis.

Der unveränderte Baumalgorithmus erfasst Verzeichnisse sowie Inhalt, Größe und
relative Pfade regulärer Dateien; Zeitstempel gehen nicht in den Digest ein.
Grenzen sind 100000 Einträge, insgesamt 4194304 Bytes relativer Pfade, 4096 Bytes
je Pfad, Tiefe 128 und 268435456 Datei-Bytes. Ein Alias des gewählten Wurzelpfads
wird zum kanonischen Verzeichnis aufgelöst; innere Links und besondere Go-Dateitypen
werden verweigert. Transparente Windows-DEDUP-Dateien, die Go als regulär einstuft,
werden als reguläre Dateien gehasht. Lesen kann OS-Zugriffsmetadaten ändern; der
Befehl schreibt nicht ausdrücklich ins Dateisystem.

Unter Windows müssen das gewählte Site-Verzeichnis und die vollständige virtuelle
Umgebung für ihre zwei unterschiedlichen Profilfelder getrennt beobachtet werden:

```powershell
skillctl runtime fingerprint --json --path 'C:\reviewed\env\Lib\site-packages'
skillctl runtime fingerprint --json --path 'C:\reviewed\env'
```

Die Umgebung muss unabhängig geprüft werden, bevor ein Digest ausdrücklich in
ihr Runtime-Profil übernommen wird. Eine Baumbeobachtung beweist weder Paketherkunft
noch die Zuordnung des aktiven Interpreters zur Site. Die verwaltete Enterprise-Installation verlangt
weiterhin das gewählte Profil, dessen genehmigte Baselines und die bestehende
Abhängigkeitsprüfung. Die Diagnose macht eine fehlende oder veraltete Baseline
nicht akzeptabel. Es wird kein MCP-Tool für beliebige Verzeichnisbeobachtungen ergänzt.

Exit: `0` vollständige Beobachtung oder Hilfe, `1` Beobachtungs-/Ausgabefehler, `2` Aufruffehler.

---

### `keygen`: Autorenschlüsselpaar erzeugen

```bash
skillctl keygen --out PATH
```

Schreibt `<PATH>.priv` mit Modus `0600` und `<PATH>.pub` mit Modus `0644`, beide als
PEM-kodiertes ed25519 (PKCS#8 privat / SPKI öffentlich). Empfohlener Speicherort:
`~/.config/m3c/skill-keys/<name>`.

| Flag | Zweck |
|------|---------|
| `-out` | Basisname des Schlüsselpaares; erzeugt `<out>.priv` und `<out>.pub`. **Verpflichtend.** |

```bash
skillctl keygen --out ~/.config/m3c/skill-keys/mykey
```

Exit: `0` erfolgreich · `1` Schreibfehler / Fehler bei der Schlüsselerzeugung · `2` Aufruffehler.

---
### `pack`: `.skb`-Bundle erstellen

```bash
skillctl pack --skill <dir> -o <out.skb> --name <n> --version <v> [options]
```

Packt ein Skill-Verzeichnis mit verpflichtender `SKILL.md` und Manifest in ein
versiegeltes `.skb`-Bundle. Datenbereiche werden **bereits beim Packen vor der
Digest-Berechnung verweigernd geprüft**, sodass die Autorensignatur sie einschließt.

> **Der Bundle-Digest ist innerhalb derselben Go-Toolchain reproduzierbar, nicht
> über Toolchain-Versionen hinweg.** `pack` hasht das gzip-komprimierte Archiv.
> Die gzip-Ausgabe ändert sich zwischen Go-Releases; identischer Inhalt ergibt
> mit anderer Toolchain daher einen anderen Digest. Zwei Läufe auf derselben
> Maschine stimmen überein; zwei Maschinen nur bei identischer Go-Version. Ein
> deshalb abweichender Digest macht das Bundle nicht fehlerhaft. Da die Signatur
> den Digest abdeckt, reproduziert erneutes Packen jedoch kein signiertes
> Artefakt. ADR-0047 verlagert den Digest in `v0.7.0` vor die Kompression und
> beseitigt diese Abhängigkeit. Bis dahin legt das `Makefile` für alle Builds
> und Tests die in `go.mod` genannte Toolchain fest.

> `pack` implementiert `--help` nicht; es gibt `Unknown flag: --help` und danach
> die Aufrufhilfe aus.

| Flag | Zweck |
|------|---------|
| `--skill <dir>` | Skill-Verzeichnis mit `SKILL.md`. **Verpflichtend.** |
| `-o, --output <path>` | `.skb`-Ausgabedatei. **Verpflichtend.** |
| `--name <s>` | Skill-Name im Manifest. **Verpflichtend.** |
| `--version <s>` | Skill-Version im Manifest. **Verpflichtend.** |
| `--summary <s>` | Einzeilige Beschreibung. |
| `--source-repo <s>` / `--source-commit <sha>` / `--source-path <s>` | Herkunft: ursprünglicher Speicherort des Skills. |
| `--author-intent green\|yellow\|red` | Unverbindlicher Governance-Hinweis; **der Verifier ignoriert ihn**, signierte Attestierungen sind maßgeblich. |
| `--author-intent-rationale <s>` | Freitextbegründung der Absicht. |
| `--compatibility <s>` | Kompatibilitätshinweis. |
| `--depends-on kind:name:constraint` | Abhängigkeit deklarieren, etwa `python:requests:>=2.31`. Wiederholbar. |
| `--data-scopes <json>` | Typisierter Datenbereich nach SPEC-0196, in `bundle.json` gebunden. Wiederholbar. Verweigernd geprüft. |
| `--data-dep <json>` | **Veralteter** Alias für `--data-scopes`. |
| `--side-effects <list>` | Kommagetrennte Nebeneffekt-Token nach SPEC-0196 §5, in die Absichtssignatur eingeschlossen. |
| `--destructive true\|false` | Autorenangabe zu irreversiblen Änderungen; Eingabe für die Querregel aus §3.3. |
| `--network true\|false` | Autorenangabe zu ausgehendem Netzwerkzugriff; Eingabe für die Querregel aus §3.3. |

```bash
skillctl pack \
  --skill ./my-skill -o my-skill.skb \
  --name my-skill --version 1.0.0 \
  --summary "What this skill does" \
  --data-scopes '{"id":"ds:fs/cwd","kind":"local_fs","access":"write","scope":"<cwd>/decks/**","reason":"write deck"}'
```

Exit: `0` erfolgreich · `1` Packfehler · `2` Aufruf-/Validierungsfehler · `18` deklarierte Absicht widerspricht `data_dependencies` (SPEC-0196 §3.3; derselbe Code wie bei `intent declare`).

---

### `sign`: Bundle signieren

```bash
skillctl sign --key PATH.priv [--identity-id ID] BUNDLE.skb
```

Berechnet den SHA-256-Digest des Bundles, signiert die 32 rohen Digest-Bytes mit
ed25519 und schreibt eine **separate** Signatur als
`<BUNDLE.skb>.<digest_hex>.author.sig` (64 Rohbytes, Modus `0644`).

| Flag | Zweck |
|------|---------|
| `-key` | Pfad des privaten ed25519-Schlüssels als PEM PKCS#8 (Modus `0600`). **Verpflichtend.** |
| `-identity-id` | Autorenidentitäts-ID: **nur Hinweis, NICHT in der Signatur eingebettet**. Die separate Signatur umfasst allein den Bundle-Digest. Die Autorenidentität wird bei der Prüfung über den fest hinterlegten Vertrauensanker gebunden (SPEC-0188 D4), nicht durch dieses Flag. Für die eigene Buchführung aufgezeichnet. |

```bash
skillctl sign --key ~/.config/m3c/skill-keys/mykey.priv my-skill.skb
```

Exit: `0` erfolgreich · `1` Signierfehler · `2` Aufruffehler.

---

### `verify-sig`: separate Signatur offline prüfen

```bash
skillctl verify-sig --pubkey PATH.pub BUNDLE.skb
```

Berechnet den Bundle-Digest erneut, sucht die passende `.author.sig` und prüft
sie. **Kein Netzwerk, keine Zertifizierungsstelle.**

| Flag | Zweck |
|------|---------|
| `-pubkey` | Pfad des öffentlichen ed25519-Schlüssels als PEM SPKI. **Verpflichtend.** |

```bash
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/mykey.pub my-skill.skb
```

Exit: `0` erfolgreich · `10` Bundle-Bytes nach Signierung verändert; Digest-Abweichung wird VOR der Signatur geprüft, da ein verändertes Bundle zuerst einen Digest-Fehler darstellt, analog zu `verify --bundle` · `11` ungültige Signatur · `1` sonstiger Fehler · `2` Aufruffehler.

---

### `trust`: Vertrauensanker verwalten

```bash
skillctl trust <list|add|remove> [flags]
```

Verwaltet `~/.claude/skill-trust-roots.yaml` (SPEC-0188 §4.4), also die von Ihnen
fest hinterlegten Registry-Schlüssel. Mehrere Schlüssel pro Registry erlauben
überlappende Rotationszeiträume. `rm` ist ein Alias für `remove`.

**`trust list`**: konfigurierte Registries und fest hinterlegte Schlüssel ausgeben.

**`trust add`**: öffentlichen Registry-Schlüssel fest hinterlegen.

| Flag | Zweck |
|------|---------|
| `-registry` | Registry-URL, etwa `https://aims.example.com/api/skills`. **Verpflichtend.** |
| `-pubkey` | Dateipfad des öffentlichen ed25519-Schlüssels als PEM SPKI. **Verpflichtend.** |
| `-id` | Optionale Schlüssel-ID; standardmäßig kurze, aus dem Fingerprint abgeleitete ID. |

**`trust remove`**: Registry einschließlich aller zugehörigen Schlüssel entfernen.

| Flag | Zweck |
|------|---------|
| `-registry` | URL der zu entfernenden Registry. **Verpflichtend.** |

```bash
skillctl trust add --registry https://aims.example.com/api/skills --pubkey registry.pub
skillctl trust list
skillctl trust remove --registry https://aims.example.com/api/skills
```

`trust --help` zeigt zusätzlich die gemeinsame Exit-Code-Tabelle des Verifiers;
siehe [Exit-Codes](manual-skillctl.md#exit-codes).

---

**`trust state`: lokale verwaltete Mutationshistorie**

Vor einer lokalen verwalteten Bundle-Installation einmal `trust state enroll`
aufrufen. Sowohl `--profile local-operator-v1` als auch `--confirm-local-trust`
sind Pflicht: Der Betreiber vertraut damit ausdrücklich dem lokalen Betreiber
und der OS-Systemuhr. Enrollment legt registryspezifische Historie unter
`<home>/.claude/mutation-state` an und verweigert ein vorhandenes oder reserviertes
Registryverzeichnis, auch bei unvollständigem Zustand. Für State-Befehle und
Installation dieselben Werte für `--home`, Registry und fest hinterlegte
Vertrauensanker verwenden.

`trust state status` gibt JSON-Metadaten aus: Registry, Anker-/Evidenzfingerprints,
Epoche, Ausgabezeitpunkt und letzte Uhrbeobachtung. Es führt kein Enrollment,
keine Reparatur und keine Fortschreibung der Beobachtung aus und kann veraltete,
authentisierte Evidenz diagnostizieren. Erfolgreicher Status erlaubt keine
Installation. `trust state adopt` benötigt vorhandene gültige Historie und eine
frische vollständige signierte Liste; Epoche und signierter Ausgabezeitpunkt
dürfen nicht zurückgehen. Ein Refresh derselben Epoche muss die Widerrufsmenge
beibehalten. Vollständige Listen sind auf 1 MiB begrenzt und müssen reguläre
Dateien statt Symlinks sein.

```bash
skillctl trust state enroll --trust-roots roots.yaml --registry https://registry.example/api/skills --home /absolute/operator-home --revocations revocations.json --profile local-operator-v1 --confirm-local-trust
skillctl trust state status --trust-roots roots.yaml --registry https://registry.example/api/skills --home /absolute/operator-home
skillctl trust state adopt --trust-roots roots.yaml --registry https://registry.example/api/skills --home /absolute/operator-home --revocations revocations.json
skillctl install --enterprise-profile /absolute/project/enterprise.json --bundle demo@1.0.0.skb --home /absolute/operator-home --revocations revocations.json
```

Verwaltetes lokales `install --bundle` benötigt weiterhin `--revocations`. Der
Befehl behält einen begrenzten Snapshot und übernimmt gültige frische Evidenz in
vorhandene Historie, auch wenn der angefragte Subject widerrufen ist oder eine
weitere optionale Richtlinieneingabe danach verweigert. Eine spätere alte Liste
kann diese übernommene Untergrenze nicht löschen. Unmittelbar vor Staging werden
die gespeicherte Historie erneut geprüft und die lokale Beobachtung dauerhaft
fortgeschrieben; eine exklusive OS-Sperre bleibt bis zum Installationsende
gehalten. Fehlender oder korrupter Zustand, Evidenz unter der gespeicherten
Untergrenze sowie unbestätigte Zustandsschreibvorgänge verweigern die Installation. Ein Fehler nach der
Fortschreibung kann neuere Historie ohne abgeschlossene Installation
hinterlassen; State und Skill-Veröffentlichung sind keine gemeinsame atomare
Transaktion. Fehler beim Sperren-Close melden ungewissen Abschluss: Status prüfen,
statt Rollback anzunehmen. Das JSON-Feld `freshness` beschreibt die Prüfung des
Snapshot-Alters; das gesamte `ok` beschreibt das Befehlsergebnis einschließlich
nachfolgender State-Prüfungen.

Dieses Modell verlangt ein betreiber- oder OS-kontrolliertes lokales Home und
entsprechende Elternpfade; State nicht unter einem fremd beschreibbaren
Gemeinschaftsverzeichnis ablegen. Rechte der ausgewählten State-Pfade werden
geprüft, die vollständige ACL-Kette aller Vorfahren jedoch nicht. Das Modell
weist neu vorgelegte Epochen oder Uhrwerte unter der erhaltenen Historie über
normale Neustarts ab und koordiniert kooperierende Writer. Das Wiederherstellen
eines älteren vollständigen gültigen Historieneintrags oder -verzeichnisses
wird ohne externen Anker nicht erkannt. Es schützt nicht gegen böswillige Änderungen
desselben Benutzers, Administratorkontrolle oder vollständigen Maschinen-/Snapshot-
Rollback. Änderungen des Anker-Richtlinienfingerprints erfordern gesonderte
Betreiber-Recovery und erzeugen niemals still eine neue Baseline.

Es gibt weder `reset` noch `--force` oder einen automatisierten Recovery-Executor.
Recovery benötigt einen dokumentierten betrieblichen Vier-Augen-Prozess; die CLI
authentisiert diese Freigaben nicht. Originalzustand und Diagnose sichern und
verlorene Historie, unvollständiges Enrollment oder eine hinter die gespeicherte
Untergrenze korrigierte Uhr eskalieren. Historie niemals still löschen und neu
enrollen. Weitere Install-/Admit-/Attest-Wege, vollständige Dependency-Durchsetzung
und Kundenplattformabnahme bleiben gesonderte Arbeit.


Verwaltetes HTTP-`install <name>@<version>` verwendet jetzt dieselbe enrollte
Historie und gehaltene Veröffentlichungssperre wie lokale Bundles. Dieselben
`--enterprise-profile` mit demselben gepinnten Anker, Registry und Installations-Home wie bei `trust state enroll` wählen;
gespeicherte Evidenz ausdrücklich mit `trust state adopt` erneuern. Der
Registry-Weg verweigert `--meta`, `--revocations`, `--checkpoint` und `--emergency`,
die zum Weg mit `--bundle` gehören.

Die öffentlichen Bibliotheksaufrufe `install.Install` und `install.InstallBundle`
erzwingen verwaltete Historie auch ohne `PostVerify`-Callback. Ihr optionales
`MutationEvidence` liefert eine neuere vollständige signierte Liste, vor dem
Kopieren auf 1 MiB begrenzt; explizite Evidenz mit unverwaltetem Anker wird
verweigert. Bei lokalen Bundles übernimmt die Bibliothek Evidenz vor einer
optionalen Caller-Policy-Verweigerung, damit die neu gelernte Untergrenze erhalten
bleibt. HTTP-Downloads nutzen je Versuch ein eigenes temporäres Verzeichnis;
konkurrierende Downloads können nicht das Staging eines anderen Versuchs löschen.
Dies macht State und Skill-Veröffentlichung nicht zu einer gemeinsamen atomaren
Transaktion. ER1-/Git-Pull und Freigabewege, vollständige Dependency-Durchsetzung
und Kundenabnahme bleiben gesonderte Arbeit.

### `peer`: föderierte Peer-Registry fest hinterlegen (SPEC-0359)

```bash
skillctl peer <add|ls|verify|rm> [args]
```

Ein Peer ist eine andere Registry, aus der Sie Bundles beziehen möchten. Die
Festlegung erfordert **ausschließlich einen unabhängigen Kanal**: `add` verweigert,
wenn `sha256(pubkey)` nicht dem angegebenen `--pin` entspricht. Es gibt daher kein
Zeitfenster mit ungeprüftem Vertrauen beim Erstkontakt.

**`peer add <name> <locator>`**

| Flag | Zweck |
|------|---------|
| `--pubkey <b64>` | ed25519-Signierschlüssel des Peers als Base64. **Verpflichtend.** |
| `--pin sha256:<hex>` | Über unabhängigen Kanal bestätigter Fingerprint des Peer-Vertrauensankers. **Verpflichtend**; `add` scheitert bei Abweichung von `--pubkey`. |
| `--floor green\|yellow` | `governance_minimum` für diesen Peer. |
| `--signer <reviewer-id>:<b64>` | Reviewer, dessen Attestierungen für diesen Peer zählen, als `id:alice@org:<pubkey_b64>`. Wiederholbar. Weglassen, wenn Herausgeber und Reviewer **denselben** Schlüssel verwenden: Ohne Signer ist nur der Registry-Schlüssel selbst als Attestierer zulässig (D2-Modell). |
| `--quorum <n>` | Anzahl **verschiedener** fest hinterlegter Signer, die mindestens auf der Mindeststufe attestieren müssen (Standard `1`). Ohne mindestens ebenso viele `--signer`-Einträge wird verweigert. |
| `--contributes-revokes` | **Signierte** Widerrufsereignisse dieses Peers für `revoke feed --gossip` mit der lokalen Widerrufsmenge vereinigen. **Nur** bei einem für Governance vertrauenswürdigen Peer setzen; dies verhindert Widerrufs-DoS durch beliebige Peers. |

**`peer ls`**: fest hinterlegte Peers mit Name, Locator, Fingerprint und Mindeststufe auflisten.
**`peer verify <name>`**: die Prüfkette aus §7 gegen Peer-Registry und fest
hinterlegten Schlüssel probeweise ausführen und erwartete Erfolge oder Fehler
anzeigen. Installiert nichts.
**`peer rm <name>`**: fest hinterlegten Peer entfernen.

```bash
skillctl peer add alice https://alice.example.com/api/skills \
  --pubkey <base64> --pin sha256:<hex> --floor yellow
skillctl peer verify alice

# publisher and reviewer are DIFFERENT keys: pin the reviewer as a signer, or the
# pull refuses a perfectly valid attestation with
# "gate 4: no attestation at or above the trust-roots governance_minimum".
skillctl peer add kup github://kup/skill-registry \
  --pubkey <publisher-b64> --pin sha256:<hex> \
  --signer id:reviewer@kup:<reviewer-b64> --quorum 1
```

---

### `cross-sign`: Governance-Vertrauensanker bestätigt Mitglieds-Reviewer (SPEC-0359)

```bash
skillctl cross-sign --member-id <id> --member-pubkey <b64> --not-after <when> [flags]
```

Stellt eine vom **Governance-Vertrauensanker signierte** Anerkennung des Schlüssels
eines Mitglieds-Reviewers aus. So können Reviewer ein N-aus-M-Attestierungsquorum
erfüllen, ohne dass jeder Reviewer einzeln fest hinterlegt werden muss.

| Flag | Zweck |
|------|---------|
| `--key <path>` | Privater Schlüssel des **Governance-Vertrauensankers** als PEM PKCS#8 ed25519. **Verpflichtend.** |
| `--member-id <id>` | Identitäts-ID des Mitglieds-Reviewers, etwa `id:alice@org`. **Verpflichtend.** |
| `--member-pubkey <b64>` | Öffentlicher ed25519-Mitgliedsschlüssel als Base64. **Verpflichtend.** |
| `--not-after <when>` | Festes Ablaufdatum als RFC3339, `YYYY-MM-DD` oder Dauer wie `8760h`. **Verpflichtend**; Gegensignaturen ohne Enddatum werden nicht ausgestellt. |
| `--locator <url>` | Optionaler Registry-Locator des Mitglieds. |
| `--out <file>` | Ausgabedatei, standardmäßig stdout. |

```bash
skillctl cross-sign --key governance-root.priv \
  --member-id id:alice@org --member-pubkey <base64> --not-after 8760h --out alice.crosssig
```

---

### `install`: abrufen, prüfen und installieren

```bash
skillctl install [flags] <name>[@<version>]
skillctl install --bundle <file.skb> [--meta <f>] [--trust-roots <f>] [--revocations <f>] [--checkpoint <f>] [--emergency <f>]
```

Ruft ein Bundle aus der Registry ab, führt den Verifier aus SPEC-0188 §7 aus und
installiert **atomar** unter `~/.claude/skills/<name>/`. Scheitert irgendein Schritt
der Vertrauenskette, wird verweigert. `<version>` kann eine lesbare Versionsnummer
(`1.0.0`) oder ein Digest-Pin (`sha256:<hex>`) sein. Ohne Angabe wird die neueste
zugelassene Version installiert.

`--bundle` installiert eine **eigenständige `.skb`-Datei** aus nicht
vertrauenswürdigem Transport, offline gegen fest hinterlegte Vertrauensanker
und die Begleitdatei `<file>.skbmeta.json` (oder `--meta`). Signierte Widerrufe,
Prüfpunkte und Notfall-Sperrlisten werden vor Staging oder Änderungen eines
installierten Skills geprüft; bei einer Verweigerung können Auditdateien
entstehen. Das signierte `bundle.json` bestimmt den Installationsnamen.
Diese drei Offline-Eingaben erfordern `--bundle`.

Bei einem verwalteten Anker (`offline_policy.enterprise: true`) ist
`--revocations` Pflicht. Die authentisierte vollständige Liste benötigt eine
positive Epoche und einen gültigen Ausgabezeitpunkt, der nicht nach der lokalen
Uhr liegt und höchstens 24 Stunden alt ist (oder die kürzere Ankergrenze).
Fehlende oder veraltete Evidenz verweigert die Installation mit `22`; eine Liste
ohne Version ist nicht vertrauenswürdig (`12`). Ein Prüfpunkt kann diese Liste
nicht verjüngen; die Fail-open-Regel für risikoarme Ausführung erlaubt keine
veraltete Installation. Explizite Prüfpunkte und Notfalldateien werden weiter
geprüft.

Verwaltete lokale Bundles benötigen zusätzlich ein explizites `--enterprise-profile` und vorheriges `trust state enroll`.
Die dauerhafte lokale Beobachtung erkennt unbeabsichtigten Uhr-/Epoch-Rücklauf
im unter `trust state` beschriebenen lokalen Betreibermodell. Andere Installationswege
und Kundenabnahme bleiben offen; diese Prüfung allein belegt keine Enterprise-Reife.

| Flag | Zweck |
|------|---------|
| `-allow-yellow` | Mindeststufe für diese Installation von green auf yellow senken; wird protokolliert. |
| `-bundle` | Eigenständige `.skb`-Datei aus nicht vertrauenswürdigem Transport vollständig offline gegen fest hinterlegte Vertrauensanker installieren (SPEC-0406 D2). |
| `-checkpoint` | Signierter Prüfpunkt bei `--bundle`; wird geprüft, kann aber die vollständige Widerrufsliste einer verwalteten Installation nicht verjüngen. Gefälscht/nicht vertrauenswürdig → `12`. |
| `-enterprise-profile` | Explizites Projekt-JSON; Pflicht für verwaltete HTTP-/lokale Bundle-Installationen. Arbeitsverzeichnis und gewähltes Home müssen dessen vorhandenen kanonischen Verzeichnissen entsprechen. |
| `-enterprise-profile-sha256` | Optionaler erwarteter SHA-256 des exakten Projekt-JSONs in Kleinbuchstaben; benötigt `--enterprise-profile`. MCP übergibt den Betreiberpin vom Serverstart. |
| `-emergency` | Signierte Notfall-Sperrliste (SPEC-0279 R5, mit `--bundle`). Genannter Digest → `17`; gefälschte Liste → `12`. |
| `-governance-min green\|yellow` | `governance_minimum` des Vertrauensankers überschreiben; leer verwendet dessen Wert. |
| `-home` | Installationswurzel überschreiben; fortgeschrittene Verwendung, Standard `$HOME`. |
| `-ignore-deps` | Legacy-Auflösung von `depends_on` überspringen; wird protokolliert. Mit Enterprise-Projektprofil verweigert. |
| `-json` | Versioniertes maschinenlesbares Vertrauensergebnis ausgeben. `--json` zuerst setzen, damit auch Fehler beim Parsen der Flags enthalten sind. |
| `-meta` | Pfad des BundleMeta-JSON-Umschlags bei `--bundle`; Standard ist die Begleitdatei `.skbmeta.json`. |
| `-registry` | Registry-Basis-URL; nur erforderlich, wenn Vertrauensanker mehrere Registries festlegen. |
| `-revocations` | Signierte Offline-Widerrufsliste bei `--bundle`; Pflicht bei verwalteten Ankern. Widerrufener Digest → `17`; gefälschte/unversionierte Liste → `12`; fehlende/veraltete verwaltete Evidenz → `22`. |
| `-tenant` | Installation an Mandantenbereich binden (§7, Schritt 5.5); überschreibt `tenant_scope` des Vertrauensankers. |
| `-timeout` | HTTP-Zeitlimit für Registry-Aufrufe, standardmäßig `30s`. |
| `-trust-roots` | Andere Vertrauensanker-YAML statt Standard verwenden; zusammen mit `--bundle` für ein portables Kit. |
| `-verbose` | Strukturierte Logzeilen je Prüfschritt auf stderr ausgeben. |

```bash
skillctl install my-skill@1.0.0
skillctl install --verbose my-skill@sha256:<hex>
skillctl install --bundle demo@1.0.0.skb --trust-roots roots.yaml --revocations revocations.json
```

Exit: `0`, `1`, `2` sowie alle von `verify.ExitCode` zugeordneten, in diesem Pfad
tatsächlich erreichbaren Codes aus §7: `10`–`17`, `20` (Selbstattestierung) und
`22` (veralteter Widerrufssnapshot). Bei `--bundle` bezeichnet `17` außerdem eine
Notfallsperre; siehe [Exit-Codes](manual-skillctl.md#exit-codes).

`23` (fehlende Log-Inklusion) gehört **nicht** dazu, obwohl `verify.ExitCode` ihn
zuordnet. `verify.CheckLogInclusion`, die einzige Quelle von
`ErrLogInclusionMissing`, wird außerhalb ihrer Tests nicht aufgerufen. Daher
können `install` und `verify` diesen Code nicht erreichen. Aktuell ist `23`
ausschließlich über `translog verify` erreichbar.

---
### Enterprise-Projektauswahl für Installationen

Verwaltete Installationen im explizit gewählten Projektverzeichnis ausführen. Das
Profil pinnt vorhandene öffentliche Trust-Dateien und das Runtime-Profil über den
SHA-256 ihrer exakten Dateibytes; relative Referenzen gelten neben dem Projekt-JSON.
Es enthält keine Zugangsdaten. Das Runtime-Profil verwendet das Schema
`m3c.skillctl.runtime-profile/v1` und dieselbe kanonische `project_root`; es wählt
absolute Python-/Toolpfade statt PATH. Versionsbedingungen verwenden die Resolver-Policy `numeric-release/v1`; nicht unterstützte Syntax wird verweigert. Der Betreiber muss Paketbaum-Baselines
prüfen und ausdrücklich vorgeben. Installation oder Beobachtung von Paketen erteilt
keine automatische Baseline-Freigabe.

Beispielform; Pfade und Hashes durch geprüfte Werte ersetzen:

```json
{
  "schema": "m3c.enterprise-project-profile/v1",
  "project_root": "/absolute/project",
  "artifact_home": "/absolute/operator-home",
  "registry_url": "https://registry.example/api/skills",
  "artifact_trust": {"path": "roots.yaml", "sha256": "<64 lowercase hex characters>"},
  "revocation_trust": {"path": "roots.yaml", "sha256": "<64 lowercase hex characters>"},
  "runtime": {"path": "runtime.json", "sha256": "<64 lowercase hex characters>"}
}
```

Diese Version unterstützt eine verwaltete HTTP-Autorität. Beide Rollenreferenzen
werden getrennt geladen und gepinnt und müssen vollständig identische Anker und
Mandantenbereiche wählen. Getrennte Autoritäten/Schlüssel, mehrere Registries und
andere Trust-Formate werden verweigert und nicht umgedeutet. `allow_loopback_http: true`
erlaubt ausdrücklich HTTP auf Loopback für die Entwicklung; entfernte Registries
benötigen HTTPS.

Mit Profil werden Trust-Datei- und Mandanten-Overrides sowie `--ignore-deps`,
`--allow-yellow` und Governance-Overrides verweigert. Widersprüchliche Registry-, Home- oder
Projektauswahl scheitert ebenfalls vor Registry-Zugangsdaten oder Anfragen. Der SDK
verlangt das Profil auch ohne CLI-Callback. Die signierten, erhaltenen Bytes von
`bundle.json` bestimmen die Runtime-Deklarationen. Python-/Systemanforderungen
werden geprüft und vor dem ersten Austausch eines installierten Skills erneut
geprüft. Danach prüft die gehaltene Sperre die signierte Widerrufshistorie und die
tatsächliche Uhr erneut.

Skill-Abhängigkeiten können eine bereits aktive HTTP-Installation verwenden, wenn
die gewählten Vertrauensanker die Autorenschlüssel ausdrücklich pinnen. Genau eine
reguläre erhaltene `.skb` und ein begrenzter `.skillctl-offline.json`-Umschlag liefern
den erhaltenen Nachweis. Archivdigest und Signaturen werden unter den gewählten
Ankern und der bestehenden Verifier-Policy geprüft. Veränderliche Projektionen im
Umschlag werden nicht unabhängig authentifiziert; Governance folgt weiterhin dieser
Policy. Unsignierte Identitätsfelder wählen keine Autorität.
Signierter Name, Typ, numerische Release-Version und Abhängigkeitsdeklarationen
bestimmen den Graphen. Entpackte Dateien müssen dem signierten Archiv entsprechen;
unerwartete Dateien oder Verzeichnisse werden verweigert. Symlinks und Spezialdateien
werden auch unter sonst ausgenommenen Metadatennamen verweigert. Unsignierte
Metadaten belegen bei gemeinsam genutzten Schlüsseln nicht die Ursprungsregistry.

Der vollständige transitive Graph wird gegen die gewählte Runtime geprüft und vor
dem Zielaustausch aus frischen aktiven Nachweisen erneut geprüft. Anschließend prüft
die gehaltene Trust-Sitzung den Root-Digest und jeden Abhängigkeitsdigest gegen die
erhaltenen Widerrufe und die aktuelle Uhr. Widerruf und fehlende Aktualität behalten
Exit `17` und `22`; unbrauchbare Abhängigkeitsnachweise liefern `14`. Aktive
Verzeichnisidentität und Descriptor-Freigabe werden geprüft; dies ist kein atomarer
Dateisystem-Snapshot und keine Isolation gegenüber einem feindlichen lokalen Betreiber.

Jede Nachweisphase begrenzt ausdrücklich verwaltete Handles insgesamt auf 64,
einschließlich Ankern und temporären Datei-/Verzeichnis-Handles; aggregierte reservierte
Arbeit ist auf 512 MiB begrenzt, Einträge auf 100.000, relative Pfadbytes auf 4 MiB, Pfadlänge auf
4096 und Tiefe auf 128. Metadaten sind auf 1 MiB und erhaltene komprimierte Archive
auf 256 MiB begrenzt. Das verbleibende Pfad-/Eintragsbudget begrenzt zusätzlich jeden
entpackten Stream konservativ; Decoder-Arbeit reserviert das 64-Fache der Streambytes.
Große sonst gültige Archive können daher unterhalb des Archivlimits verweigert
werden. Zwischen I/O-Operationen wird Abbruch geprüft; blockierte Dateisystemoperationen
haben dadurch keine garantierte Frist.

Agenten und erhaltene Nachweise, deren Autorenschlüssel von der Registry autorisiert
werden müssen, bleiben mit Installations-/Neuinstallationshinweis gesperrt. Ein Verzeichnis oder eine unsignierte Begleitdatei allein
erfüllt den Guard nicht. Abhängigkeiten werden nicht automatisch installiert. Diese
Verweigerungen bedeuten keine vollständige Unterstützung oder Enterprise-Abnahme;
ER1/Git/self und Admit-/Attest-Integration bleiben offen.
Status und Diagnose benötigen dieses Installationsprofil nicht.

Für MCP `skill_install` setzt der Betreiber `SKILLCTL_ENTERPRISE_PROFILE`,
`SKILLCTL_PROJECT_ROOT` und `SKILLCTL_ARTIFACT_HOME` sowie das vorgesehene
`SKILLCTL_BIN` vor dem Serverstart. Der Server hält Profilhash und Pfade fest und
ruft die echte CLI mit explizitem Projekt-Arbeitsverzeichnis und Dateipin auf.
Unvollständige/ungültige Konfiguration oder spätere Änderungen der Profilbytes
sperren die Installation; nach absichtlichen Betreiberänderungen neu starten.
`enterprise_profile` in einer Toolanfrage darf nur den Betreiberpfad wiederholen
und keine andere Trust-Policy auswählen.

---

### `verify`: Vertrauenskette erneut prüfen

```bash
skillctl verify [flags] <name>
skillctl verify --all [--quarantine]
skillctl verify [--json] --bundle <file.skb> [--trust-roots <file>]
```

Prüft die Vertrauenskette aus SPEC-0188 §7 erneut für einen installierten Skill.
Das erkennt etwa nachträgliche Widerrufe oder gedrehte Vertrauensanker. `--all`
prüft sämtliche Installationen erneut.

**Zwei Träger, ein Befehl** (FR-0116). Ein mit `install` installierter Skill ist
an die HTTP-Vertrauensanker-Datei gebunden. Ein mit `pull --install` aus self/ER1
oder einer Git-Registry installierter Skill ist dagegen an
`~/.claude/trust-roots.yaml` oder einen mit `peer add` festgelegten Peer gebunden;
`.m3c-provenance.json` und `.skillctl-attest.json` belegen dies. `verify <name>`
versucht zuerst das HTTP-Modell und danach diese Begleitdatei-Ebene. Dabei wird
der Peer ausgewählt, dessen Locator der in den Herkunftsdaten gespeicherten
Registry entspricht. Eine fehlende `skill-trust-roots.yaml` beendet deshalb
nur einen von zwei Pfaden, nicht mehr den gesamten Befehl.
`--bundle` prüft eine **eigenständige `.skb`-Datei** ohne Installationszustand oder
Netzwerk gegen lokale Vertrauensanker. Dieser Prüfpfad für nicht vertrauenswürdige
Dritte benötigt `<file>.skbmeta.json` oder `--meta` als Begleitdaten.

| Flag | Zweck |
|------|---------|
| `-bundle` | Eigenständige `.skb`-Datei vollständig offline gegen fest hinterlegte Vertrauensanker prüfen (SPEC-0276 R4.2). |
| `-meta` | Pfad des BundleMeta-JSON-Umschlags für `--bundle`; standardmäßig Begleitdatei `.skbmeta.json`. |
| `-trust-roots` | Andere Vertrauensanker-YAML statt Standard; mit `--bundle` für ein portables Kit kombinieren. |
| `-offline` | Ohne Netzwerk prüfen: gespeicherte Metadaten verwenden und lokale Inhalte an das signierte `.skb` binden. Keine Registry-Aufrufe. |
| `-revocations` | Bei `--bundle` offline durchgesetzte signierte Widerrufsliste. Widerrufener Digest → `17`; gefälschte Liste → `12`. |
| `-checkpoint` | Signierter Aktualitätsprüfpunkt (SPEC-0279 R4), der die Überalterungsfrist von `--revocations` erneuert. Gefälscht/nicht vertrauenswürdig → `12`; zurückgesetzter oder zu alter Prüfpunkt erneuert die Frist nicht, Snapshot bleibt veraltet → `22`. |
| `-emergency` | Signierte Notfall-Sperrliste (SPEC-0279 R5). Genannter Digest → `17`; gefälschte Liste → `12`. |
| `-allow-yellow` | Gelbes Ergebnis trotz grün verlangendem Vertrauensanker zulassen; kein erneutes Audit. |
| `-governance-min green\|yellow` | `governance_minimum` des Vertrauensankers überschreiben. |
| `-home` | Installationswurzel überschreiben. |
| `-json` | Versioniertes maschinenlesbares Vertrauensergebnis für einzelne Registry-, Installed-offline- oder eigenständige Bundle-Prüfungen ausgeben. `--json` zuerst setzen, damit auch Fehler beim Parsen der Flags enthalten sind. |
| `-registry` | Registry-Basis-URL; nur bei mehreren fest hinterlegten Registries erforderlich. |
| `-tenant` | Prüfung an einen Mandantenbereich binden (§7, Schritt 5.5). |
| `-timeout` | HTTP-Zeitlimit für Registry-Aufrufe, standardmäßig `30s`. |
| `-verbose` | Strukturierte Logzeilen je Prüfschritt auf stderr ausgeben. |

Maschinenleser setzen `--json` vor den Namen: `skillctl install --json my-skill`
oder `skillctl verify --json --offline my-skill`. `--json` steht zuerst, damit auch Fehler beim Parsen der Flags als JSON erscheinen;
alle weiteren Flags stehen vor Positionsargumenten. Ein unbekanntes Flag vor `--json`
beendet das Parsen, bevor die JSON-Ausgabe aktiviert ist.
Jeder unterstützte Pfad für ein einzelnes Skill gibt genau ein JSON-Objekt mit `schema`
als `m3c.skillctl.trust-result/v1`, `operation` (`install` oder `verify`), `ok` und
`exit_code` aus. Fehler enthalten `error`; Erfolg enthält `digest`, `author_identity`,
`registry_key_id`, `governance_level`, `governance_verified`, das nullable Feld
`self_attested` und `chain_summary`. Install enthält zusätzlich `install_path` und,
wenn vorhanden, `archived_path`. Die bisherigen Bundle-Felder `data_scopes` und
`freshness` bleiben verfügbar, wenn der Verifier sie liefert. Diagnosen stehen auf
stderr. Ein Fehler beim Schreiben des JSON liefert einen Exit-Code ungleich null.
Prozess-Exit-Code und JSON-Feld `exit_code` müssen übereinstimmen.

`governance_verified:false` bedeutet, dass die gemeldete Governance-Stufe nur beratend
ist. `self_attested:null` bedeutet, dass keine bindende Reviewer-Beziehung festgestellt
wurde; `false` allein beweist keine unabhängige Prüfung. Verbraucher müssen beide
Felder erhalten und ihre konfigurierte Verifier-Policy anwenden. MCP install/verify
fordert diesen JSON-Vertrag an und lehnt fehlerhafte, unvollständige oder widersprüchliche
Erfolgsmeldungen ab. Die menschenlesbare Standardausgabe bleibt erhalten. Der Sidecar-Pfad
hat derzeit keinen maschinenlesbaren Vertrauensvertrag; `verify --json` lehnt diesen
Fallback explizit ab. Der gesonderte Sweep `verify --all` hat den nachfolgend beschriebenen versionierten Inventarvertrag.

**`verify --all`: Flottenprüfung** (SPEC-0247 P0.2). `--all` wird *vor* dem
Flag-Parsing erkannt und aktiviert einen anderen Flag-Satz: Alle installierten
Skills prüfen, ein Urteil je Skill ausgeben und Fehlerfälle optional quarantänisieren
ist eine eigene Aufgabe.

| Flag | Zweck |
|------|---------|
| `--all` | Alle installierten Skills prüfen statt einen nach Namen; `-all` funktioniert ebenfalls. |
| `--quarantine` | An VERTRAUENSPRÜFUNGEN scheiternde *verwaltete* Skills aus `~/.claude/skills/` ins Quarantäneverzeichnis verschieben. |
| `--budget` | Gesamtes Echtzeitbudget. Nicht erreichte Skills erhalten `unverified` und werden niemals quarantänisiert; eine langsame Registry kann Ihre Skills daher nicht löschen. |
| `--session-id` | Gespeicherte Urteilscache-Zeilen mit dieser Sitzungs-ID aus dem `SessionStart`-Ereignis versehen. |


Der JSON-Vertrag des Sweeps lautet `m3c.skillctl.sweep-result/v1`, Operation `verify_all`.
`--json` muss zuerst stehen, damit auch Fehler beim Flag-Parsing JSON liefern. Stdout
enthält genau ein JSON-Objekt, auch bei fehlendem oder leerem Skills-Verzeichnis
(`total: 0`, `entries: []`). Ein erfolgreicher leerer Lauf belegt ausschließlich,
dass dieser Sweep keine Skills zur Prüfung gefunden hat.

Text- und JSON-Modus liefern Prozess-Exit `0` nur bei vollständig gültigem oder leerem
Bestand, `1` bei ungültigen, unvollständig geprüften oder übersprungenen Skills sowie
I/O-/Aktionsfehlern und `2` bei ungültigen Argumenten. Dies ersetzt den früher immer
erfolgreichen Sweep-Exit `0`. `exit` je Eintrag erhält den konkreten Verifier- oder
Policy-Ablehnungsgrund. `complete` bedeutet, dass die erforderliche Entscheidung
abschließend getroffen wurde; ein ungültiges Ergebnis kann vollständig sein, während
`ok` false bleibt. Auswerter müssen sowohl `ok` als auch `complete` prüfen.

Jeder Eintrag enthält `status` (`valid`, `invalid`, `incomplete`, `skipped`), das bisherige
`state`, eine Begründung und benannte Prüfungen für Inhaltsbindung, Vertrauenskette,
Governance, Abhängigkeiten und Widerrufe. Prüfergebnisse sind `pass`, `fail`,
`unconfirmed` oder `not_checked`. `check_scope` unterscheidet Online-/Offline-Ketten,
erneut verankerte Sidecars, Legacy-Sidecars und reine Policy-Entscheidungen. Ein
Offline-Erfolg bestätigt keine frischen Widerrufsinformationen. `revocation_source`
kennzeichnet die konfigurierte Online-Autorität, authentifizierten Cache, Gossip-Ablehnung,
unbestätigte oder nicht verfügbare Nachweise; Gossip allein belegt keinen sauberen
Widerrufsstand.

`digest` wird, sofern verfügbar, aus den tatsächlichen hinterlegten Bundle-Bytes
berechnet; `digest_source` ist `actual_bundle`. Lokale Provenienzmetadaten liefern
diesen Wert nicht. `digest_verified` verlangt zusätzlich authentifizierte Prüfung
und Inhaltsbindung. `governance_verified` erhält die Information, ob Governance
kryptografisch geprüft wurde; eine erlaubte advisory Entscheidung kann false belassen.
Das nullable Feld `self_attested` belegt allein keine unabhängige Prüfung. Legacy-Sidecars
bleiben unvollständig. Deklarierte Abhängigkeiten ohne Resolver sind `unconfirmed`,
wodurch der Sweep insgesamt scheitert; eine transitive Auflösung wird nicht behauptet.

`total = verified + invalid + unverified + skipped`; `unverified` zählt unvollständige
Ergebnisse. `quarantined` zählt nur tatsächliche Verschiebungen; `quarantine_candidates`
zählt auch nur gemeldete und fehlgeschlagene Versuche. `disposition` unterscheidet
`unchanged`, `would_quarantine`, `quarantined` und `quarantine_failed`. Nur ein tatsächliches
Verschieben hat einen `quarantine_path`; ein anschließender Schreibfehler der Notiz erhält
diesen Pfad und meldet `action_error`, Unvollständigkeit und einen Fehler-Exit insgesamt.
Ohne `--quarantine` bleiben Skills am Ort; Urteils- und Audit-Caches können aktualisiert werden.

Budgetprüfungen erfolgen zwischen Skills und begrenzen die Online-Prüfung; synchrone
Dateisystem- und Widerrufsoperationen sind keine unterbrechbare Transaktion. Ein Timeout
kann nach bereits abgeschlossenen Verschiebungen eintreten. Vor Wiederholung Bestand prüfen.

MCP bietet `skill_verify_all(quarantine=False, registry="", governance_min="",
budget_seconds=60, timeout=90)`. Das Budget ist ganzzahlig von 1 bis 300 Sekunden;
der Timeout muss größer sein und darf höchstens 600 Sekunden betragen. Standardmäßig
werden keine Skills verschoben. Der Server erhält den validierten CLI-Inhalt einschließlich
aller fehlgeschlagenen Einträge und weist fehlerhafte oder widersprüchliche Ergebnisse
zurück, statt menschlichen Ausgabetext zu parsen.

```bash
skillctl verify my-skill
skillctl verify --all
skillctl verify --json --bundle my-skill.skb --trust-roots ./roots.yaml
```

Exit: wie `install`; siehe [Exit-Codes](manual-skillctl.md#exit-codes).

---

### `attest`: Governance-Attestierung veröffentlichen

```bash
skillctl attest <bundle-digest> --level <green|yellow|red> \
  --rationale "<text>" --reviewer-id <id> --key <path> \
  [--registry <url>] [--timeout <duration>]
```

Erstellt die kanonische Attestierungsnachricht
(`attestation\n<digest>\n<level>\n<attested_at>\n<reviewer_id>\n`), signiert sie mit
dem angegebenen ed25519-Schlüssel und sendet sie per POST an
`<registry>/attestations`.

`attest` verwendet seine an die Origin gebundenen Registry-Zugangsdaten und
lädt den ER1-Gerätetokenspeicher nicht automatisch. Hilfe und ungültige Argumente
laden daher diesen unabhängigen Gerätetoken nicht. Das Laden der
Registry-Zugangsdaten für eine gültige Anfrage bleibt davon getrennt.

| Flag | Zweck |
|------|---------|
| `-json` | Versionierten Registry-Annahme-Receipt ausgeben. `--json` zuerst setzen, um Fehler beim Parsen der Flags einzuschließen. |
| `-level green\|yellow\|red` | Governance-Urteil. **Verpflichtend.** |
| `-rationale` | Freitextbegründung als Audit-Metadaten, **nicht** Teil der signierten Bytes. **Verpflichtend.** |
| `-reviewer-id` | Identitäts-ID des Reviewers, etwa `id:reviewer@m3c`. **Verpflichtend.** |
| `-key` | Privater ed25519-Schlüssel als PEM PKCS#8, Modus `0600`. **Verpflichtend.** |
| `-author-id` | Bundle-Autoren-ID für die Prüfung Reviewer≠Autor nach SPEC-0246 §5, wenn der Zulassungseintrag offline nicht verfügbar ist. Optional. |
| `-registry` | Registry-Basis-URL, standardmäßig `http://localhost:8080/api/skills`. |
| `-timeout` | HTTP-Anfragezeitlimit, standardmäßig `30s`. |

```bash
skillctl attest sha256:<hex> --level green --rationale "reviewed" \
  --reviewer-id id:reviewer@m3c --key ~/.config/m3c/skill-keys/reviewer.priv \
  --registry https://aims.example.com/api/skills
```

Umgebungs-Credentials für HTTP-Registry-Lesezugriffe und `attest` benötigen einen
passenden `M3C_REGISTRY_TOKEN_ORIGIN`-Pin (Schema, Hostname, effektiver Port), unabhängig
von `--registry`. Ungebundene Lesezugriffe bleiben anonym; `attest` bricht vor dem
Laden des Schlüssels oder Signieren ab. Siehe
[Migration und native Store-Schalter](../betrieb/ops-registry-tokens.de.md#http-registry-credential-origin-und-migration).

`--json` zuerst setzen, um einen maschinenlesbaren Receipt einschließlich Fehlern
beim Parsen der Flags zu erhalten. Das Schema lautet
`m3c.skillctl.attestation-receipt/v1`, mit `operation:"attest"`, `ok` und `exit_code`.
Ein Erfolg enthält `attestation_id` aus der HTTP-201-Antwort der Registry sowie
`bundle_digest`, `governance_level`, `reviewer_id` und `attested_at` aus der tatsächlich
signierten POST-Nachricht. Die Zeit ist kanonisches UTC (`YYYY-MM-DDTHH:MM:SSZ`).
Dies bestätigt die Annahme dieser Übermittlung durch die Registry; es prüft kein Bundle
unabhängig, belegt keine Reviewer-Unabhängigkeit und stellt kein bindendes
Governance-Urteil fest. MCP fordert diesen JSON-Vertrag an und lehnt unvollständige
oder widersprüchliche Receipts ab, auch Werte, die nicht zum übermittelten Digest,
zur Stufe und zum Reviewer passen. Fehlende Receipt-Felder werden nie aus der Anfrage
ergänzt. Fehler enthalten `error`; Prozess- und JSON-Exit-Code müssen übereinstimmen.
Die menschenlesbare Ausgabe bleibt Standard. Ein Schreibfehler des Receipts liefert
einen Exit-Code ungleich null, auch wenn die Registry den POST schon angenommen hat;
vor einem erneuten Versuch die Registry prüfen, um eine doppelte Übermittlung zu vermeiden.
Antwort-Bodies werden in Fehlerdiagnosen nicht reflektiert. Dieser signierte POST
verlangt vor dem Laden des Schlüssels HTTPS oder Loopback-HTTP, auch ohne Token.
Redirects werden abgelehnt. Eine nicht unterstützte oder fehlerhafte Erfolgsantwort ist
ein Fehler und kein Annahme-Receipt.

Exit: `0` erfolgreich · `1` allgemeiner Fehler/Netzwerk/Nicht-2xx · `2` Aufruffehler.

---

### `revoke`: zugelassenes Bundle widerrufen und Notabschaltungsfeed

```bash
skillctl revoke <bundle-digest> --reason <code> [--registry <url>] [--timeout <duration>]
skillctl revoke feed [--status] [--refresh] [--registry <url>] [--tenant <T>]
```

Widerruft ein zugelassenes Bundle (SPEC-0188 §4.5), indem ein **signiertes,
offline überprüfbares** `BundleRevokedEvent` in der Registry veröffentlicht wird.
Der Verifier setzt dies mit Aktualitätsregeln (SPEC-0279) durch und **verweigert**
bei überalterter oder zurückgesetzter Liste. `<bundle-digest>` ist der zu
widerrufende Digest `sha256:<hex>`.

| Flag | Zweck |
|------|---------|
| `-reason key_compromise\|vulnerability\|governance_retraction\|author_request\|duplicate` | Begründungscode. **Verpflichtend.** |
| `-actor-identity` | Als `governance_reviewer` statt standardmäßig `original_author` widerrufen; mit `--key` kombinieren. |
| `-role registry_operator\|governance_reviewer\|original_author` | Akteursrolle ausdrücklich angeben statt aus `--actor-identity` ableiten. |
| `-key` | Signierschlüssel des Widerrufsereignisses; für `original_author` (Standard) und `governance_reviewer` erforderlich. |
| `-registry` | Registry-Basis-URL. |
| `-timeout` | HTTP-Anfragezeitlimit. |

Drei Akteursrollen: **`original_author`** (Standard, signiert mit Autorenschlüssel),
**`governance_reviewer`** (`--actor-identity` + `--key`) und
**`registry_operator`** (unsigniert, per Betreiberanmeldung authentifiziert).

```bash
skillctl revoke sha256:<hex> --reason key_compromise --registry https://aims.example.com/api/skills
```

**`revoke feed`: Notabschaltungsfeed für die Flotte (FR-0045 D5).** Dieser eigene
Betreibermodus zeigt oder erneuert den signierten **Widerrufs-HEAD**: einen
signierten, HEAD-bewussten Snapshot der aktuellen Widerrufsmenge, den der Verifier
abruft und verweigernd durchsetzt. `feed` wird als erstes Argument **vor** jedem
Digest-Parsing abgefangen und daher nie als Bundle-Digest missverstanden.

| Flag | Zweck |
|------|---------|
| `-status` | **Standard**: Signierten Widerrufs-HEAD abrufen, gegen fest hinterlegten Registry-Schlüssel prüfen und Epoche, Ausstellungszeit, Alter und Anzahlen ausgeben. Nur lesend; **keine** Übernahme in den lokalen Cache. |
| `-refresh` | Widerrufsprüfung sofort ausführen: neuesten signierten HEAD abrufen **und übernehmen**, in lokalen Cache und vom Gate gelesenen Aktualitätsanker. |
| `-registry` | Registry-Basis-URL. |
| `-tenant` | Feed auf einen Mandanten begrenzen. |
| `-gossip` | **Signierte** Widerrufsereignisse fest hinterlegter Peers mit `peer add --contributes-revokes` zur dauerhaften lokalen Widerrufsmenge hinzufügen (SPEC-0359 D5(b)). Nur signierte Ereignisse ausdrücklich beitragender Peers zählen; diese Grenze verhindert Widerrufs-DoS durch beliebige Peers. |

Da der HEAD signiert und gegen einen **fest hinterlegten** Registry-Schlüssel
geprüft wird, werden manipulierte, gespiegelte, gekürzte, zurückgesetzte,
wiederholte oder gefälschte Feeds abgelehnt. Dies ist die transportseitige,
verweigernde Notabschaltung. Gegen einen kompromittierten lokalen Prozess mit
derselben UID bietet sie **keinen** Manipulationsnachweis. Die Live-Verteilung
des HEAD in der Flotte wird noch ausgerollt; die Offline-Regeln (widerrufener
Digest → `17`, veralteter Snapshot → `22`) sind bereits implementiert und prüfbar.

```bash
skillctl revoke feed --status
skillctl revoke feed --refresh --registry https://aims.example.com/api/skills
```

Exit: `0` Widerruf angenommen · `1` allgemeiner Fehler, Netzwerk oder HTTP 403 ·
`2` Aufruf-/Flag-Fehler oder HTTP 400 der Registry · `15` HTTP 404 (Digest nie
zugelassen) oder HTTP 409 (bereits widerrufen) · `22` `revoke feed --refresh`
konnte auf einem verwalteten Rechner keine Widerrufsmenge abrufen und verweigerte.

`15` ist dieselbe Nummer, nicht dasselbe Thema: Das Register verwendet sie für
`verify`/`blob_missing`. Deshalb je Befehl auswerten, niemals als Kettenfehler
interpretieren. Gemessen am Programm gegen lokalen Registry-Stub sowie gegen
`cmd/skillctl/revoke_cmds.go`.

`revoke feed --refresh` ergänzt `22`, wenn der Rechner MANAGED ist (eine
`trust-roots.yaml` existiert), der Widerrufsabruf nicht verfügbar ist und kein
authentifizierter Kulanzcache existiert. Bewusst dieselbe Nummer
`revocation_stale` wie im Hook und in `verify --all`
(`cmd/skillctl/revoke_feed_cmds.go`), damit eine Skriptverzweigung die Verweigerung
an allen drei Stellen erkennt. Gemessen mit vorhandener, aber nicht ladbarer
`~/.claude/trust-roots.yaml`.

Verwandte Pfade: `publish --revoke` veröffentlicht dasselbe `BundleRevokedEvent`
in Ihrer persönlichen ER1-Registry `self`; siehe
[`publish`](manual-skillctl.md#publish-admit--attest--revoke-via-er1-self-registry).
`agentid revoke` fügt `agent:<id>` einer signierten AgentID-Widerrufsliste hinzu.
Alle drei erzeugen signierte, offline überprüfbare Listen, die der Verifier
verweigernd durchsetzt.

---

### `audit`: antivirenähnliches Urteil je Skill

```bash
skillctl audit [flags]
```

Gibt pro Skill `OK | UNVERIFIED | BROKEN | BELOW_MIN` aus. Die Bereinigung ist
ein **zweistufiger** destruktiver G-23-Vorgang: zuerst signiertes Vorschau-Token,
dann Bestätigung mit erneuter Prüfung der aktuellen Menge. **Kein `--force`.**

| Flag | Zweck |
|------|---------|
| `-minimum-governance green\|yellow\|red` | Mindeststufe, unter der ein Skill markiert wird; standardmäßig `governance_minimum` aus den Vertrauensankern, sonst green. |
| `-format table\|json` | Ausgabeformat: am Terminal standardmäßig table, in einer Pipe json. |
| `-source claude\|user\|plugins\|all` | Bereich der Skill-Quellen. |
| `-include-shadowed` | Überschattete Skills einschließen, deren Namen von höher priorisierten Skills verdeckt werden. |
| `-cleanup` | Betroffene Skills nach Auflistung löschen; nur mit `--dry-run-cleanup` oder `--confirm-delete`. |
| `-dry-run-cleanup` | **Schritt 1**: Betroffene Menge und signiertes Fünf-Minuten-Token ausgeben; **keine Löschung**. |
| `-confirm-delete` | **Schritt 2**: Tatsächlich löschen; benötigt frisches `--dry-run-cleanup-token`. |
| `-dry-run-cleanup-token <sig>` | Token eines vorherigen `--dry-run-cleanup`. |
| `-keep-unverified` | `UNVERIFIED`-Skills bei `--cleanup` nicht automatisch bereinigen. |

```bash
skillctl audit
skillctl audit --cleanup --dry-run-cleanup                                  # step 1: plan + token
skillctl audit --cleanup --confirm-delete --dry-run-cleanup-token <sig>     # step 2: re-check + delete
```

**Der zweistufige G-23-Vertrag.** Schritt 1 (`--cleanup --dry-run-cleanup`)
berechnet die betroffene Menge und gibt ein **signiertes Token** mit **fünf Minuten**
Gültigkeit aus. Der HMAC bindet Hostname, sortierte betroffene Skill-Pfade und
Ausstellungszeit. Nichts wird gelöscht. Schritt 2
(`--cleanup --confirm-delete --dry-run-cleanup-token <sig>`) **berechnet die
aktuelle betroffene Menge erneut und prüft das Token dagegen**. Bei **Drift**
(neuer, entfernter oder geänderter Skill), Ablauf oder Manipulation wird mit
Exit `2` verweigert; nichts wird gelöscht. Plan und Verweigerung sind auditierbar.
Es gibt **kein `--force`**, das diese Prüfung umgeht. Eine destruktive Aktion,
die nicht mehr zum freigegebenen Plan passt, wird nicht ausgeführt.

Exit: `0` alles OK · `1` interner Fehler (Inventarscan fehlgeschlagen,
Cleanup-Token nicht erzeugbar oder `--confirm-delete` nur teilweise erfolgreich) ·
`2` mindestens ein `UNVERIFIED`/`BELOW_MIN`, **oder** verweigerte
confirm-delete-Vorbedingung (Drift/Ablauf/Manipulation), **oder** Aufruf-/Flag-Fehler ·
`3` mindestens ein `BROKEN`.

Nur `0/2/3` gehören zum **Zustandsurteil** (`exitCodeFor`,
`pkg/skillctl/audit/audit.go`). `1` ist der gewöhnliche interne Fehlercode aller
Befehle; gemessen am Programm mit confirm-delete in einem schreibgeschützten
Skills-Verzeichnis.

---

### `envreport`: Skill-Umgebungsbericht für eine regulierte Umgebung

```bash
skillctl envreport --mandant <id> --prinzipal <id> --einwilligung-art <selbst|eingesetzt> \
                   --einwilligung-beleg <text> --aufbewahrung-tage <n> [flags]
```

Fasst die Sicht von `audit` in einem **Skill-Umgebungsbericht** zusammen
(SPEC-0428): einer unveränderlichen, datierten Aussage über den Inhalt einer
Umgebung zu einem bestimmten Zeitpunkt. Der Inhalt entspricht unverändert dem
Payload `posture.snapshot` aus SPEC-0351 §5.1.

**Standard ist die Vorschau.** Ohne `-schreiben` wird nichts gespeichert. Die
häufig umgekehrte Vorgabe wäre hier falsch, weil ein Versehen personenbezogene
Daten erzeugt, nicht bloß eine Datei. Die Grenzen des Berichts (gehashter Host,
keine Quelltexte außerhalb des Rechners, Einwilligung, Aufbewahrungsfrist) gelten
auch in der Vorschau. Andere Vorschau-Regeln würden nichts über den echten
Vorgang nachweisen.

| Flag | Zweck |
|------|---------|
| `-mandant <id>` | Mandant der Umgebung; verpflichtend und Salt des Host-Hashes. |
| `-prinzipal <id>` | Person, deren Umgebung beschrieben wird. Verpflichtend. |
| `-einwilligung-art selbst\|eingesetzt` | Einwilligungsart. Verpflichtend; die beobachtete Person muss informiert sein. |
| `-einwilligung-beleg <text>` | Grundlage der Einwilligung oder Benachrichtigung. Verpflichtend; Einwilligung ohne Nachweis genügt nicht. |
| `-aufbewahrung-tage <n>` | Aufbewahrung in Tagen. Verpflichtend ohne Standard: Eine nie ablaufende Aussage über das Arbeitsverhalten einer Person ist keine Aufbewahrungsfrist. |
| `-source claude\|user\|plugins\|all` | Erfassungsbereich, standardmäßig all. |
| `-json` | Bericht als JSON statt Tabelle. |
| `-schreiben` | Bericht speichern; ohne Flag nur Vorschau. |
| `-er1-target prod\|stage\|local` | ER1-Ziel, standardmäßig prod. Nur mit `-schreiben` ausgewertet. |
| `-er1-context <id>` | ER1-Kontext, standardmäßig `<owner-sub>___skillenv`. Eigentümer ist der authentifizierte Nutzer, NICHT der Mandant der Umgebungsadresse. `_owner(ctx_id)` in aims-core ist alles vor `___` und wird gegen den Prinzipal geprüft. Nur mit `-schreiben` ausgewertet. |

Der Host erscheint nie im Klartext. Die Umgebungsadresse enthält einen gesalzenen
Hash; es gibt bewusst keine Funktion zur Rückauflösung.

Mit `-schreiben` wird der Bericht als ER1-Eintrag mit den acht Merkmalen aus
SPEC-0428 E3 gespeichert und über `link/parent` am Ankereintrag der Umgebung
angehängt. Die Speicherung ist **append-only**: Ein bereits verwendetes
`(env, seq)` wird abgelehnt, niemals überschrieben. Anschließend **liest der
Befehl den Bericht zurück** und scheitert, wenn er ihn nicht findet. Eine nur
behauptete erfolgreiche Speicherung wäre hier der besonders teure Fehler.


### `trust-freeze`: Zustand eines Hosts erfassen, freigeben und vergleichen (SPEC-0466)

```bash
skillctl trust-freeze doctor [--profile <name>] [--output <dir>] [--format text|json]
skillctl trust-freeze capture --profile <name> --output <dir> [--actor <id>] [flags]
skillctl trust-freeze baseline approve --capture <dir> --output <dir> --reviewer <id> \
                                       --change-id <id> --reason <text|@file> --key <file> [flags]
skillctl trust-freeze verify --bundle <dir> [--trust-policy <file>] [--trusted-key <public.pem>]...
skillctl trust-freeze diff --baseline <dir> --current <dir> [flags]
skillctl trust-freeze report --input <dir> --output <file|dir> [--format json|yaml|html]
```

Trust Freeze erfasst den Zustand eines Hosts als **Capture**-Bundle, lässt eine
Person ein Capture als signierte **Baseline** freigeben, prüft Bundles offline und
vergleicht ein späteres Capture mit der Baseline als **Diff**. Zuständig sind
SPEC-0466 bis SPEC-0471. Es ist eigenständig gegenüber `drift`, `envreport` und
`audit`, deren Bedeutung unverändert bleibt.

Der Host wird ausschließlich gelesen: kein sudo, keine Rechteerhöhungsabfrage,
keine Installation, kein Dienststart, keine Konfigurationsänderung, kein Netz.
Geschrieben wird nur in das benannte Ausgabeverzeichnis. Ein Capture ist niemals
eine Baseline; nur `baseline approve` wandelt es in eine um. Es gibt keine
automatische Baseline-Aktualisierung: Ein geänderter Zustand benötigt immer eine
neue ausdrückliche Freigabe, und `capture` ruft den Freigabecode niemals auf.

**Was diese Version erfasst.** `common.identity` läuft auf jeder Plattform:
das Artefakt `device/os` (`os_family`, `arch`, `os_name`, `os_version`,
`os_build`, `kernel_release`) und `device/host` (`hostname`, Sensitivität
`internal`). `arch` bezeichnet die vom Betriebssystem gemeldete Maschine, in
der Schreibweise von Gos `GOARCH` (`amd64`, `arm64`, ...), niemals die
Build-Architektur von skillctl: Ein `amd64`-Build unter Rosetta 2 oder unter
Windows-x64-Emulation erfasst `arm64`. Das Profil `walking-skeleton` verlangt
nur diese Probe.

Zwölf weitere Probes erfassen einen Linux-Host. Sie sind auf jeder Plattform
registriert und werden dort, wo sie nicht laufen können, als `unsupported`
mit der Plattform als Begründung erfasst. Ein Capture verbirgt sie daher nie:

| Probe | Liest | Ehrliche Ergebnisse außer `captured` |
|-------|-------|------------------------------------|
| `linux.packages` | `dpkg-query -W -f`, `apt-mark showmanual`, `snap list` | `unavailable` ohne `dpkg-query`; lässt sich `snap` nicht auflösen, ist das Snap-Inventar `unavailable` mit den durchsuchten Verzeichnissen, niemals eine leere Snap-Liste |
| `linux.users` | `getent passwd`, `getent group`, `id` | `unavailable` ohne `getent`. Niemals ein Passwort-Hash: `getent` gibt keinen aus, und nichts anderes wird gelesen. Gibt `getent passwd` Konten aus, aber kein Inventarartefakt hat uid 0, benennt eine Diagnose `account_root_missing` diese Lücke und die Probe ist `partial`: Das fehlende Root-Konto wird ausdrücklich genannt und muss nicht aus den übrigen Konten erschlossen werden |
| `linux.sudo` | `/etc/sudoers`, `/etc/sudoers.d` (Dateinamen, Modi, Eigentümer, Größen, ausgewertete Regeln) | `permission_denied` für jede als normaler Benutzer unlesbare Datei; die beobachtete Struktur wird trotzdem erfasst |
| `linux.ssh` | `/etc/ssh/sshd_config` und `sshd_config.d/*.conf` (deklariert), `sshd -T` (wirksam), `getent passwd` sowie `authorized_keys` je Konto | `permission_denied` für den wirksamen Zustand ohne Root; `partial`, wenn eine Quelle fehlt und der Rest gelesen wurde (ein Host ohne `sshd` behält den deklarierten Zustand und ist partial, nicht `unavailable`); deklarierter Zustand bleibt `declared` und wird nie als beobachtet dargestellt |
| `linux.systemd` | `systemctl list-unit-files`, `systemctl show` | `unavailable` ohne `systemctl`. Aktivierungs- und Laufzustand sind unterschiedliche Tatsachen und werden als zwei Artefakte erfasst. Eine TEMPLATE-Unit (`getty@.service`, leerer Instanzteil) wird nie abgefragt: Ohne Instanz besitzt sie keinen Laufzeitzustand. Ihr Unit-Artefakt enthält deshalb `template=true` und `runtime_state=not_applicable` mit Begründung; das Manager-Artefakt zählt sie unter `template_unit_count`. Endet ein `systemctl show` für mehrere Units vor der vollständigen Antwort, bleiben eingegangene Blöcke erhalten und die übrigen Namen werden einzeln abgefragt. Ein vom Manager verweigerter Name kostet damit nur eine Unit statt einen ganzen Batch; `show_batch_split` nennt die Anzahl erneuter Abfragen und `unit_state_not_read` jede weiterhin unbekannte Unit |
| `linux.mounts` | `findmnt --json` | `unavailable` ohne `findmnt` |
| `linux.network.listeners` | `ss -H -lntup` | Unprivilegiert `partial`: Der Eigentümerprozess eines fremden Sockets ist nicht sichtbar, und die Diagnose benennt das |
| `linux.network.routes` | `ip -j route show`, `ip -6 -j route show`, `ip -j addr show` | `unavailable`, wenn `ip` nicht gefunden wird, mit durchsuchten Verzeichnissen; `permission_denied`, wenn das Programm existiert, dieses Konto es aber nicht ausführen darf; `partial`, wenn einer der drei Aufrufe antwortet und ein anderer nicht oder ein Datensatz nicht auswertbar ist, mit einer Diagnose je Datensatz. Ein Host ohne IPv6-Route ist `captured` mit null IPv6-Routen, niemals `not_applicable`: Auch das Fehlen einer Route ist eine Antwort über den Host. Eine nicht gelesene Familie erhält dagegen keine Anzahl und kann so nie mit einer leeren Tabelle verwechselt werden |
| `linux.dns` | `resolvectl status --no-pager` (beobachtet), `/etc/resolv.conf` (deklariert) | Die Probe ist auf Linux unabhängig vom Verhalten von `resolvectl` verfügbar, weil der deklarierte Zustand eine Datei ist: Ein `unavailable` wegen eines fehlenden Binaries würde `/etc/resolv.conf` aus dem Bundle verlieren. Ein fehlendes `resolvectl` wird im Ergebnis mit den durchsuchten Verzeichnissen dokumentiert; der Lauf ist `partial` und die Datei bildet die gesamte Antwort, wie auch auf einem Host ohne systemd-resolved. Nur wenn keine der beiden Quellen erreichbar ist, gilt `unavailable`. Beobachteter Zustand je Link und deklarierte Datei sind zwei Artefakte und werden nie zusammengeführt |
| `linux.firewall` | `nft --json list ruleset`, sonst `ufw status` | `permission_denied`, wenn ein installiertes Backend ohne Root verweigert; `unavailable`, wenn keines der Tools gefunden wird, mit durchsuchten Verzeichnissen. Nicht `not_applicable`: Ein Host kann Pakete mit Backends filtern, die dieser Build nicht liest |
| `linux.containers` | `docker ps`, `docker info`, dasselbe für podman | `unavailable`, wenn kein Client gefunden wird, mit durchsuchten Verzeichnissen; `permission_denied`, wenn der Daemon-Socket verweigert, einschließlich der Client-Ausgabe; `failed`, wenn der Daemon unerreichbar ist. Das Laufzeitartefakt erfasst den aufgelösten Pfad (`/snap/bin/docker` bei einem Snap) und die Client-Version dieses Pfads |
| `linux.executables` | `systemctl show -p Id,ExecStart` und `ss -H -lntup` für Kandidatenpfade, danach je Pfad `stat -L` und `dpkg -S` | `unavailable`, wenn weder `systemctl` noch `ss` gefunden wird, weil dann kein Programm des Hosts benannt werden kann; `permission_denied`, wenn die Tools existieren, aber dieses Konto sie nicht ausführen darf; `partial` bei verweigertem, unlesbarem oder zu großem Pfad oder wenn eine der beiden Obergrenzen die Liste kürzt, mit einer Diagnose je Fall und Angabe von Pfad und Grenze; `timeout`, wenn während des Lesens der Programme die Capture-Zeit endet. Nicht mehr erreichte Programme tragen dann `hash_state: not_read`, niemals `unreadable`, weil über ihre Bytes nichts gelernt wurde. Ein keinem Paket zugeordnetes Programm ist `captured` mit `package_owner: none` und der Ermittlungsmethode: Das Vertrauensurteil gehört zur Policy, nicht zur Probe |

Das Profil `ubuntu-bastion` hat Version `3` und verlangt `common.identity`
sowie die elf obigen Linux-Probes außer `linux.containers`, das optional ist.
Version `3` ergänzt `linux.executables`, `linux.network.routes` und
`linux.dns` und vervollständigt damit die Pflichtliste nach SPEC-0471 TF06-R3.
Ein Host mit zuvor `complete` unter Version `2` ist unter Version `3`
`incomplete`, bis diese drei Probes gelaufen sind: Eine umfassendere Frage
macht eine ältere Antwort nicht vollständiger. Das ist Berechnung statt
Regression. Den Host erneut erfassen und eine neue Baseline freigeben.

Das Profil führt weiterhin `common.git` und `common.claude`, die diese Version
nicht implementiert: Sie werden als `unsupported` mit Begründung
`not_implemented` erfasst. Daher ist ein `ubuntu-bastion`-Capture selbst auf
Linux `incomplete` (Exit `1`). Unprivilegiert ist zusätzlich `linux.firewall`
`permission_denied`; diese korrekte Antwort hält das Capture unvollständig.
Ein vollständiges `ubuntu-bastion`-Capture benötigt die von den Probes
benannten Rechte. Ohne `nft` und `ufw` bleibt es ebenfalls unvollständig,
weil `linux.firewall` dann `unavailable` ist, keine Aussage über eine fehlende
Firewall. Die Profile `agentic-workstation`, `windows-wsl-workstation` und
`macos-workstation` führen überhaupt nicht implementierte Probes; auch diese
Captures sind deshalb `incomplete`.

**Die Programme hinter den Diensten (`linux.executables`).** Die Probe hasht
keine selbst gewählten Pfade. Ihre Quellen sind `ExecStart` der durch
`linux.systemd` ausgewählten Units und das durch `ss` benannte Programm
hinter einem lauschenden Socket. Das Artefakt dokumentiert unter
`discovered_by`, welche Quelle es fand. Pro unterschiedlichem aufgelöstem
Programm entsteht ein Artefakt `executable/<path>` mit `path`,
`requested_path` (bei verfolgtem Symlink), `size`, `mode`, `owner`, `group`,
`sha256`, `hash_state`, `package_owner`, `package_owner_source`, `diverted_by`,
`discovered_by`, `units` und `unit_count`. Hinzu kommt eine Zusammenfassung
`system/executables` mit den Anzahlen (`program_count`, `hashed_count`,
`candidate_path_count`, `refused_count`, `unreadable_count`,
`over_size_limit_count`, `package_owner_none_count`,
`package_owner_unknown_count`, `from_systemd_count`, `from_listener_count`,
`candidate_paths_dropped`, `program_list_truncated`) und den verwendeten
Grenzen (`roots`, `max_file_bytes`, `max_files`, `max_candidate_paths`,
`hash_algorithm`, `stat_version`, `dpkg_version`) sowie
`package_contents_verified`, das in dieser Version `false` ist und das im
Bundle aussagt: Kein Programm wird gegen sein Paket geprüft.
`package_owner` ist daher die Datenbankaussage über den Pfad; `sha256`
ist die einzige Aussage über die Bytes.

Die Grenzen gehören zum Vertrag, nicht zur Feinabstimmung: höchstens 1024
Kandidatenpfade je Capture, 256 Dateien je Capture, 128 MiB je Datei und nur
Pfade unter `/bin`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/opt`, `/sbin`,
`/snap`, `/usr` oder `/usr/local`. Die vier Bibliothekswurzeln stehen darin,
weil sie auf jeder usrmerge-Distribution Symlinks nach `/usr` sind. Eine
Unit mit `/lib/apparmor/apparmor.systemd` benennt deshalb eine Datei innerhalb
einer Wurzel. Ohne diese Einträge verweigerte die Prüfung solche Pfade als
außerhalb der Wurzeln und meldete das im Bundle, obwohl sie darin liegen.
Pfade unter `/home` oder `/root` werden unabhängig von ihrer Quelle niemals
gelesen; Symlinks aus den Wurzeln heraus werden verweigert. Kandidaten- und
Dateigrenze zählen unterschiedliche Arbeit und sind beide nötig: Jeder
Kandidat kostet eine Pfadauflösung (bei lauschenden Prozessen ein `readlink`
von `/proc/<pid>/exe`), auch wenn die Datei nie gehasht wird. Eine Grenze
nur für verbleibende Dateien würde die Zahl der Auflösungen von Units und
Sockets des Hosts abhängig machen. Die Kandidatengrenze greift daher VOR
jeder Auflösung, benennt verworfene Pfade und erscheint in
`candidate_paths_dropped`. Jede einen Hash verhindernde Grenze erzeugt
eine Diagnose mit Pfad und Grenze; das Artefakt behält `hash_state`
`over_size_limit`, `permission_denied`, `unreadable` oder `not_read` statt
eines Hashs. `sha256` existiert nur bei tatsächlich berechnetem Hash;
`hash_state` benennt den Fall. Ein fehlender Hash bedeutet daher niemals
versehentlich eine unveränderte Datei.

`hash_state` unterscheidet Aussagen über die DATEI von Aussagen über das
CAPTURE: `over_size_limit`, `permission_denied` und `unreadable` sind
Eigenschaften der vorgefundenen Datei. `not_read` bedeutet, dass die
Capture-Zeit vor Erreichen der Datei ablief; dieses Bundle sagt dann nichts
über ihre Bytes. Ein abgelaufenes Capture ist `timeout` mit Timeout-Fehler,
niemals ein `partial`-Ergebnis mit einer Liste unlesbarer Programme.

**Was an einem Artefakt `executable/<path>` beobachtet ist und was eine
Datenbankaussage.** Der Artefaktwert `State` ist `observed`; `path`, `size`,
`mode`, `owner`, `group` und `sha256` wurden tatsächlich während dieses
Captures vom Host gelesen. `package_owner` und `diverted_by` sind KEINE
Dateibeobachtungen. Sie dokumentieren die Antwort der Paketdatenbank zum
Pfad neben dem Digest, weil ein nicht zugeordnetes Programm ein Befund für
eine Bastion ist. `package_owner_source` benennt die Antwort (`dpkg`,
`dpkg_no_match`, `snap_path`, `dpkg_unavailable`). Diese Version prüft nie
Dateien gegen Pakete: kein `dpkg --verify`, kein Abruf oder Vergleich von
Paket-Digests. Ein zugeordneter Pfad sagt daher nicht, dass die Bytes auf
Platte dem Paket entsprechen; das danebenstehende `sha256` bleibt die
einzige Aussage dieses Bundles über diese Bytes.

**Abhängigkeitskanten einer Unit (`linux.systemd`).** Das Laufzeitartefakt
`service/systemd/runtime/<unit>` enthält nun auch `requires`, `wants`,
`after`, `binds_to` und `required_by`, jeweils als kommaseparierte Unit-Liste,
sowie `<name>_count` daneben, falls die Liste gekürzt werden musste.
Bewusst liegen sie am Laufzeitartefakt statt am deklarierten: Der Manager
ergänzt Kanten, die keine Unit-Datei enthält (`system.slice`, `-.mount`,
`sysinit.target`); `required_by` existiert überhaupt in keiner Unit-Datei,
weil der Manager es aus allen anderen geladenen Units berechnet. Als
deklarierter Zustand würde dies eine nicht vorhandene Dateiaussage
behaupten (Playbook L3).

**Nachweisniveau je Plattform** (diese Änderung):

| Probe | Plattform | Quelle | Nachweisniveau |
|-------|----------|--------|----------------|
| `common.identity` | linux | `/etc/os-release` (sonst `/usr/lib/os-release`), `uname -r`, `uname -m` | implementiert, mit Fixtures getestet, crosskompiliert |
| `common.identity` | darwin | `sw_vers`, `uname -r`, `uname -m` sowie `sysctl -n sysctl.proc_translated`, wenn `uname -m` `x86_64` meldet | implementiert, mit Fixtures getestet, crosskompiliert |
| `common.identity` | windows | Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`; die native Maschine aus `IsWow64Process2` | implementiert, mit Fixtures getestet, crosskompiliert |
| Die zwölf Probes `linux.*` | linux | Die in der obigen Tabelle genannten Werkzeuge | implementiert, mit Fixtures getestet, crosskompiliert |
| Die zwölf Probes `linux.*` | darwin, windows | n/a | nicht implementiert; als `unsupported` mit der Plattform als Begründung erfasst |

Keine Plattform wurde im Rahmen dieser Änderung auf einem echten Zielsystem
getestet. Dieses Niveau wird je Commit in Nachweisen dokumentiert, nie vom
Build behauptet; vollständige Plattformunterstützung ist nicht festgestellt.
`doctor` gibt dieselbe Matrix aus dem Code aus.

**Der vollständige Lebenszyklus:**

```bash
mkdir -p ./keys ./tf
skillctl keygen --out ./keys/reviewer                    # reviewer.priv (0600), reviewer.pub
skillctl trust-freeze capture --profile walking-skeleton --output ./tf/capture-1
skillctl trust-freeze baseline approve --capture ./tf/capture-1 --output ./tf/baseline-1 \
    --reviewer alice --change-id CHG-0001 --reason @./reason.txt --key ./keys/reviewer.priv
skillctl trust-freeze verify --bundle ./tf/baseline-1 --trusted-key ./keys/reviewer.pub
skillctl trust-freeze capture --profile walking-skeleton --output ./tf/capture-2
skillctl trust-freeze diff --baseline ./tf/baseline-1 --current ./tf/capture-2 \
    --trusted-key ./keys/reviewer.pub --output ./tf/diff-1
skillctl trust-freeze report --input ./tf/diff-1 --output ./tf/report-1.json
```

`scripts/trustfreeze-acceptance.sh` führt diesen Pfad mit einem frisch
gebauten Binary in einem temporären Verzeichnis und einem Wegwerfschlüssel aus.

**Datenschutz: Bundles, Diffs und Berichte sind interne Hostdaten.** Ein
Capture oder eine Baseline und deren Bericht enthalten den Hostnamen im
Klartext (`device/host`, Sensitivität `internal`) sowie Betriebssystemdetails.
Ein Linux-Capture enthält deutlich mehr, alles im Klartext und vom
Inhalts-Digest abgedeckt:

- Jedes lokale Konto mit Name, uid, gid, Login-Shell und Home-Pfad
  (`device/user/*`) sowie jede Gruppe mit gid und Mitgliederliste
  (`device/group/*`);
- `capture.actor`, also die vom Betreiber an `--actor` übergebene Kennung,
  möglicherweise eine E-Mail-Adresse;
- Für jede lesbare `authorized_keys`-Datei das zugehörige Konto sowie je
  Schlüssel Typ, SHA-256-Fingerprint und Optionsnamen
  (`ssh/authorized-key/*`). Niemals den Schlüsselkörper oder Kommentar;
- Die Prinzipale jeder sudo-Regel (`sudo/rule/*.users`), ihre Befehle und
  Tags sowie Modus, Eigentümer und Größe jeder Regeldatei;
- Jede lauschende Adresse und jeden Port mit sichtbarem Eigentümerprozess
  (`network/listener/*`), alle Mountpunkte und Quellen, Containernamen,
  Images und veröffentlichte Ports sowie Paket- und Unit-Inventar;
- Die aufgelösten Capabilities mit ausdrücklich benannten Konten und Gruppen
  (`state/capabilities.json`).

Ein Diff und sein Bericht enthalten keine Attributwerte, sind aber auch
nicht anonym:

- `before_digest` und `after_digest` sind einfache SHA-256-Hashes über das
  kanonische JSON der normalisierten Attribut-Map, ohne Schlüssel oder Salt.
  Kurze Werte wie Hostnamen oder Betriebssystemversionen lassen sich durch
  Hashen eines Wörterbuchs von Kandidaten rekonstruieren.
- Die Subject-ID (`device/` plus 16 Hexzeichen aus SHA-256 über
  Betriebssystemfamilie und kleingeschriebenen Hostnamen) ist ein Pseudonym,
  keine Anonymisierung: Wer den Hostnamen kennt oder errät, berechnet sie
  erneut. Auch Bundle-IDs enthalten sie.

Bundles, Diffs und Berichte innerhalb ihrer ursprünglichen Vertrauensgrenze
halten und nicht außerhalb teilen. Ein schlüsselgebundener Digest (HMAC),
der diese Werte außerhalb der Grenze unverknüpfbar machen würde, bleibt
zukünftige Arbeit; diese Version besitzt keinen.

**Ergebnisklassen.** Der Exit-Raum ist der gemeinsame Basisraum ohne neue
Nummer. Exit `1` hat mehrere Ursachen; die JSON-Ausgabe jedes Unterbefehls
benennt sie in `result_class`:

| `result_class` | Exit | Bedeutung |
|----------------|------|---------|
| `ok` | `0` | Der Befehl hat die angeforderte Arbeit erledigt. Bei `diff`: Der Schwellenwert wurde nicht erreicht. |
| `usage_error` | `2` | Ein Flag fehlt, ist fehlerhaft oder benennt eine nicht implementierte Option. Für jede über Flags benannte Eingabedatei gilt dieselbe Regel (`--key`, `--trusted-key`, `--trust-policy`, `--policy`, `--reason @file`): Scheitert das Laden (fehlend, unlesbar, fehlerhaft, Schlüsseldatei mit offenerem Modus als `0600`), ist das `usage_error`, niemals `execution_error`. |
| `execution_error` | `1` | Der Lauf scheiterte: unbrauchbares Ausgabeziel, nicht auflösbare Home-Wurzel, Schreibfehler. |
| `verification_failure` | `1` | Ein Bundle bestand die Prüfung nicht, oder eine blockierte Selbstfreigabe verweigerte die Freigabe. |
| `drift_threshold_exceeded` | `1` | `diff`: Der höchste Befundschweregrad liegt auf oder über `fail_on`. |
| `incomplete_capture` | `1` | `capture`: Das Bundle wurde geschrieben, aber eine Pflichtprobe hat eine Lücke. |

Exit: `0` ok · `1` fehlgeschlagener Lauf (`execution_error`,
`verification_failure`, `drift_threshold_exceeded`, `incomplete_capture`)
· `2` Aufruf- oder Flagfehler einschließlich "not implemented in this version".
Durch die Tests von `runTrustFreeze` in
`cmd/skillctl/trustfreeze_cmds.go` gemessen.

#### `trust-freeze doctor`: was ein Capture hier erfassen könnte

Führt nur die Unterstützungsprüfung jeder Probe eines Profils aus und zeigt
Plattform, Berechtigungen, erwartete Lücken, Nachweismatrix je Plattform
und Umgebungsprüfungen. Schreibt kein Bundle und erfasst nichts.

| Flag | Zweck |
|------|---------|
| `--profile <name>` | Zu planendes eingebautes Profil (Vorgabe `walking-skeleton`). |
| `--output <dir>` | Bundle-Verzeichnis für ein späteres Capture (optional). doctor prüft nur die Schreibmöglichkeit; es schreibt kein Bundle und erstellt kein Verzeichnis. Berührt wird ein Verzeichnis: das vorhandene Ziel selbst, sonst dessen unmittelbarer Elternordner. |
| `--format text\|json` | Ausgabeformat (Vorgabe `text`). |

Das JSON enthält `platform_support: "not_established"` und die Matrix mit
`implemented` oder `not_implemented` je Probe und Plattform.

**Umgebungsprüfungen** (`checks` im JSON, ein Eintrag je Punkt, `status`
ist `ok`, `problem` oder `not_checked`):

| Punkt | Verhalten von doctor |
|------|------------------|
| `claude_roots` | Löst die Home-Wurzel wie alle anderen skillctl-Pfade auf und führt darunter `lstat` auf `.claude`, `.claude/agents`, `.claude/commands`, `.claude/skills`, `.claude/skillctl` und `.claude/trust-roots.yaml` aus. Öffnet keine Datei, folgt keinem Link und erstellt nichts. `detail` benennt die Wurzel sowie vorhandene und fehlende Pfade. Ein Symlink oder nicht lesbarer vorhandener Pfad ist `problem`. |
| `file_roots` | Nennt alle Dateiwurzeln, die ein Capture auf dieser Plattform öffnen darf, ohne etwas zu lesen. Zwei Listen, weil auch der Code zwei hat: die Wurzeln des eingeschränkten Dateilesers der Engine (`capture.DefaultAllowedRoots`, der jeden anderen Pfad verweigert) und die Hash-Wurzeln des eigenen Lesers von `linux.executables` (`linux.ExecutableRoots`). Letztere stehen nicht in der ersten Liste, weil Hashen eine Datei streamt statt sie in den Speicher zu lesen. `detail` nennt beide samt zugehörigem Leser. Liest auf einer Plattform keine registrierte Probe Dateien, bleibt der Punkt `not_checked`. |
| `output_location` | Nur mit `--output`. Wählt das Arbeitsverzeichnis eines Captures, erstellt dort EINE temporäre Datei, schließt und entfernt sie wieder und berührt sonst nichts. Das Verzeichnis ist das vorhandene Ziel selbst, sonst sein UNMITTELBARER Elternordner, weil capture das Ziel darin erstellt und keine Verzeichnisse darüber anlegt. doctor steigt niemals weiter auf: `--output /srv/freeze/2026-09-23` berührt bei vorhandenem `/srv/freeze` diesen Ordner; fehlt er, wird der Punkt `problem` mit seinem Namen, niemals eine Probedatei unter `/`. Berechtigungsbits ersetzen diesen Test nicht: Read-only-Mount, ACL, Container-Benutzerzuordnung oder Windows können vom tatsächlichen Schreibverhalten abweichen. Ohne `--output` bleibt der Punkt `not_checked`. |
| `tools` | Löst jedes von einer Probe benannte Programm über denselben festen Suchpfad wie der Befehlsrunner auf, ohne es auszuführen. `detail` nennt aufgelöste Tools als `<probe-id>:<tool>` und nicht aufgelöste mit ihrer Klasse (`tool_missing`, `permission_denied`). Probes ohne benannte Programme sind so nicht prüfbar; benennt keine Probe des Profils eines, bleibt der Punkt mit dieser Begründung `not_checked`. Die Zeilen je Probe führen dasselbe Ergebnis unter `tools`. |

`not_checked` wiederholt alle von doctor nicht bestimmbaren Punkte mit
Begründung; die Lücken bleiben so ohne Filtern von `checks` sichtbar.

Exit: `0` Plan ausgegeben, auch bei erwarteten Lücken und `problem` in
Prüfungen (siehe `expected_complete` und `expected_gaps`; doctor berichtet,
es urteilt nicht) · `1` Probe-Registry konnte nicht aufgebaut werden
(`execution_error`) · `2` Usage einschließlich unbekanntem Profil.

#### `trust-freeze capture`: ein Capture-Bundle schreiben

| Flag | Zweck |
|------|---------|
| `--profile <name>` | Eingebautes Profil (erforderlich). |
| `--output <dir>` | Neues Bundle-Verzeichnis (erforderlich). Darf nicht existieren oder muss leer sein; darf nicht in einem bestehenden trust-freeze-Bundle liegen. |
| `--actor <id>` | Stabile Kennung der erfassenden Person oder Automation (optional). Als `capture.actor` erfasst und als `identities.capture_actor` in die signierte Freigabe übernommen; dort das Gegenüber des Reviewers für den personenbezogenen Teil der Selbstfreigabeprüfung. Gleicher Zeichensatz wie `--reviewer` (siehe Kennungen unten); umgebender Leerraum wird entfernt, alles andere vor Schreibvorgängen mit Exit `2` verweigert. Ohne Angabe hat das Capture keinen Akteur und der Personenvergleich wie bisher keine Grundlage. |
| `--force` | Ein bestehendes **Capture**-Bundle bei `--output` ersetzen, aber nur wenn es vollständig prüfbar ist (alle Dateien im Manifest und unbeschädigt), damit keine fremden Dateien entfernt werden. Niemals eine Baseline, Home-Wurzel oder deren Vorfahren, Dateisystem- oder Volumewurzel oder einen Mountpunkt. |
| `--probe <id>` | Nur diese Probe des Profils ausführen (wiederholbar). Alle anderen Probes werden als übersprungen erfasst (siehe unten). |
| `--exclude-probe <id>` | Diese Probe überspringen (wiederholbar). Übersprungene Probes werden erfasst, nicht ausgelassen (siehe unten). |
| `--timeout <d>` | Timeout je Probe-Lauf, etwa `30s` (Vorgabe: die der Probe). |
| `--project <path>` | In dieser Version nicht implementiert (Exit `2`). |
| `--policy <file>` | In dieser Version nicht implementiert (Exit `2`). |
| `--format text\|json` | Ausgabeformat (Vorgabe `text`). Gibt den Manifestwert `content_digest` aus. |

Das Bundle wird in ein Staging-Verzeichnis neben dem Ziel geschrieben,
geprüft und an seinen Zielort umbenannt. Ein Probe-Fehler bricht das Capture
nie ab; er wird als `captured`, `partial`, `unsupported`, `unavailable`,
`permission_denied`, `timeout`, `failed` oder `not_applicable` erfasst.
Daraus wird die Vollständigkeit berechnet.

Durch `--probe` oder `--exclude-probe` ausgelassene Probes erscheinen weiterhin
als `unsupported` mit Begründung `excluded_by_operator`; das Bundle nennt
somit jede Probe seines Profils. Eine übersprungene Pflichtprobe macht das
Capture unvollständig, und `diff` meldet jede übersprungene Probe als
`collection_gap`, das die Policy wie jede andere Lücke bewertet.

Struktur: `manifest.json`, `capture.json`, `state/device.json`,
`probes/<probe-id>.json`, `evidence/<probe-id>/<name>` (vor dem Schreiben
redigierte Rohnachweise) und auf Plattformen mit Capability-Resolver
`state/capabilities.json`.

**Capabilities.** Nach den Probes wandelt der Capability-Resolver der
Plattform deren Artefakte in Aussagen um, wer was darf: eine sudo-Regel für
alle Befehle als Root, Mitgliedschaft in einer sudo-berechtigenden Gruppe
(`sudo`, `admin`, `wheel`), Mitgliedschaft in einer Gruppe mit Zugriff auf
einen Container-Runtime-Socket (`docker`, `lxd`), ein autorisierter Schlüssel
für ein Konto sowie ein vom Runtime als privilegiert gemeldeter Container.
Bei Letzterem ist das Subject der CONTAINER, kein Prinzipal: Ein privilegierter
Container behält die Geräteknoten des Hosts und darf dessen Dateisystem
mounten und beschreiben; sein Inhalt handelt damit als Root, ohne dass
jemand angemeldet ist. Sein Zustand ist `declared` (der Runtime meldet das
Flag, niemand hat Hostzugriff beobachtet), sein Privileg
`root-via-privileged-container`, seine Quelle das Containerartefakt.
Ein Container, dessen Privileg-Flag wegen eines unbeantworteten `inspect`
nicht gelesen wurde, erzeugt in keiner Richtung eine Capability. Jede
Capability nennt ihre Quellartefakte, ihr Privileg und nötigenfalls
begründende Attribute: Eine Capability der Gruppe `docker` enthält
`grant_path: container-runtime-socket` und eine `rationale`, die erklärt,
dass über diesen Socket gestartete Container das Hostdateisystem mounten
und als Root schreiben können. Daher heißt ihr Privileg
`root-via-container-runtime` statt eines sudo-Werts. Von den Artefakten nicht
getragene Aussagen werden als Diagnose statt durch Schweigen behandelt:
Unlesbare sudo- oder `authorized_keys`-Dateien erzeugen
`privilege_source_unreadable`, Gruppen ohne erhobene Mitglieder
`group_membership_unknown`, Runtime-Gruppenmitgliedschaften
`capability_from_runtime_group` mit dem beobachteten oder nicht beobachteten
Runtime (eine Diagnose je Capability, auch wenn dasselbe Konto sowohl im
Gruppenartefakt als auch in seiner eigenen Gruppenliste vorkommt).
Ein privilegierter Container erzeugt `capability_from_privileged_container`,
mit dem Hinweis, dass dieses Capture nicht beantwortet, wer ihn starten
oder betreten darf. Das Dokument nennt seinen Resolver. Linux hat einen
(`linux.privilege/v1`); darwin und windows besitzen in dieser Version keinen.
Ein Bundle ohne `state/capabilities.json` bedeutet daher, dass niemand
Capabilities auflöste, niemals, dass der Host nichts erlaubt. Der Resolver
sieht nur Probe-Ergebnisse: War `linux.sudo` `permission_denied`, fehlen die
Privilegien dieser Datei im Dokument; die Erfassungslücke in `capture.json`
macht das deutlich. Die Textausgabe nennt Anzahl, Resolver und die Anzahl
Root gewährender Capabilities, danach je Capability eine Zeile mit ID und
Privileg. So erkennt man die Kontrolle über den Host ohne Öffnen von
`state/capabilities.json`. Das JSON enthält `capabilities` mit `resolver`,
`resolved`, `diagnostics` und `critical`, den sortierten IDs derselben
Capabilities. Als Root-gewährend zählen `root`, `root-via-container-runtime`,
`root-via-privileged-container`, `root-via-sudo` und
`root-via-sudo-nopasswd`. Das ist eine Projektion des Resolver-Dokuments,
kein Urteil: Schweregrade gehören zur Policy, und diese bewertet einen Diff.

Exit: `0` vollständig · `1` geschrieben, aber unvollständig
(`incomplete_capture`), oder nicht geschrieben (`execution_error`) · `2` Usage.

#### `trust-freeze baseline approve`: Capture als signierte Baseline freigeben

| Flag | Zweck |
|------|---------|
| `--capture <dir>` | Freizugebendes Capture-Bundle (erforderlich). Wird nur gelesen und muss die Prüfung bestehen. |
| `--output <dir>` | Neues Baseline-Verzeichnis (erforderlich). Darf nicht existieren oder muss leer sein; muss außerhalb des Captures und anderer trust-freeze-Bundles liegen. Eine Baseline wird nie überschrieben. |
| `--reviewer <id>` | Reviewer-Kennung (erforderlich): ein Bezeichner, siehe unten. |
| `--change-id <id>` | Änderungs- oder Ticketkennung (erforderlich): ein Bezeichner, siehe unten. |
| `--reason <text\|@file>` | Begründung der Zustandsannahme (erforderlich). `@file` liest Text aus einer Datei; CRLF wird LF, damit signierte Bytes nicht vom Editor abhängen. Die als `--key` verwendete Datei wird vor dem Lesen verweigert. |
| `--key <file>` | Privater ed25519-Schlüssel, PEM PKCS#8, Modus `0600` (erforderlich), etwa aus `skillctl keygen`. Ein nicht ladbarer Schlüssel (fehlend, falscher Typ, offenerer Modus als `0600`) ist ein Aufruffehler. |
| `--expires-at <rfc3339>` | Optionaler Ablaufzeitpunkt mit beliebigem Offset, in UTC gespeichert. Die Baseline gilt einschließlich dieses Zeitpunkts. |
| `--self-approval allow\|warn\|block` | Behandlung einer Selbstfreigabe (Vorgabe `warn`). |
| `--format text\|json` | Ausgabeformat (Vorgabe `text`). |

Die Pflichtfelder werden vor dem Lesen von Capture oder Schlüssel und lange
vor einer Signatur geprüft.

**Kennungen.** Reviewer- und Änderungskennung bestehen nach Entfernen
umgebenden Leerraums aus 1 bis 128 ASCII-Buchstaben, Ziffern und `.` `_`
`-` `@` `+` `:` (`alice@example.com`, `CHG-0001`). Innerer Leerraum,
Schrägstriche, ähnlich aussehende Nicht-ASCII-Zeichen oder größere Länge
werden vor jedem Lesen oder Signieren mit Exit `2` verweigert. So geht
eine Kennung plattformübergreifend identisch in die signierte Freigabe ein.
verify wendet dieselbe Regel auf `reviewer`, `change_id`,
`identities.reviewer_id` und `identities.capture_actor` an und verweigert
abweichende Freigaben als `approval_invalid`.

Freigabetext wird signiert und kann danach nie redigiert werden. Reviewer,
Änderungskennung, Begründung oder Policy-Referenz, die von Redaktionsmustern
als Secret-Material erkannt werden (privater Schlüsselblock, Bearer- oder
Authorization-Wert, Token, Schlüssel-Wert-Paar wie `password=...` oder
`?token=...`), werden mit Exit `2` zurückgewiesen. Genannt werden Feld und
Musterklasse, niemals der Text. Das Capture wird bytegenau ins neue
Verzeichnis kopiert und niemals verändert; hinzu kommen `approval.json`,
ein neues `manifest.json` (Art `baseline`) und danach
`signatures/manifest.ed25519.json`.

**Selbstfreigabe.** Die Freigabe erfasst das aufgenommene Subject, den
Capture-Akteur (falls vorhanden), Reviewer, Signaturschlüssel-ID und
freigebendes Gerät. Dessen Subject-ID wird wie beim erfassten Gerät aus
Betriebssystemfamilie und Hostnamen abgeleitet. `warn` meldet
`self_approval_same_device` (Freigabe auf dem erfassten Host) oder
`self_approval_same_person` (Reviewer entspricht Capture-Akteur); `block`
verweigert die Freigabe. Ist das Freigabegerät unbekannt (Hostname unlesbar),
kann die Geräteprüfung nicht laufen: `warn` meldet
`self_approval_device_unknown`; `block` verweigert bei Freigabe und Prüfung,
statt eine nicht auswertbare Prüfung passieren zu lassen. Die
Personenprüfung vergleicht `identities.capture_actor` nach Entfernen
umgebenden Leerraums ohne Beachtung der Groß-/Kleinschreibung mit dem
Reviewer. Ohne `capture --actor` wird kein Akteur erfasst; dieser Teil
hat dann keine Vergleichsgrundlage.

**Signatur.** Die signierte Nachricht besteht aus der Domainzeile
`m3c-tools/trust-freeze/baseline/v1`, einem Zeilenumbruch und kanonischem
JSON der Aussage `{domain, schema_version:
"trust-freeze/baseline/v1", kind: "baseline", capture_content_digest,
baseline_content_digest, approval}`. `key_id` ist `ed25519:` plus die
ersten 16 Hexzeichen von SHA-256 über den rohen öffentlichen Schlüssel.
`statement_sha256` ist SHA-256 der signierten Nachricht; verify rekonstruiert
die Aussage aus den Dateien und vertraut diesem Wert nie allein.
Nirgends wird privates Schlüsselmaterial geschrieben.

Exit: `0` Baseline geschrieben · `1` Capture-Prüfung fehlgeschlagen (auch
bei Baseline oder Diff als `--capture` oder widersprüchlichen
Capture-Dokumenten) oder Selbstfreigabe blockiert (`verification_failure`),
oder nicht geschrieben (`execution_error`) · `2` Usage einschließlich
fehlender oder fehlerhafter Reviewer-/Änderungskennung, fehlender
Begründung, Secret-ähnlichem Freigabetext oder nicht ladbarer Datei bei
`--key` oder `--reason @file`.

#### `trust-freeze verify`: ein Bundle offline prüfen

| Flag | Zweck |
|------|---------|
| `--bundle <dir>` | Zu prüfendes Bundle (erforderlich): Baseline, Capture oder Diff. |
| `--trust-policy <file>` | Trust-Policy-Datei (JSON oder YAML). |
| `--trusted-key <public.pem>` | Zu vertrauender öffentlicher ed25519-Schlüssel (PEM SPKI, etwa `.pub` aus `keygen`), wiederholbar. |
| `--format text\|json` | Ausgabeformat (Vorgabe `text`). |

Eine **Baseline** wird vollständig geprüft (`scope: "baseline"`): Manifest,
jede Größe und jeder Digest, unerwartete Dateien, das Layout ihrer Art
(unter `signatures/` nur die eine nicht im Manifest gelistete Signaturdatei),
`capture.json`, `approval.json` mit Pflichtfeldern, Capture-Digest, Signatur
über die rekonstruierte Aussage, Schlüsselvertrauen, Ablauf, Freigabezeit
und Selbstfreigabemodus. Bei Capture und Capture innerhalb einer Baseline
müssen `capture.json`, alle `probes/<probe-id>.json` und `state/device.json`
übereinstimmen (Probe-Liste, Status und Begründung, aus Ergebnissen neu
berechnete Vollständigkeit, Gerätezustand, sämtliche Nachweisreferenzen).
Widersprüche scheitern als `capture_invalid`. Eine gültige Signatur eines
nicht vertrauten Schlüssels scheitert als `key_not_trusted` und meldet
weiterhin `signature_valid: true`. Ohne Vertrauensmaterial scheitert jede
Baseline so. Ein **Capture** oder **Diff** trägt keine Signatur; seine
Prüfung (`scope: "integrity"`) umfasst Manifest und striktes Parsen der Dokumente.

**Capture-Digest.** `approval.json` benennt das freigegebene Capture über
`capture_digest`. verify übernimmt den Wert nicht ungeprüft, sondern baut
das Capture-Manifest aus der Baseline selbst neu auf (Art `capture`,
`created_at` = `finished_at` aus `capture.json`, aus dieser Zeit und dem
Subject abgeleitete Bundle-ID, Subject der Baseline,
`reject_additions: true`, Baseline-Dateien ohne `approval.json`). Weicht
der Inhalts-Digest dieses Manifests ab, folgt `capture_digest_mismatch`.
`capture` schreibt genau dieses Manifest, daher stimmt eine aus einem
unveränderten Capture freigegebene Baseline überein. `baseline approve`
prüft diese Regel noch nicht: Ein anders aufgebautes, nicht von `capture`
geschriebenes Manifest wird freigegeben, seine Baseline scheitert danach
bei verify mit `capture_digest_mismatch`.

**Zeit.** Ablauf und Freigabezeit werden gegen die Uhr des Prüfenden
geprüft und besitzen eigene Toleranzen, weil sie unterschiedliche
Aussagen darstellen.

`max_clock_skew` (Vorgabe `5m`, `0s` deaktiviert es) ist die
Freigabetoleranz: Ein `approved_at`, das mehr als diese Spanne nach jetzt
liegt, scheitert als `approved_in_future`, weil eine Freigabe nicht nach
dem Zeitpunkt ihrer Prüfung stattgefunden haben kann. Die Toleranz
berücksichtigt die üblichen Sekundenabweichungen zweier Rechneruhren;
eine vorgehende Signaturuhr soll eine sonst gültige Baseline nicht scheitern
lassen. Fünf Minuten liegen weit unter jeder sinnvollen Baseline-Lebensdauer.

`max_expiry_skew` (Vorgabe `0s`) ist die Ablauftoleranz: Ein `expires_at`,
das mehr als diese Spanne vor jetzt liegt, scheitert als `expired`. Mit
Vorgabe gilt der Ablauf damit nanosekundengenau. Diese getrennte Einstellung
hat bewusst null als Vorgabe: Ein Ablauf ist kein Versehen, sondern ein
Versprechen des Freigebenden an den Prüfenden. Eine Dehnung würde eine
bewusst festgelegte Gültigkeit verlängern. Soll auch der Ablauf Uhrendrift
abfedern, muss der Betreiber `max_expiry_skew` ausdrücklich setzen; die
Trust-Policy dokumentiert das dann.

Eine Policy ohne beide Felder erhält beide Vorgaben. Negative Werte
werden für beide abgelehnt.

Fehlergründe: `integrity` (mit `integrity_reason`: `missing`, `extra`,
`size_mismatch`, `digest_mismatch`, `duplicate_path`, `bad_path`, `symlink`,
`content_digest_mismatch`, `unknown_kind`, `unknown_schema`,
`kind_layout_violation`, `manifest_invalid`, `not_regular`, `unreadable`),
`wrong_kind`, `missing_approval`, `missing_signature`, `capture_invalid`,
`approval_invalid`, `signature_malformed`, `domain_mismatch`,
`signing_key_mismatch`, `statement_mismatch`, `bad_signature`,
`key_not_trusted`, `capture_digest_mismatch`, `expired`,
`approved_in_future`, `self_approval_blocked`, `trust_policy_invalid`,
`canceled` sowie bei Diff-Bundles `diff_invalid`.

Trust-Policy-Datei (Schema `trust-freeze/trust-policy/v1`):

```yaml
schema_version: trust-freeze/trust-policy/v1
self_approval: warn                  # allow | warn | block
reject_additions: true               # false is not implemented in this version
max_clock_skew: 5m                   # approved_at; Go duration, default 5m, 0s disables
max_expiry_skew: 0s                  # expires_at; Go duration, default 0s
trusted_keys:
  - key_id: ed25519:0123456789abcdef # optional; checked against the key when present
    public_key: <base64 of the raw 32-byte ed25519 public key>
```

JSON-Trust-Policies werden so strikt wie YAML gelesen: Doppelte Schlüssel
oder Schlüssel, die sich nur durch Groß-/Kleinschreibung vom Feldnamen
unterscheiden, werden abgelehnt.

Exit: `0` PASS · `1` FAIL (`verification_failure`) · `2` Usage einschließlich
nicht ladbarer Trust-Policy- oder Schlüsseldatei.

#### `trust-freeze diff`: geprüfte Baseline mit aktuellem Bundle vergleichen

| Flag | Zweck |
|------|---------|
| `--baseline <dir>` | Baseline-Bundle (erforderlich). |
| `--current <dir>` | Aktuelles Bundle (erforderlich): Capture oder Baseline. |
| `--trust-policy <file>` | Trust-Policy zur Eingabeprüfung. |
| `--trusted-key <public.pem>` | Vertrauter Schlüssel zur Eingabeprüfung (wiederholbar). |
| `--policy <file\|id>` | Policy-Datei (JSON oder YAML, Schema `trust-freeze/policy/v1`) oder Kennung einer eingebauten Policy: `trust-freeze/policy/default-v0`, `trust-freeze/policy/default-v1`. Vorgabe `trust-freeze/policy/default-v1`. |
| `--fail-on none\|low\|medium\|high\|critical` | Schwelle für Exit `1` (Vorgabe: `fail_on` der Policy, `high` bei default-v1). Ändert nur Exit-Code und `threshold_exceeded`. |
| `--allow-subject-mismatch` | Absichtlicher Vergleich verschiedener Geräte für Golden-Image- oder Flotten-Baselines. `subject_changed` bleibt im Diff und wird als erlaubt bewertet (`info` unter default-v1); der Diff dokumentiert die Zustimmung (`allow_subject_mismatch: true`). |
| `--output <dir>` | Zusätzlich Diff-Bundle schreiben: `diff.json`, `verdict.json`, `policy/evaluated-policy.json`. Niemals innerhalb bestehender trust-freeze-Bundles, einschließlich beider Eingaben. |
| `--format text\|json` | Ausgabeformat (Vorgabe `text`). `markdown` und `sarif` sind in dieser Version nicht implementiert (Exit `2`). |

Beide Eingaben werden zuerst geprüft; scheitert eine, wird nichts verglichen
und stattdessen das Prüfergebnis ausgegeben. Artefakte werden anhand ihrer
ID verglichen, nachdem das versionierte Normalisierungsregelwerk flüchtige
Werte entfernt hat. Vorgabe ist `trust-freeze/normalize/v2` (Zeitstempel,
Dauern, Prozess-IDs, Uptime, `route_metric`, `current_dns_server`);
`trust-freeze/normalize/v1` (Zeitstempel, Dauern, Prozess-IDs, Uptime) wird
weiter ausgeliefert, damit damit aufgezeichnete Diffs lesbar bleiben.
Veröffentlichte Regelwerke werden nur ersetzt, niemals editiert:
`route_metric` ändert sich bei Umordnung durch den Netzwerkstack ohne
Routenänderung; `current_dns_server` ist der gerade von systemd-resolved
aus der konfigurierten Liste abgefragte Server. Beide sind daher flüchtig,
Gateway, Resolverliste und Programm-Hash dagegen nicht; kein Regelwerk
entfernt diese. Ein Regelwerk entfernt Werte, nie Artefakte: Zwischen
Captures erschienene oder verschwundene Routen bleiben `added` oder
`removed`. Werte innerhalb einer Artefakt-ID sind ebenfalls unerreichbar,
weil Artefakte VOR der Regelanwendung anhand ihrer ID gepaart werden.
`linux.network.routes` bildet daher bei zwei Routen gleicher Familie,
Tabelle, Schnittstelle und Ziel die ID aus dem GATEWAY, das sich nur mit
der Topologie ändert, und ergänzt die Metrik nur, wenn der Kernel diese
Routen ausschließlich dadurch unterscheidet. Diese Gruppe wird mit
`route_id_carries_metric` gemeldet, weil nur dort eine Metrikänderung
tatsächlich als entfernte und hinzugefügte Route erscheint. Jeder Diff
erfasst Kennung und Digest des Regelwerks. Gleiche Eingaben, Zustimmung
und Policy ergeben bytegleiche Ausgabe. Eine Baseline, deren Probes alle
`captured` oder begründet `not_applicable` waren, erzeugt beim Selbstvergleich
keinen Befund über `info` und Exit `0`; Lücken eines freigegebenen
unvollständigen Captures bleiben in jedem Diff Lücken.

**Quellprobe.** Jedes Artefakt nennt seine erzeugende Probe im Feld
`source`. Diese gilt im Bundle als *beobachtet*, wenn genau ein Ergebnis
`captured` oder begründet `not_applicable` vorliegt (die Probe hat
beobachtet, dass nichts zutrifft). Eine Quelle ohne Probe-ID gilt als
beobachtet. Nur auf beiden Seiten Beobachtetes kann `removed` oder
`changed` sein: Ein aktuell nicht beobachtbares Artefakt oder Attribut ist
`not_observed`, niemals `removed` oder `changed`; zusätzlich wird seine
Probe als `collection_gap` gemeldet.

**Capabilities** werden getrennt von Artefakten anhand ihrer Capability-ID
verglichen, nur soweit beide Bundles sie aufgelöst haben. Eine Baseline
ohne `state/capabilities.json` erzeugt keinerlei Capability-Eintrag:
Niemand hatte sie damals aufgelöst, also darf keine aktuelle Capability
als neu gelten. Hat die Baseline das Dokument und das aktuelle Bundle
nicht, entsteht je Baseline-Capability `capability_not_observed`.

Die andere Richtung besitzt den **Abdeckungsschutz** und betrachtet die
ENTSCHEIDENDEN Quellen: die Quellen, zu deren Artefakten DIESER Vergleich
einen Eintrag meldet, weil darauf der Unterschied beruht. `capability_added`
oder `capability_changed` wird zu `coverage_increased`, wenn jede
entscheidende Quelle von einer in der Baseline nicht erfassten Probe
stammt. Dann änderte sich die Erfassungstiefe statt des Hosts;
`baseline_gap_probes` benennt diese Probes, und die eingebaute Policy
bewertet den Eintrag mit `info`.
Eine einzige entscheidende Quelle aus einem von beiden Läufen erfassten
Bereich belässt den Eintrag bei `capability_added` oder `capability_changed`
mit vollem Schweregrad; `coverage_caveat_probes` nennt daneben schwächer
erfasste Probes. Beispiel: eine Public-Key-Capability, deren Kontoartefakt
in der Baseline vorlag, deren Schlüsselartefakt aber wegen unlesbarer
`authorized_keys` fehlte. Neu ist dann die Erfassung, nicht das Konto.

Auch eine Capability, deren Quellprobes in der Baseline ALLE blind waren,
ist unabhängig von entscheidenden Quellen `coverage_increased`: Die
Baseline deckte ihre gesamte Grundlage nicht ab. Blind bedeutet ohne
brauchbare Beobachtung: kein eindeutiges einzelnes Ergebnis oder Status
`unsupported`, `unavailable`, `permission_denied`, `timeout`, `failed` oder
`not_applicable`. Eine Baseline-Probe mit `partial` hat hingegen geprüft
und berichtet, ist daher nicht blind; darauf beruhende Capabilities
behalten ihre Art. Quellen ohne Artefakt in beiden Bundles lassen sich
keiner Probe zuordnen und werden nirgends gezählt, weil der Schutz keine
ungemessene Lücke erfindet. Auch Einträge ganz ohne entscheidende Quelle
behalten ihre Art.

**Änderungsarten**, in der Sortierreihenfolge des Diffs (danach Artefakt-ID,
Capability-ID, Probe-ID):

| Art | Wird gemeldet, wenn |
|------|---------------|
| `subject_changed` | Baseline und aktuelles Bundle unterschiedliche Geräte beschreiben (abweichende Subject-IDs). Genau ein Eintrag mit `before_subject_id`, `after_subject_id` und `subject_mismatch_allowed`. |
| `added` | Die Artefakt-ID nur im aktuellen Bundle existiert. |
| `removed` | Die Artefakt-ID nur in der Baseline existiert und ihre Quellprobe im aktuellen Bundle beobachtet ist. |
| `changed` | Ein verglichenes Feld abweicht oder ein beidseitig beobachtetes Attribut (dort vorhanden oder unter einer beobachteten Probe fehlend) unterschiedliche Werte besitzt. Benennt geänderte Attribute und Felder mit Vorher-/Nachher-Digests, niemals die Werte. |
| `not_observed` | Die Artefakt-ID nur in der Baseline existiert oder Baseline-Attribute im aktuellen Artefakt fehlen und seine Quellprobe aktuell nicht beobachtet ist. Nennt `probe_id` und `unobserved_attributes`. |
| `confidence_changed` | `provenance.confidence` abweicht. |
| `became_effective` | Der Zustand zu `observed` wechselt. |
| `became_ineffective` | Der Zustand von `observed` wegwechselt. |
| `capability_added` | Die Capability-ID nur aktuell existiert UND mindestens eine in diesem Vergleich neue oder geänderte Quelle von einer in der Baseline erfassten Probe stammt (oder die Baseline einen Teil der Grundlage abdeckte, ohne entscheidende Änderung). Enthält `capability_id` und `after_privilege` sowie `coverage_caveat_probes`, wenn eine Quellprobe damals nur `partial` oder neben einer abgedeckten Quelle blind war. |
| `capability_removed` | Die Capability-ID nur in der Baseline existiert und jedes zugrunde liegende Artefakt aktuell beobachtet wurde; ihr Fehlen wurde also beobachtet. |
| `capability_changed` | Ein Capability-Feld abweicht und nicht jede hier neue oder geänderte Quelle aus einer in der Baseline blinden Probe stammt. Benennt geänderte Felder (`privilege`, `sources`, `state`, `attributes`, ...) mit Vorher-/Nachher-Digests und `coverage_caveat_probes` bei damals geringerer Abdeckung. |
| `capability_not_observed` | Eine Baseline-Capability nicht beobachtbar war: Ein zugrunde liegendes Artefakt fehlt aktuell oder das aktuelle Bundle besitzt kein Capability-Dokument. Niemals als entfernt gemeldet. |
| `coverage_increased` | Bei `capability_added` oder `capability_changed` jede ENTSCHEIDENDE Quelle (deren Artefakt dieser Vergleich neu oder geändert fand) aus einer damals nicht erfassten Probe stammt oder damals sämtliche Quellprobes blind waren. Der Unterschied heißt nicht Drift; `baseline_gap_probes` benennt die Probes. Bei Hinzufügung enthält der Eintrag nur `after_digest`, bei Änderung beide Digests und `changed_fields`. Das Gegenstück zu `capability_not_observed` verhindert, dass verschiedene Erfassungstiefen eine Wand kritischer Befunde erzeugen. |
| `applicability_changed` | Eine Probe mit Begründung zwischen `captured` und `not_applicable` wechselt, in beliebiger Richtung (`before_status`, `after_status`): Der Host hat sich geändert, nicht die Erfassung. |
| `collection_gap` | Eine aktuelle Probe nicht `captured` ist oder eine Pflichtprobe kein Ergebnis hat. |

Jedes `collection_gap` enthält `required`, den erfassten `status` (falls
vorhanden), die `reason` der Probe (falls angegeben) und genau eine `cause`:

| `cause` | Bedeutung |
|---------|---------|
| `not_captured` | Ein Ergebnis mit anderem Status: `partial`, `unsupported` (auch über `--probe` oder `--exclude-probe` übersprungen), `unavailable`, `permission_denied`, `timeout` oder `failed`. |
| `not_applicable` | Begründetes `not_applicable`: für das Capture vollständig, hier trotzdem sichtbar. |
| `not_applicable_without_reason` | `not_applicable` ohne Begründung. |
| `no_result` | Eine Pflichtprobe hat kein Ergebnis. |
| `duplicate_result` | Mehr als ein Ergebnis für die Probe. |
| `invalid_status` | Ein unbekannter Probe-Status. |

Das Diff-Dokument erfasst `allow_subject_mismatch` (auch bei `false`) und
`counts` mit der Eintragszahl jeder Art, einschließlich null. Jeder
Urteilsbefund besitzt eine stabile ID: Art und Artefakt-ID
(`changed:device/os`), Capability-ID bei Capability-Einträgen, Probe-ID bei
`collection_gap` und `applicability_changed`, aktuelle Subject-ID bei
`subject_changed`.

**Policy `trust-freeze/policy/default-v1`** (`fail_on: high`). Jede Änderung
erhält genau einen Befund mit dem höchsten Schweregrad aller passenden
Regeln; ohne passende Regel gilt `default_severity`, also `info`.

Änderungen an der Bewertung erhalten eine neue Policy-ID, niemals eine
Bearbeitung einer veröffentlichten Policy. Die ältere Policy bleibt
eingefroren und über `--policy` auswählbar:
`trust-freeze/policy/default-v0` bewertet überhaupt keine Capability-Einträge;
selbst eine neue Root-Capability erhält unter v0 daher die Vorgabe `info`.
Nur zum Reproduzieren damit berechneter Urteile verwenden. Jedes Diff-Urteil
erfasst in `verdict.json` ID und Regeldigest der bewertenden Policy;
Diff-Bundles enthalten sie unter `policy/evaluated-policy.json` selbst.

| Änderung | Schweregrad | Regel |
|--------|----------|------|
| `subject_changed` ohne Zustimmung | `high` | `TF-POL-SUBJECT-CHANGED` |
| `subject_changed` mit `--allow-subject-mismatch` | `info` | `TF-POL-SUBJECT-CHANGED-ALLOWED` |
| `collection_gap` einer Pflichtprobe, jede Ursache außer `not_applicable` | `critical` | `TF-POL-GAP-REQUIRED` |
| `collection_gap` einer optionalen Probe, jede Ursache außer `not_applicable` | `medium` | `TF-POL-GAP-OPTIONAL` |
| `collection_gap` mit Ursache `not_applicable`, Pflicht oder optional | `info` | `TF-POL-GAP-NOT-APPLICABLE` |
| `device/os` oder `device/host` `changed` | `medium` | `TF-POL-DEVICE-IDENTITY` |
| Jedes andere `added`, `removed` oder `changed` | `low` | `TF-POL-ARTIFACT-DRIFT` |
| `not_observed` | `low` | `TF-POL-NOT-OBSERVED` |
| `capability_added` oder `capability_changed` mit Privileg `root`, `root-via-container-runtime`, `root-via-privileged-container`, `root-via-sudo` oder `root-via-sudo-nopasswd` | `critical` | `TF-POL-CAPABILITY-ROOT` |
| Jedes andere `capability_added` | `high` | `TF-POL-CAPABILITY-ADDED` |
| Jedes andere `capability_changed` | `medium` | `TF-POL-CAPABILITY-CHANGED` |
| `capability_removed` oder `capability_not_observed` | `low` | `TF-POL-CAPABILITY-GONE` |
| `coverage_increased` | `info` | `TF-POL-COVERAGE-INCREASED` |
| `applicability_changed` | `low` | `TF-POL-APPLICABILITY` |
| `confidence_changed`, `became_effective`, `became_ineffective` | `info` | `default_severity` |

Unter default-v1 blockiert damit bereits der Vergleich verschiedener Geräte.
Mit `--allow-subject-mismatch` blockiert dieser eine Befund nicht mehr;
alle anderen behalten ihren Schweregrad. Eine fehlende Pflichtprobe blockiert;
eine begründet auf diesem Host nicht zutreffende Probe nicht.

**Eigene Policy** (`--policy`, JSON oder YAML; unbekannte Felder werden verweigert):

```yaml
schema_version: trust-freeze/policy/v1
id: example/policy-v1
fail_on: high                       # none | low | medium | high | critical
default_severity: info              # for a change no rule matches
rules:
  - id: EX-GAP-TIMEOUT
    severity: high
    match:                          # every condition that is set must hold
      change_kinds: [collection_gap]
      required: false               # with change_kinds [collection_gap] only
      gap_causes: [not_captured]    # with change_kinds [collection_gap] only
      gap_statuses: [timeout]       # with change_kinds [collection_gap] only
  - id: EX-FLEET-BASELINE
    severity: low
    match:
      change_kinds: [subject_changed]
      subject_mismatch_allowed: true  # with change_kinds [subject_changed] only
  - id: EX-ROOT-CAPABILITY
    severity: critical
    match:
      change_kinds: [capability_added]
      privileges: [root, root-via-sudo, root-via-sudo-nopasswd]  # capability kinds only
```

`change_kinds` ist erforderlich und darf nicht leer sein. `artifact_ids`
beschränkt eine Regel auf genaue Artefakt-IDs und ist nicht mit
`collection_gap` oder einer Capability-Art kombinierbar, da beide keine
Artefakt-ID haben. `privileges` ist nur erlaubt, wenn sämtliche
Änderungsarten der Regel Capability-Arten sind. Es vergleicht das aktuell
beobachtete Privileg und bei aktuell fehlender Capability das der Baseline.
Listen `gap_causes` und `gap_statuses` dürfen nicht leer sein und nur bekannte
Ursachen beziehungsweise Probe-Status benennen. Eine Lücke ohne Status
(`no_result`, `duplicate_result`, `invalid_status`) passt nie auf
`gap_statuses`. Bei Regeln desselben Schweregrads benennt die frühere den
Befund. Die Regel-ID `default_severity` ist reserviert.

Exit: `0` Schwelle nicht erreicht · `1` Schwelle erreicht
(`drift_threshold_exceeded`), Eingabeprüfung fehlgeschlagen
(`verification_failure`) oder Lauf fehlgeschlagen (`execution_error`)
· `2` Usage.

#### `trust-freeze report`: Bundle als Berichtsdokument oder Seite darstellen

| Flag | Zweck |
|------|---------|
| `--input <dir>` | Capture-, Baseline- oder Diff-Bundle (erforderlich). Muss seine Integritätsprüfung bestehen. |
| `--output <file\|dir>` | Zu erstellende Berichtsdatei (erforderlich); ein bestehendes Verzeichnis erhält formatabhängig `report.json`, `report.yaml` oder `report.html`. Nie überschrieben und niemals im Eingabebundle oder anderen trust-freeze-Bundles. Modus `0600`, weil Berichte Hostnamen enthalten können. |
| `--format json\|yaml\|html` | Format der Berichts**datei** (Vorgabe `json`). Sagt nichts über die Standardausgabe aus, die immer ein JSON-Statusdokument ist. `markdown` und `sarif` sind in dieser Version nicht implementiert (Exit `2`). |

Ein Lauf schreibt genau eine Datei in genau einem Format. Es gibt keinen
Schalter für alle drei: Er müsste die Frage "niemals über eine bestehende
Datei" dreimal in einem Aufruf stellen.

Der Bericht (Schema `trust-freeze/report/v1`) projiziert nur das Bundle und
entscheidet nichts. Er prüft die Eingabeintegrität (Manifest, Größen,
Digests, Layout), aber weder Signatur noch Schlüsselvertrauen oder Ablauf.
Er liest keine Uhr; der Bericht eines unveränderten Bundles hat daher
unabhängig vom Erstellungszeitpunkt identische Bytes. Bei Baselines enthält
`signature` stets `{"result": "not_evaluated", "verify_with":
"skillctl trust-freeze verify"}`. Die Vertrauensentscheidung trifft
`verify --trusted-key`; ein Bericht belegt niemals die Baseline-Gültigkeit.
Unabhängig von `--format` enthält stdout einen JSON-Status mit
`result_class`, Eingabe, bei Baselines derselben Sektion `signature` und
dem SHA-256 der geschriebenen Berichtsdatei. Berichte enthalten interne
Hostdaten (siehe Datenschutz oben).

**YAML** (`--format yaml`) ist dieselbe Projektion mit identischen Feldern,
Werten und Reihenfolge. Es wird aus den kanonischen JSON-Bytes konvertiert,
nicht über einen zweiten Satz Tags geschrieben; dadurch können beide
Darstellungen nicht auseinanderlaufen. Zeichenketten, die YAML 1.1 als
Boolean oder Basis-60-Zahl auslegen würde (`no`, `yes`, `on`, `off`, `y`,
`n`, `N`, `Y`, `1:30`), werden gequotet; `PasswordAuthentication no`
bleibt so unverändert Text.

**Die Seite** (`--format html`) ist eine eigenständige Datei zum Lesen und
Drucken: kein Skript, Stylesheet, Font, Bild oder Data-URI, sodass sie auch
auf Hosts ohne Netz öffnet. Sie zeigt alle Digests ihrer Bundle-Art
vollständig, jeweils mit Quelldatei, Quellfeld und Prüfbefehl; eine je
Bundle-Art unterschiedliche Anleitung für Leser ohne `skillctl`-Kenntnisse;
Vollständigkeit; Probes mit Status als **Wort** und voller Begründung;
Capabilities mit eigenen Resolver-Diagnosen; die Baseline-Freigabe und
Einträge sowie Urteil eines Diffs. Den Baseline-Signaturabschnitt zeigt sie
als Zitat (`not_evaluated`) samt auswertendem Befehl; die Seite selbst
bewertet nichts. Bewusst ausgelassene Artefaktlisten und rohe Probe-Ergebnisse
werden mit Anzahl und anzeigendem Befehl auf der Seite genannt.

**Capabilities.** Der Bericht eines Captures oder einer Baseline projiziert
`state/capabilities.json` unter `capture.capabilities`: ausgeführter
Resolver, ein Eintrag je Capability mit `id`, `subject_id`, `action`,
`resource`, `effect`, `privilege`, `exposure`, `scope`, `state`, `confidence`,
ihren `attributes` und `sources` sowie daneben die eigenen `diagnostics`
des Resolvers. Eine leere Liste bedeutet deshalb nie "dieser Host erlaubt
nichts". Sortiert wird nach Reichweite des Privilegs (`root`, danach
`root-via-sudo-nopasswd`, dann beide Containerpfade, `root-via-sudo`,
Unbekanntes und zuletzt `user`) und innerhalb einer Stufe nach ID. Dies
ist Darstellung, kein Urteil: Der Bericht bewertet weiterhin nichts.
Bundles ohne `state/capabilities.json` besitzen gar keinen Schlüssel
`capabilities`.

Exit: `0` Bericht geschrieben · `1` Eingabeprüfung fehlgeschlagen
(`verification_failure`) oder Datei nicht schreibbar (`execution_error`)
· `2` Usage.

#### `trust-freeze`: Ausführung der Probes und bekannte Grenzen

- **Befehle** laufen als Programm plus Argumentvektor, niemals über eine
  Shell. Die Auflösung erfolgt nur in `/usr/bin`, `/bin`, `/usr/sbin`,
  `/sbin`, unter Linux danach `/snap/bin` (Windows: das vom Betriebssystem
  gemeldete Systemverzeichnis). Unter `/snap/bin` legt snapd die Einstiegspunkte
  installierter Snaps ab; unter Ubuntu ist `docker` häufig ein solcher.
  Der Pfad kommt zuletzt, damit ein Distributionspaket vor einem gleichnamigen
  Snap gewinnt. Der `PATH` des Aufrufenden wird nie gelesen. Die Umgebung
  besteht nur aus der Probe-Positivliste plus `LC_ALL=C` und `TZ=UTC0`;
  Arbeitsverzeichnis ist `/` (Windows: das Windows-Verzeichnis). `sudo`,
  `su`, `doas`, `pkexec`, `run0`, `runuser` und `runas` werden anhand von
  Name, Pfad oder Symlink-Ziel verweigert. Unter Unix läuft jedes Werkzeug
  in eigener Sitzung und Prozessgruppe ohne steuerndes Terminal: Eine
  Passwortabfrage scheitert sofort, und beim Timeout wird die gesamte
  Gruppe beendet. Unter Windows werden der gestartete Prozess und alle
  über Parent-PID verfolgbaren Nachfahren beendet, nicht aber von Diensten
  oder Brokern gestartete oder erhöht laufende Nachfahren. Ctrl-C und
  SIGTERM brechen ein laufendes Capture genauso ab.
- **Ausgabe** ist je Stream begrenzt (Vorgabe 1 MiB stdout, 64 KiB stderr).
  Kürzung wird erfasst und macht die Probe auf zwei Ebenen `partial`:
  Die Capture-Engine stuft jeden Lauf mit getroffener Grenze herab;
  jede Linux-Probe liest zusätzlich das Flag und ergänzt
  `output_truncated` mit Stream, Grenze und dem dadurch Unbekannten.
  Auch gekürzte Listen nennen dies im eigenen Artefakt
  (`network/listeners.listener_list_truncated`,
  `container/runtime/<name>.container_list_truncated`), damit niemand
  die danebenstehende Anzahl für den gesamten Host hält.
- **Mengen** sind je Probe begrenzt, sodass auch große Hosts begrenzte
  Bundles erzeugen: 5000 Pakete, 4096 Listener, 4096 Mountpunkte, 2048
  Container, 2000 Konten und 2000 Gruppen, 512 Units in der Auswahl für
  `systemctl show`, 64 Konten und 64 Schlüssel je Konto für
  `authorized_keys`. Jede wirksame Grenze erzeugt `volume_capped` oder
  eine familienspezifische Diagnose und macht die Probe `partial`;
  die vom Tool gemeldete Anzahl bleibt im Mengenartefakt. `docker inspect`
  wird wie `systemctl show` in Batches von 40 Containern aufgerufen,
  sodass kein Argumentvektor mit dem Host wächst. Alles wird vor dem
  Schreiben redigiert: private Schlüsselblöcke, Bearer- und
  Authorization-Werte, Cloud- und Chat-Tokens, JWT-artige Strings,
  Werte unter Schlüsseln wie `password` oder `token` sowie das
  Home-Verzeichnis in beliebiger Groß-/Kleinschreibung und Separatorform
  (bei Windows-Home auch die WSL-Form `/mnt/<drive>/...`). Nicht
  redigierbare Werte werden verworfen, die Probe mindestens `partial`.
  Jede Nachweisdatei passiert vor dem Schreiben erneut den Redaktor
  des Captures samt allen Secrets aus den Befehlsargumenten ihrer Probe.
  So verschwinden auch Secrets, die ein Befehl erhält und ein anderer
  ausgibt. Eine durch Größen- oder Dateianzahlgrenze verweigerte
  Nachweisdatei macht die Probe `partial`.
- **Der Ersatzmarker** ist `[REDACTED_<class>]`, ein einzelnes Token aus
  Buchstaben, Ziffern, Unterstrichen und den beiden Klammern. Bewusst
  fehlen Doppelpunkt, Tab, Komma, Semikolon, Gleichheitszeichen,
  Leerzeichen und Zeilenende, weil die Probes dieselbe Ausgabe danach
  positionsabhängig parsen: Doppelpunkt trennt `getent passwd` und
  `getent group`, Tab `dpkg-query` und `ss`, Komma Gruppenmitglieder,
  Gleichheitszeichen ein `id`-Token, Leerraum tabellarische Ausgaben.
  Ein solcher Separator im Marker würde ein Feld aufteilen und den
  Datensatz ungültig machen. Deshalb nutzt die Befundklasse einen
  Unterstrich, damit die Form des Datensatzes erhalten bleibt.
- **Ein Wert, der kein Secret sein kann, wird nicht ersetzt.** Zur Regel,
  die Werte wegen credential-artiger SCHLÜSSEL ersetzt, gehört als
  zweite Hälfte der Wert selbst. Ein kurzes Token aus einer geschlossenen
  Konfigurationsmenge (`yes`, `no`, `true`, `false`, `none`, `any`, `all`,
  `default`, `prohibit-password`, `without-password`,
  `forced-commands-only`, ein Wert der Familie `yes-with-...`, eine
  einfache Ganzzahl mit höchstens zehn Stellen oder eine Dauer wie
  `90s` oder `1h30m`) ist eine Einstellungsantwort, kein Credential,
  und bleibt stehen. Alles andere wird weiter ersetzt; etwa
  `password_hash` mit einem 60-Zeichen-Wert wird entfernt. Gemessen
  bei einem erhöhten Capture einer Ubuntu-Bastion:
  `passwordauthentication`, `permitemptypasswords` und das sudo-Flag
  `nopasswd` wurden zu `[REDACTED_password]`. Dadurch konnte das
  Bundle nicht aussagen, ob Passwortanmeldung erlaubt war, und der
  dieses Flag lesende Capability-Resolver bewertete einen unbegrenzten
  passwortlosen Root-Zugriff als `root-via-sudo`.
- **Eine Probe beschreibt ihre eigenen Felder.** Kennt sie die
  Feldsemantik, erfasst sie die Klasse am Artefakt (`attribute_classes`):
  `policy` für den sshd-Direktivensatz von `ssh/sshd/declared` und
  `ssh/sshd/effective` sowie Attribute von `sudo/rule/...`, `sensitive`
  für unabhängig von Name und Form zwingend zu ersetzende Felder.
  `policy` nimmt nur die Schlüsselnamenregel aus: Alle Wertmuster
  laufen weiter, private Schlüsselblöcke unter solchen Feldern werden
  also trotzdem entfernt. Die Klasse wird nur bei sonst greifender
  Schlüsselnamenregel erfasst; die meisten Artefakte tragen keine.
  Sie steht im Bundle, sodass Leser den Grund für Klartextwerte
  erkennen; das Manifest deckt sie wie alle anderen Bytes ab.
  Der Digest je Artefakt umfasst weiterhin nur Identität und Attribute.
- **Ein Pfadsegment ist kein Schlüssel.** Ein direkt an einen
  Vorwärtsschrägstrich anschließender Name ist das letzte Pfadsegment;
  der Text nach dessen Doppelpunkt ist eine Nachricht, kein Wert.
  Gemessen an der Verweigerung des Testhosts: `cat: /etc/sudoers.d/alice-nopasswd:
  Permission denied` wurde zu `... [REDACTED_password] denied` und
  verbarg den Grund für die unlesbare Datei. Ein mit Backslash
  abgetrennter Name wird weiter als Schlüssel behandelt.
- **Architektur.** `arch` stammt aus `uname -m` (linux, darwin) und
  `IsWow64Process2` (windows). Unter macOS wird `x86_64` mittels
  `sysctl.proc_translated` geprüft: `1` bedeutet Rosetta-2-Übersetzung
  von skillctl, daher `arch` gleich `arm64` mit Diagnose
  `value_derived`; ein Intel-Mac antwortet "unknown oid". Ein
  Linux-Prozess unter User-Mode-Emulation (etwa qemu-user) sieht in
  `uname -m` die emulierte Maschine.
- **Identitätsgrenzen.** Unter macOS enthält `os_version` ein installiertes
  Rapid-Security-Response-Tag (`13.4.1 (c)`); dessen Installation oder
  Entfernung ändert `device/os`. Ohne konfigurierten HostName kann
  der macOS-Hostname dem Netzwerk folgen; das ändert `device/host`
  und Subject-ID zwischen Captures. Bei Linux-Rolling-Releases
  (Arch: `BUILD_ID=rolling`, kein `VERSION_ID`) ist `os_version`
  `not_applicable`. In Containern oder WSL beschreibt os-release
  das Image, `uname -r` dagegen den Host- oder VM-Kernel. Unter
  Windows 11 sagt Registry-`ProductName` weiterhin Windows 10;
  `os_name` wird aus der Buildnummer abgeleitet, die Nachweise
  behalten die Registry-Originalwerte, und `value_derived`
  dokumentiert die Regel.
- **Windows-Dateirechte.** Bundle-Dateien entstehen mit Modus `0600`,
  Verzeichnisse mit `0700`; Windows ignoriert das und vererbt die
  ACL des Ausgabeordners. Bundles daher unter einem nur selbst
  lesbaren Verzeichnis schreiben. Go meldet Cloud-Sync-Platzhalter
  und ähnliche Reparse Points als irreguläre Dateien; ein Bundle
  im synchronisierten Ordner kann deshalb mit `not_regular`
  scheitern. Vorher in einen lokalen Ordner kopieren.
- **Bundle auf eine andere Maschine übertragen.** Ein Bundle besteht
  nur in seiner ursprünglichen Form: Ergänzungen werden verweigert,
  jede nicht im Manifest stehende Datei unabhängig vom Namen als
  `extra`, geänderte Bytes als `digest_mismatch` gemeldet. Diese
  Strenge ist Absicht. Übertragen ohne neue Dateien oder geänderte
  Bytes und anschließend am Ziel `verify` ausführen:
  - `tar`. Unter macOS mit `COPYFILE_DISABLE=1 tar -cf bundle.tar <dir>`
    erstellen. Sonst legt macOS-`tar` neben jeder Datei und jedem
    Verzeichnis mit erweiterten Attributen einen AppleDouble-Eintrag
    `._<name>` ab (unter macOS 15 können selbst gewöhnliche Dateien
    und Ordner `com.apple.provenance` tragen); Linux- oder Windows-`tar`
    entpackt diese Einträge als Dateien.
  - `rsync -a` ohne Übernahme erweiterter Attribute (`-X` bei rsync 3,
    `-E` beim mit macOS ausgelieferten rsync).
  - `cp -R -X` unter macOS (`-X`: keine erweiterten Attribute oder
    Resource Forks kopieren).

  Zwei macOS-Gewohnheiten erzeugen `extra`-Fehler: Kopieren auf ein
  Volume ohne erweiterte Attribute (FAT, exFAT, viele Netzwerkfreigaben)
  schreibt `._<name>`-Dateien; Finder kann `.DS_Store` in angezeigte
  Bundle-Ordner schreiben. Ein Git-Checkout mit Zeilenende-Konvertierung
  ändert Bytes. Das Entfernen zusätzlicher `._<name>`- oder
  `.DS_Store`-Dateien nach Prüfung ihrer Herkunft stellt das Bundle
  wieder her, weil verify dann erneut jedes manifestierte Byte
  prüft. verify selbst überspringt solche Dateien niemals.
- **Bekannte Lücken dieser Version.** `doctor` prüft Claude-Wurzeln,
  Ausgabeort und Werkzeuge je Probe (siehe eigenen Abschnitt).
  Nicht Bestimmbares bleibt mit Begründung `not_checked`, etwa
  bei Probes ohne Angabe ihrer verwendeten Programme. `diff`
  liefert eine Änderungsliste mit `counts` je Art statt separater
  Abschnitte für System, Artefakte, Capabilities und Erfassungslücken.
  Capabilities werden nur unter linux und nur aus sudo-Regeln,
  Gruppenmitgliedschaften und autorisierten Schlüsseln abgeleitet;
  anders begründete Privilegien fehlen daher im Dokument.
  `report --format markdown|sarif` und `diff --format markdown|sarif`
  sind nicht implementiert (Exit `2`).


### `publish`: über ER1 zulassen, attestieren und widerrufen (Registry `self`)

```bash
skillctl publish <name[@ver]> [flags]
skillctl publish --attest <name[@ver]> --level green --rationale '<why>' [flags]
skillctl publish --revoke <name> --digest sha256:<hex> --reason '<code>' [flags]
```

Veröffentlicht in Ihrer persönlichen ER1-Registry `self` (SPEC-0225). Drei Modi:
Bundle zulassen (Standard), Governance-Attestierung veröffentlichen (`--attest`)
oder `BundleRevokedEvent` veröffentlichen (`--revoke`). `--all` bündelt Zulassung
und Attestierung für jeden Eintrag im Veröffentlichungsmanifest.

| Flag | Zweck |
|------|---------|
| `-attest` | Modus: `AttestationPublishedEvent` statt Zulassung veröffentlichen. |
| `-revoke` | Modus: `BundleRevokedEvent` veröffentlichen; benötigt `--digest` und `--reason`. |
| `-all` | Alle Einträge in `--manifest` gemeinsam zulassen und attestieren. |
| `-bundle` | Pfad eines fertigen `.skb`; leer packt das Skill-Verzeichnis direkt. Das innere Manifest bestimmt die Art; widersprechendes `--kind` wird verweigert. |
| `-kind skill\|agent` | Bundle-Art (SPEC-0432). `agent` packt EINE Definitionsdatei in den Agentenbereich. Muss bei vorhandenem Bundle-Manifest mit diesem übereinstimmen. |
| `-agent-file` | `[--kind agent]` Pfad der Agentendefinition, standardmäßig `~/.claude/agents/<name>.md`. |
| `-skill-dir` | Skill-Verzeichnis, standardmäßig `~/.claude/skills/<name>`. |
| `-version` | Skill-Version; überschreibt SKILL.md-Frontmatter. Für Zulassung erforderlich. |
| `-digest` | `[--attest\|--revoke]` vorhandener Bundle-Digest `sha256:<hex>`; ohne Angabe aus `--bundle` abgeleitet. |
| `-level green\|yellow\|red` | `[--attest]` Governance-Stufe, standardmäßig `green`. |
| `-rationale` | `[--attest\|--revoke]` einzeilige Begründung. |
| `-reason` | `[--revoke]` kurzer Begründungscode, etwa `key-compromise` oder `deprecated`. |
| `-registry` | Registry-Angabe: `self` (empfohlen, Standard) oder `er1://…`. HTTP-Registries verwenden `install`. |
| `-er1-target prod\|stage\|local` | ER1-Ziel, standardmäßig `prod`. |
| `-er1-context` | ER1-Kontext, standardmäßig `skills`. |
| `-identity` | In Ereignis und Tags eingetragene Autoren-/Registry-Identitäts-ID. **Verpflichtend.** |
| `-key` | Privater ed25519-Schlüssel als PEM PKCS#8; Standard `$SIGNING_KEY_LOCATION` oder `~/.config/m3c/skill-registry-self.key`. |
| `-manifest` | Veröffentlichungsmanifest bei `--all`; Standard `INFRA/skill-registry/self/publish-manifest.txt`. |
| `-share-room <label>` | Bundle einem gemeinsamen Lernraum nach SPEC-0096 zuordnen. Wiederholbar. |
| `-inline-max` | Obergrenze eingebetteter Base64-Daten, standardmäßig `262144`; größere Bundles benötigen Claim-Check. |
| `-no-checkpoint` | Keinen Prüfpunkt an die offene Sitzung nach SPEC-0213 anhängen. |
| `-no-runbook-publish` | Runbook des Skills nicht automatisch im THOH-Katalog registrieren (SPEC-0275). |
| `-dry-run` | Plan und gerenderten Eintragsinhalt ausgeben; weder POST noch Packen. |
| `-yes` | 🟡 Bestätigungspause für Skriptläufe überspringen. |

```bash
skillctl publish my-skill --bundle my-skill.skb --version 1.0.0
skillctl publish --attest my-skill --level green --rationale "reviewed"
skillctl publish --revoke my-skill --digest sha256:<hex> --reason superseded
```

Exit: `0` erfolgreich · `1` allgemeiner Fehler/Netzwerk/ER1 · `2` Aufruffehler.

---

### `pull`: fünfstufige Prüfung gegen `self`

```bash
skillctl pull [flags]
```

Führt die fünf Vertrauensprüfungen gegen Ihre Registry `self` durch und bereitet
bestätigte Bundles vor. `--install` schreibt sie mit Herkunftsbegleitdatei unter
`~/.claude/skills/<name>/`. Die Installation erfolgt als zweistufiger G-23-Vorgang
(`--dry-run-install` → `--confirm-install`).

| Flag | Zweck |
|------|---------|
| `-install` | Bestätigte Bundles mit Herkunftsbegleitdatei unter `~/.claude/skills/<name>/` installieren. |
| `-trust-mode` | Für `--install` erforderlich: Vertrauensmodus ausdrücklich bestätigen; schreibt `.m3c-provenance.json`. |
| `-dry-run-install` | G-23-Schritt 1: Erstellungs-/Überschreibplan und Token ausgeben; nichts schreiben. |
| `-confirm-install` | G-23-Schritt 2: `--dry-run-install-token` prüfen und schreiben. |
| `-dry-run-install-token` | Von `--dry-run-install` ausgegebenes Token; bei jedem zu überschreibenden Skill erforderlich. |
| `-allow-downgrade` | Ältere über neuere Version installieren lassen. |
| `-skill` | Nur diesen Skill-Namen auswählen. |
| `-kind skill\|agent` | Auf eine Bundle-Art beschränken (SPEC-0432). Leer ruft beide Bereiche ab; unbekannter Wert → Exit `2`. Nur von der self-Registry `er1` unterstützt. |
| `-digest` | Nur diesen exakten Bundle-Digest `sha256:<hex>` auswählen. |
| `-since` | Bestmöglich berücksichtigte Untergrenze für `occurred_at` als RFC3339. |
| `-skills-dir` | Installationsverzeichnis; Standard `~/.claude/skills`. |
| `-trust-roots` | Vertrauensanker-YAML nach SPEC-0225; Standard `~/.claude/trust-roots.yaml`. |
| `-registry self` | Registry-Angabe; hier nur `self` / `er1://…`; HTTP verwendet `install`. |
| `-er1-target prod\|stage\|local` / `-er1-context` | ER1-Ziel/Kontext; Standards `prod` / `skills`. |
| `-emit-installed` | Nach Installation `BundleInstalledEvent` per POST senden, damit die andere Maschine sie sieht. |
| `-identity` / `-key` | `[--emit-installed]` Identität und Signierschlüssel des Installationsereignisses. **Verpflichtend.** (`-identity` nur zusammen mit `--emit-installed`.) |
| `-no-checkpoint` | Nach Installation keinen Sitzungsprüfpunkt nach SPEC-0213 anhängen. |
| `-verbose` | Eine Zeile je Gate-Entscheidung ausgeben. |

```bash
skillctl pull --verbose
skillctl pull --install --trust-mode --dry-run-install
skillctl pull --install --trust-mode --confirm-install --dry-run-install-token <sig>
```

Exit: `0` alle Bundles vorbereitet · `7` NULLTREFFER: Abfrage ohne Ergebnis,
bewusst kein Erfolg (BUG-0254: Ein leerer Lauf war von einem Lauf ohne offene
Arbeit nicht unterscheidbar; ein grünes Gate ohne Prüfung erzeugt unbelegtes
Vertrauen) · `2` Aufruffehler oder verweigerte `--install`-Vorbedingung (fehlender
`--trust-mode`, fehlendes/abgelaufenes/gefälschtes G-23-Token) · `1` Bundles aus
MEHREREN Gründen übersprungen; eine Nummer kann nicht mehrere Ursachen nennen,
daher die Gate-Angabe jeder Zeile lesen · bei einem übersprungenen Gate dessen
Code: `12` Umschlag/Registry nicht vertrauenswürdig, `10` Digest, `11`
Bundle-Signatur, `13` Governance unter Minimum, `6` widerrufen. `--install`
liefert `10`, wenn `CHECKSUMS` den extrahierten Bundle-Inhalt nicht mehr
beschreibt (SPEC-0188 §7, Schritt 8). Gegen `skipExitCode` / `gateExit` in
`cmd/skillctl/pull_cmds.go` gemessen.

---

### `registry`: Registry `self` untersuchen

```bash
skillctl registry <ls|show> [flags]
```

**`registry ls`**: Bundles der Registry `self` nach Skill gruppiert auflisten.
Flags: `[--latest] [--skill <name>] [--er1-target …] [--er1-context …]`.

**`registry show`**: vollständige Ereignisfolge (Zulassung/Attestierung/Widerruf/
Installation) für einen Skill oder Digest anzeigen.
Aufruf: `registry show <name | sha256:<hex>> [--er1-target …] [--er1-context …]`.

```bash
skillctl registry ls --latest
skillctl registry show my-skill
skillctl registry show sha256:<hex>
```

---

### `drift`: lokaler Bestand gegenüber Katalog

```bash
skillctl drift [flags]
```

Vergleicht jedes lokal installierte Artefakt (Skills und Agenten, SPEC-0432) mit
dem neuesten Katalogeintrag in `self`. Je Artefakt wird eine Zeile ausgegeben:
`aktuell`, `veraltet`, `ohne Nachweis` (keine bestätigende Herkunftsbegleitdatei;
normal auf der Autorenmaschine), `fehlt lokal` oder `nicht im Katalog`.
Ein Artefakt ohne Begleitdatei wird als unbestätigt gemeldet, nie stillschweigend
als einwandfrei eingeordnet.

| Flag | Zweck |
|------|---------|
| `-kind skill\|agent` | Auf eine Art beschränken; leer vergleicht beide. |
| `-only-findings` | Nur von `aktuell` abweichende Zeilen ausgeben. |
| `-er1-target prod\|stage\|local` | ER1-Ziel, standardmäßig `prod`. |
| `-er1-context` | ER1-Kontext, standardmäßig `skills`. |

```bash
skillctl drift
skillctl drift --kind agent --only-findings
```

Exit: `0` nichts veraltet, fehlend oder unkatalogisiert · `1` mindestens eine
Zeile `veraltet` / `fehlt lokal` / `nicht im Katalog` oder Transportfehler · `2`
Aufruffehler. `ohne Nachweis` allein lässt den Lauf nicht fehlschlagen; dies
bezeichnet fehlende Bestätigung, keine Abweichung. Gegen `runDrift` in
`cmd/skillctl/drift_cmds.go` gemessen.

---

### `verify-hook`: verweigernde Claude-Code-Vertrauensprüfung

```bash
skillctl verify-hook
```

Ein `PreToolUse(Skill)`-Hook: Liest ein Hook-Ereignis von **stdin**, prüft die
Kette nach SPEC-0188 §7 und gibt eine allow/deny-Entscheidung als JSON auf stdout
aus. **Fail-closed**: Kann er das Ereignis nicht lesen oder prüfen, verweigert er.
In Claude Code als Hook konfigurieren, **nicht manuell ausführen**. Interaktiver
Aufruf erzeugt wegen unlesbarem stdin eine Verweigerung mit Exit `2`.

**Auch die Widerrufsaktualität wird verweigernd durchgesetzt (FR-0045 D4).**
Zusätzlich zur Vertrauenskette erzwingt der Hook die Aktualitätsregeln nach
SPEC-0279. Eine **Notfallsperre** oder ein für die Aktion zu alter Widerrufssnapshot
(`bundle_revocation_stale` / `agent_revocation_stale`, SPEC-0279 R3/R5) führt zur
Verweigerung. Dies ist die Laufzeitgrenze der Notabschaltung nach FR-0045:
Widerrufs-HEAD wird gegen einen fest hinterlegten Registry-Schlüssel geprüft;
manipulierter, zurückgesetzter oder gefälschter Feed wird abgelehnt.

**Der Prozess endet immer mit `2`**, sowohl bei blockierender Verweigerung als
auch wegen unlesbarem stdin; Claude Code interpretiert `2` als „Werkzeugaufruf
blockieren“. Der Grund steht stattdessen in `refusal_code`. Es gibt genau vier,
gemessen gegen `cmd/skillctl/verify_hook_cmds.go`:

| `refusal_code` | Bedeutung |
|---------------:|---------|
| `17` | Bundle widerrufen oder in einer Notfall-Sperrliste genannt. |
| `22` | Widerrufssnapshot für einen Hochrisiko-Aufruf zu alt oder signierter HEAD nicht verifizierbar. |
| `25` | `offline_unverifiable_managed`: ältere verwaltete Installation ohne Offline-Metadaten; `offline_policy` steuert den Online-Ausweichpfad anhand des Zustands. |
| `28` | `offline_locked`: managed-enterprise-Rechner ohne jede Vertrauensbasis. |

`26` gehört zu `enforce` und `27` zu `guard-path`, nicht hierher. Beide sind eigene
Gates mit derselben Konvention Exit 2 plus `refusal_code`. Andere Verweigerungen
nennen den entsprechenden Kettencode (`10`-`17`, `20`, `22`, `23`) in der Meldung.

**Netzwerkzugriff erfolgt nur in einem eng begrenzten Pfad, mit acht Sekunden
Zeitlimit pro Anfrage** (`verifyHookTimeout`, `cmd/skillctl/verify_hook_cmds.go`).
Alle Bedingungen müssen erfüllt sein: verwalteter Skill, Urteilscache ohne
Treffer, keine gespeicherten Offline-Prüfmetadaten (ältere Installation;
`skillctl install <skill>` speichert sie) und keine Unterdrückung durch das
Enterprise-Offline-Zustandsgate. Alle anderen Fälle, einschließlich sämtlicher
Erlaubnisse aus Cache oder Offline-Kette, werden ohne Registry-Rundreise
entschieden. Der schnelle Offline-Pfad gehört zu SPEC-0247 P1; das Zeitlimit
begrenzt den verbleibenden P0.1-Ausweichpfad.

`verifyHookTimeout` begrenzt jede einzelne Anfrage, nicht den gesamten Aufruf.
Es ist das `Timeout`-Feld des von `install.HTTPClientOf` erstellten `http.Client`.
Dieser Pfad stellt mindestens zwei Anfragen: `GetBundleMeta` und danach
`GetIdentity` für den Autor. Die zweite entfällt nur bei
`identity_keys_authorized: pinned` im Vertrauensanker
(`pkg/skillctl/verify/verify.go`, Zweig für fest hinterlegte Autoren).
Im schlechtesten Fall daher acht Sekunden je Anfrage einplanen, nicht insgesamt.

```json
// settings.json (excerpt): wire it as a PreToolUse(Skill) hook
{ "hooks": { "PreToolUse": [ { "matcher": "Skill", "hooks": [ { "type": "command", "command": "skillctl verify-hook" } ] } ] } }
```

Exit: `0` erlaubt · `2` jede Verweigerung einschließlich unlesbarem stdin.
Der Grund steht nach obiger Tabelle in `refusal_code`: `17`, `22`, `25` oder `28`.

---

### `gate-stats`: Gate-Entscheidungen zusammenfassen

```bash
skillctl gate-stats [--since <168h|YYYY-MM-DD>] [--json]
```

Fasst `gate-audit.jsonl` zusammen: Entscheidungen, häufigste Sperren, Cache-Trefferquote.

| Flag | Zweck |
|------|---------|
| `-since` | Nur neuere Ereignisse als diese Go-Dauer, etwa `168h`, oder dieses Datum `YYYY-MM-DD`. |
| `-json` | Zusammenfassung als stabiles JSON ausgeben. |

```bash
skillctl gate-stats --since 168h
skillctl gate-stats --since 2026-06-01 --json
```

---

### `auditlog`: Beobachtbarkeit des Audit-Subsystems (SPEC-0403 §8)

```bash
skillctl auditlog <status|test|flush> [--json]
```

Beobachtbarkeits-CLI für die Audit-Ereignisebene. Hat **einen eigenen Befehlsnamen**
und **einen eigenen Exit-Bereich `0/1`**: `0` gesund/angenommen/übertragen,
`1` ungesund/abgelehnt/Übertragungsfehler; `2` ist ein Aufruffehler. Das ist
bewusst getrennt: `skillctl audit` bewertet antivirenähnlich den **Zustand** mit
`0/2/3`. Ein Gesundheitsbefund darf nie als Zustandsbefund interpretiert werden.
`auditlog` ist als erster Eintrag im Befehlsregister nach FR-0113 vorgesehen.

| Unterbefehl | Zweck |
|------------|---------|
| `status` | Gesundheit des Subsystems melden: aktiviert, Modus, Sink-Art und -Pfad, ausstehende Outbox-/Spool-Einträge und letztes Ereignis. Exit `0` gesund / `1` ungesund. |
| `test` | EIN ausdrücklich synthetisches Ereignis `skillctl.audit.v1` durch die echte Standard-Sink senden und Annahme bestätigen. Exit `0` angenommen / `1` abgelehnt. |
| `flush` | Lokale Spool-Warteschlange in die dauerhafte Outbox übernehmen; lokaler Teil von `sync`, kein Broker-Versand. Ausstehende Einträge vorher/nachher melden. Exit `0` / `1`. |

| Flag | Zweck |
|------|---------|
| `-json` | Ergebnis als stabiles JSON ausgeben. |

Es gibt **kein Kafka**: Eine direkte Broker-Sink gehört zu FR-0112 und ist
EC-blockiert (§7.2). `status` meldet nur tatsächlich vorhandene Sink, Outbox und
Spool, niemals einen erfundenen Broker-Endpunkt. `flush` erreicht nur den lokalen
Spool (REQ-6.10b); Netzwerkexport erfolgt über das standardmäßig ausgeschaltete
`skillctl sync`. Transportfehler werden als sichtbare Ereignisse
`audit.sink.fail` / `audit.queue.flush` auf stderr ausgegeben und nicht wieder
an die ausgefallene Sink geschickt; keine rekursive Fehlerschleife (REQ-8.2).

Exit: `0` gesund/angenommen/übertragen · `1` ungesund/abgelehnt/Übertragungsfehler ·
`2` Aufruf- oder Flag-Fehler einschließlich unbekanntem Unterbefehl
(`auditlogExitUsage`, `cmd/skillctl/auditlog_cmds.go`). Nur `0/1` ist das
Gesundheitsurteil und darf nicht als Zustandsurteil von `audit` gelesen werden.
`2` ist der gewöhnliche Aufruffehler aller Befehle.

```bash
skillctl auditlog status
skillctl auditlog status --json
skillctl auditlog test
skillctl auditlog flush
```

---

### `pin`: Gate über verwaltete Einstellungen gegen Entfernen schützen (SPEC-0247 §7.3)

```bash
skillctl pin <generate|status|install> [flags]
```

Gibt die Claude-Code-Datei `managed-settings.json` aus, die das Vertrauensgate
`verify-hook` festlegt, und bereitet sie optional vor. Schon ohne `--strict`
können unprivilegierte Nutzer das Gate nicht entfernen; seine Verweigerung ist
verbindlich und eigene Betreiber-Hooks funktionieren weiter. root oder jeder
mit Schreibrecht im managed-settings-Verzeichnis kann es dennoch entfernen.

**`pin generate`** gibt das JSON aus. **`pin install`** bereitet die Datei vor
und gibt die sudo-Anleitung aus; als root schreibt `--confirm` die Datei.

Die Installation ersetzt das Ziel über eine temporäre Datei im geöffneten
Zielverzeichnis und erhält vorhandene POSIX-Zugriffsrechte. Bestehender Inhalt
wird unter einem Zeitstempel mit Zufallssuffix gesichert; Backups werden exklusiv
erzeugt. Symlinks und nicht reguläre Ziele werden abgewiesen. Das übergeordnete
Verzeichnis muss unter Administratorkontrolle bleiben; gleichzeitige Änderungen
der Richtlinie werden damit nicht koordiniert.

Beide akzeptieren:

| Flag | Zweck |
|------|---------|
| `--binary <path>` | Absoluter Pfad zu `skillctl`, standardmäßig diese Binärdatei. |
| `--strict` | `allowManagedHooksOnly: true` ergänzen: vollständige CISO-Sperre, die auch **alle anderen Nutzer-/Projekt-Hooks deaktiviert**. |
| `--harden` | Impliziert `--strict` **und** blockiert `claude --dangerously-skip-permissions`. |
| `--enterprise` | `skillctlEnterprise: true` ergänzen; aktiviert den Offline-Zustand `locked` nach R-7.2. |
| `--require-local-audit` | `skillctlRequireLocalAudit: true` ergänzen, impliziert `--enterprise`. Verknüpft das PreToolUse-Gate mit `skillctl enforce`, dem einzigen auswertenden Befehl: R-8.2, Verweigerung mit Exit 26, wenn eine Erlaubnis nicht aufgezeichnet werden kann. |
| `--state-gate-fallback` | `skillctlStateGateFallback: true` ergänzen, impliziert `--enterprise`: R-1.4 P2 hält den schnellen Pfad vollständig lokal, ohne Online-Ausweichpfad bei fehlender Verbindung. |
| `--out <file>` | Bei `generate` JSON in Datei statt stdout schreiben. |
| `--path <file>` | Zielpfad der verwalteten Einstellungen bei `install` oder Prüfpfad bei `status`. |
| `--confirm` | Nur `install`, nur als root: Datei tatsächlich schreiben. |

**`pin status`** meldet, ob das Gate festgelegt ist; akzeptiert `--path <file>` und `--json`.

Exit: `0` erfolgreich (`generate` hat ausgegeben, `status` fand festgelegtes Gate,
`install --confirm` hat als root geschrieben) · `1` jeder Fehler einschließlich
unbekanntem Unterbefehl · `2` `pin status` fand KEIN festgelegtes Gate · `3`
`pin install` als unprivilegierter Nutzer: zusammengeführte Datei vorbereitet und
sudo-Anleitung ausgegeben, nichts geschrieben. Gegen `pinExitNeedPrivMsg` in
`cmd/skillctl/pin_cmds.go` am Programm gemessen.

```bash
skillctl pin generate --harden --enterprise
skillctl pin status --json
```

---
### `guard-path`: Zugriffsschutz für Skill-Verzeichnisse

```bash
skillctl guard-path [flags]
```

Der PreToolUse-Begleiter zu `verify-hook` erkennt Zugriffe auf Skill-Verzeichnisse
und **erlaubt und protokolliert sie standardmäßig**. Verweigerung muss ausdrücklich
aktiviert werden, da sie sonst alle nicht verwalteten Skill-Verzeichnisse blockieren würde.

| Flag | Zweck |
|------|---------|
| `--deny` | Zugriffe auf Skill-Verzeichnisse ausdrücklich VERWEIGERN (Exit `2`) statt protokolliert erlauben. |
| `--explain` | Tatsächlichen Umfang und Abdeckungslücken ausgeben und beenden. Vor dem Einsatz als Schutzmaßnahme lesen. |
| `--home <dir>` | Home-Verzeichnis überschreiben, standardmäßig `$HOME`. |

```bash
skillctl guard-path --explain
```

Exit: `0` erlaubt, Standard und jeder Erlaubnisfall · `2` ausdrücklich aktiviertes
`--deny` blockiert den Zugriff oder Aufruffehler. Das signierte Guard-Ereignis
enthält `27` (`sidechannel_denied`) als Verweigerungscode; der Prozessstatus bleibt
`2`, weil nur dies den `PreToolUse`-Aufruf blockiert.

---

### `session-baseline`: informativer SessionStart-Kontext (SPEC-0317 R-7)

```bash
skillctl session-baseline [flags]
```

Gibt den benannten Offline-Zustand `online` / `degraded` / `offline` / `locked`
und den Hinweis auf Unverbindlichkeit bis zum Festlegen aus. **Liest nur und
sperrt nichts.**

| Flag | Zweck |
|------|---------|
| `--online` | Erreichbarkeit der Registry behaupten. `SessionStart` prüft das Netzwerk standardmäßig ausdrücklich **nicht**. |
| `--managed-settings <file>` | Pfad der `managed-settings.json` überschreiben; standardmäßig Plattformpfad. |
| `--trust-roots <file>` | Vertrauensanker-Pfad überschreiben; Standard `~/.claude/skill-trust-roots.yaml`. |
| `--home <dir>` | Home-Verzeichnis überschreiben. |
| `--json` | JSON ausgeben. |

Exit: `0` Zustand ausgegeben · `1` jeder Fehler EINSCHLIESSLICH Flag-Parsing.

Ein eigener Aufruffehlercode existiert hier nicht. Da der Befehl nichts sperrt,
unterscheidet er ungültige Flags nicht von anderen Fehlern. Jeder Pfad in
`cmd/skillctl/session_baseline_cmds.go` liefert einen dieser beiden Codes.

---

### `sync`: Outbox der Durchsetzungsnachweise übertragen (SPEC-0317 R-5)

```bash
skillctl sync [--once | --daemon] [flags]
```

Überträgt die gerätesignierte Outbox `audit_events` an KafShield-Ingest. Läuft
**als eigener Prozess, niemals im Hook-Pfad**, getrennt von der
Skill-Telemetrieübertragung `sync-usage`. Zeilen werden **nur** nach gültiger
signierter durable-seq-Bestätigung als synchronisiert markiert. Ein lügender oder
Antworten wiederholender Endpunkt kann lokale Nachweise daher nicht verschwinden lassen.

| Flag | Zweck |
|------|---------|
| `--once` | Ausstehende Nachweise einmal übertragen und beenden. |
| `--daemon` | Regelmäßig mit `--interval` übertragen; signalgesteuertes Herunterfahren. |
| `--interval <dur>` | Daemon-Intervall, standardmäßig `1m0s`. |
| `--batch <n>` | Höchste Zeilenanzahl pro Übertragungsbatch, standardmäßig `100`. |
| `--endpoint <url>` | HTTPS-Basis-URL des Ingest-Endpunkts. **Standard AUS**: Bis zur Einstellung bleiben Nachweise ausschließlich lokal. |
| `--backend <name>` | Audit-Export-Backend, bekannt: `er1`. **Kein Standard**: Netzwerkexport erfordert einen ausdrücklich benannten Backend-Typ (SPEC-0455 D1). Umgebung: `SKILLCTL_AUDIT_BACKEND`; das Flag hat Vorrang. |
| `--ingest-pubkey <path>` | Öffentlicher ed25519-Schlüssel als PEM SPKI zum Prüfen von durable-seq-Bestätigungen. **Erforderlich für die Markierung als synchronisiert.** |
| `--log-id <id>` | Log-ID, an die die durable-seq-Signatur gebunden ist; Standard `skillctl-local`. |
| `--insecure` | TLS-Prüfung überspringen; nur Loopback-Endpunkte. |

Netzwerkexport benötigt Backend-Name UND Endpunkt. Ein Endpunkt ohne benanntes
Backend wird ausdrücklich mit `40` (`audit_backend_config`) abgelehnt. Die ältere
reine Endpunktkonfiguration vor SPEC-0455 wird niemals stillschweigend einem
Backend zugeordnet (REQ-5.1a). Ohne beide Einstellungen bleibt `sync` wie bisher
lokal und endet mit `0`.

Für einen echten Sync ist die unabhängige `$ER1_DEVICE_TOKEN_ORIGIN`
verpflichtend. Sie muss für das gewählte Credential bereits bekannt sein,
darf keinen API-Pfad, Query oder Fragment enthalten und muss zu Schema,
kanonischem Host und effektivem Port des Endpunkts passen. Leiten Sie sie
nicht aus einem neu gewählten Endpunkt ab. Fehlende oder abweichende Pins
scheitern vor dem Lesen des Umgebungs-Bearers oder gespeicherten Tokens,
Öffnen der Outbox oder Senden von Nachweisen. Hilfe, ungültige Argumente,
Default-off und unbekannte Backend-Auswahl liegen ebenfalls vor diesen Reads.

Ein expliziter nichtleerer `$ER1_DEVICE_TOKEN` gewinnt. Ein ungültiger gewählter
Wert fällt nicht auf den Store zurück. Andernfalls liest Sync nach der Bindung
den nativen OS-Credential-Store und prüft seine gespeicherten Login-Origin-Metadaten
ohne Migration, Save oder Clear.
Dies schreibt weder Umgebungsvariablen um noch ergänzt es Aussteller-,
Audience- oder Mandantenmetadaten; das globale Autoload gespeicherter Tokens
ist deaktiviert. `attest` verwendet seine separaten
Registry-Zugangsdaten. Werte werden für diesen Sync-Aufruf festgehalten, ohne
die exportierten Ingest-Client-Felder als unveränderlich zu bezeichnen.
HTTPS bleibt auch mit `--insecure` verpflichtend. Automatisierte Storetests
verwenden In-Memory-Provider; sie belegen keine Abnahme des nativen Stores auf
Kundenbetriebssystemen.
Der zurückgezogene Datei-Fallback leitete seinen Verschlüsselungsschlüssel nur aus
nichtgeheimen Geräte-/Nutzerkennungen ab, ohne unabhängige geheime Entropie.
Ein kopierter Blob kann bei bekannten Kennungen auf einem anderen Rechner
entschlüsselt werden; behandeln Sie Kopien und Backups als credentialhaltige
Daten.

Der übergebene HTTP-Client nutzt nun die bestehende Credential-Redirectpolicy:
Origin-übergreifende 302/303 dürfen nur als GET ohne Credentials oder Body
folgen; Redirects mit erhaltenem Nachweisbody an eine fremde Origin werden
abgelehnt. Das Redirectverhalten innerhalb derselben Origin bleibt erhalten.
Signierte dauerhafte Bestätigungen bleiben eine getrennte Voraussetzung, um
Datensätze als synchronisiert zu markieren. Netzwerk-/Lesefehler zeigen auch
in gespeicherten Backoff-Einträgen eine konstante Diagnose; entfernte URLs
und Fehlertexte werden nicht übernommen. Das bestehende Verhalten bei
transienten Fehlern bleibt erhalten: `--once` kann mit `0` enden, während
Nachweise zur Wiederholung ausstehen. Dieser Exit beweist keine dauerhafte
entfernte Bestätigung.

```bash
ER1_DEVICE_TOKEN_ORIGIN=https://ingest.example.com skillctl sync --once --backend er1 --endpoint https://ingest.example.com --ingest-pubkey ingest.pub
```

Exit: `0` erfolgreich · `1` Übertragungs-/Transportfehler · `2` Aufruffehler ·
`29` Ingest lehnt Batch wegen Authentifizierung oder Validierung mit 4xx ab ·
`40` Audit-Backend-Auswahl verweigert (SPEC-0455 REQ-5.1a).

---

### `agentid`: offline überprüfbare Agentenidentität

```bash
skillctl agentid <issue|verify|show|revoke> [flags]
```

Eine **AgentID** ist ein vom Eigentümer signiertes Mandat (SPEC-0277): *Dieser
Agent darf diese Skills für diese Absichten verwenden.* Es wird **offline**
gegen fest hinterlegte Eigentümer-/Genehmigerschlüssel geprüft.

**`agentid issue`**: Mandat erstellen und vom Eigentümer signieren.

| Flag | Zweck |
|------|---------|
| `--owner <plm-id>` / `--owner-key <path>` | Eigentümeridentität und Signierschlüssel. |
| `--for-agent <ref>` | Agenteninstanz, für die das Mandat ausgestellt wird. |
| `--skills a,b` | Erlaubte Skills. |
| `--intents x,y` | Erlaubte Absichten. |
| `--data-scopes s,t` | Optional erlaubte Datenbereiche. |
| `--approver <id>` / `--approver-key <path>` | Optionaler mitzeichnender Genehmiger; erhöht die Genehmigerschwelle. |
| `--limit k=v` | Wiederholbare Berechtigungsgrenzen. |
| `--display-name N` / `--agent-id <id>` / `--trust-root URL` | Optionale Metadaten. |
| `--expires <RFC3339>` | Ablauf, etwa `2026-12-31T00:00:00Z`. |
| `--out <file>` | Mandat als JSON schreiben, etwa `agentid.json`. |

**`agentid verify`**: Mandat offline prüfen.

| Flag | Zweck |
|------|---------|
| `--bundle <agentid.json>` | Zu prüfendes Mandat. |
| `--offline` | Prüfung ohne Netzwerk. |
| `--trust-roots <file>` / `--registry <url>` | Fest hinterlegte Schlüssel / Registry-Auswahl. |
| `--revocations <file>` / `--checkpoint <file>` / `--emergency <file>` | Signierte Listen zur Aktualitätsdurchsetzung nach SPEC-0279. |
| `--json` | Ergebnis als JSON ausgeben. |

**`agentid show`**: Eigentümer, Berechtigungen, Ablauf, Fingerprints und Signaturen
anzeigen: `skillctl agentid show <agentid.json>`.

**`agentid revoke <agent-id>`**: `agent:<id>` einer signierten
Offline-Widerrufsliste hinzufügen (SPEC-0276).

| Flag | Zweck |
|------|---------|
| `--reason <text>` | Widerrufsgrund des Mandats. |
| `--registry <url>` | Registry, für die die Liste gilt. |
| `--key <path>` | Signierschlüssel der Widerrufsliste. |
| `--out <list.json>` | Ausgabepfad der signierten Liste. |
| `--epoch <n>` | Einzutragende Epoche. `0` als Standard bedeutet automatisch: vorhandene Epoche um eins erhöhen oder bei eins beginnen. Die Epoche macht Zurücksetzen der Liste erkennbar. |

```bash
skillctl agentid issue --owner id:you@m3c --owner-key mykey.priv \
  --for-agent agent-42 --skills my-skill --intents summarize --out agentid.json
skillctl agentid verify --bundle agentid.json --offline
skillctl agentid show agentid.json
skillctl agentid revoke agent-42 --reason compromised --registry https://aims.example.com/api/skills
```

Exit (`verify`): `0` erfolgreich · `11` Eigentümersignatur/nicht fest hinterlegt ·
`20` Genehmigerschwelle · `21` abgelaufen · `17` widerrufen/Notfallsperre · `12`
Registry nicht fest hinterlegt · `22` Widerruf veraltet · `1` sonstiger Fehler ·
`2` Aufruffehler.

---

### `translog`: L1-Transparenz-Log

```bash
skillctl translog <append|sth|prove|verify|consistency|witness> [flags]
```

Lokales RFC-6962-Merkle-Log (SPEC-0278, nur Standardbibliothek). L1 macht
widersprüchliche Ansichten und Zurückhalten von Einträgen **erkennbar**, nicht
unmöglich. Ereignisdaten bleiben *außerhalb des Logs*; nur der Digest des bereits
signierten Ereignisses wird angehängt. Standarddatei:
`~/.claude/skillctl/transparency-log.jsonl`; `--log` überschreibt sie,
`--log-id` ist standardmäßig `skillctl-local`.

**`translog append <type> <digest>`**: Ereignis anhängen, mit `type` aus
`admit | attest | revoke | agentid-issue | agentid-revoke`. `digest` ist
`sha256:<64 lowercase hex>` des bereits signierten Ereignisses.

| Flag | Zweck |
|------|---------|
| `--subject <s>` | Optionaler Ereignisgegenstand neben dem Digest, etwa Skill-Name oder Agenten-ID. |
| `--log` / `--log-id` | Logpfad / Log-ID überschreiben. |

**`translog sth`**: aktuellen Baumkopf anzeigen oder signieren.

| Flag | Zweck |
|------|---------|
| `-key` | Privater ed25519-Schlüssel des Logs als PEM; falls gesetzt, Kopf als STH signieren. |
| `-log` / `-log-id` | Logpfad / ID. |

**`translog prove <digest>`**: offline prüfbaren Inklusionsbeleg ausgeben.

| Flag | Zweck |
|------|---------|
| `--key <path>` | Privater ed25519-Logschlüssel als PEM zum Signieren des zum Beleg gehörenden Kopfes. **Verpflichtend.** |
| `--out <file>` | Beleg hierhin schreiben, standardmäßig stdout. |

**`translog verify`**: Offline-Inklusionsprüfung.

| Flag | Zweck |
|------|---------|
| `--receipt <file>` | Von `prove` erzeugter Inklusionsbeleg als JSON. **Verpflichtend.** |
| `--log-pubkey <path>` | Fest hinterlegter öffentlicher ed25519-Logschlüssel als PEM SPKI. **Verpflichtend**; ein nicht festgelegter Schlüssel würde nichts belegen. |

**`translog consistency`**: Append-only-Eigenschaft zwischen zwei Köpfen prüfen.

| Flag | Zweck |
|------|---------|
| `--sth1 <file>` | Älterer, kleinerer STH als JSON. **Verpflichtend.** |
| `--sth2 <file>` | Neuerer, größerer STH als JSON. **Verpflichtend.** |
| `--proof <json>` | Konsistenznachweis als JSON-Array von Hex-Hashes. **Verpflichtend.** |

**`translog witness`**: STHs verschiedener Zeugen auf widersprüchliche Ansichten prüfen.

| Flag | Zweck |
|------|---------|
| `--sths <file>` | JSON-Array der von unterschiedlichen Zeugen gesammelten STHs. **Verpflichtend.** |
| `--log-pubkey <path>` | Fest hinterlegter öffentlicher Logschlüssel, gegen den jeder STH gültig sein muss. **Verpflichtend.** |

```bash
skillctl translog append admit sha256:<hex> --subject my-skill
skillctl translog sth --key ~/.config/m3c/skill-keys/log.priv
skillctl translog prove sha256:<hex> --key ~/.config/m3c/skill-keys/log.priv --out receipt.json
skillctl translog verify --receipt receipt.json --log-pubkey log.pub
skillctl translog witness --sths sths.json --log-pubkey log.pub
```

Exit: `translog verify` → `0` erfolgreich · `23` nicht enthalten · `1` sonstiger Fehler · `2` Aufruffehler.
`translog witness` → `0` konsistent · `24` widersprüchliche Ansichten erkannt · `1` sonstiger Fehler · `2` Aufruffehler.
`translog consistency` → `0` konsistent · `25` Umschreiben eines Append-only-Logs erkannt · `1` sonstiger Fehler · `2` Aufruffehler.

---

### `session`: Sitzungszustand in ER1 (SPEC-0213)

```bash
skillctl session <open|checkpoint|close|resume|list|show> [flags]
```

Speichert die Arbeitssitzung als ER1-Eintrag und hängt Prüfpunkte an; die Sitzung
kann auf jeder Maschine fortgesetzt werden. Alle Befehle teilen einen Flag-Satz,
wobei pro Befehl nur ein Teil gilt.

Session-Operationen validieren das endgültige HTTPS-Ziel nach CLI-/Descriptor-
Overrides. Setzen Sie die unabhängig bekannte `ER1_DEVICE_TOKEN_ORIGIN` für
Bearer oder `ER1_API_KEY_ORIGIN` für einen API-Key. Ein gesetzter Pin wählt diese
Familie; alle gesetzten Pins müssen passen, bevor eine Quelle gelesen wird.
Ohne Pin wird kein Credential gelesen. Ungültige gewählte Werte lösen keinen
Fallback zwischen Familien aus. Ein nichtleerer externer Wert gewinnt innerhalb
seiner Familie; sonst nutzt Bearer den N2B-gebundenen nativen DeviceToken und
API-Key den bestehenden macOS-Keychain-Eintrag. Andere Plattformen benötigen
einen externen API-Key, wenn diese Familie gewählt wird. Dies ist weder ein
plattformübergreifender API-Key-Vault noch ein authentifizierter Aussteller-/
Mandantennachweis.

Ein privater Client hält Credentials und Ziel für alle GETs und Uploads der
Operation fest. GET kann beide unabhängig gebundenen Header senden; Upload
bevorzugt Bearer. Spätere Umgebungsänderungen ersetzen sie nicht. Redirects
tragen weder Credentials noch Anfragekörper über Origin-Grenzen und erlauben
kein HTTPS-Downgrade; ein bereinigter GET ohne Credentials kann dennoch einem
Redirect folgen. Fehlgeschlagene Lookups stoppen open/checkpoint vor jedem
Upload. Null, skalare Zeilen und unbekannte Suchantwortformen sind Fehler,
keine bestätigten leeren Trefferlisten. HTTP- und Parse-Diagnosen enthalten keine Antwortkörper; wörtlich
bekannte Credentials werden nach regulärem JSON-Decodieren erfolgreicher
Antworten abgewiesen. Dies erkennt
keine beliebigen Kodierungen.

Kontextpriorität: `--er1-context`, Descriptor `er1.context`, dann `main`.
Derselbe Wert gilt im Session-Dokument, GET und Multipart-Upload;
`ER1_CONTEXT_ID` überschreibt ihn nicht mehr. Ein erfolgreicher Upload muss eine nichtleere Dokument-ID ohne Kontrollzeichen
bestätigen. Eine fehlende Bestätigung ist ein Fehler, auch wenn der Server POST
bereits empfangen hat; sie beweist keinen Rollback. Prüfen Sie den entfernten
Zustand vor einer Wiederholung. Dies behebt die bisherige
Abweichung zwischen Descriptor-/CLI-Metadaten und Transportkontext. Groß- und
Kleinschreibung sowie Präfixe des URL-Pfads bleiben erhalten. Bestehende Einträge
ohne Login-Origin-Bindung verlangen eine erneute Anmeldung. Andere ER1-
Befehlsfamilien bleiben getrennte Prüfbereiche.


| Befehl | Zweck |
|------|---------|
| `open` | Sitzungszustandseintrag für diese Sitzung idempotent erstellen. |
| `checkpoint` | Untergeordneten Prüfpunkt anhängen; `--auto` erzeugt Git-/Todo-Snapshot. |
| `close` | Abschließenden Prüfpunkt schreiben; `--summary` unverändert oder `--distill`. |
| `list` | Sitzungszustände auflisten; `--project` / `--host` / `--open-only`. |
| `show` | Sitzungszustand nach `session_id` oder `doc_id` anzeigen. |
| `resume` | Fortsetzungshinweis für eine frühere Sitzung ausgeben. |

| Flag | Zweck |
|------|---------|
| `-session` | Sitzungs-ID `session_id` des Harness; bei checkpoint/close erforderlich. |
| `-C` | Projektkontext relativ zu diesem Verzeichnis auflösen. |
| `-project` | PLM-Projekt-ID überschreiben; standardmäßig aus `.m3c/project.yaml`. |
| `-er1-target prod\|local\|stage\|<url>` / `-er1-context` | ER1-Ziel/Kontext überschreiben. |
| `-intent` | Sitzungsabsicht; nur open. |
| `-continues <ctx>/<doc_id>` | Kette mit früherem Sitzungszustand verknüpfen; nur open. |
| `-model` | Als `opened_by` gespeicherter Agent/Modellname, standardmäßig `skillctl`. |
| `-auto` | Beim Prüfpunkt Git-Diff-/Todo-Snapshot statt Prosa erzeugen; ohne Änderungen überspringen. |
| `-note` | Notiztext des Prüfpunkts. |
| `-todos` | Text offener Aufgaben für den Prüfpunkt. |
| `-summary` | Abschlusszusammenfassung unverändert in Ihren Worten. |
| `-distill` | Abschlussprüfpunkt als `auto:generated` kennzeichnen; Agentenzusammenfassung, SPEC-0210. |
| `-host` | Nach Host filtern; list/resume. |
| `-open-only` | Bei list geschlossene Sitzungen ausschließen. |
| `-latest` | Bei resume neueste Sitzung wählen; standardmäßig true, wenn genau eine passt. |

```bash
skillctl session open --intent "port whisper"
skillctl session checkpoint --session <id> --auto
skillctl session close --session <id> --summary "shipped v0.4.0"
skillctl session list --open-only
skillctl session resume --latest
```

---

### `project`: PLM-Projektkontext (SPEC-0214)

```bash
skillctl project <show|resolve|channels|path> [-C dir] [--field name] [--kind kind]
```

Löst den PLM-Projektkontext des aktuellen Verzeichnisses aus `.m3c/project.yaml`
auf; ohne Deskriptor wird ein Verzeichnis-Slug verwendet.

| Befehl | Zweck |
|------|---------|
| `show` | Aufgelösten Kontext ausgeben: Projekt-ID, ER1-Ziel/Kontext, Deskriptorquelle. |
| `resolve` | Ein Feld ausgeben: `--field project_id\|er1-target\|er1-context\|channel:<kind>\|…`. |
| `channels` | Block `channels:` der Version 2 auflisten; `--kind` filtert. |
| `path` | Deskriptorpfad oder `(none)` ausgeben. |

```bash
skillctl project show
skillctl project resolve --field project_id
skillctl project channels --kind repo
skillctl project path
```

---

### `awareness`: Brücke zur Zulassung (SPEC-0195)

```bash
skillctl awareness <sync|verify|reset> [flags]
```

**`awareness sync`**: lokale Skills durch Scannen oder Einlesen eines gespeicherten
Scans in einer Registry zulassen. Standardmäßig Vorschau; erst `--confirm` sendet
POST. Registry-Auswahl:
`--registry` > Vertrauensanker `default_registry` > `$M3C_REGISTRY_URL`.

| Flag | Zweck |
|------|---------|
| `-confirm` | Zum tatsächlichen Registry-Schreibzugriff erforderlich; Schutz vor unbeabsichtigten Änderungen. |
| `-dry-run` | Umschlag erstellen, keinen POST senden. |
| `-source claude\|user\|plugins\|all` | Scanquelle, standardmäßig `claude`; bei `--inventory` ignoriert. |
| `-inventory <file\|->` | Scan-JSON aus FILE lesen; `-` liest stdin. |
| `-registry` | Registry-URL überschreiben. |
| `-key` | Pfad des Autorenschlüssels als PEM PKCS#8; Standard `~/.claude/skillctl-keys/author.key`. |
| `-author-identity` | Autorenidentität überschreiben. |
| `-require-intent` | Einträge ohne Absicht oder mit SPEC-0196-Platzhalter `UNKNOWN` verweigern. |
| `-default-intent yellow\|green` | Einträgen ohne Absicht oder mit UNKNOWN diese Stufe geben; leer deaktiviert. |
| `-default-attest yellow\|green\|none` | Nach Zulassung Standardattestierung anfordern, standardmäßig `none`. |
| `-session` | Sitzungs-Tag, standardmäßig `skill-awareness/<host>/<YYYY-MM-DD>`. |
| `-help-advanced` | Erweiterte Flags wie `--allow-overwrite` anzeigen. |

**`awareness verify`**: Zulassungen je Sitzung zurücklesen.
Aufruf: `skillctl awareness verify [--session TAG] [--registry URL]`.

**`awareness reset`**: auf `session_tag` begrenzte admit-from-scan-Dokumente
löschen. Destruktiv, daher **zweistufig nach G-23**: Die Vorschau erzeugt ein
kurzlebiges Token; ohne dieses wird die Löschung verweigert.

| Flag | Zweck |
|------|---------|
| `--dry-run-reset` | Schritt 1: betroffene Dokumente anzeigen und Fünf-Minuten-Token ausstellen. Löscht nichts. |
| `--dry-run-reset-token <token>` | Schritt 2: Token aus Schritt 1; zur Bestätigung der destruktiven Aktion erforderlich. |
| `--confirm-reset` | Schritt 2: zusätzlich zu `--dry-run-reset-token` erforderlich, um tatsächlich DELETE auszuführen. |

```bash
skillctl awareness sync --source claude --dry-run
skillctl awareness sync --confirm --require-intent
skillctl awareness verify --session skill-awareness/host/2026-07-02
```

---

### `intent`: Absicht eines Bundles nach SPEC-0196 deklarieren oder anzeigen

```bash
skillctl intent <declare|show> [flags]
```

**`intent declare <skill-name|@digest>`**: `intent`-Block eines bereits zugelassenen
Bundles aktualisieren und den Awareness-Platzhalter `UNKNOWN` durch eine echte
Deklaration ersetzen. `--confirm` ist für PATCH erforderlich. Typisierte
Datenbereiche werden als wiederholbare JSON-Eingaben mit `--data-scopes` angegeben.

| Flag | Zweck |
|------|---------|
| `--from-yaml <file>` | Vollständigen Block aus Absicht und `data_dependencies` aus YAML lesen statt jedes Flag einzeln setzen. |
| `--governance-intent green\|yellow\|red` | Governance-Absicht des Bundles; gegen Querregel `destructive_green` aus §3.3 geprüft. |
| `--human-review-required true\|false` | Autorenangabe: Dieser Skill benötigt zusätzlich zur Governance-Attestierung menschliche Prüfung. |
| `--subprocess <list>` | Kommagetrennte Freigabeliste für Unterprozesse, etwa `pandoc,git`. |

Exit-Codes: `0` erfolgreich · `1` allgemeiner Fehler/Netzwerk · `2` Aufruffehler ·
`18` Absicht widerspricht `data_dependencies` (SPEC-0196 §3.3).

**`intent show <skill-name|@digest> --registry URL`**: deklarierte Absicht und
`data_dependencies` ausgeben. Ein Bereich gilt nur dann als **AUTHORITATIVE**,
wenn die Autorensignatur des lokalen `.skb` gegen einen **fest hinterlegten**
Vertrauensanker bestätigt ist (`--bundle` und vollständige Prüfkette).
Bloße Digest-Übereinstimmung ergibt `UNVERIFIED`. `--json` für maschinenlesbare Ausgabe.

```bash
skillctl intent show my-skill --registry https://aims.example.com/api/skills
skillctl intent declare my-skill --data-scopes '{"id":"…","kind":"local_fs","access":"read","scope":"…","reason":"…"}' --confirm
```

---

### `propose`: Freigabereife prüfen (SPEC-0194)

```bash
skillctl propose <skill-name> [flags]
```

Führt das Freigabereife-Gate aus SPEC-0194 §6 gegen einen lokalen Skill aus und
registriert bei Erfolg einen Vorschlagseintrag. So kann der Hook nach der
Zulassung `pending → admitted` setzen.

| Flag | Zweck |
|------|---------|
| `-intent green\|yellow\|red` | Governance-Absicht des Autors. |
| `-rationale` | Bei yellow/red erforderlich. |
| `-dry-run` | Nur Gate ausführen, keinen Vorschlagseintrag per POST senden. |
| `-bug-reports-dir` | Prüfung Nr. 8 aktivieren: offener BUG-NNNN gegen diesen Skill. |
| `-last-admitted-version` | Prüfung Nr. 10 aktivieren: vorgeschlagene Version größer als letzte zugelassene. |
| `-skip-smoke` | Prüfung Nr. 9, Smoke-Test-Markierung, überspringen. |
| `-bodyscan-rationale` | 🟡 Bodyscan-Urteil in Prüfung Nr. 11 begründen; 🔴 kann nicht übergangen werden. |
| `-proposal-id` | Clientseitige Vorschlags-ID als ULID, standardmäßig lokal erzeugt. |
| `-registry` | Registry-Basis-URL, standardmäßig `http://localhost:8080/api/skills`. |
| `-bump major\|minor\|patch` | Version in `SKILL.md` automatisch erhöhen. In Version 1 **eingelesen, aber noch nicht angebunden**; ändert aktuell nichts. |

Exit: `0` Gate bestanden · `1` allgemeiner Fehler/Netzwerk · `2` Gate nicht
bestanden; mindestens eine Zeile zeigt `FAIL`. **`--dry-run` erzwingt kein `0`**:
Es verhindert nur den Vorschlags-POST; das Urteil bleibt im Exit-Code enthalten.
Dies wurde gemessen, weil die frühere Formulierung „0 gate passed (or --dry-run)“
fälschlich jedes gescheiterte Gate für Skripte als erfolgreich erscheinen ließ.

---
### `export-verification-kit`: portables Kit ohne Vertrauensvoraussetzung (SPEC-0276)

```bash
skillctl export-verification-kit --bundle <file.skb> --out <dir> [flags]
```

Erstellt ein portables Offline-Prüfkit, das Dritte ohne Netzwerk und ohne
Vertrauen in Sie prüfen können.

Der Bundle-Dateiname muss auf `.skb` enden und darf nur ASCII-Buchstaben, Ziffern,
`@`, `+`, `_`, `-` und Punkte enthalten. Führende Punkte und Windows-Gerätenamen
werden abgewiesen. Damit bleibt der Name im erzeugten Shell-Befehl sicher und
auf den unterstützten Plattformen portabel. Kit-Dateien werden exklusiv erzeugt:
Vorhandene Dateien oder Symlinks werden nicht überschrieben. Nach einem fehlgeschlagenen
Export ein frisches Ausgabeverzeichnis verwenden. Das optionale ZIP enthält nur
die erzeugten Kit-Einträge; ein vorhandenes ZIP-Ziel wird abgewiesen.

**Leicht übersehene Voraussetzung:** Grundlage ist der `BundleMeta`-Umschlag
(`<name>.skbmeta.json`) mit Autoren-, Registry- und Governance-Signaturen. Er
entsteht erst bei **Zulassung in einer Registry**. Kein Befehl erzeugt ihn lokal;
ein lediglich gepacktes und signiertes Bundle kann deshalb noch nicht als Kit
exportiert werden. Umschlag aus der zulassenden Registry abrufen oder mit `--meta`
übergeben. Offline bleibt ohne ihn nur `verify-sig` gegen den Autorenschlüssel.
Dies belegt die Urheberschaft, aber nichts über Governance, Widerruf oder
Mandantenbereich (BUG-0215).

| Flag | Zweck |
|------|---------|
| `-bundle` | Einzupackendes signiertes `.skb`. **Verpflichtend.** |
| `-out` | Zielverzeichnis des Kits. **Verpflichtend.** |
| `-meta` | BundleMeta-Umschlag als JSON; standardmäßig Begleitdatei `.skbmeta.json`. |
| `-trust-roots` | Vertrauensanker-YAML mit fest hinterlegten Schlüsseln; muss Pinned-Modus verwenden. |
| `-revocations` | Optionale signierte Widerrufsliste; vor Aufnahme gegen fest hinterlegten Schlüssel geprüft. |
| `-registry` | Registry-URL zur Auswahl bei mehreren Vertrauensankern. |
| `-zip` | Zusätzlich `<out>.zip` erzeugen. |

Exit: `0` Kit geschrieben · `1` allgemeiner Fehler · `2` Aufruffehler oder fehlendes
Pflichtflag · zusätzlich die von `verify.ExitCode` aus der Kette nach §7
zugeordneten Codes `10`-`17` und `20`; ein scheiterndes Bundle wird nicht eingepackt.

Dies ist der vollständige Bereich: 18 und 19 entstehen durch intent und awareness,
nicht durch die Kette. 22 und 23 stammen aus Aktualitäts- und
Log-Inklusionsprüfungen, die `install` und `verify` um die Kette herum durchführen,
dieser Befehl aber nicht.

```bash
skillctl export-verification-kit --bundle my-skill.skb --out ./kit --zip
```

---

### `compliance`: Offline-Nachweishilfe (SPEC-0276)

```bash
skillctl compliance report --framework <eu-ai-act|nist-ai-rmf|soc2> [--format md|json] [--out file]
```

Erzeugt eine **Offline-Nachweishilfe**, die den Vertrauenszustand installierter
Skills den Kontrollen eines Rahmenwerks zuordnet. Dies liefert *Nachweise*,
**keine Zertifizierung**.

| Flag | Zweck |
|------|---------|
| `-framework eu-ai-act\|nist-ai-rmf\|soc2` | Rahmenwerk. **Verpflichtend.** |
| `-format md\|json` | Ausgabeformat, standardmäßig `md`. |
| `-out` | In Datei statt stdout schreiben. |
| `-skills-dir` / `-home` | Skill-Verzeichnis / Home-Verzeichnis überschreiben. |
| `-offline` | Offline-Modus; Standard und einziger Modus in Version 1. |

```bash
skillctl compliance report --framework eu-ai-act --format md --out evidence.md
```

---

### `login`: ER1-Gerätekopplung (FR-0043)

```bash
skillctl login [--no-browser] [--timeout 5m] [--base-url URL]
skillctl login --status | --logout
```

Browsergestützte Gerätekopplung mit ER1. Speichert den Token ausschließlich
im nativen OS-Credential-Store, den sich `skillctl` und `m3c-tools` teilen.
Die Anmeldung validiert die gewählte HTTPS-URL vor dem Start des Rückrufs und
speichert versionierte, vom Client beobachtete Origin-Metadaten. Diese lokalen
Metadaten authentifizieren weder Aussteller noch Mandanten.

Das globale Token-Autoload ist in beiden Programmen deaktiviert. Sync verwendet
einen gespeicherten Token erst nach Abgleich des endgültigen Endpunkts mit
`ER1_DEVICE_TOKEN_ORIGIN` und anschließender Prüfung der gespeicherten Bindung.
Alte Einträge ohne Bindung, unbekannte Versionen und abweichende Origins verlangen
eine erneute Anmeldung, ohne automatische Neuzuordnung. Andere bisherige ER1-
Befehlsfamilien benötigen explizite externe Credentials, bis ihre Anfragekontexte
gebundene Speicherzugriffe unterstützen. Deren bisheriges Verhalten mit externen
Tokens ist keine allgemeine Garantie für Origin-Isolation. Separat gebundene
Registry-Zugangsdaten bleiben getrennt. Der Besitzerkontext stammt ausschließlich
aus explizitem `ER1_USER_ID` oder `ER1_CONTEXT_ID`, niemals aus einem fremden
gespeicherten Token.

Der explizite Export `m3c-tools token --print` verlangt HTTPS `ER1_API_URL`, ein
passendes unabhängiges `ER1_DEVICE_TOKEN_ORIGIN` und einen passenden, nicht
abgelaufenen gespeicherten Eintrag. Für den exportierten Token ist anschließend
der Betreiber verantwortlich. Status und Logout bleiben als Verwaltungsaktionen
verfügbar; der Speicherstatus beweist keine Freigabe eines bestimmten Ziels.

Der Gerätetokenspeicher akzeptiert `$M3C_TOKEN_STORE` ungesetzt, `keychain` oder
`auto`; `auto` bedeutet jetzt ausschließlich nativ. Der bisherige Wert `file`
und unbekannte Werte werden vor nativem Zugriff abgewiesen. Ein nicht
verfügbarer, gesperrter oder überfüllter nativer Store löst niemals eine
Dateispeicherung aus. `skillctl login` meldet Persistenzfehler mit einem
Exitcode ungleich null statt einer erfolgreichen Tokenspeicherung. Auf
Headless-Hosts kann `$ER1_DEVICE_TOKEN` für unterstützende Verbraucher extern
bereitgestellt werden; deren unabhängige Origin-Vorgaben bleiben notwendig.
Dies ist keine neue Secret-Manager-Integration.

Bestehende Dateien `~/.m3c-tools/device-token.enc` werden ignoriert: Save, Load
und `login --logout` lesen, migrieren oder löschen sie nicht. Melden Sie sich
mit funktionsfähigem nativem Store erneut an oder stellen Sie einen neuen
Token extern bereit. Entfernen Sie stillgelegte Dateien und Backup-Kopien
über Ihr kontrolliertes Credential-Bereinigungsverfahren; ihre alte, aus
Kennungen abgeleitete Verschlüsselung bietet keinen starken Offline-Schutz.
Logout löscht nur den nativen Gerätetoken, keine extern bereitgestellten
Credentials. Fehler des nativen Stores bleiben Fehler. Andere Credential-
Familien und authentifizierte Aussteller-/Mandantenprüfung sind getrennte Arbeit.
Die gemeinsame Capture-Anmeldung kann nach einem Token-Persistenzfehler
weiterhin einen erfolgreichen Context-Login melden; das beweist keinen
dauerhaft gespeicherten Token.

| Flag | Zweck |
|------|---------|
| `-base-url` | ER1-Server-Basis-URL; standardmäßig öffentliches SaaS `https://onboarding.guide` oder, falls gesetzt, `ER1_API_URL`. |
| `-no-browser` | Anmelde-URL ausgeben, ohne Browser zu öffnen; für Headless/SSH. |
| `-timeout` | Wartezeit auf Browser-Rückruf, standardmäßig `5m0s`. |
| `-status` | Anzeigen, ob ein nicht abgelaufenes Geräte-Token gespeichert ist, und beenden. |
| `-logout` | Gespeichertes Geräte-Token entfernen und beenden. |

```bash
skillctl login
skillctl login --status
skillctl login --logout
```

---

### `version` / `help`

```bash
skillctl version     # print the build version
skillctl help        # the grouped command map
```

Beide sind auch als Flags auf oberster Ebene erreichbar:

| Flag | Zweck |
|------|---------|
| `-v`, `--version` | Aliasse für `skillctl version`. |
| `-h`, `--help` | Aliasse für `skillctl help`. |

Jeder Befehl akzeptiert `--help`; einige Gruppen mit Unterbefehlen geben die
Aufrufhilfe bereits beim übergeordneten Befehl aus, etwa `skillctl agentid --help`
oder `skillctl translog`.

---

### Scanner-Familie und weitere Befehle

Diese Befehle bilden die Inventar-/Berichtsfamilie nach SPEC-0189 sowie einige
Betreiberwerkzeuge. Gemeinsames Vokabular: `--path` wählt wiederholbar Verzeichnisse,
`--recursive` durchsucht sie rekursiv, `--include-home` ergänzt `~/.claude/skills`,
`--input` liest gespeichertes Scan-JSON statt erneut zu scannen, `--out` schreibt
in eine Datei statt stdout.

> `scan`, `report`, `diff`, `seal`, `import`, `menubar`, `review`, `browse`,
> `consolidate` und `sync-usage` implementieren `-h`/`--help` **nicht**. Ohne
> Argumente aufrufen, um ihre jeweilige Aufrufhilfe zu sehen. Alle anderen
> Befehle akzeptieren `--help`.

**`scan`**: Skill-Verzeichnisse scannen und JSON-Inventar ausgeben.

| Flag | Zweck |
|------|---------|
| `--source claude\|user\|plugins\|all` | Scanquelle nach SPEC-0189, standardmäßig `claude`; bei `--input` ignoriert. |
| `--include-shadowed` | Durch höher priorisierte Kopien überschattete Skills ebenfalls melden. |
| `--with-trust` | Vertrauenszustand jedes Eintrags ergänzen. |
| `--path <dir>` | Bisherige Pfadauswahl nach SPEC-0115; wiederholbar, impliziert Quelle `projects`. |
| `--recursive` | Angegebene Pfade rekursiv durchsuchen. |
| `--include-home` | Skill-Verzeichnis im Home-Verzeichnis einschließen. |
| `--format <fmt>` / `--output <fmt>` | Ausgabeformat. |
| `--out <file>` | Inventar in Datei schreiben. |
| `--verbose` | Ausführlichen Fortschritt auf stderr ausgeben. |

`scan` kann Funde auch direkt zulassen (SPEC-0189 §13), indem es an
`awareness sync` delegiert:

| Flag | Zweck |
|------|---------|
| `--push-to-registry` | Scan-Einträge in der Registry zulassen; impliziert `--with-trust`. |
| `--dry-run-push` | Zulassungsumschlag erstellen und Plan ausgeben; kein POST. |
| `--registry <url>` | Ziel-Registry. |
| `--default-attest yellow\|green\|none` | Nach Zulassung Standardattestierung anfordern, standardmäßig `none`. |
| `--default-attest-yellow` | Kurzform für `--default-attest yellow`. |
| `--default-attest-green` | Kurzform für `--default-attest green`. |
| `--no-default-attest` | Kurzform für `--default-attest none`. |

**`scan --body [<skill-dir>]`** ist ein *anderer* Befehl mit demselben Namen:
Verhaltens-Bodyscan nach SPEC-0246 §4.5 für den Inhalt einer `SKILL.md`. Dieser
Modus wird vor jedem Inventar-Flag erkannt, sodass beide sich nicht beeinflussen.

| Flag | Zweck |
|------|---------|
| `--body` | Zum Bodyscan wechseln; zur Wahl dieses Modus **verpflichtend**. |
| `--format table\|json` / `--json` | Ausgabeformat. |

Exit: `0` grün · `1` Scan-/Ein-/Ausgabefehler · `2` jeder Befund oder Aufruffehler.

**`report`**: Scan als Bericht darstellen.

| Flag | Zweck |
|------|---------|
| `--input <scan.json>` | Darzustellender Scan; auch als bloßes Positionsargument möglich. |
| `--format html\|md` | Berichtsformat. |
| `--out <file>` | In Datei statt stdout schreiben. |

**`diff`**: zwei Scans vergleichen: `skillctl diff <scan1.json> <scan2.json>`.

| Flag | Zweck |
|------|---------|
| `--output json\|md\|html\|text` | Delta-Format. |
| `--out <file>` | In Datei statt stdout schreiben. |

**`review`**: lokale Review-Oberfläche für einen Delta-Bericht bereitstellen.

| Flag | Zweck |
|------|---------|
| `--input <delta.json>` | Zu prüfender Delta-Bericht. **Verpflichtend.** |
| `--port <n>` | Empfangsport, standardmäßig `9115`. |
| `--no-browser` | Keinen Browser öffnen. |

**`browse`**: lokalen Skill-Graphen aufbauen und interaktiven Browser unter
`http://127.0.0.1:<port>/?token=…` bereitstellen.

| Flag | Zweck |
|------|---------|
| `--input <scan.json>` | Gespeicherten Scan statt aktuellem Scan untersuchen. |
| `--port <n>` | Empfangsport, standardmäßig `9116`. |
| `--path <dir>` / `--recursive` / `--include-home` | Scanbereich ohne `--input`. |
| `--no-browser` | Keinen Browser öffnen. |

**`consolidate`**: projektübergreifend doppelte, verwaiste, abweichende Skills oder
solche ohne Frontmatter melden.

| Flag | Zweck |
|------|---------|
| `--input <scan.json>` / `--path <dir>` / `--recursive` / `--include-home` | Analysebereich. |
| `--output text\|json\|md` | Berichtsformat, standardmäßig `text`. |
| `--out <file>` | Bericht in Datei schreiben. |
| `--report-only` | Nur berichten, niemals Änderungen anbieten. |
| `--fix` | Nach dem Bericht **interaktiv** anbieten, fehlende Frontmatter-Annotationen zu ergänzen; fragt `[y/N]` und tut sonst nichts. `--report-only` hat Vorrang. |

**`seal`**: alle installierten Skills als signiertes Inventarsiegel unter
`~/.m3c-tools/skill-seals/` erfassen.

| Flag | Zweck |
|------|---------|
| `--input <scan.json>` / `--path <dir>` / `--include-home` | Zu versiegelnder Bereich. |
| `--by <who>` | Siegelnde Person; wird im Siegel aufgezeichnet. |
| `--list` | Vorhandene Siegel auflisten statt neues erstellen. |
| `--latest` | Neuestes Siegel anzeigen. |
| `--status` | Aktuelles Inventar mit neuestem Siegel vergleichen. |

**`import`**: Scan in entferntes Ziel importieren.

| Flag | Zweck |
|------|---------|
| `--target <url>` | Erforderliches Importziel samt eventuellem API-Pfadpräfix. |
| `--api-key <key>` | Expliziter API-Key; gewinnt gegenüber einem ambienten Bearer-Token. |
| `--api-key-origin <origin>` | Unabhängige API-Key-Origin; gewinnt gegenüber `$M3C_API_KEY_ORIGIN`. |
| `--allow-loopback-http` | Explizites Entwicklungs-HTTP nur für localhost oder eine numerische Loopbackadresse. |
| `--user-id <id>` | Importiertes Inventar dieser Nutzer-ID zuordnen. |
| `--input <scan.json>` / `--path <dir>` / `--recursive` / `--include-home` | Importbereich. |
| `--dry-run` | Ziel und Inventar prüfen und Vorschau ausgeben; kein Secret-, Store- oder HTTP-Zugriff. |

Ein echter Import wählt zuerst `--api-key`, andernfalls
`$ER1_DEVICE_TOKEN`, dann `$M3C_API_KEY`, dann das alte Sitzungsfeld `api_key`.
Der gewählte Bearer benötigt seine eigene `$ER1_DEVICE_TOKEN_ORIGIN`; eine
API-Key-Origin autorisiert keinen Bearer. Jeder gewählte API-Key benötigt
`--api-key-origin` oder `$M3C_API_KEY_ORIGIN`. Die Origin muss unabhängig vom
neuen Ziel bekannt sein, darf keinen API-Pfad, Query oder Fragment enthalten
und muss zu Schema, kanonischem Host und effektivem Port passen. Fehlende oder
abweichende Pins scheitern ohne Rückfall auf eine andere Quelle; der
Sitzungsschlüssel wird erst danach gelesen. Reine Kontext-Sitzungen enthalten
keinen API-Key; mehrdeutige doppelte API-Key-Felder werden abgelehnt. Die
Zuordnung ist lokale Operatorprovenienz, kein Beweis für Ausstellung oder
Mandantenberechtigung. `--user-id` bleibt Anfragezuordnung.

Der Client hält Ziel und Credential für Healthcheck und Import fest und behält
die Redirectprüfung. HTTP-Fehler zeigen nur den Status; eine erfolgreiche
Antwortnachricht mit dem gewählten Key im Klartext wird abgelehnt. Geprüft wird
die angezeigte Nachricht, nicht beliebige Credentials oder weitere Kodierungen.
Import lädt keine nativen Gerätetoken-Stores; andere Clients bleiben getrennte
Prüfbereiche.

**`menubar`**: macOS-Menüleistenmonitor für Skills starten; interaktiv und dauerhaft laufend.

| Flag | Zweck |
|------|---------|
| `--path <dir>` | Überwachtes Verzeichnis, wiederholbar; standardmäßig aktuelles Verzeichnis. |
| `--interval <dur>` | Neues Scanintervall als Go-Dauer, standardmäßig `30m0s`. |
| `--include-home` | Home-Skill-Verzeichnis ebenfalls überwachen. |

**`sync-usage`**: lokale Skill-Nutzungszähler mit ER1 synchronisieren. Zielpriorität:
`--target <url>`, `$M3C_API_URL`, dann `https://onboarding.guide`. Schlüsselpriorität:
`--api-key <key>`, `$M3C_API_KEY`, dann das alte Sitzungsfeld `api_key` in
`~/.m3c-tools/er1_session.json`. Eine reine Kontext-Sitzung enthält keinen API-Key.

Vor Schlüsselabfrage und Datenbankzugriff muss die unabhängig bekannte Herkunft
über `--api-key-origin <origin>` oder `$M3C_API_KEY_ORIGIN` angegeben werden; das
Flag gewinnt. Eine Origin enthält Schema, Host und effektiven Port, keinen
API-Pfad, Query oder Fragment. Den Wert nicht aus einem neu konfigurierten Ziel
ableiten: Er ordnet einen bestehenden Schlüssel bewusst seinem bekannten Server
zu und beweist weder serverseitige Ausstellung noch Mandantenberechtigung.
Fehlende oder abweichende Origins scheitern ohne Anfrage; alte Sitzungen werden
nicht automatisch neu zugeordnet. API-Pfadpräfixe im Ziel bleiben erhalten.
HTTPS ist Standard. `--allow-loopback-http` erlaubt ausdrücklich lokales
Entwicklungs-HTTP nur für localhost oder eine numerische Loopbackadresse; die
Origin muss weiterhin passen. Fehlgeschlagene Requests erzeugen einen Exitcode
ungleich null; es gibt keine automatische Wiederholung.

Der MCP-Server verlangt separat `$M3C_API_KEY_ORIGIN`, bevor er
`$M3C_API_KEY` oder den alten Sitzungsschlüssel liest. Sein Ziel ist
`$M3C_API_URL` oder `https://onboarding.guide`; nur
`$M3C_ALLOW_LOOPBACK_HTTP=1` aktiviert Loopback-HTTP. Beim Kopieren oder Starten
des Servers muss `api_connection.py` neben `mcp-skill-server/server.py` bleiben.
Ungültige API-Konfiguration lässt lokale MCP-Tools verfügbar und blockiert
standardmäßige oder credential-tragende API-Anfragen mit einer Diagnose. Eine
explizite HTTPS-`registry_url` bei `skill_data_source_query` erlaubt weiterhin
einen anonymen GET ohne lokale Credentials; Transport- und Redirectprüfungen
bleiben verbindlich. Die lokale Origin-Zuordnung
beweist weder Ausstellung noch Mandantenberechtigung. Eine reine
Kontext-Sitzung wird nicht dadurch repariert, dass man einen API-Key aus dem
Gerätelogin annimmt. Der eigenständige Usage-Hook ist nicht an
diesen MCP-Bootstrap angeschlossen.

Der eigenständige PostToolUse-Usage-Hook hat einen eigenen Bootstrap mit
demselben kanonischen `api_connection.py`. Kopieren Sie vom Repository-Stamm
beide Dateien in ein eigenes Verzeichnis, bevor Sie Ihren Client zum Aufruf
des Hooks konfigurieren:

```bash
mkdir -p "$HOME/.claude/hooks/m3c-skill-usage"
cp scripts/skill-usage-hook.py mcp-skill-server/api_connection.py "$HOME/.claude/hooks/m3c-skill-usage/"
python3 "$HOME/.claude/hooks/m3c-skill-usage/skill-usage-hook.py"
```

Die Übertragung benötigt Python 3.10 oder neuer für den gemeinsamen Helper.
Der Befehl liest ein Hook-Ereignis als JSON von stdin. Dies ist ein Beispiel für
manuelle Einrichtung, keine automatische Installation oder Hook-Registrierung.
Der Loader akzeptiert nur `api_connection.py` neben dem installierten Hook.
Der Quell-Hook ohne diese Nachbardatei blockiert die Übertragung; er sucht
weder in CWD noch in `PYTHONPATH` oder einem Repository-Fallback. Eine lokale
Aufzeichnung wird weiterhin versucht.

Der Hook verlangt die unabhängige `$M3C_API_KEY_ORIGIN`, bevor er
`$M3C_API_KEY` oder ein strikt geprüftes altes Sitzungsfeld `api_key` liest.
Der Umgebungs-Key hat Vorrang; ungültige gewählte Konfiguration fällt nicht
auf eine andere Quelle zurück. Ziel ist `$M3C_API_URL` oder
`https://onboarding.guide`. Nur `$M3C_ALLOW_LOOPBACK_HTTP=1` erlaubt HTTP für
localhost oder numerische Loopbackadressen. Jeder Redirect wird abgelehnt,
auch innerhalb derselben Origin. Für diesen Hook und MCP-API-Anfragen umgeht
explizites Loopback-HTTP ambiente HTTP-Proxys; das HTTPS-Proxyverhalten bleibt
unverändert. Fehlerdiagnosen enthalten weder Key noch
entfernten Antwortbody. Die lokale Quellenzuordnung beweist keine Ausstellung
oder Mandantenberechtigung.

Zuerst wird die Übertragung versucht, danach eine lokale SQLite-Aufzeichnung
nach bestem Bemühen, einschließlich eines unsynchronisierten Datensatzes nach
einer verweigerten Anfrage. Es gibt weder eine harte Zwei-Sekunden- oder
Gesamtprozessfrist noch garantierten Exit null bei beliebigen Eingabe- oder
Dateisystemfehlern, Queue-Dauerhaftigkeit oder garantierte Speicherung. Der
Request-Timeout beträgt drei Sekunden pro Operation, kein Gesamtbudget für
den Hook; stdin, DNS und SQLite bleiben getrennte Zuverlässigkeitsgrenzen.
Dieser Hook ist von der Trust-Durchsetzung getrennt.

**`runbook publish <runbook.html>`**: Onboarding-Runbook im THOH-Katalog
veröffentlichen (SPEC-0272/0275).

| Flag | Zweck |
|------|---------|
| `--tag <tag>` | Release-Tag des Runbooks, etwa `skillctl/v0.2.11-rc3`; Version ist das letzte Pfadsegment. **Verpflichtend.** |
| `--base <url>` | THOH-Katalog-Basis-URL, standardmäßig `https://onboarding.guide`. |
| `--id <id>` | Runbook-ID im Katalog. |
| `--title <s>` | Katalogtitel. |
| `--purpose <s>` | Einzeiliger Zweck. |
| `--goal <s>` | Abschlussziel. |
| `--dry-run` | Plan und Deskriptor ausgeben; kein POST. |
| `--yes` | 🟡 Bestätigungspause für Skriptläufe überspringen. |

**`room <share|unshare> [<skill>]`**: Skill einem gemeinsamen Lernraum nach
SPEC-0096 zuordnen oder daraus entfernen.

| Flag | Zweck |
|------|---------|
| `--room <label>` | Raumbezeichnung für Zuordnung oder Entfernung, etwa `aims-basics`. **Verpflichtend.** |
| `--skill <name>` | Zu- oder abzuordnender Skill; alternativ als Positionsargument. |
| `--digest sha256:<hex>` | Nur Bundle mit diesem Digest zuordnen. |
| `--all` | Alle Einträge `m3c-skill-bundle` im Kontext zuordnen. |
| `--er1-context <ctx>` | ER1-Kontext der Bundles, standardmäßig `skills`. |
| `--er1-target prod\|stage\|local` | ER1-Ziel, standardmäßig `prod`. |
| `--registry <spec>` | Registry-Angabe; hier nur `self` / `er1://…`. |
| `--dry-run` | Geplante Änderungen anzeigen; kein POST. |
| `--yes` | Bestätigungspause überspringen. |

---
## Rollen und Arbeitsabläufe

Skill-Governance trennt Verantwortlichkeiten: Keine einzelne Rolle darf einen
Skill zugleich erstellen und freigeben. Jede folgende Rolle beschreibt ihren
Verantwortungsbereich und die tatsächlich verfügbaren `skillctl`-Befehle.
HTTP-Registry und ER1 `self` werden unter
[Vertrauensanker und Registries](manual-skillctl.md#trust-roots--registries-which-file-when)
unterschieden; rollenübergreifende [Exit-Codes](manual-skillctl.md#exit-codes)
stehen im gleichnamigen Abschnitt.

### Autor / Skill-Verantwortlicher

Sie schreiben den Skill und signieren ihn zuerst. Ihr eigenes Governance-Urteil
dürfen Sie nicht selbst bestätigen. Der private Schlüssel bleibt lokal;
ausschließlich die `.pub`-Datei verlässt Ihren Rechner.

```bash
skillctl keygen --out ~/.config/m3c/skill-keys/author            # -> author.priv + author.pub
skillctl pack --skill ~/.claude/skills/my-skill -o my-skill.skb \
  --name my-skill --version 1.0.0 --summary "…" \
  --data-scopes '{"id":"ds:fs/cwd","kind":"local_fs","access":"write","scope":"<cwd>/out/**","reason":"…"}'
skillctl sign --key ~/.config/m3c/skill-keys/author.priv my-skill.skb
skillctl verify-sig --pubkey ~/.config/m3c/skill-keys/author.pub my-skill.skb   # offline self-check
```

Sie dürfen Ihren eigenen Skill **nicht** attestieren; Reviewer≠Autor wird
durchgesetzt (SPEC-0246). `--author-intent` ist nur ein Hinweis; importierte
Bundles sind höchstens yellow.

### Reviewer

Sie verantworten das verbindliche Governance-Urteil. Bundle lesen,
Autorensignatur offline prüfen und eine signierte Attestierung für den Digest
unter einer vom Autor *verschiedenen* Identität veröffentlichen.

```bash
skillctl verify --json --bundle my-skill.skb --trust-roots ./roots.yaml   # inspect offline, no install
skillctl attest sha256:<hex> --level green \
  --rationale "activation gate passed; intent matches data-scopes" \
  --reviewer-id id:reviewer@m3c --author-id id:author@m3c \
  --key ~/.config/m3c/skill-keys/reviewer.priv \
  --registry https://aims.example.com/api/skills
skillctl attest sha256:<hex> --level red --rationale "…" --reviewer-id id:reviewer@m3c --key …   # demote / retract
```

`--author-id` aktiviert die Offline-Prüfung Reviewer≠Autor. Die neueste
qualifizierte Attestierung gilt; erneutes Attestieren mit `red` nimmt ein Urteil zurück.

### Registry-Betreiber

Sie verantworten Registry-Signierschlüssel und Vertrauensverteilung. Im
ER1-Modell `self` *sind Sie selbst* die Registry und lassen Bundles zu und
signieren sie. Im HTTP-Modell betreiben Sie den Server, verteilen seinen
öffentlichen Schlüssel, registrieren Autorenidentitäten und steuern den
Widerrufsfeed.

```bash
# ER1 self: admit a bundle into your own context
skillctl publish my-skill --bundle my-skill.skb --version 1.0.0 \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-registry-self.priv --identity id:op@m3c
skillctl registry ls                                             # inspect the self registry
skillctl revoke sha256:<hex> --reason key_compromise --registry https://aims.example.com/api/skills
skillctl revoke feed --refresh --registry https://aims.example.com/api/skills   # roll the signed kill-switch HEAD
```

`--er1-context skills` erhält automatisch das Präfix `<your-sub>___skills`.
Veröffentlichung ist **nur** im eigenen Kontext möglich; sonst 403 / BUG-0165.
Eine *Autorenidentität* in einer HTTP-Registry zu registrieren ist eine
serverseitige Verwaltungsaufgabe, kein `skillctl`-Befehl; siehe
[Mandantenbetrieb](manual-skillctl.md#tenant-operations).

### Mandantenadministrator

Sie verantworten den Vertrauenszustand der Flotte: fest hinterlegte
Registry-Schlüssel, Mindeststufe `governance_minimum` und Mandantenbereich.
Dies steht in der von Ihnen verteilten Vertrauensanker-Datei.

```bash
# HTTP fleet: pin the registry the whole tenant trusts (writes ~/.claude/skill-trust-roots.yaml)
skillctl trust add --registry https://aims.example.com/api/skills --pubkey registry.pub --id aims-prod
skillctl trust list
skillctl install my-skill@1.0.0 --tenant kup-berlin              # installs respect tenant scope + floor
```

`governance_minimum` in der verteilten Datei setzen, standardmäßig green.
Eine Mandantensperre in der CISO-Konsole erscheint beim Consumer als Exit `16`.

### CISO (Sicherheitsverantwortlicher des Mandanten)

Sie genehmigen Ausführungen im Mandanten und greifen bei bösartigem Verhalten
ein. Auf `skillctl`-Seite stehen Widerruf, Notabschaltungsfeed, Audit und
Herabstufung zur Verfügung.

```bash
skillctl revoke feed --status --registry https://aims.example.com/api/skills   # inspect the signed revocation HEAD
skillctl revoke sha256:<hex> --reason governance_retraction --actor-identity governance_reviewer --key reviewer.priv
skillctl audit --format json                                     # fleet inventory verdicts
```

Ein widerrufener Digest scheitert bei install/verify mit `17`; ein veralteter
Widerrufssnapshot führt **verweigernd** zu `22`.

### Endnutzer / Consumer

Sie legen Vertrauensanker einmal fest, installieren geprüfte Skills und lassen
das Laufzeitgate die Kette bei jedem Aufruf durchsetzen. Sie veröffentlichen nicht.

```bash
# HTTP path: pin, install, verify
skillctl trust add --registry https://aims.example.com/api/skills --pubkey registry.pub --id aims-prod
skillctl install didactic-session@1.0.0 --tenant kup-berlin
skillctl verify didactic-session

# ER1 self path: hand-written ~/.claude/trust-roots.yaml (fingerprint checked out-of-band), then pull
skillctl pull --registry self --er1-target prod --er1-context <publisher-sub>___skills \
  --install --trust-mode --dry-run-install                       # G-23 step 1 (plan + token)
skillctl audit                                                   # OK | UNVERIFIED | BROKEN | BELOW_MIN
```

Binden Sie das verweigernde Gate ein, damit nichts ungeprüft läuft. Wenn es nicht
prüfen kann, verweigert es:

```json
{ "hooks": { "PreToolUse": [ { "matcher": "Skill",
  "hooks": [ { "type": "command", "command": "skillctl verify-hook" } ] } ] } }
```

Installierte Skills unter `~/.claude/skills/` nicht manuell ändern;
`skillctl audit` meldet diese Drift als `BROKEN`. Der Ablauf mit Autor, Reviewer
und Consumer steht im **[Tutorial: der erste signierte Skill](../nutzer/tutorial-szenario-02-erster-signierter-skill.de.md)**.

---

## Mandantenbetrieb

Betreiberverfahren mit ausdrücklicher Zuordnung zur **HTTP-Registry `/api/skills`**
oder **ER1-Registry `self`**. Beide verwenden unterschiedliche Vertrauensanker-Dateien;
siehe [Vertrauensanker und Registries](manual-skillctl.md#trust-roots--registries-which-file-when).

### Mandanten bereitstellen

**ER1 `self` (persönlich / kleines Team).** Keine Infrastruktur aufzubauen:
Der Mandant ist der Kontext `<sub>___skills` Ihrer ER1-Anmeldung.
Registry-Schlüssel erzeugen, im eigenen Kontext veröffentlichen und den
Fingerprint des öffentlichen Schlüssels über unabhängigen Kanal verteilen.

```bash
skillctl keygen --out ~/.config/m3c/skill-registry-self          # -> .priv + .pub
skillctl publish my-skill --bundle my-skill.skb --version 1.0.0 \
  --registry self --er1-target prod --er1-context skills \
  --key ~/.config/m3c/skill-registry-self.priv --identity id:op@m3c
# consumers hand-write ~/.claude/trust-roots.yaml (registry: self, pubkey_b64, fingerprint,
# governance_minimum) and pull from <your-sub>___skills: NOT `trust add`.
```

**HTTP-Registry `/api/skills` (Flotte / regulierter Einsatz).** Die Serverseite
mit Bucket, Namensraum und Registry-Schlüssel je Mandant wird durch die
aims-core-Infrastruktur bereitgestellt, *nicht* durch `skillctl`. Danach legt
jede Consumer-Maschine den Schlüssel fest und installiert im Mandantenbereich:

```bash
skillctl trust add --registry https://aims.example.com/api/skills --pubkey registry.pub --id aims-prod
skillctl install my-skill@1.0.0 --tenant <tenant-id>
```

### Registry-Schlüssel rotieren (überlappender Veröffentlichungszeitraum)

Schlüssel niemals abrupt austauschen. In einem **Überlappungszeitraum** beide
Schlüssel akzeptieren, mit dem neuen erneut signieren und danach den alten entfernen.

**HTTP-Registry:** `skill-trust-roots.yaml` unterstützt mehrere Schlüssel je
Registry. Den neuen während des Übergangs neben dem alten fest hinterlegen:

```bash
skillctl keygen --out ~/.config/m3c/skill-registry-v2                       # 1) new keypair
skillctl trust add --registry https://aims.example.com/api/skills \
  --pubkey ~/.config/m3c/skill-registry-v2.pub --id aims-prod-v2            # 2) pin new (old still pinned)
# 3) re-admit / re-sign current bundles under the new key during the window
skillctl trust remove --registry https://aims.example.com/api/skills        # 4) after cutover, re-pin new-only
```

**ER1 `self`:** Die flache `~/.claude/trust-roots.yaml` legt einen einzelnen
`pubkey_b64` fest. Während des Übergangs aktuelle Bundles mit dem v2-Schlüssel
erneut veröffentlichen. Vor Stilllegung von v1 müssen alle Consumer ihre
`pubkey_b64` / `fingerprint` gegen die über unabhängigen Kanal übertragenen Werte
austauschen. Attestierungen binden den `bundle_digest`, nicht den Signierschlüssel,
und überstehen eine Rotation deshalb üblicherweise.

### Autorenidentität registrieren

**ER1 `self`:** Die Identität besteht aus der in Ereignisse eingetragenen
`id:you@m3c` und dem zugehörigen Schlüsselpaar; kein Self-Service-Endpunkt.
Schlüsselpaar erzeugen, bei publish `--identity` und bei `sign` `--identity-id`
setzen und den `.pub`-Fingerprint über unabhängigen Kanal an Consumer geben.

**HTTP-Registry:** Den öffentlichen Autorenschlüssel zu registrieren ist eine
**serverseitige Verwaltungsaufgabe** der aims-core-Registry:
`POST /api/skills/identities` mit Betreiber-Bearer-Token, kein `skillctl`-Befehl.
Der Autor übermittelt seine `.pub`, der Betreiber registriert sie. `verify` /
`install` prüfen die Autorensignatur dagegen; bei Abweichung Exit `11`.

---

## `token`: Zugangsdatenablage für Registries

Speichert ein Registry-Token im geschützten Plattformspeicher, zeigt vorhandene
Einrichtungen und entfernt Tokens. Es ist die Schreibseite der
Zugangsdatenauflösung, aus der `pull`, `verify`, `install` und `attest` bereits lesen.

**Das Secret wird von STDIN gelesen, niemals aus einem Argument.** Argumente
sind während des Aufrufs über `ps` für alle Prozesse auf dem Rechner sichtbar
und landen bei manuellem Aufruf in der Shell-Historie.

```bash
skillctl token set --backend gitlab --host git.example.de --read-only
# paste the token, then Ctrl-D. Or: echo "$TOK" | skillctl token set …
```

| Flag | Bedeutung |
|------|---------|
| `--backend <name>` | Zugangsdatenfamilie: `gitlab`, `github` oder `registry` für HTTP-Registry. Bei `set` und `rm` **verpflichtend**. |
| `--host <host>` | Registry-Host, etwa `git.example.de`. **Verpflichtend.** Zugangsdaten werden je Host gespeichert; ein Rechner kann Tokens mehrerer Instanzen halten. |
| `--read-only` | **Leseberechtigung** statt Schreibberechtigung speichern. Pull bevorzugt Lesezugang und fällt nur auf Schreibzugang zurück; sind beide eingerichtet, wird für einen Lesevorgang nie ein Schreib-Token übertragen. |

`token list --host <host>` zeigt je Backend und Berechtigungsstufe die
**Herkunft** eines Tokens, niemals seinen Wert. Besonders relevant ist die
Quellspalte: Eine Umgebungsvariable hat Vorrang vor dem geschützten Speicher.
Ein veralteter exportierter Wert kann daher einen Fehler erklären, den das
gespeicherte Token nicht verursacht hätte.

`token rm` entfernt die lokale Kopie. Das ist **Hygiene, kein Widerruf**:
Das Token bleibt beim Aussteller gültig, bis es dort widerrufen wird.
Nur dieser Schritt stoppt es tatsächlich.

| Plattform | Geschützter Speicher |
|---|---|
| macOS | Keychain (`security`), ein generic-password-Eintrag je Dienst und Host |
| Windows | DPAPI; an das Nutzerkonto gebundener verschlüsselter Inhalt unter `%LOCALAPPDATA%\m3c\artifactauth` |
| Linux | Hier keiner. `set` verweigert und nennt die passende Umgebungsvariable, statt das Token ungeschützt zu speichern. |

Den gesamten Ablauf einschließlich benötigtem GitLab-Token und Begründung,
warum ein Schreib-Token dem Projekt statt einer Person gehört, beschreibt die
[Ops-Routine: Zugangstoken](../betrieb/ops-registry-tokens.de.md).

---

## Dateien und Speicherorte

| Pfad | Inhalt |
|------|----------|
| `~/.claude/skill-trust-roots.yaml` | Fest hinterlegte öffentliche **HTTP-Registry-Schlüssel**, verwaltet durch `trust`. Gelesen von `install` / `verify` / `audit`. |
| `~/.claude/trust-roots.yaml` | Vertrauensanker der **ER1-Registry `self`**, flach als `registry: self` und `pubkey_b64`; manuell erstellt oder über unabhängigen Kanal übertragen. Gelesen von `pull`; siehe [Vertrauensanker und Registries](manual-skillctl.md#trust-roots--registries-which-file-when). |
| `~/.claude/skills/<name>/` | Installierte Skills aus `install` und `pull --install`; atomare Installation. |
| `<stem>.priv` (Modus `0600`) / `<stem>.pub` (Modus `0644`) | Mit `keygen` erzeugtes ed25519-Schlüsselpaar, PEM PKCS#8 / SPKI. |
| `<bundle>.<digest_hex>.author.sig` | Separate Autorensignatur aus `sign`; 64 Rohbytes, Modus `0644`. |
| `~/.claude/skillctl/transparency-log.jsonl` | Standard-L1-Transparenz-Log für `translog`; `--log` überschreibt den Pfad. |
| `gate-audit.jsonl` | Append-only-Audit-Log der `verify-hook`-Entscheidungen; mit `gate-stats` zusammengefasst. |
| `~/.m3c-tools/skill-seals/` | Von `seal` erzeugte Inventarsiegel. |
| `.m3c/project.yaml` | PLM-Projektdeskriptor nach SPEC-0214, aufgelöst von `project`, `publish` und `session`. |
| `~/.config/m3c/skill-registry-self.key` | Standard-Signierschlüssel der Registry `self` für `publish` / `pull`; alternativ `$SIGNING_KEY_LOCATION`. |

ER1-Zugangsdaten werden je Befehlsfamilie aufgelöst. Session verwendet die oben
beschriebenen unabhängigen Pins und gebundenen Snapshots; andere Registry-
Befehle besitzen weiterhin gesonderte Legacy-Pfade. Es gibt keine gemeinsame
zugesicherte Keychain-/Secret-Manager-/Umgebungskette für alle Befehle.

---

## Fehlerbehebung

| Symptom | Ursache | Abhilfe |
|---------|-------|-----|
| `skillctl version` zeigt `dev` | Veraltete Binärdatei früher in `PATH`, etwa `~/go/bin/skillctl` vor `~/.local/bin/skillctl` | `which -a skillctl`; alte Kopie entfernen oder neu bauen |
| `403 not authorized for this context` bei `publish` | Zielkontext hat eine andere `<sub>` als die Anmeldung (BUG-0165) | Nur im eigenen `<sub>___skills` veröffentlichen |
| `pull` lehnt Vertrauensanker-Datei ab | `skill-trust-roots.yaml` des gehosteten Modells für `self` verwendet | `~/.claude/trust-roots.yaml` verwenden; siehe [Vertrauensanker und Registries](manual-skillctl.md#trust-roots--registries-which-file-when) |
| `exit 12` (`registry_not_trusted`) | Registry-Schlüssel nicht fest hinterlegt | HTTP: `trust add`; self: `trust-roots.yaml` korrigieren |
| `exit 13` (`governance_below_min`) | Keine Attestierung erfüllt die Mindeststufe | Grüne Attestierung veröffentlichen oder Mindeststufe bewusst absenken |

---

## Siehe auch

- **[Schnellstart: skillctl](../nutzer/quickstart-skillctl.de.md)**: regulärer Ablauf in fünf Minuten.
- **[Tutorial: der erste signierte Skill](../nutzer/tutorial-szenario-02-erster-signierter-skill.de.md)**: getrennte Rollen für Autor, Reviewer und Consumer.
- **[Schnellstart: Offline-Demo](../nutzer/quickstart-skillctl-demo.de.md)**: Kata-Anleitung für `skillctl-demo`, für CISO und Messestand.
- **[Handbuch: m3c-tools](manual-m3c-tools.de.md)**: gemeinsam mit `skillctl` ausgelieferte Werkzeuge zur Erinnerungserfassung.
