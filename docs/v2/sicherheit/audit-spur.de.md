# Runbook: die Audit-Spur, drei Traeger, drei Fragen

Wer die Audit-Spur von skillctl lesen will, steht vor drei Verben, die
aehnlich klingen und drei verschiedene Fragen beantworten. Diese Seite
konsolidiert sie. Grundlage: die drei Abschnitte im
[Manual: skillctl](../referenz/manual-skillctl.md) (`audit`, `auditlog`,
`translog`) und der Code (`pkg/skillctl/audit/audit.go`,
`cmd/skillctl/auditlog_cmds.go`, SPEC-0278), gelesen am 2026-09-16.

Zielgruppe: Sicherheit / CISO und Betrieb. Der Einstieg in die ganze
Sicherheitssicht ist der [Ueberblick](ueberblick.de.md); die Zeitleiste des
Registrys (admit, attest, revoke, install) liest das
[Incident-Runbook, Abschnitt 1](../betrieb/ops-incident-response.de.md).

Rolle: Sicherheit, Betrieb · Sprache: DE · Stand: 2026-09-16

## Die Grundregel in einem Satz

**Drei Traeger, drei getrennte Exit-Raeume, und keiner darf als der andere
gelesen werden:** `audit` urteilt ueber den Bestand (Posture), `auditlog`
ueber die Gesundheit des Audit-Subsystems, `translog` ueber die
Unveraenderlichkeit der Ereignis-Historie. Die Trennung ist Absicht: ein
Gesundheitsbefund, der als Posture-Befund gelesen wird, ist ein falscher
Alarm oder eine falsche Entwarnung (Manual, Abschnitt `auditlog`).

| Traeger | Frage | Exit-Raum |
|---|---|---|
| `skillctl audit` | Was liegt auf dieser Maschine, und ist es in Ordnung? | `0` alles OK · `2` UNVERIFIED/BELOW_MIN oder Verweigerung/Usage · `3` BROKEN · `1` interner Fehler |
| `skillctl auditlog` | Funktioniert die Audit-Ereignisschicht selbst? | `0` gesund/angenommen/geleert · `1` ungesund/abgelehnt/Fehler · `2` Usage |
| `skillctl translog` | Ist die Historie unveraendert und vollstaendig? | `verify`: `0`/`23` not-included · `witness`: `0`/`24` split-view · `consistency`: `0`/`25` rewrite · je `1` sonst, `2` Usage |

## Traeger 1: `skillctl audit`, das Urteil je Skill

Druckt je Skill ein Verdikt `OK | UNVERIFIED | BROKEN | BELOW_MIN`. Nur
`0/2/3` sind das Posture-Verdikt (`exitCodeFor`,
`pkg/skillctl/audit/audit.go`); `1` ist der gewoehnliche interne Fehlercode.

Aufraeumen ist eine destruktive Operation und laeuft als G-23-Zweischritt,
ohne `--force`:

```bash
skillctl audit --cleanup --dry-run-cleanup                               # Schritt 1: Plan + signiertes Token
skillctl audit --cleanup --confirm-delete --dry-run-cleanup-token <sig>  # Schritt 2: Re-Check + Loeschen
```

Schritt 1 loescht nichts und druckt ein signiertes Token (HMAC ueber
Hostname, sortierte betroffene Pfade, Ausstellungszeit, 5 Minuten gueltig).
Schritt 2 berechnet die betroffene Menge NEU und prueft das Token dagegen:
bei Drift, Ablauf oder Manipulation verweigert er mit Exit `2` und loescht
nichts. Eine destruktive Operation, die ihrem genehmigten Plan nicht mehr
entspricht, laeuft schlicht nicht (Manual, "The G-23 two-step contract").

## Traeger 2: `skillctl auditlog`, die Gesundheit der Ereignisschicht

Die Observability-CLI der Audit-Ereignisschicht (SPEC-0403 §8), mit eigenem
Verb-Stamm und eigenem Exit-Raum `0/1` (`2` Usage, `auditlogExitUsage` in
`cmd/skillctl/auditlog_cmds.go`):

| Subkommando | Zweck |
|---|---|
| `status` | Gesundheit: enabled, Modus, Sink-Typ und -Pfad, Outbox- und Spool-Rueckstand, letztes Ereignis |
| `test` | EIN klar synthetisches `skillctl.audit.v1`-Ereignis durch den echten Sink, Annahme bestaetigt |
| `flush` | Lokalen Spool in die dauerhafte Outbox ueberfuehren; nur die lokale Haelfte, kein Broker-Egress |

Zwei Grenzen, beide dokumentiert und im Code verankert: **es gibt kein
Kafka** (ein direkter Broker-Sink ist FR-0112 und EC-blockiert, `status`
erfindet keinen Endpunkt), und Netz-Egress ist ausschliesslich
`skillctl sync` (default-OFF). Ein Transportfehler erscheint als
beobachtbares Ereignis auf stderr und wird nie durch den Sink gemeldet, der
gerade versagt hat (keine rekursive Fehlerschleife, REQ-8.2).

## Traeger 3: `skillctl translog`, das L1-Transparenz-Log

Ein lokales RFC-6962-Merkle-Log (SPEC-0278, nur Stdlib). L1 macht
Equivocation und Zurueckhalten **erkennbar**, nicht unmoeglich. Die
Ereignisdaten bleiben dem Log fern; angehaengt wird nur der Digest des
bereits signierten Ereignisses
(`sha256:<64 hex>`, Typen `admit | attest | revoke | agentid-issue |
agentid-revoke`). Standardpfad:
`~/.claude/skillctl/transparency-log.jsonl`.

Die Kette fuer eine Pruefung, jede Stufe offline:

```bash
skillctl translog append admit sha256:<hex> --subject mein-skill
skillctl translog sth --key <log.priv>                        # Kopf zeigen/signieren
skillctl translog prove sha256:<hex> --key <log.priv> --out receipt.json
skillctl translog verify --receipt receipt.json --log-pubkey log.pub   # 0 ok · 23 not-included
skillctl translog consistency --sth1 a.json --sth2 b.json --proof '[..]'  # 25 = Rewrite erkannt
skillctl translog witness --sths sths.json --log-pubkey log.pub           # 24 = Split-View erkannt
```

`verify` verlangt den gepinnten Log-Public-Key ausdruecklich: ein
ungepinnter Schluessel wuerde nichts verifizieren (Manual, Abschnitt
`translog`).

## Was diese Seite nicht behauptet

Die Nummern `23/24/25` sind die dokumentierten Befund-Codes der
translog-Pruefungen; das Register dahinter prueft `cmd/exitaudit` gegen
`pkg/skillctl/exitcode` bei jedem Lauf von `scripts/check-docs.sh`. Diese
Seite zitiert Manual und Code, sie ersetzt weder das
[Manual](../referenz/manual-skillctl.md) noch das Verb-Register
[CLI-VERBS](../referenz/CLI-VERBS.md).
