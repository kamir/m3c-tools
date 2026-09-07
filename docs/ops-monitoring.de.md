# Ops-Runbook: Monitoring und Alarmierung

Was an einem skillctl-Betrieb heute beobachtbar ist, woran eine Überwachung
andocken kann, und was mit den vorhandenen Mitteln **nicht** geht.

Zielgruppe: die Person, die die Flotte betreibt, und die Person, die eine
Überwachung dafür einrichten soll.

## Die ehrliche Zusammenfassung zuerst

**Es gibt keine Metrik-Fläche.** Kein `/metrics`, kein Prometheus-Exporter, kein
OpenTelemetry, kein statsd. Gemessen am 2026-09-07 über den gesamten Baum:

```
$ grep -rn "prometheus\|/metrics\|statsd\|opentelemetry\|otel" --include="*.go" pkg/skillctl cmd/skillctl
pkg/skillctl/auditevent/event_test.go:28:  if err := e.SetExt("trace_id", "otel-abc"); err != nil {
```

Ein einziger Treffer, und der ist ein Testwert. Nichts stellt Zähler bereit,
nichts meldet von sich aus etwas an ein Zielsystem.

**Was es stattdessen gibt: Kommandos, die man fragt.** Alles unten ist ein Pull:
ein Aufruf, ein Exit-Code, wahlweise JSON auf stdout. Eine Überwachung baut man
darauf als geplante Aufgabe, nicht als Abonnement.

Das ist kein Versehen, sondern die Bauart: die Entscheidung des Tors darf nicht
davon abhängen, ob eine Beobachtung gelingt. Die Protokollierung ist deshalb
absichtlich vom Entscheidungspfad getrennt, und dieselbe Trennung schneidet die
Meldewege mit ab.

## 1. Die vier Kommandos, die eine Überwachung tragen

### `skillctl auditlog status`

Sagt, ob das Audit-Subsystem überhaupt noch schreiben kann.

```
$ skillctl auditlog status
skillctl auditlog status
  Audit:        ENABLED
  Mode:         best-effort (gate default, decision-invariant; durable outbox available)
  Sink:         file
  Sink path:    /…/.claude/skillctl/gate-audit.jsonl
  Outbox:       0 pending (awaiting `skillctl sync` egress, default-OFF)
  Spool:        0 pending (un-reconciled; drain with `skillctl auditlog flush`)
  Last event:   (none recorded)
  Health:       HEALTHY
$ echo $?
0
```

Maschinell:

```
$ skillctl auditlog status --json
{
  "enabled": true,
  "mode": "best-effort (gate default, decision-invariant; durable outbox available)",
  "sink": "file",
  "sink_path": "/…/.claude/skillctl/gate-audit.jsonl",
  "outbox_pending": 0,
  "spool_pending": 0,
  "healthy": true
}
```

| Exit | Bedeutung |
|---|---|
| 0 | gesund: das Audit-Verzeichnis ist beschreibbar |
| 1 | ungesund |
| 2 | Aufruf- oder Flag-Fehler |

Der Exit-Code ist hier ein echtes Alarmsignal, weil er an einer Probe hängt
(ist das Verzeichnis beschreibbar) und nicht an einer Meinung.

**Die zwei Zahlen, die man überwacht.** `spool_pending` sollte nach einem
`skillctl auditlog flush` auf 0 gehen; bleibt sie stehen, kommt der heisse Pfad
nicht in den dauerhaften Outbox durch. `outbox_pending` wächst, solange kein
`skillctl sync` läuft, und das ist der **Normalfall**: die Ausleitung ist
standardmässig aus. Eine Schwelle auf `outbox_pending` ist deshalb nur sinnvoll,
wenn `sync` tatsächlich eingerichtet ist.

### `skillctl gate-stats`

Fasst zusammen, was das Tor entschieden hat.

```
$ skillctl gate-stats --since 168h
gate-audit summary, 0 event(s) since 168h
  (no events, the gate hasn't logged anything in this window)
$ echo $?
0
```

`--json` liefert dieselbe Zusammenfassung maschinenlesbar, mit den Feldern
`total`, `since`, `by_decision`, `by_source`, `hook_count`,
`hook_cache_hit_rate`, `top_denied_skills`, `top_deny_reasons` und
`recent_denials`.

**Der Exit-Code ist hier kein Alarmsignal.** `gate-stats` gibt 0 zurück, egal ob
es 0 oder 10000 Blockaden gefunden hat. Wer alarmieren will, wertet
`by_decision` aus dem JSON aus. Und `gate-stats` liest **nur die lokale Datei
dieser einen Maschine**; eine Flottenaussage entsteht erst durch Einsammeln.

### `skillctl doctor`

Der Zustand einer Maschine: Pinnungen, Schlüssel, Verzeichnisse.

```
$ skillctl doctor
skillctl doctor
--------------------------------------------------------------
ok    version      skillctl dev (darwin/arm64, go1.26.6)
ok    home         /…  ($HOME)
todo  skills dir   /…/.claude/skills does not exist yet
                   -> it is created by the first `skillctl install`
todo  trust roots  /…/.claude/skill-trust-roots.yaml not present
…
--------------------------------------------------------------
USABLE, 4 step(s) not done yet. Nothing here is broken.
$ echo $?
0
```

**Achtung, der Exit-Code trügt.** `doctor` gibt 1 zurück, wenn etwas **vorhanden
und unbrauchbar** ist ("NOT READY"), und 0 sowohl bei "READY" als auch bei
"USABLE, n step(s) not done yet". Eine Maschine ohne jede Vertrauenswurzel
liefert also Exit 0. Wer den Unterschied überwachen will, prüft die Schlusszeile
auf `READY:` und nicht den Exit-Code. Das ist der einzige Ort in diesem Runbook,
an dem der naheliegende Weg das Falsche misst.

### `skillctl pin status`

Ob das Tor unentfernbar verankert ist oder nur eine Empfehlung.

```
$ skillctl pin status
managed settings: /Library/Application Support/ClaudeCode/managed-settings.json
gate pinning:     absent
  SessionStart sweep hook: no
  PreToolUse verify-hook:  no
  - no managed-settings file at …: the gate is ADVISORY (a user can delete the user-level hook). Run `skillctl pin install`.
$ echo $?
2
```

| Exit | Bedeutung |
|---|---|
| 0 | verankert |
| 1 | Fehler beim Lesen |
| 2 | **nicht** verankert |

Hier ist der Exit-Code die Alarmquelle, und die 2 ist der interessante Wert.
Ungewöhnlich, weil 2 sonst überall im Werkzeug "Aufruffehler" heisst; auf diesem
Verb heisst sie "nicht gepinnt".

## 2. Zwei weitere Andockpunkte

### `skillctl verify --all --json`

Der Flottenzustand einer Maschine, als Bericht:

```json
{
  "skills_dir": "/…/.claude/skills",
  "total": 0,
  "verified": 0,
  "quarantined": 0,
  "unverified": 0,
  "skipped": 0,
  "entries": null
}
```

Zu überwachen ist `quarantined > 0` (etwas ist durchgefallen) und
`unverified > 0` (der Lauf hat es im Zeitbudget nicht geschafft, also weiss
niemand etwas über diese Skills). `unverified` ist die stillere und deshalb
wichtigere der beiden Zahlen.

**Ein Umleiten nach `> bericht.json` ergibt keine gültige JSON-Datei.** Gibt es
nichts zu prüfen, schreibt das Kommando eine Klartextzeile **auf stdout**, vor
das JSON. Gemessen mit unterdrücktem stderr:

```
$ skillctl verify --all --json 2>/dev/null
skillctl verify --all: no installed skills at /…/.claude/skills (nothing to sweep)
{
  "skills_dir": "/…/.claude/skills",
  "total": 0,
  …
}
```

Ein Auswerter schneidet deshalb ab der ersten `{`-Zeile, etwa mit
`sed -n '/^{/,$p'`. `gate-stats --json` und `auditlog status --json` haben dieses
Verhalten nicht; beide schreiben nur das Dokument.

### `skillctl revoke feed --status`

Ob die Maschine den signierten Widerruf-HEAD frisch hat:

```bash
skillctl revoke feed --status --registry https://<host>/api/skills
```

Prüft die Signatur des HEAD gegen den **gepinnten** Registry-Schlüssel und gibt
Epoche, Ausstellungszeit und Veraltung aus. `--refresh` holt ihn. Ohne diesen
Aufruf altert die lokale Sicht, und die Alterung ist genau das, was eine
Überwachung hier sehen soll.

## 3. Die Dateien darunter

| Datei | Was drinsteht |
|---|---|
| `~/.claude/skillctl/gate-audit.jsonl` | eine Zeile je Torentscheidung, Schema `skillctl.audit.v1` |
| `~/.claude/skillctl/gate-audit.jsonl.1` | die eine rotierte Generation |
| der SPEC-0317-Outbox | dauerhafte, ausleitbare Nachweiszeilen |

Das ist eine **strukturierte Zeilendatei**, also durchaus etwas, worauf ein
Log-Versand andocken kann. Zwei Einschränkungen, beide gemessen im Code:

1. **Rotation mit genau einer Generation.** Bei 5 MiB wird auf `.jsonl.1`
   rotiert; die vorherige `.1` ist dann weg. Ein Log-Versand, der langsamer ist
   als der Anfall, verliert Zeilen von der Platte. Der dauerhafte Nachweis ist
   der Outbox, nicht diese Datei.
2. **Die Datei ist Telemetrie, kein Vertrauenseingang.** Beschädigte Zeilen
   werden übersprungen, nicht gemeldet. Aus einer plausiblen `gate-audit.jsonl`
   folgt keine Aussage über die Vollständigkeit.

Ausleiten, wenn es eingerichtet ist:

```bash
skillctl sync --once --endpoint https://<ingest>/… --ingest-pubkey <pem>
skillctl sync --daemon --interval 1m --endpoint https://<ingest>/… --ingest-pubkey <pem>
```

Die Ausleitung ist **standardmässig aus** ("Default OFF, local-only evidence").
Ohne `--endpoint` und ohne `--ingest-pubkey` werden keine Zeilen als ausgeleitet
markiert.

`skillctl auditlog flush` schreibt zusätzlich ein Beobachtungsereignis auf
stderr, auf einem **anderen** Kanal als die Senke, über die es berichtet:

```
{"event_id":"01M1XM…","event_type":"audit.queue.flush","message":"reconciled 0 spooled row(s) into the durable outbox","observability":true,"outcome":"success","producer":"skillctl/dev","schema":"skillctl.audit.v1","severity":"info","timestamp":"2026-09-07T09:48:06.147Z"}
```

## 4. Das Token-Register ist Teil der Überwachung

Ablaufdaten von Token stehen **in keinem Token**, und `skillctl` kennt sie
nicht. `skillctl token list --host <host>` zeigt, was hinterlegt ist, und gibt
weder einen Token noch ein Datum aus:

```
$ skillctl token list --host git.kieback-peter.de
credentials for git.kieback-peter.de
  protected store: macOS Keychain

  gitlab    read   not provisioned              env: M3C_GITLAB_RO_TOKEN
  gitlab    write  not provisioned              env: M3C_GITLAB_TOKEN
  …
```

Die einzige Stelle, an der ein Ablaufdatum steht, ist das Register in
[Teil C der Token-Routine](ops-registry-tokens.de.md#teil-c-das-token-register).
Eine Überwachung der Ablaufdaten ist deshalb heute eine Kalendererinnerung auf
die Spalte "Läuft ab", und nichts, was ein Werkzeug erzeugen könnte.

## 5. Ein Minimal-Monitoring, das heute funktioniert

Eine geplante Aufgabe je Maschine (launchd, Aufgabenplanung, cron), täglich, mit
Ausgabe in eine Datei, die der vorhandene Log-Versand ohnehin abholt:

```bash
#!/usr/bin/env bash
# skillctl-health.sh: pull-basierte Zustandsprobe, ein Aufruf je Signal.
# Kein Alarm hier drin: die Datei ist das Signal, das Auswerten macht das
# vorhandene Log- oder Monitoring-Werkzeug.
set -u
out=${1:-/var/log/skillctl-health.json}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# JSON erst ab der ersten offenen Klammer: `verify --all --json` stellt bei
# einem leeren Lauf eine Klartextzeile auf stdout davor.
only_json() { sed -n '/^{/,$p' "$1"; }

skillctl auditlog status --json > "$tmp/auditlog.json" 2>/dev/null
auditlog_exit=$?

skillctl pin status > /dev/null 2>&1
pin_exit=$?

skillctl gate-stats --since 24h --json > "$tmp/gate-stats.json" 2>/dev/null
skillctl verify --all --json      > "$tmp/verify-all.json" 2>/dev/null

skillctl doctor > "$tmp/doctor.txt" 2>&1
doctor_ready=$(grep -c '^READY:' "$tmp/doctor.txt" || true)

cat > "$out" <<JSON
{
  "ts": "$(date -u +%FT%TZ)",
  "host": "$(hostname)",
  "auditlog_exit": $auditlog_exit,
  "pin_status_exit": $pin_exit,
  "doctor_ready": $doctor_ready,
  "auditlog": $(only_json "$tmp/auditlog.json"),
  "gate_stats": $(only_json "$tmp/gate-stats.json"),
  "verify_all": $(only_json "$tmp/verify-all.json")
}
JSON
```

Die Exit-Codes werden **unmittelbar** nach ihrem Kommando eingesammelt. Wer sie
erst in der Ausgabezeile liest, liest den Exit-Code der Ausgabezeile.

Das Skript ist am 2026-09-07 gegen ein frisches `$HOME` gelaufen und hat gültiges
JSON geschrieben: `auditlog_exit=0`, `pin_status_exit=2`, `doctor_ready=0`,
`verify_all.total=0`.

Die vier Alarme, die sich daraus lohnen:

| Alarm | Bedingung | Warum |
|---|---|---|
| Audit tot | `auditlog_exit != 0` | ab hier entstehen keine Nachweise mehr |
| Tor nicht verankert | `pin_status_exit == 2` | das Tor ist nur noch eine Empfehlung |
| Skill durchgefallen | `verify_all.quarantined > 0` | etwas Installiertes besteht die Kette nicht |
| Blinder Fleck | `verify_all.unverified > 0` | der Lauf hat es nicht geschafft, niemand weiss etwas |

Ein fünfter, sobald `sync` eingerichtet ist: `auditlog.outbox_pending` wächst
über mehrere Läufe monoton, also kommt die Ausleitung nicht durch.

## 6. Was damit ausdrücklich nicht geht

**Keine Metriken.** Kein `/metrics`, kein Exporter, keine Zähler, keine
Histogramme. Wer ein Dashboard braucht, baut es auf den JSON-Ausgaben oben, und
die Auflösung ist der Abstand der geplanten Läufe, nicht die Zeit des Ereignisses.

**Keine Alarmierung.** Nichts sendet. Alarme entstehen ausschliesslich dort, wo
jemand die Exit-Codes und JSON-Felder oben auswertet.

**Keine Flottensicht.** Jedes Kommando spricht über **diese** Maschine. Es gibt
keine Abfrage "welche Maschinen sind veraltet". Das Einsammeln ist Aufgabe des
vorhandenen Log- oder Konfigurationswerkzeugs.

**Kein Ereignisstrom.** Eine Broker-Senke ist nicht gebaut (FR-0112, gesperrt);
`auditlog status` erfindet deshalb bewusst keinen Endpunkt und kein Topic. Was es
gibt, ist die Datei und die Ausleitung per `skillctl sync`.

**Keine Vollständigkeitsgarantie auf der Platte.** Siehe die Rotation in
Abschnitt 3. Der dauerhafte Nachweis ist der Outbox.

**Keine Ablaufwarnung für Token.** Siehe Abschnitt 4.

**Kein Alarm auf einen eingetroffenen Widerruf.** Der Widerruf-HEAD wird geholt,
nicht zugestellt. Ohne einen geplanten `revoke feed --refresh` merkt eine
Maschine nichts; siehe [Incident Response](ops-incident-response.de.md).

## Verwandte Runbooks

| Runbook | Wofür |
|---|---|
| [Ops-Routine: Zugangstoken](ops-registry-tokens.de.md) | das Token-Register mit den Ablaufdaten |
| [Incident Response](ops-incident-response.de.md) | was zu tun ist, wenn ein Alarm zutrifft |
| [Registry-Backup und Restore](ops-registry-backup-restore.de.md) | dass die Sicherung läuft, prüft niemand von selbst |
