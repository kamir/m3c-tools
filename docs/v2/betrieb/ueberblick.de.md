# Ops-Ueberblick: der Betrieb und seine Runbooks

Welches Runbook in welcher Lage gilt, was die Runbooks gemeinsam voraussetzen,
und wo ihre Grenzen ausdruecklich benannt sind. Diese Seite fuehrt; die
Handgriffe selbst stehen in den verlinkten Runbooks und bleiben dort kanonisch.

Zielgruppe: die Person, die ein Registry oder eine Flotte betreibt, und die
Person, die ein Release schneidet. Wer ein Mensch-Agent-Team erst einrichtet,
beginnt nicht hier, sondern im
[Einrichtungs-Runbook](../../ops-human-agent-team.de.md).

Rolle: Betrieb · Sprache: DE · Stand: 2026-09-16

## Die Grundregel in einem Satz

**Ein "Gemessen"-Block gilt fuer das Binary, das Datum und die Umgebung, die
er nennt, und fuer nichts sonst:** die Ops-Runbooks dieses Repos kennzeichnen
jede gelaufene Messung als solche, und wer gegen ein anderes Release prueft,
prueft ein anderes Objekt.

## Wann welches Runbook

| Lage | Runbook | Sprache |
|---|---|---|
| Ein Team wird eingerichtet, der erste Skill wechselt die Maschine | [Ops-Runbook: Mensch-Agent-Team](../../ops-human-agent-team.de.md), auch als [Doku-Seite](../../pages/ops-human-agent-team.html) | DE |
| Wer besorgt welchen Token, wo liegt er, was passiert beim Ausscheiden | [Ops-Routine: Zugangstoken](../../ops-registry-tokens.de.md) | DE |
| Ein Schluessel oder das Registry ist kompromittiert | [Ops-Runbook: Incident Response](../../ops-incident-response.de.md) | DE |
| Sicherung und Wiederherstellung des Registrys, je Backend | [Ops-Runbook: Registry-Backup und Restore](../../ops-registry-backup-restore.de.md) | DE |
| Was ist heute beobachtbar, woran dockt eine Ueberwachung an | [Ops-Runbook: Monitoring und Alarmierung](../../ops-monitoring.de.md) | DE |
| Eine Maschine verhaelt sich falsch (Diagnose) | [Monitoring, Abschnitt 1](../../ops-monitoring.de.md#1-die-vier-kommandos-die-eine-überwachung-tragen): `skillctl doctor`, `auditlog status`, `pin status`; das `--home`-Kaveat steht unten | DE |
| Die Capture-Seite haengt: Upload fehlgeschlagen, Queue voll | [Ops-Runbook: m3c-tools-Capture](runbook-m3c-tools-capture.de.md) | DE |
| Ein Release wird geschnitten (beide Linien, tag-getrieben) | [Release flow](../../releasing.md) | EN |
| Zwei Personen weisen den Skill-Austausch ueber ER1 nach | [Runbook: two-person ER1 exchange](../../runbook-two-person-er1-exchange.md) | EN |
| Die volle Abnahme des Skill-Lebenszyklus (Bob und Alice) | [Acceptance & Handover](../../acceptance-skillctl-lifecycle.md) | EN |
| Ein frisches Zielgeraet wird aufgesetzt (Intel Mac, Windows) | [Setup & Operations](../../setup-target-devices.md) | EN |
| Ein frischer Install wird auf dem Zielgeraet validiert | [QA Acceptance Track](../../QA-target-device-setup.md) | EN |

Hinweis zu den letzten beiden Zeilen: beide Seiten sind auf **v2.10.0**
festgeschrieben, waehrend `git tag` in diesem Baum am 2026-09-16 bis
`v2.12.0` reicht. Die Vorgehensweise dort ist der kanonische Stand; die
Versionsnummer im Titel ist es nicht mehr.

## Datierte Entscheidungen, die den Betrieb binden

| Entscheidung | Quelle |
|---|---|
| Entschieden am 2026-09-06: produktiv ist die GitLab-Instanz `git.kieback-peter.de`, mit dem dort genannten Registry-Locator | [Ops-Routine: Zugangstoken](../../ops-registry-tokens.de.md), Kopfabschnitt |
| Schreibtoken gehoeren der Rolle Herausgeber, nicht einer Person; Personalwechsel rotiert das Token | [Ops-Routine: Zugangstoken](../../ops-registry-tokens.de.md) |
| Der Install-Einzeiler ist auf einen unveraenderlichen Commit gepinnt, nicht auf `master` | [Ops-Runbook: Mensch-Agent-Team, Abschnitt 0.2](../../ops-human-agent-team.de.md) |
| Releases sind tag-getrieben; es gibt keine VERSION-Datei, und die Produkt- und die skillctl-Linie werden getrennt geschnitten | [Release flow](../../releasing.md) |

## Was der Betrieb wissen muss, bevor etwas brennt

1. **Die drei Dateien, die Trust-Roots heissen.** Ein Pin traegt nur einen der
   Wege; die Falle und ihre Aufloesung stehen in
   [Ops-Runbook: Mensch-Agent-Team, Abschnitt 6](../../ops-human-agent-team.de.md).
2. **Exit-Codes sind das Alarm-Vokabular.** Die Runbooks verweisen auf die
   Fehlerbehandlung nach Exit-Code; das Register ist
   [CLI-VERBS](../../CLI-VERBS.md), die Tabelle je Kommando steht im
   [Manual: skillctl](../../manual-skillctl.md#exit-codes).
3. **`skillctl doctor --home` misst ein gemischtes Objekt.** Mit gesetztem
   `--home` prueft doctor skills-dir und audit-logs im Override, trust-roots
   und signing-key aber weiter im echten Home: im Code nimmt
   `checkTrustRoots()` keinen Override an, und `checkSigningKey` loest den
   Pfad ueber `defaultSelfKeyPath()` aus dem echten Home auf
   (`cmd/skillctl/doctor_cmds.go`, nachgelesen am 2026-09-16; so auch vom
   Operator-Review am selben Tag gemessen). Wer hermetisch messen will, darf
   sich auf `--home` allein nicht verlassen.
4. **Die Grenzen sind benannt.** Jedes der fuenf DE-Runbooks traegt einen
   eigenen Abschnitt darueber, was es ausdruecklich nicht loest
   (nachgesehen am 2026-09-16: "Was offen bleibt", "Was diese Routine nicht
   loest", "Was dieses Runbook nicht loest" zweimal, "Was damit ausdruecklich
   nicht geht"); wer den Umfang einschaetzen muss, liest zuerst diese
   Abschnitte.
