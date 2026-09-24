# Wegweiser: die Dokumentation nach Rollen / the documentation, by role

Diese Seite beantwortet eine Frage: **wer bist du, und welche Seite brauchst du
jetzt?** Die tor-gebundenen Dateien liegen an ihrem Rollenplatz unter `docs/v2/`
und werden von hier verlinkt, nie kopiert.

This page answers one question: **who are you, and which page do you need right
now?** The gate-bound files live at their role place under `docs/v2/` and are
linked from here, never copied.

Zielgruppe: jede Person, die dieses Repository zum ersten Mal oeffnet, und jede,
die eine bestimmte Seite sucht und nicht weiss, wo sie liegt.

Rolle: alle · Sprache: DE/EN · Stand: 2026-09-16

## Die Grundregel in einem Satz

**Tor-gebundene Seiten werden verlinkt, nie kopiert:** die Manuals, das
Verb-Register, die Indizes, die Tutorials und die Ops-Runbooks tragen maschinelle
Pruefungen (docaudit, verbaudit, exitaudit, tutorial-smoke, check-index,
check-docpages), und ein Duplikat waere ab der zweiten Aenderung eine zweite,
abweichende Aussage.

Entschieden am 2026-09-16, in zwei Runden: zuerst wurde `docs/v2/` additiv
aufgebaut, dann zog der Bestand in der Umzugs-PR um. Seither ist `docs/v2/`
kanonisch: Referenz unter `referenz/`, Tutorials unter `nutzer/`, Runbooks
unter `betrieb/`; die Indizes bleiben unter `docs/`, der fruehere
Prosa-Bestand liegt unkanonisch unter `docs/old/`.

## Wer bist du, was suchst du, wohin gehst du

| Wer bist du | Was suchst du | Wohin gehst du |
|---|---|---|
| **Nutzerin / Nutzer** | m3c-tools installieren, erste Aufnahme, Menueleisten-App, die drei Tutorials | [Anleitung: der Einstieg (DE)](nutzer/einstieg.de.md) |
| **Entwicklerin / Entwickler** | Architektur, Pakete, Datenfluss | [Reference: architecture overview (EN)](entwickler/architecture.md) |
| **Entwicklerin / Entwickler** | bauen, testen, die Tore, beitragen | [Guide: developer setup, build, test, gates (EN)](entwickler/getting-started.md) |
| **Betrieb** | Registry betreiben, Token, Backup, Monitoring, Incident, Release | [Ops-Ueberblick: Betrieb und Runbooks (DE)](betrieb/ueberblick.de.md) |
| **Sicherheit / CISO** | Vertrauensmodell, Threat Model, Nachweise, Decks | [Ueberblick: Sicherheits- und Vertrauensmodell (DE)](sicherheit/ueberblick.de.md) |

## Direktzugriffe / direct routes

| Seite | Was sie ist | Sprache |
|---|---|---|
| [Manual: m3c-tools](referenz/manual-m3c-tools.md) | jedes Kommando, jedes Flag, jede Konfigurationsvariable; docaudit-getort | EN |
| [Manual: skillctl](referenz/manual-skillctl.md) | der volle Trust-Lebenszyklus, Kommando fuer Kommando; docaudit- und exitaudit-getort | EN |
| [CLI-VERBS](referenz/CLI-VERBS.md) | das Allokationsregister der skillctl-Verben; verbaudit-getort | EN |
| [Program-Index](../program-index.md) · [Service-Index](../service-index.md) · [Component-Index](../component-index.md) | was man startet, was laeuft, woraus alles gebaut ist; Index-Tor auf Program und Component | EN |
| [Tutorial Szenario 01](nutzer/tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md) · [Szenario 02](nutzer/tutorial-szenario-02-erster-signierter-skill.de.md) · [Katas und Test Ride](nutzer/tutorial-katas-und-test-ride.de.md) | die drei gefuehrten Tutorials; Szenario 01 und 02 sind tutorial-smoke-getort | DE |
| [Ops-Runbook: Mensch-Agent-Team](betrieb/ops-human-agent-team.de.md) | das Einrichtungs-Runbook, auch als [Doku-Seite](pages/ops-human-agent-team.html) | DE |
| [Runbook: skillctl-sim](entwickler/skillctl-sim.md) | die Trust-Plane-Simulation lesen | EN |
| [Reference: secretctl](entwickler/secretctl.md) | wer ein Geheimnis haelt und ob es noch gilt; liest und vergleicht, druckt nie einen Wert; check-docpages-getort | EN |
| [Acceptance und Handover: der skillctl-Lebenszyklus](betrieb/acceptance-skillctl-lifecycle.md) | der Leitfaden hinter dem Protokoll, mit dem Windows-Schnelltest und den zwei Bahnen fuer zwei Personen, auch als [Doku-Seite](pages/betrieb-acceptance-skillctl-lifecycle.html); check-docpages-getort | EN |
| [QA-Abnahme: skillctl auf Windows](betrieb/QA-abnahme-skillctl-windows.de.md) | das Protokoll zum Ausdrucken, Ankreuzen und Unterschreiben, auch als [Doku-Seite](pages/betrieb-qa-abnahme-skillctl-windows.html); check-docpages-getort | DE |
| [Runbook: die Audit-Spur](sicherheit/audit-spur.de.md) | die drei Traeger audit, auditlog, translog konsolidiert | DE |
| [docs/security/](../security/required-checks.txt) | Backlogs, Baselines und die Namensbindung der Pflicht-Checks | EN |
