# Wegweiser: die Dokumentation nach Rollen / the documentation, by role

Diese Seite beantwortet eine Frage: **wer bist du, und welche Seite brauchst du
jetzt?** Sie ersetzt keine bestehende Seite; jede tor-gebundene Datei bleibt an
ihrem Platz kanonisch und wird von hier nur verlinkt.

This page answers one question: **who are you, and which page do you need right
now?** It replaces nothing; every gate-bound file stays canonical where it is
and is only linked from here.

Zielgruppe: jede Person, die dieses Repository zum ersten Mal oeffnet, und jede,
die eine bestimmte Seite sucht und nicht weiss, wo sie liegt.

Rolle: alle · Sprache: DE/EN · Stand: 2026-09-16

## Die Grundregel in einem Satz

**Tor-gebundene Seiten werden verlinkt, nie kopiert:** die Manuals, das
Verb-Register, die Indizes, die Tutorials und die Ops-Runbooks tragen maschinelle
Pruefungen (docaudit, verbaudit, exitaudit, tutorial-smoke, check-index,
check-docpages), und ein Duplikat waere ab der zweiten Aenderung eine zweite,
abweichende Aussage.

Entschieden am 2026-09-16: `docs/v2/` wird additiv aufgebaut; keine Bestandsdatei
wird verschoben, geaendert oder geloescht, bis der Umzug in einer eigenen PR
abgenommen ist.

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
| [Manual: m3c-tools](../manual-m3c-tools.md) | jedes Kommando, jedes Flag, jede Konfigurationsvariable; docaudit-getort | EN |
| [Manual: skillctl](../manual-skillctl.md) | der volle Trust-Lebenszyklus, Kommando fuer Kommando; docaudit- und exitaudit-getort | EN |
| [CLI-VERBS](../CLI-VERBS.md) | das Allokationsregister der skillctl-Verben; verbaudit-getort | EN |
| [Program-Index](../program-index.md) · [Service-Index](../service-index.md) · [Component-Index](../component-index.md) | was man startet, was laeuft, woraus alles gebaut ist; Index-Tor auf Program und Component | EN |
| [Tutorial Szenario 01](../tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md) · [Szenario 02](../tutorial-szenario-02-erster-signierter-skill.de.md) · [Katas und Test Ride](../tutorial-katas-und-test-ride.de.md) | die drei gefuehrten Tutorials; Szenario 01 und 02 sind tutorial-smoke-getort | DE |
| [Ops-Runbook: Mensch-Agent-Team](../ops-human-agent-team.de.md) | das Einrichtungs-Runbook, auch als [Doku-Seite](../pages/ops-human-agent-team.html) | DE |
| [docs/security/](../security/required-checks.txt) | Backlogs, Baselines und die Namensbindung der Pflicht-Checks | EN |
