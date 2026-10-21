# Wegweiser: Dokumentation nach Rollen

Sprachen / Languages: [Deutsch](index.md) | [English](index.en.md)

Diese Seite hilft bei der Auswahl der passenden Anleitung. Sie richtet sich an
Personen, die das Repository erstmals öffnen oder eine bestimmte Seite suchen.
Referenzen liegen unter `referenz/`, Anleitungen unter `nutzer/`, Betriebsanleitungen
unter `betrieb/`; Programm-, Dienst- und Komponentenindizes liegen unter `docs/`.

## Verbindliche Inhalte und Sprachfassungen

Deutsch und Englisch enthalten dieselben fachlichen Aussagen. Beide Fassungen
werden gemeinsam geprüft. Die implementierungsbezogenen Prüfungen lesen weiterhin
die bestehenden Originalpfade: docaudit, verbaudit, exitaudit, tutorial-smoke und
check-index. `check-doc-languages.py` prüft die Sprachpaare, ihre nach dem Review
gespeicherten Prüfsummen und identische Codebeispiele. Die Prüfsummen erkennen
nachträgliche Änderungen; sie beweisen keine korrekte Übersetzung.
`check-docpages` hält die erzeugten HTML-Seiten mit ihren Quellen synchron.

## Nach Rolle einsteigen

| Rolle | Gesuchter Inhalt | Einstieg |
|---|---|---|
| Nutzung | Installation, erste Aufnahme, Menüleisten-App und Tutorials | [Einstieg](nutzer/einstieg.de.md) |
| Entwicklung | Architektur, Pakete und Datenfluss | [Architekturübersicht](entwickler/architecture.de.md) |
| Entwicklung | Bauen, testen, Qualitätsprüfungen und Beiträge | [Entwicklungsumgebung](entwickler/getting-started.de.md) |
| Betrieb | Registry, Token, Sicherung, Monitoring und Vorfälle | [Betriebsübersicht](betrieb/ueberblick.de.md) |
| Sicherheit / CISO | Vertrauensmodell, Bedrohungen und Nachweise | [Sicherheitsübersicht](sicherheit/ueberblick.de.md) |

## Direktzugriffe

| Seite | Inhalt |
|---|---|
| [m3c-tools-Handbuch](referenz/manual-m3c-tools.de.md) | Alle Befehle, Flags und Konfigurationsvariablen; Original durch docaudit geprüft |
| [skillctl-Handbuch](referenz/manual-skillctl.de.md) | Vollständiger Vertrauenslebenszyklus; Original durch docaudit und exitaudit geprüft |
| [CLI-Verben](referenz/CLI-VERBS.de.md) | Zuordnung der skillctl-Verben; Original durch verbaudit geprüft |
| [Programme](../program-index.de.md) · [Dienste](../service-index.de.md) · [Komponenten](../component-index.de.md) | Ausführbare Programme, laufende Dienste und Bibliotheken; Programm- und Komponentenoriginal durch check-index geprüft |
| [Szenario 01](nutzer/tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md) · [Szenario 02](nutzer/tutorial-szenario-02-erster-signierter-skill.de.md) · [Katas und Test Ride](nutzer/tutorial-katas-und-test-ride.de.md) | Geführte Tutorials; Szenarien 01 und 02 durch tutorial-smoke geprüft |
| [skillctl-sim](entwickler/skillctl-sim.de.md) | Simulation der Vertrauensebene auswerten |
| [secretctl](entwickler/secretctl.de.md) | Halter und Aktualität von Geheimnissen prüfen, ohne Werte auszugeben |
| [Audit-Spur](sicherheit/audit-spur.de.md) | Die drei Protokollträger audit, auditlog und translog |
| [Technische Sicherheitsnachweise](../security/required-checks.txt) | Scanner-Baselines, Release-Evidence-Schema und Pflichtprüfungen |
