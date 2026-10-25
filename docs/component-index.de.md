---
layout: default
title: Komponenten
---

# Komponenten

Sprachen / Languages: [Deutsch](component-index.de.md) | [English](component-index.md)

**Die Bausteine.** Importierbare Go-Bibliothekspakete ohne `main`, aus denen
[Programme](program-index.de.md) und [Dienste](service-index.de.md) bestehen.
Öffentliche Pakete liegen unter `pkg/`, rein interne unter `internal/`.

Nach Domäne gegliedert:
[A. Erfassung und Medien](#a-erfassung-und-medien-pkg) ·
[B. ER1 und Sitzungen](#b-er1-wissensupload-und-sitzungen-pkg) ·
[C. Aufnahmequellen](#c-aufnahmequellen-pkg) ·
[D. Konfiguration und Infrastruktur](#d-konfiguration-infrastruktur-und-hilfen-pkg) ·
[E. Desktop-UI](#e-desktop-ui-pkg) ·
[F. skillctl-Vertrauen](#f-skillctl-vertrauenssubsystem-pkgskillctl-und-nachbarpakete) ·
[G. Weitere interne Pakete](#g-weitere-interne-pakete-internal)

---

## A. Erfassung und Medien (`pkg/`)

| Paket | Verantwortung |
|---------|----------------|
| `transcript` | Reine Go-Portierung von youtube-transcript-api über InnerTube ohne API-Schlüssel. Videoseite → API-Schlüssel → Untertitel-XML → Ausschnitte; vier Ausgabeformate Text/SRT/JSON/WebVTT, Proxykonfigurationen und Vorschaubilder mit Größenfallback. |
| `impression` | Beobachtungserfassung, zusammengesetzte Dokumente und Tags. Verbindet Videotranskript und Nutzerkommentar zu einem strukturierten ER1-Dokument; automatische Tags je Beobachtungstyp. |
| `whisper` | Spracherkennung über den CLI-Unterprozess `whisper` ohne C-Bindings; findet das Programm, führt `--output_format json` aus und liest Segmente. |
| `recorder` | Mikrofonaufnahme mit PortAudio über cgo; 16 kHz/16 Bit PCM-Mono-WAV, kompatibel mit whisper. |
| `screenshot` | Bildschirmaufnahme unter macOS über `screencapture`. |
| `draft` | Laufende Beobachtungen als Entwürfe speichern und laden. |
| `importer` | Audio-Stapelimport: Ordner durchsuchen, Duplikate erkennen, kopieren und nachverfolgen. |
| `bulkprogress` | Plattformneutrale Fortschrittsbegriffe für die Audiopipeline. |

## B. ER1, Wissensupload und Sitzungen (`pkg/`)

| Paket | Verantwortung |
|---------|----------------|
| `er1` | ER1-Konfiguration, Multipart-HTTP-Upload mit `transcript_file_ext`/`audio_data_ext`/`image_data` und Ersatz-Audio/-Bild bei fehlenden Daten sowie JSON-Retry-Queue mit Mutex-Synchronisierung. |
| `er1login` | Browserbasierte Gerätekopplung mit aims-core; liefert Zugangsdaten zurück. |
| `session` | SPEC-0213: Arbeitssitzung als rechnerbezogenen Wissenseintrag mit Checkpoint-Kette in ER1 speichern. |
| `tracking` | SQLite-gestützte Exportverfolgung für ER1-Uploads. |
| `timetracking` | Lokale Zeiterfassung im jeweiligen PLM-Projektkontext. |
| `m3cproject` | Löst den PLM-Projektkontext des Arbeitsverzeichnisses über `.m3c/project.yaml` auf. |
| `auth` | Gerätetoken speichern und abrufen. |

## C. Aufnahmequellen (`pkg/`)

| Paket | Verantwortung |
|---------|----------------|
| `plaud` | API-Client für die Rekorder-Cloud Plaud.ai. |
| `pocket` | Client für die Pocket-Cloud-API (SPEC-0173). |

## D. Konfiguration, Infrastruktur und Hilfen (`pkg/`)

| Paket | Verantwortung |
|---------|----------------|
| `config` | Initialisierung und Konfigurations-Bootstrap über `.env` / `~/.m3c-tools.env`. |
| `setup` | Grundlage des Onboarding-Ablaufs SPEC-0175. |
| `httpsafe` | Kleine HTTP-Härtungshilfen ohne Abhängigkeiten, gemeinsam von Clients verwendet. |
| `diag` | Diagnosetypen und Darstellung für doctor/check. |
| `testutil` | Gemeinsame Testhilfen. |

## E. Desktop-UI (`pkg/`)

| Paket | Verantwortung |
|---------|----------------|
| `menubar` | Typen, Konfiguration und Callback-Schnittstellen der Menüleisten-App. |
| `tray` | Plattformübergreifende Benachrichtigungen über das reine Go-Paket `beeep`. |

## F. skillctl-Vertrauenssubsystem (`pkg/skillctl/*` und Nachbarpakete)

Die offline prüfbare Skill-Vertrauensebene als Bibliothek hinter der
[`skillctl`](program-index.de.md)-CLI. Es gibt 53 Unterpakete in `pkg/skillctl/`
und die am Abschnittsende genannten Nachbarpakete, gegliedert nach Rolle.
`scripts/check-index.sh` prüft im Original sowohl Liste als auch Anzahl: Es gleicht
`pkg/**` und `internal/**` in beiden Richtungen ab und zählt Verzeichnisse neu.
Ein neues Paket darf nicht nur eine Tabellenzeile ergänzen und die Anzahl veralten lassen.
Die Prüfung läuft in `scripts/check-docs.sh` und dem Job `docs-gate` von `ci.yml`,
`release.yml` und `skillctl-release.yml`.

**Inventar und Parsing**

| Paket | Verantwortung |
|---------|----------------|
| `skillctl/model` | Datentypen für das Skill-Inventarsystem. |
| `skillctl/parser` | Liest YAML-Frontmatter aus Markdown-Skill-Dateien. |
| `skillctl/scanner` | Durchsucht Verzeichnisse nach Claude-Code-Skill-Quellen. |
| `skillctl/hasher` | Inhalts-Hashing und Duplikaterkennung. |

**Kryptografie und Identität**

| Paket | Verantwortung |
|---------|----------------|
| `skillctl/signing` | Kryptografische Primitive der Phase 2 (SPEC-0188). |
| `skillctl/verify` | Clientseitiger Prüfalgorithmus (SPEC-0188). |
| `skillctl/device` | DEVICE KEY je Rechner zum Signieren von SPEC-0202-Aufrufen. |
| `skillctl/agentid` | Reiner, ausschließlich auf der Standardbibliothek beruhender Kern der Agenteninstanz-Identität SPEC-0277. |
| `skillctl/translog` | L1-Transparenzprotokoll (SPEC-0278). |
| `skillctl/trustcore` | Gemeinsame Primitive signierter Umschläge für Backends sowie pull/gossip/gauntlet (FR-0090): Vertrauensentscheidungen lesen Ereignisart und Digest aus dem signierten Umschlag, niemals aus einer unsignierten Trägerprojektion. |

**Lebenszyklus, Zulassung und Installation**

| Paket | Verantwortung |
|---------|----------------|
| `skillctl/install` | Client-Installationspipeline nach SPEC-0188 §7. |
| `skillctl/importer` | Zugriff auf die aims-core-Skill-Profil-API. |
| `skillctl/registry` | HTTP-Client für das aims-core-Skill-Registry. |
| `skillctl/awareness` | Zulassungsbrücke nach SPEC-0195. |
| `skillctl/propose` | Freigabeprüfung ready-to-promote nach SPEC-0194 §6. |
| `skillctl/pin` | Pinning verwalteter Einstellungen nach SPEC-0247 §7.3. |
| `skillctl/semver` | Ein zentraler Loose-Semver-Vergleicher wählt backendübergreifend die höchste nicht widerrufene Version und prüft Versionsmonotonie bei propose. Ersetzt vier Kopien mit unterschiedlicher Behandlung eines führenden `v`. |
| `skillctl/homeroot` | Zentrale Auflösung des Nutzerverzeichnisses. Ausgelieferte Windows-Builds ignorieren `$HOME` für Sicherheitspfade; ausschließlich `%USERPROFILE%` zählt. |

**Artefakt-Backends (SPEC-0356)**

| Paket | Verantwortung |
|---------|----------------|
| `skillctl/artifact` | Austauschbare Artefakt-Repository-Abstraktion: ER1, Git-Forges und OCI-Registrys stehen gleichberechtigt hinter `Backend`. Der Inhaltsdigest ist die gemeinsame Invariante; alles andere sind backendnative Projektionen desselben SPEC-0190-Ereignisumschlags. |
| `skillctl/artifact/conformance` | Backendneutrale Lebenszyklus-Suite für jedes `artifact.Backend` (D8), ausgeführt gegen Git, ER1 und In-Memory-Fake. Backendparität wird damit getestet. |
| `skillctl/backend/git` | Git-Registry-Backend für `github://`, `gitlab://` und `local://`, einschließlich eingefrorenem Git Wire Format v1 als Datenträgervertrag. |
| `skillctl/backend/oci` | OCI-Registry-Backend D7: `.skb` als Layer mit Digest als Identität; Lebenszyklusereignisse als Referrer. |
| `skillctl/artifactauth` | Nur lesende Zugangsdatenauflösung je Backend D5: Umgebungsvariable vor Betriebssystem-Schlüsselbund; schreibt oder löscht keinen Zugangsdatenstore. |
| `skillctl/netguard` | Zentral geprüfte Entscheidung, ob ein Host nachweislich lokal ist; kontrolliert Zugangsdaten und TLS-Prüfausnahmen in Backends und ER1-Client. |

**Governance und Nachweise**

| Paket | Verantwortung |
|---------|----------------|
| `skillctl/outbox` | Transaktionale Audit-Outbox nach SPEC-0317 P0. |
| `skillctl/mutationstate` | Dauerhafte lokale Registry-/Epoch-/Uhrbeobachtungen mit explizitem Enrollment und gehaltener Mutationssperre; keine Garantie gegen Änderungen desselben Benutzers oder Maschinen-Rollback. |
| `skillctl/statemachine` | Benannter Offline-Zustandsautomat SPEC-0317 R-7. |
| `skillctl/govlevel` | Zentrales Vokabular der Governance-Stufen. |
| `skillctl/datascope` | Typisierter clientseitiger Vertrag nach SPEC-0196. |
| `skillctl/bodyscan` | Semantische Erkennung gefährlicher Prosa nach SPEC-0246 §4. |
| `skillctl/exitcode` | Zentrales Register der skillctl-Prozess-Exit-Codes. |
| `skillctl/auditevent` | Audit-Grundlage SPEC-0403: gemeinsamer Umschlag, Senken und Dispatcher, der das Verhalten bei Schreibfehlern bestimmt; stiller Verlust ist kein Standard. |
| `skillctl/auditexport` | Schnittstelle SPEC-0455 zwischen Audit-Drain und wählbarer Senke: Vertragstypen und Backend-Konformitätssuite T-00; Implementierungen folgen mit T-01. |
| `skillctl/secfile` | Härtet Rechte sicherheitsrelevanter Dateien. Unter Unix kein Zusatzschritt, da der Kernel 0600 durchsetzt; unter Windows echte DACL-Verarbeitung, weil Unix-Rechtebits dort nicht greifen. |

**Analyse, Berichte und UI**

| Paket | Verantwortung |
|---------|----------------|
| `skillctl/audit` | Ergebnisse je Skill für `skillctl audit`. |
| `skillctl/consolidate` | Analyse von Duplikaten und verwaisten Einträgen im Inventar. |
| `skillctl/delta` | Vergleicht zwei Inventare. |
| `skillctl/envreport` | Skill-Umgebungsberichte SPEC-0428: ENV-Adresse als Host-Hash, unveränderlicher Bericht je Umgebung und Erfassung aus einem Auditlauf. Entscheidend ist die Aufbewahrung. |
| `skillctl/report` | HTML- und Markdown-Berichte aus Inventaren. |
| `skillctl/review` | Lokaler HTTP-Server zur Prüfung von Delta-Berichten. |
| `skillctl/browse` | Interaktiver D3.js-Browser des Skill-Graphen. |
| `skillctl/menubar` | macOS-Menüleisten-App für den skillctl-Zustand. |
| `skillctl/sim` | Bibliothek hinter [`skillctl-sim`](program-index.de.md): Übergangssystem, erzeugter Szenarienkorpus und Orakel zum Vergleich SPEC-abgeleiteter Erwartungen mit beobachteten Läufen. |

**Trust Freeze (SPEC-0466 bis SPEC-0471)**

Bibliothek hinter `skillctl trust-freeze`: beobachtbaren Hostzustand erfassen,
als signierte Baseline genehmigen, offline prüfen und vergleichen. Importrichtung:
`redact` ist ein Blatt; der Kern importiert nur `redact`. Darauf bauen `probe`,
`platform/common`, `platform/linux` und `capture`. `seal`, `compare`, `policy`
und `report` lesen Bundles über den Kern. Nur `seal` erzeugt Baselines. `capture`,
`compare`, `policy`, `report`, `probe`, `redact` und Plattformpakete importieren es
nie; ein Guard-Test in `seal` prüft dies.

Nachweisstufe je Plattform in dieser Änderung: `common.identity` ist implementiert,
mit Fixtures getestet und für linux, darwin und windows crosskompiliert. Die zwölf
Probes in `platform/linux` sind implementiert, fixturegetestet und für linux
crosskompiliert. Auf darwin und windows sind sie nicht implementiert und werden
mit der Plattform als Grund als unsupported erfasst. Keine davon ist auf einer
realen Zielplattform getestet; diese Stufe wird je Commit in Nachweisdateien
festgehalten, niemals vom Build behauptet. Vollständige Plattformunterstützung
ist damit nicht belegt.

| Paket | Verantwortung |
|---------|----------------|
| `skillctl/trustfreeze` | Kernmodell: Schema-IDs, geschlossene Enums, kanonisches JSON, Manifest- und Inhaltsdigest, Bundle-Leser/-Schreiber, Integrität, Vollständigkeit, Subject-ID und Uhr. Führt keine Probes aus und signiert nicht. |
| `skillctl/trustfreeze/redact` | Redaktor und ausschließlich hier erzeugbarer Bytetyp `Redacted`. Der Bundle-Schreiber akzeptiert Nachweise nur in diesem Typ, damit rohe Toolausgabe nie ungeschwärzt ins Bundle gelangt. Die Schlüsselnamenregel prüft Wertformen über `IsPolicyAnswer`, eine geschlossene Menge von Konfigurationsantworten, und berücksichtigt die von einer Probe deklarierten Schlüsselklassen. |
| `skillctl/trustfreeze/probe` | Probe-Schnittstelle/-Register, shellfreier Befehlsrunner mit Ausgabelimits und Abbruch des Tools samt Kindern zur Deadline: Prozessgruppe unter Unix, Parent-PID-Baum mit dokumentierten Lücken unter Windows. Außerdem deterministischer Fake-Runner, Dateiwurzeln, Grenzen und Plattformmatrix. |
| `skillctl/trustfreeze/platform/common` | `common.identity` für `device/os` und `device/host`: os-release, `uname -r`, `uname -m` unter linux; `sw_vers`, `uname -r`, `uname -m` samt Rosetta-2-Prüfung unter darwin; CurrentVersion-Registry und `IsWow64Process2` unter windows. Architektur stammt immer vom Betriebssystem statt vom Build. |
| `skillctl/trustfreeze/platform/linux` | Linux-Probes und Resolver wirksamer Privilegien: `linux.packages`, `linux.users`, `linux.sudo`, `linux.ssh`, `linux.systemd`, `linux.mounts`, `linux.network.listeners`, `linux.network.routes`, `linux.dns`, `linux.firewall`, `linux.containers`, `linux.executables`. Dünne Leser über reine Parser aufgezeichneter Toolausgaben. Keine Rechteerhöhung: Für Root erfordernde Antworten wird `permission_denied` statt einer leeren Liste gemeldet. Der Resolver bildet sudo-Regeln, sudo- und Containergruppenmitgliedschaften sowie autorisierte Schlüssel auf Befugnisse mit Quellen, Privileg und Begründung ab. |
| `skillctl/trustfreeze/platform/linux`, die drei Probes aus T-03b | `linux.network.routes` liest `ip -j route show`, `ip -6 -j route show` und `ip -j addr show`: ein Artefakt je Route (`network/route/...`) und Adresse (`network/address/...`), dazu `network/routes`. `linux.dns` erfasst `resolvectl status --no-pager` als beobachteten Zustand (`dns/resolver`, `dns/link/<iface>`) und `/etc/resolv.conf` als deklarierten Zustand (`dns/resolv-conf`); beide werden nie zusammengeführt. `linux.executables` hasht die von anderen Probes benannten Programme aus Unit-`ExecStart` und Listener-Prozessen als `executable/<path>` sowie `system/executables`: sha256, Größe, Modus, Eigentümer, Gruppe und Paket über `dpkg -S` oder Snap-Pfad. Fehlende Zuordnung ist ein Befund statt eines Fehlers. Grenzen je Erfassung: 1024 Kandidaten vor Pfadauflösung, 256 Dateien, 128 MiB je Datei und Wurzeln `/bin`, `/opt`, `/sbin`, `/snap`, `/usr`, `/usr/local`. Home-Verzeichnisse werden nie gelesen. Bei Zeitablauf steht `timeout`; ungelesene Programme tragen `hash_state: not_read` statt `unreadable`. |
| `skillctl/trustfreeze/capture` | Erfassungsengine mit eingebetteten Profilen: führt Profil-Probes aus, erfasst jede Lücke einschließlich ausgelassener Probes, schwärzt alle Nachweisdateien vor dem Schreiben erneut und erzeugt ein Capture-Bundle. Genehmigt und signiert nie. |
| `skillctl/trustfreeze/seal` | Freigabe, domänengetrennte ed25519-Baseline-Erklärung, `baseline approve`, Offline-Prüfung, Vertrauensrichtlinie und Selbstfreigabeprüfung. Einziges Paket, das Baselines erzeugt. |
| `skillctl/trustfreeze/compare` | Struktureller Vergleich verifizierter Baseline und aktuellem Bundle mit versionierten Normalisierungsregeln `trust-freeze/normalize/v1` und standardmäßig `trust-freeze/normalize/v2`. V2 ergänzt Routenmetrik und den aktuell von systemd-resolved abgefragten Resolver. Vergleicht, bewertet aber nicht. |
| `skillctl/trustfreeze/policy` | Reiner Richtlinienprüfer: ein Befund je Änderung, höchste Schwere gewinnt; `fail_on` steuert nur den Exit-Code. Liefert die Standardrichtlinie mit. |
| `skillctl/trustfreeze/report` | Deterministischer Bericht eines Capture-, Baseline- oder Diff-Bundles als kanonisches JSON, daraus erzeugtes YAML oder eigenständige HTML-Seite mit Digests und Hinweisen. Reine Projektion ohne Entscheidung; Markdown und SARIF fehlen. |

**Benachbarte Pakete auf oberster Ebene**

| Paket | Verantwortung |
|---------|----------------|
| `skillgate` | Kooperatives Aufruf-Gateway nach SPEC-0202. |
| `skillbundle` | Deterministisches Packen von `.skb`-Skill-Bundles. |

## G. Weitere interne Pakete (`internal/*`)

Die zuvor hier aufgeführten Thinking-Engine-Interna wurden am 2026-09-17 entfernt.
Die experimentelle Engine liegt jetzt in einem eigenen Repository
(BUILD-AUDIT-0001, Eigentümerentscheidung E-2a). Unter `internal/` bleibt das eine
Paket, auf das der übrige Baum angewiesen ist.

| Paket | Verantwortung |
|---------|----------------|
| `internal/dbdriver` | Gemeinsame Datenbanktreiber-Unterstützung für `cmd/skillctl`, `pkg/skillctl/browse`, `pkg/skillctl/outbox`, `pkg/timetracking` und `pkg/tracking`; deshalb beim Engine-Umzug erhalten. |
