# Bedrohungsmodell: die skillctl-Vertrauensebene

Sprachen / Languages: [Deutsch](THREAT_MODEL.de.md) | [English](THREAT_MODEL.md)

`skillctl` bildet die Befugnisebene von m3c-tools: Es signiert, lässt zu, prüft,
installiert und widerruft Agenten-Skills, die Wissen lesen und in deinem Auftrag
handeln. Als Vertrauenswerkzeug muss sein Bedrohungsmodell denselben
Nachweisstandard erfüllen: Jede Aussage nennt eine Gegenmaßnahme samt prüfenden
Tests oder ausdrücklich eine **GAP** mit erfasstem Folgeauftrag.

Dieses Dokument wird fortgeschrieben. Bedrohungs-IDs `R01` bis `R12` sollen direkt
in den Tests zitiert werden; siehe [Abschnitt 6](#6-das-modell-aktuell-halten).
So bleibt die Verbindung zwischen behauptetem Schutz und tatsächlichem Testnachweis
bei Codeänderungen erhalten.

**Begleitdokumente:** [SECURITY.de.md](SECURITY.de.md) für Meldungen und Lieferkette,
[CONTRIBUTING.de.md](CONTRIBUTING.de.md) für CI-Prüfungen und
[README.de.md](README.de.md#sicherheit-und-lieferkette) für Releases und Herkunft.
Dieses Modell behandelt die Laufzeit-Vertrauenskette vom signierenden Autor bis
zur Ausführung beim Nutzer. Die Release-Lieferkette behandeln die Begleitseiten.

**Geltungsbereich.** Erfasst werden `skillctl` und seine erzeugten beziehungsweise
konsumierten Vertrauensartefakte. Nicht erfasst wird die m3c-tools-Erfassungspipeline
von YouTube, Audio und Screenshot nach ER1 mit ihrem anderen Risikoprofil.
Auch die frühere Thinking Engine mit HMAC zu Flask, Kafka und lokalem LLM sowie die
Python-MCP-Server `mcp-skill-server` und `rag-mcp-server` liegen außerhalb dieses Modells.
Die Engine wurde aus diesem Repository entfernt; die MCP-Server benötigen eigene Modelle.
Wo Skills auf ER1-Wissen zugreifen, bilden die deklarierten `data_dependencies`
die Grenze; siehe R11.

---

## 1. Geltungsbereich und Schutzgüter

Angreifer wollen folgende Güter fälschen, ersetzen, unterdrücken oder offenlegen.
Die Reihenfolge reicht vom vielfach weitergegebenen `.skb` bis zu Vertrauenswurzeln.

| # | Schutzgut | Beschreibung | Bedeutung |
|---|-------|------------|----------------|
| A1 | **Skill-Bundles (`.skb`)** | Paketierte, signierte Einheit aus Inhalt und Manifest, adressiert über den Digest. | Ausführbare Nutzlast; Zulassung manipulierter Bundles ermöglicht beliebigen Skill-Code. Der Digest bildet die Identität der gesamten Kette. |
| A2 | **ed25519-Vertrauenskette** | Autoren- und Registry-Signatur je Bundle samt Identitätsdatensätzen zur Prüfung. | Offline-Nachweis der Identität. Ein Bruch ermöglicht Identitätsübernahme oder unbemerkte Änderung. |
| A3 | **Signaturschlüssel** | Private ed25519-Schlüssel der Autoren und des Registrys sowie Eigentümerschlüssel der agentid-Identitäten. | Schlüsselbesitz ist Identitätskontrolle. Nach Offenlegung kann der Angreifer signieren; Gegenmaßnahme ist Widerruf A4. |
| A4 | **Widerrufslisten und Widerrufs-HEAD** | Signierte Erklärung nicht mehr vertrauenswürdiger Identitäten/Bundles mit Epoche und monotoner Untergrenze. | Einziger Weg zum Vertrauensentzug nach Schlüssel- oder Skill-Kompromittierung; muss bei fehlenden Daten sperren und durch unsignierte Trägerdaten unfälschbar sein. |
| A5 | **Vertrauenswurzeln** | `~/.claude/skill-trust-roots.yaml` mit gepinnten Registry-Schlüsseln, `governance_minimum` und Richtlinien wie `require_independent_review`. | Grundlage der Offline-Entscheidung. Der Prüfer vertraut dieser Datei; Integrität und ACLs sind entscheidend. |
| A6 | **Installationsziel** | Verzeichnis zum Entpacken verifizierter Bundles, etwa unter `~/.claude/…`. | Umwandlung nicht vertrauenswürdiger Bytes in Dateien; Angriffsfläche für Path Traversal, Symlink-Ausbruch und Archivbomben. |
| A7 | **Transparenzprotokoll (`translog`) und Audit-Spur** | Lokale, anhängende Aufzeichnung von Vertrauensentscheidungen, Installation, Widerruf und Aufrufbelegen. | Nachträgliche Nachweise müssen Replay und Manipulation widerstehen und dürfen keine Zugangsdaten offenlegen. |

Zwei übergreifende Eigenschaften sind selbst Schutzgüter:

- **Offline-Prüfbarkeit:** Die Vertrauenskette muss ohne Netzwerk und gehostete CA
  entscheiden. Eine erreichbare Autorität wäre zusätzliche Angriffsfläche und Ausfallursache.
- **Sperren im Fehlerfall:** Bei Mehrdeutigkeit, Panic, fehlenden Daten oder unbekannter
  Richtlinie lautet die Entscheidung deny statt allow.

---

## 2. Vertrauensgrenzen

Ein Skill gelangt vom Autorenrechner über einen nicht vertrauenswürdigen Träger zur
Ausführung beim Nutzer; für eigene Skills liegt CI dazwischen. Jeder Pfeil markiert
Datenübergabe und eine erneut zu prüfende Vertrauensgrenze.

```
   ┌────────────┐   sign (ed25519, A3)   ┌──────────────────────┐   admit + sign      ┌────────────┐
   │  AUTHOR    │ ─────────────────────▶ │  REGISTRY / CARRIER  │ ──────────────────▶ │  CONSUMER  │
   │ (trusted   │      .skb + author sig │  ER1 · Git · OCI     │  registry sig, meta │ (installs, │
   │  key held) │                        │  ── UNTRUSTED ──     │                     │  runs)     │
   └────────────┘                        └──────────────────────┘                     └────────────┘
         │                                          │                                        │
         │ CI/build (first-party): keyless          │  carries bytes + UNSIGNED metadata     │  offline verifier +
         │ cosign/OIDC, SLSA L3: see SECURITY.md    │  (annotations, filenames, status)      │  local install root (A6)
         ▼                                          ▼                                        ▼
   provenance over releases            *projection ≠ proof*: R05              trust roots (A5) + translog (A7)
```

**B1: Autor ↔ Registry.** Der Autor signiert, das Registry speichert und liefert.
Der Träger ist nicht vertrauenswürdig. OCI-Annotationen, Git-Datei-/Verzeichnisnamen
und `status` sind Komfortmetadaten ohne Authentisierung. Identität und Widerruf
müssen aus dem **signierten Umschlag** kommen statt aus dessen Trägerprojektion.
Dies ist R05 und der Grund für die Regel zur signierten Identität von Git-Ereignissen.

**B2: Registry ↔ Nutzer.** Bundle und Metadaten werden über ein fremdes Netzwerk
geladen. Bis zur Prüfung der ed25519-Kette und Widerrufsuntergrenze sind alle
Eingaben angreiferbeeinflussbar. Pull prüft in Stufen; Gate 5 prüft den Widerruf.
Ein veralteter oder wiederholter Registry-Stand ist eine eigene Bedrohung, R03/R04.

**B3: CI / Build.** Eigene Releases unterliegen SECURITY.md: schlüsselloses cosign
über Prüfsummen, SLSA L3 für `skillctl/v*`, ed25519-Fallback auf `SHA256SUMS` und
gepinnter Bootstrap. Dieses Modell setzt diese Zusagen voraus und untersucht die
Verwendung der gelieferten Artefakte durch den Prüfer.

**B4: Offline-Prüfer.** Die wichtigste Grenze: Bundle, Vertrauenswurzeln und lokaler
Widerrufsstand müssen ohne Netzwerk oder gehostete CA zur Zulassung oder Ablehnung
führen. Eingaben sind A5 und die signierten Artefakte; die Zusage ist fail-closed.
`verify-hook` trifft diese Entscheidung direkt vor einer Skill-Aktion in Claude Code.

**B5: Lokales Installationsverzeichnis.** Übergang vom geprüften Bundle zu Dateien
auf dem Datenträger A6. Auch ein korrekt signiertes Bundle eines vertrauenswürdigen
Autors ist eine feindliche Eingabe für den Entpacker. Pfade, Symlinks und
Kompressionsverhältnisse wählt der Autor. R02 und R07 sichern diese Grenze.

---

## 3. Angreifer und Annahmen

Die Tabelle beschreibt angenommene Fähigkeiten und Grenzen der Angreifer.
Ein belastbares Modell benennt auch seine eigenen Grenzen.

| Angreifer | Kann | Kann laut Annahme nicht |
|-----------|-----|------------------|
| **Kompromittiertes/bösartiges Registry** | Beliebige Bytes, Metadaten und `status` liefern; zurückhalten oder wiederholen; OCI-Annotationen ändern; Git-Objekte umbenennen; alten Widerrufs-HEAD liefern. | Ohne privaten Schlüssel Autoren-/Registry-Signaturen fälschen oder signiert die monotone Widerrufsepoche senken. |
| **Kompromittiertes Autorenkonto ohne Schlüssel** | Im Registry unter dem Autor veröffentlichen und Metadaten schreiben. | Ohne A3 als Autor signieren; bei zusätzlichem Schlüsseldiebstahl gilt die nächste Zeile. |
| **Gestohlener Signaturschlüssel A3** | Bis zum Widerruf beliebige Bundles unter dieser Identität signieren. | Einen signierten, fail-closed Widerruf umgehen, sobald er ausgestellt ist und den Nutzer erreicht, R01. Dies begrenzt Schlüsseldiebstahl. |
| **Kompromittierte CI** | Eigene Produktbuilds beeinflussen. | Außerhalb der Laufzeitkette: B3 und SECURITY.md behandeln schlüssellose Signierung, Selbstprüfung im Job und SLSA L3; Restrisiko in Abschnitt 5. |
| **Bösartiger Autor mit gültiger Identität** | Innerhalb deklarierter Befugnisse schädlichen Skill-Code liefern und breite `data_dependencies` erklären. | Entpacker-Sandbox R02/R07 verlassen, aus nicht vertrautem Registry zugelassen werden R11 oder nach Tenant-/Datenquellenverweigerung beziehungsweise Widerruf handeln R11/R01. Schädliches Verhalten signierter Skills ist eine Governance-/Attestierungsfrage mit unabhängigem Review und `governance_minimum`; Signaturprüfung allein löst sie nicht. |
| **Bösartige Referenzdaten** | Präparierte Archive, übergroße Nutzlasten und Traversal-Pfade liefern. | Außerhalb des Installationsziels schreiben oder unbegrenzt Ressourcen beanspruchen; R02/R07 begrenzen dies. Zur Laufzeit geladene Referenzdaten muss der Skill selbst beurteilen, siehe Abschnitt 5. |
| **Netzwerk/passiver Träger** | Verwerfen, verzögern, wiederholen und umordnen. | Offline-Ergebnisse durch Unerreichbarkeit herabstufen; veraltete Zustände werden durch die Epochenuntergrenze erkannt, R03/R04/R12. |

**Schlüsselverwahrung A3.** Eigentümer halten private Schlüssel außerhalb dieses
Repositorys. keygen schreibt `*.priv`/`*.pub`; private Teile gelangen weder in Bundles
noch ins Registry. Vorausgesetzt wird normale Verwahrung durch das Betriebssystem.
Bei Versagen reagiert das System mit Widerruf statt Verhinderung. Deshalb tragen
R01/R04/R05 mit fail-closed, Monotonie und Unfälschbarkeit aus unsignierten Daten
wesentlich zum Modell bei.

**Keine gehostete CA.** Der Prüfpfad hat bewusst keine verpflichtende Online-Autorität,
zugunsten von Souveränität und Verfügbarkeit. Es gibt keinen abzufragenden
Widerrufsserver; Widerruf reist als **signierter, offline prüfbarer, monotoner Zustand**,
den der Nutzer besitzt oder abruft und neu prüft, R03/R04/R05/R12.

---

## 4. Bedrohungsregister R01 bis R12

Jeder Eintrag nennt Bedrohung, Code-Gegenmaßnahme und abdeckende Testfunktionen samt
Datei oder ausdrücklich GAP. Die Zuordnung wurde beim Schreiben gegen den Baum
inventarisiert und per Suche stichprobengeprüft; alle genannten Tests waren vorhanden.

### R01: Widerruf muss im Fehlerfall sperren

**Bedrohung.** Ein kompromittierter Schlüssel oder Skill bleibt installierbar,
weil Widerruf zurückgehalten, ein widerrufener Bundle-Digest ausgeliefert oder eine
widerrufene Autorenidentität als gültig dargestellt wird. Fehlender Widerruf darf
nicht als Erlaubnis interpretiert werden.

**Gegenmaßnahme.** Jede Vertrauensentscheidung prüft Widerruf und sperrt im
Fehlerfall: Der Prüfer lehnt widerrufene Digests ab, das Claude-Code-Gate verweigert
widerrufene Bundles, Pull stoppt an Gate 5. Installation mit widerrufenem Autor
endet mit `17` (`RevokeIdentityRevoked`) und nennt den Widerruf in stderr zur Audit-Zuordnung.

**Abdeckende Tests.**
- `TestVerifyBundle_RevokedDigest`: `cmd/skillctl/verify_bundle_test.go`
- `TestVerifyHook_RevokedBundle_Denied`: `cmd/skillctl/revoked_cache_test.go`
- `TestPullBundles_Revoked_RejectsAtGate5`: `pkg/skillctl/registry/er1_pull_test.go`
- `TestInstall_RevokedAuthor_Exit17`: `cmd/skillctl/install_e2e_test.go`

### R02: Path Traversal und Symlink-Ausbruch bei Installation

**Bedrohung.** Bundle oder Git-Registry-Baum schreiben beim Entpacken außerhalb
von A6, durch `../`, absolute Pfade oder Symlinks, die spätere Schreibvorgänge umleiten.

**Gegenmaßnahme.** Der Entpacker verweigert Traversal, absolute Pfade und Symlink-
Einträge und kanonisiert Pfade einschließlich Symlink-Auflösung vor dem Schreiben.
Aufgelöste Pfade außerhalb der Wurzel werden abgewiesen; das Git-Backend prüft Objektpfade ebenso.

**Abdeckende Tests.**
- `TestInstall_TarPathTraversal_Refused`: `pkg/skillctl/install/install_test.go`
- `TestExtractSkb_SymlinkRefused`: `pkg/skillctl/registry/install_trust_mode_test.go`
- `TestGitPathTraversalRejected`: `pkg/skillctl/backend/git/git_test.go`
- `TestCanonicalPath_ResolvesSymlink`: `pkg/skillctl/install/canonical_path_test.go`

### R03: Wiederholung eines veralteten Vertrauensstands

**Bedrohung.** Ein ehemals gültiges Registry-HEAD, eine Attestierung oder ein
Aufrufprotokolleintrag wird erneut geliefert, um auf einen Zustand vor Widerruf
oder Governance-Herabstufung zurückzusetzen.

**Gegenmaßnahme.** Pull verweigert wiederholte/veraltete Widerrufs-HEADs durch eine
Epochenuntergrenze. Das Aufrufprotokoll erkennt Replay beim Lesen, die
Governance-Prüfung verweigert wiederholte Attestierungen.

**Abdeckende Tests.**
- `TestPullBundles_ReplayedStaleHead_RejectedByEpochFloor`: `pkg/skillctl/registry/er1_pull_revoke_head_test.go`
- `TestReadAndVerifyTrail_DetectsReplay`: `cmd/skillctl/invocation_trail_test.go`
- `TestGovernance_ReplayedAttestationRefused`: `pkg/skillctl/verify/governance_signed_test.go`

### R04: Rollback und nicht monotone Epochen

**Bedrohung.** Ältere signierte Zustände mit kleinerer Widerrufsepoche oder früherer
Version erscheinen aktuell. Sie könnten Widerrufe aufheben oder verwundbare Versionen
zurückbringen. Anders als beim wortgleichen Replay R03 können die Daten echt signiert, aber alt sein.

**Gegenmaßnahme.** Epochen müssen monoton wachsen; niedrigere Epochen werden auch
bei Notfall-Rollback abgewiesen. Installation verweigert Versions-Downgrades.
Die Semver-Schicht prüft monotone Versionsordnung.

**Abdeckende Tests.**
- `TestEmergency_RollbackEpochRefused`: `pkg/skillctl/verify/emergency_test.go`
- `TestCheckEpochMonotonic`: `pkg/skillctl/registry/revocation_head_test.go`
- `TestInstall_RefusesDowngrade`: `pkg/skillctl/registry/install_trust_mode_test.go`
- `TestMonotonicity`: `pkg/skillctl/semver/semver_test.go`

### R05: Widerrufsumgehung durch unsignierte Trägerprojektionen

**Bedrohung.** Unsignierte OCI-Annotationen, Git-Datei-/Verzeichnisnamen oder JSON-
`status` werden wie signierte Daten behandelt. Umbenennung kann Widerrufe verstecken;
eine unsignierte Liste kann die Untergrenze fälschen. Dies ist die Klasse „Projektion ist kein Beweis“.

**Gegenmaßnahme.** Kind/Digest, revoked-by und bundle-digest stammen aus dem signierten
Umschlag. OCI-Umbenennung wirkt nicht; unsigniertes JSON kann die Widerrufsuntergrenze
nicht fälschen, ein unsignierter Widerruf unterdrückt keine Installation.

**Abdeckende Tests.**
- `TestOCIAnnotationRelabelDefeated`: `pkg/skillctl/backend/oci/oci_test.go`
- `TestRevokedFloor_UnforgeableViaUnsignedJson`: `cmd/skillctl/kill_switch_hardening_test.go`
- `TestPullBundles_UnsignedRevoke_DoesNotSuppress`: `pkg/skillctl/registry/er1_pull_test.go`

### R06: TOCTOU zwischen Prüfung und Nutzung, abgedeckt

**Bedrohung.** Geprüfte und genutzte Bytes unterscheiden sich, weil zwischen Digest-
Prüfung und Lesen Dateien ausgetauscht oder extrahierte Bäume vor der Ausführung verändert werden.

**Status: abgedeckt.** `TestVerifyThenUse_MutatedAfterVerify_RechecksAndFailsClosed`
in `pkg/skillctl/install/offline_verify_test.go` prüft zunächst eine unveränderte
Extraktion erfolgreich. Anschließend wird ein Byte verändert, die ganze Datei per
atomarem `rename` über den geprüften Inode ausgetauscht oder eine normale Datei auf
einen Symlink außerhalb des Baums umgebogen. Letzterer Vektor war zuvor nicht erfasst.
Jeder spätere Aufruf liest und hasht erneut und scheitert mit `ErrDigestMismatch`.
`verifyExtractedMatchesBlob` liegt auf dem Aufrufpfad von `verify_hook_cmds.go` zu
`VerifyInstalledOffline`/`VerifyInstalledSidecar` und ist zustandslos: kein gecachtes
Urteil und kein wiederverwendetes Prüfhandle. Die geprüften Bytes sind damit die
verwendeten Bytes. Eine Negativkontrolle ohne Mutation lässt den Untertest scheitern.
`TestVerdict_TamperedFile_MissesCache` deckt ergänzend die Nutzung des Urteilscaches ab.

### R07: Archivbomben durch Größen- oder Dateianzahl

**Bedrohung.** Ein signiertes, feindliches Bundle erschöpft beim Entpacken Speicher
oder Datenträger, etwa als gzip-Bombe oder Archiv mit extrem vielen Einträgen.

**Gegenmaßnahme.** Größen- und Dateianzahlgrenzen stoppen das Entpacken vor dem
Übernehmen der Bytes, sobald eine Grenze überschritten wird.

**Abdeckende Tests.**
- `TestInstall_GzipBomb_Refused`: `pkg/skillctl/install/install_test.go`
- `TestExtractSkb_OversizedAborts`: `pkg/skillctl/registry/install_trust_mode_test.go`
- `TestExtractSkb_TooManyFilesAborts`: `pkg/skillctl/registry/install_trust_mode_test.go`

### R08: Signaturmanipulation

**Bedrohung.** Bundle, Widerrufs-HEAD oder signierter Ereignisumschlag wird nach dem
Signieren geändert und in der Hoffnung ausgeliefert, dass die Änderung unentdeckt bleibt.

**Gegenmaßnahme.** ed25519 verweigert Änderungen nach der Signatur:
`EnvelopeVerify` scheitert bei manipuliertem Umschlag, die Prüfung einer separaten
Bundle-Signatur bei geänderten Bytes und die HEAD-Prüfung bei manipuliertem Widerruf.

**Abdeckende Tests.**
- `TestEnvelopeVerify_TamperedAfterSign`: `pkg/skillctl/registry/event_test.go`
- `TestVerifyDetached_TamperedBundle`: `pkg/skillctl/signing/verify_test.go`
- `TestRevocationHead_TamperDetected`: `pkg/skillctl/registry/revocation_head_test.go`

### R09: Falscher Schlüssel und Identitätsübernahme, Exit 11

**Bedrohung.** Ein Artefakt wird mit einem fremden Schlüssel signiert und als
Artefakt der behaupteten Identität ausgegeben.

**Gegenmaßnahme.** Eine nicht zum gepinnten öffentlichen Identitätsschlüssel passende
Signatur endet mit `11` (`ExitAuthorSigInvalid`). Dies unterscheidet sich für gezielte
Aufruferreaktionen von Widerruf `17` und Digest-Abweichung `10`. agentid-Mandate
prüfen Agentenidentitäten nach derselben Regel.

**Abdeckende Tests.**
- `TestAgentID_WrongKeyExit11`: `cmd/skillctl/agentid_cmds_test.go`
- `TestInstall_BadAuthorSig_Exit11`: `cmd/skillctl/install_e2e_test.go`
- signing **AC5** (sign with key A → verify with key B → exit 11), inside `TestEndToEnd`: `cmd/skillctl/signing_cmds_test.go`

### R10: Zugangsdatenoffenlegung, abgedeckt

**Bedrohung.** Signaturschlüssel, Git-Zugangsdaten oder andere Geheimnisse erscheinen
in Fehlermeldungen, Logs oder gespeichertem Zustand und werden später ausgelesen.

**Nachgewiesene Gegenmaßnahme.** Signieren legt private Schlüssel nicht in
Fehlerausgaben offen; das Git-Backend gibt keine Zugangsdaten aus.

**Status: abgedeckt.** `TestNoSecretAtRest_PersistedArtifacts` in
`cmd/skillctl/threat_r10_test.go` erzeugt die drei dauerhaften A7-Artefakte:
gerätesigniertes Aufrufprotokoll, HMAC-signierter Urteilscache und ed25519-signierter
Transparenz-HEAD/STH. Alle geschriebenen Dateien werden nach Geräteschlüssel-Seed,
Urteils-HMAC-Schlüssel und translog-Schlüssel in sieben Kodierungen (roh, Hex,
Base64-Varianten) durchsucht. Ausgenommen sind ausschließlich die eigenen
0600-Schlüsseldateien. Positivkontrolle im eigenen Schlüssel und Negativkontrolle
mit eingepflanztem Seed verhindern einen inhaltsleeren Test. Artefakte enthalten
nur öffentliche KeyIDs und separate Signaturen.

**Abdeckende Tests.**
- `TestNoSecretAtRest_PersistedArtifacts`: `cmd/skillctl/threat_r10_test.go` (no secret at rest)
- `TestSignBundle_DoesNotLeakKeyInError`: `pkg/skillctl/signing/sign_test.go` (error-path)
- `TestGitCredNoLeak`: `pkg/skillctl/backend/git/git_test.go` (error-path)

### R11: Bösartige und unsignierte Zulassung ablehnen

**Bedrohung.** Ein nicht vertrautes Registry oder ein eigentlich gesperrter Skill
wird trotzdem zugelassen, insbesondere wenn das Gate selbst Fehler oder Panic
meldet und dabei freigibt.

**Gegenmaßnahme.** Installation aus nicht in den Wurzeln verankertem Registry
endet mit `12` (`ExitRegistryNotTrusted`). Claude Code sperrt bei unmanaged-policy deny.
Eine Panic im Gate führt ebenfalls zur Ablehnung, niemals zur Freigabe.

**Abdeckende Tests.**
- `TestInstall_UntrustedRegistry_Exit12`: `cmd/skillctl/install_e2e_test.go`
- `TestVerifyHook_UnmanagedPolicyDeny_Blocks`: `cmd/skillctl/verify_hook_cmds_test.go`
- `TestVerifyHook_PanicInGate_FailsClosedDeny`: `cmd/skillctl/verify_hook_cmds_test.go`

### R12: Offline-Prüfung ohne Netzwerk oder gehostete CA

**Bedrohung.** Der Prüfer wird von einer Online-Autorität abhängig gemacht.
Netzwerkkontrolle oder Ausfall könnte dann „nicht prüfbar“ zur Freigabe machen
oder die Verfügbarkeit verhindern.

**Gegenmaßnahme.** Die Kette entscheidet ohne Netzwerk und gehostete CA.
agentid stellt Mandate offline aus und prüft sie offline. Das Claude-Code-Gate
verweigert auch ohne Netz eine schlechte Signatur. translog-Belege bleiben beim
Offline-Roundtrip prüfbar.

**Abdeckende Tests.**
- `TestAgentID_IssueVerifyOffline`: `cmd/skillctl/agentid_cmds_test.go`
- `TestVerifyHook_OfflineFirst_DeniesBadSig`: `cmd/skillctl/verify_hook_cmds_test.go`
- `TestReceipt_VerifyOfflineRoundTrip`: `pkg/skillctl/translog/receipt_test.go`

---

## 5. Restrisiken und Lücken

Einige Risiken liegen strukturell außerhalb der Reichweite von skillctl.
Ein abgedeckter Eintrag bedeutet keine vollständige Absicherung aller Oberflächen.

**Kürzlich geschlossen:** Die früheren Testlücken sind jetzt abgedeckt:

- **R06:** `TestVerifyThenUse_MutatedAfterVerify_RechecksAndFailsClosed` prüft
  Byteänderung, Dateiaustausch und Symlink-Umbiegung nach der Verifikation jeweils neu und sperrt.
- **R10:** `TestNoSecretAtRest_PersistedArtifacts` durchsucht Aufrufprotokoll,
  Urteilscache und translog/STH nach Geräte-, HMAC- und translog-Schlüsseln in sieben Kodierungen.

**Strukturelle Restrisiken, andernorts oder durch Entwurf behandelt:**

- **Schädliches Verhalten signierter Skills.** Eine gültige Signatur belegt Identität
  und Unverändertheit statt Sicherheit. Innerhalb erlaubter Befugnisse bleibt Schaden
  möglich. Governance, unabhängiges Review (`require_independent_review`),
  `governance_minimum` und Tenant-/Datenquellenverweigerung mit Exits 16/17 begrenzen dies.
  Die Vertrauenskette belegt Authentizität, Governance behandelt Sicherheit.
- **Zur Laufzeit geladene Referenzdaten.** Außerhalb des von R02/R07 begrenzten Bundles
  ist deren Inhaltsvertrauen Aufgabe des Skills. `data_dependencies` deklariert die
  Oberfläche, bereinigt sie aber nicht.
- **Kompromittierte CI/Builds B3.** [SECURITY.de.md](SECURITY.de.md) behandelt diese
  durch schlüsselloses cosign, Selbstprüfung im Job, SLSA L3 und gepinnten Bootstrap.
  Der Nachweis wird hier nicht wiederholt; kompromittierte eigene Builds sind ein Lieferkettenvorfall.
- **ACLs der Vertrauenswurzeln und lokalen Zustände A5/A7.** Der Prüfer vertraut
  `skill-trust-roots.yaml`. Schreibzugriff darauf oder auf Caches verschiebt die
  Vertrauenswurzel. Dateisystem-ACLs sind vorausgesetzte OS-Kontrolle und werden von
  diesem Modell nicht selbst durchgesetzt. Plattformhärtung, etwa Windows-ACLs für
  Wurzeln/Caches, wird in Sicherheitsreviews verfolgt.
- **Schlüsselverwahrung A3.** Die Verhinderung von Schlüsseldiebstahl liegt außerhalb
  des Modells. Gemessen wird die Stärke des Widerrufs als Antwort, R01/R04/R05.

---

## 6. Das Modell aktuell halten

Bedrohungs-IDs sind nur mit Verbindung zum Code nützlich. Eine Kommentarzeile am
abdeckenden Test ermöglicht das Verfolgen vom Risiko zum Nachweis und zurück.
Gemessen am 2026-09-16: `grep -rn 'THREAT-R' pkg/ cmd/` fand für R01 bis R12
jeweils mindestens einen abdeckenden Test.

```go
// THREAT-R05: an unsigned OCI annotation relabel must not suppress a signed revoke.
func TestOCIAnnotationRelabelDefeated(t *testing.T) { ... }
```

Regeln:

- Beim Ergänzen oder Verschieben eines Tests seinen `THREAT-Rxx`-Kommentar und dieses
  Register gemeinsam aktualisieren; die Zuordnung ist nur so aktuell wie die letzte Änderung.
- Beim Schließen einer Lücke wie R06/R10 GAP/THIN durch Testname und Datei ersetzen
  und den passenden `THREAT-Rxx`-Kommentar im Test ergänzen.
- Neue Klassen erhalten neue IDs ab `R13`, statt bestehende Zeilen umzudeuten.
  IDs bleiben stabile Referenzen.
- Abschnitt 4 wurde beim Schreiben inventarisiert und per Suche stichprobengeprüft.
  Regelmäßiger Abgleich von `grep -rn 'THREAT-R'` mit dem Register erkennt Drift kostengünstig.

Ein Bedrohungsmodell ohne Verweise aus Tests veraltet zu unbelegten Behauptungen.
Deshalb im Test zitieren.
