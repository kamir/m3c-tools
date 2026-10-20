# Ueberblick: das Sicherheits- und Vertrauensmodell

Was die Vertrauensschicht behauptet, wo jede Behauptung belegt ist, und in
welcher Reihenfolge eine Sicherheitspruefung dieses Repository liest. Diese
Seite bewertet nichts selbst; sie fuehrt zu den Dokumenten, die je einen Teil
der Beweislast tragen.

Zielgruppe: eine CISO-Leserin oder ein Security-Reviewer vor einer Freigabe,
und die Person, die einer solchen Pruefung zuarbeitet.

Rolle: Sicherheit · Sprache: DE · Stand: 2026-09-16

## Die Grundregel in einem Satz

**Jede Vertrauensaussage zeigt auf eine Mitigation und die Tests, die sie
ausueben, oder sie ist als GAP markiert:** das ist der Massstab, den
[THREAT_MODEL.md](../../../THREAT_MODEL.md) an sich selbst anlegt, und der
Massstab, an dem dieses Repository gemessen werden will.

## Das Modell in drei Saetzen

1. `skillctl` gibt jedem Agent-Skill eine pruefbare Identitaet und einen
   Lebenszyklus: author, pack, sign, admit, attest, verify/install, use,
   audit, revoke ([Manual: skillctl](../referenz/manual-skillctl.md)).
2. Die Kette verifiziert offline; ein gehostetes Registry, ein Ledger oder
   ein Transparenz-Log ist komplementaer, nie Voraussetzung des Pruefpfads
   (Kopfabsatz des Manuals).
3. Der Bedrohungskatalog traegt zitierbare IDs (R01 bis R12). Testkommentare
   zitieren alle zwoelf; gemessen am 2026-09-16 trifft
   `grep -rn 'THREAT-R' pkg/ cmd/` jede der zwoelf IDs R01 bis R12. Die
   Konvention steht in [THREAT_MODEL.md](../../../THREAT_MODEL.md), §6.

## Leseweg fuer eine Pruefung

| Schritt | Dokument | Was dort steht |
|---|---|---|
| 1 | [THREAT_MODEL.md](../../../THREAT_MODEL.md) | Laufzeit-Trust-Kette: Bedrohungen R01 bis R12 mit Mitigationen, Tests und den dokumentiert geschlossenen frueheren GAPs |
| 2 | [SECURITY.md](../../../SECURITY.md) | Meldeweg (privat, GitHub Security Advisories), unterstuetzte Versionen, Supply-Chain-Zusagen |
| 3 | [required-checks.txt](../../security/required-checks.txt) | das Manifest der vorgesehenen Pflicht-Checks |
| 4 | [gosec-diff-gate.yml](../../../.github/workflows/gosec-diff-gate.yml) | das no-new-findings-Tor gegen die [Signatur-Baseline](../../security/gosec-inci-baseline.txt) |
| 5 | [Supply-chain security](../../../SECURITY.md#verifying-a-release) | Signaturen und Provenance eines Downloads pruefen |
| 6 | [Ops-Runbook: Incident Response](../betrieb/ops-incident-response.de.md) | kompromittierter Schluessel oder Registry: erkennen, widerrufen, rotieren, neu pinnen |
| 7 | [Ops-Routine: Zugangstoken](../betrieb/ops-registry-tokens.de.md) | Token-Lebenszyklus inkl. Ausscheiden: Lese-Token endet mit dem Konto der Person, das Schreibtoken gehoert der Rolle und wird beim Personalwechsel rotiert |
| 8 | [Runbook: die Audit-Spur](audit-spur.de.md) | die drei Traeger konsolidiert: `audit` urteilt je Skill, `auditlog` zeigt das Audit-Subsystem (SPEC-0403 §8), `translog` ist das L1-Transparenz-Log; die Manual-Abschnitte sind dort verlinkt, die Registry-Zeitleiste (admit, attest, revoke, install) liest das [Incident-Runbook, Abschnitt 1](../betrieb/ops-incident-response.de.md) |

## Vorfuehren statt behaupten

| Format | Traeger | Sprache |
|---|---|---|
| Offline-Demo mit echten Exit-Codes: laut Quickstart wird ein vergiftetes Bundle mit Exit 10 abgewiesen und eine erzwungene Governance-Aktion mit Exit 2 verweigert | [Quickstart: skillctl-demo](../nutzer/quickstart-skillctl-demo.md) | EN |
| Selbst nachvollziehen, offline, ohne Server | [Quickstart: skillctl](../nutzer/quickstart-skillctl.md) | EN |
| Autor, Reviewer und Konsument getrennt einrichten | [Tutorial: erster signierter Skill](../nutzer/tutorial-szenario-02-erster-signierter-skill.de.md) | DE |

## Grenzen, die diese Seite nicht verschweigt

1. Das Threat Model deckt die Laufzeit-Trust-Kette ab, nicht die
   Capture-Pipeline von m3c-tools; die Abgrenzung steht in seinem Scope-Hinweis.
2. Es gibt zwei gosec-Baselines, und nur eine traegt ein Tor: das blockierende
   no-new-findings-Tor
   ([gosec-diff-gate.yml](../../../.github/workflows/gosec-diff-gate.yml),
   im CI-Workflow) prueft gegen die Signatur-Baseline
   `gosec-inci-baseline.txt`; die SARIF-Punktaufnahme
   [gosec-baseline.sarif](../../security/gosec-baseline.sarif) ist
   unverdrahtet und dient nur der Triage.
3. Ein Pflicht-Check ist an einen Job-NAMEN gebunden; eine Umbenennung
   entkoppelt die Durchsetzung lautlos. Die Begruendung steht in
   [required-checks.txt](../../security/required-checks.txt) selbst.
4. Reaktionszeiten: [SECURITY.md](../../../SECURITY.md) nennt als Ziel eine
   Bestaetigung "within a few working days" und sagt keine feste Frist fuer
   Fix oder Disclosure zu. Entschieden am 2026-09-16: es bleibt bewusst bei
   dem weichen Ziel, eine harte SLA wird nicht zugesagt; SECURITY.md traegt
   die Entscheidung datiert.
