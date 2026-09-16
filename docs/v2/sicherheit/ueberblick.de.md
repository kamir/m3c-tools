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
   audit, revoke ([Manual: skillctl](../../manual-skillctl.md)).
2. Die Kette verifiziert offline; ein gehostetes Registry, ein Ledger oder
   ein Transparenz-Log ist komplementaer, nie Voraussetzung des Pruefpfads
   (Kopfabsatz des Manuals).
3. Der Bedrohungskatalog traegt zitierbare IDs (R01 bis R12). Heute zitieren
   Testkommentare drei davon; gemessen am 2026-09-16 trifft
   `grep -rn 'THREAT-R' pkg/ cmd/` genau R01, R06 und R10. Die Konvention,
   nach der die uebrigen nachzuziehen sind, steht in
   [THREAT_MODEL.md](../../../THREAT_MODEL.md), §6.

## Leseweg fuer eine Pruefung

| Schritt | Dokument | Was dort steht |
|---|---|---|
| 1 | [THREAT_MODEL.md](../../../THREAT_MODEL.md) | Laufzeit-Trust-Kette: Bedrohungen R01 bis R12 mit Mitigationen, Tests und den dokumentiert geschlossenen frueheren GAPs |
| 2 | [SECURITY.md](../../../SECURITY.md) | Meldeweg (privat, GitHub Security Advisories), unterstuetzte Versionen, Supply-Chain-Zusagen |
| 3 | [docs/security/required-checks.txt](../../security/required-checks.txt) | die Pflicht-Checks auf `master` und warum die Namensbindung im Baum liegt |
| 4 | [gosec-backlog](../../security/gosec-backlog.md) und [codeql-backlog](../../security/codeql-backlog.md) | der offene Static-Analysis-Bestand, klassifiziert, mit Datum |
| 5 | [gosec-diff-gate.yml](../../../.github/workflows/gosec-diff-gate.yml) | das blockierende no-new-findings-Tor: Pflicht-Check auf `master` (required-checks.txt), prueft gegen die Signatur-Baseline `gosec-inci-baseline.txt`; die aeltere SARIF-Punktaufnahme [gosec-baseline](../../security/gosec-baseline.md) ist ein anderes, unverdrahtetes Artefakt |
| 6 | [Release flow, "What CI signs"](../../releasing.md) | was ein Release signiert und woran ein Installierender es prueft |
| 7 | [Ops-Runbook: Incident Response](../../ops-incident-response.de.md) | kompromittierter Schluessel oder Registry: erkennen, widerrufen, rotieren, neu pinnen |
| 8 | [Ops-Routine: Zugangstoken](../../ops-registry-tokens.de.md) | Token-Lebenszyklus inkl. Ausscheiden: Lese-Token endet mit dem Konto der Person, das Schreibtoken gehoert der Rolle und wird beim Personalwechsel rotiert |
| 9 | Audit-Spur: [`audit`](../../manual-skillctl.md#audit-antivirus-style-verdict-per-skill), [`auditlog`](../../manual-skillctl.md#auditlog-audit-subsystem-observability-spec-0403-8), [`translog`](../../manual-skillctl.md#translog-l1-transparency-log) | drei Traeger im Manual: `audit` urteilt je Skill, `auditlog` zeigt das Audit-Subsystem (SPEC-0403 §8), `translog` ist das L1-Transparenz-Log; die Registry-Zeitleiste (admit, attest, revoke, install) liest das [Incident-Runbook, Abschnitt 1](../../ops-incident-response.de.md) |

## Vorfuehren statt behaupten

| Format | Traeger | Sprache |
|---|---|---|
| Offline-Demo mit echten Exit-Codes: laut Quickstart wird ein vergiftetes Bundle mit Exit 10 abgewiesen und eine erzwungene Governance-Aktion mit Exit 2 verweigert | [Quickstart: skillctl-demo](../../quickstart-skillctl-demo.md) | EN |
| Selbst nachvollziehen, offline, ohne Server | [Quickstart: skillctl](../../quickstart-skillctl.md) | EN |
| Argumentation fuer Security-Expertin und CTO als Infografik | [CISO-Deck (EN)](../../skillctl-ciso-deck.html) · [CISO-Deck (DE)](../../skillctl-ciso-deck.de.html) | EN/DE |
| Zwei-Personen-Nachweis ueber ER1, mit Pass-Kriterien | [Runbook: two-person ER1 exchange](../../runbook-two-person-er1-exchange.md) | EN |

## Grenzen, die diese Seite nicht verschweigt

1. Das Threat Model deckt die Laufzeit-Trust-Kette ab, nicht die
   Capture-Pipeline von m3c-tools; die Abgrenzung steht in seinem Scope-Hinweis.
2. Es gibt zwei gosec-Baselines, und nur eine traegt ein Tor: das blockierende
   no-new-findings-Tor
   ([gosec-diff-gate.yml](../../../.github/workflows/gosec-diff-gate.yml),
   Pflicht-Check auf `master`) prueft gegen die Signatur-Baseline
   `gosec-inci-baseline.txt`; die SARIF-Punktaufnahme
   [gosec-baseline](../../security/gosec-baseline.md) (2026-09-03) ist
   unverdrahtet und dient nur der Triage.
3. Ein Pflicht-Check ist an einen Job-NAMEN gebunden; eine Umbenennung
   entkoppelt die Durchsetzung lautlos. Die Begruendung steht in
   [required-checks.txt](../../security/required-checks.txt) selbst.
4. Reaktionszeiten: [SECURITY.md](../../../SECURITY.md) nennt als Ziel eine
   Bestaetigung "within a few working days" und sagt keine feste Frist fuer
   Fix oder Disclosure zu. Ob eine harte SLA zugesagt wird, ist eine offene
   Owner-Entscheidung (Stand 2026-09-16); diese Seite weist das aus, statt
   eine Frist zu erfinden.
