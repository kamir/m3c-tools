# Overview: the security and trust model

Sprachen / Languages: [Deutsch](ueberblick.de.md) | [English](ueberblick.en.md)

What the trust layer claims, where each claim is supported, and the order in
which a security review reads this repository. This page does not make its
own assessment; it points to the documents that each carry part of the evidence.

Audience: a CISO or security reviewer before approval, and the person
supporting that review.

Role: Security · Language: EN · Updated: 2026-09-16

## The core rule in one sentence

**Every trust claim points to a mitigation and the tests exercising it, or
is marked as a GAP:** this is the standard
[THREAT_MODEL.md](../../../THREAT_MODEL.md) applies to itself, and the standard
against which this repository asks to be measured.

## The model in three sentences

1. `skillctl` gives every agent skill a verifiable identity and a lifecycle:
   author, pack, sign, admit, attest, verify/install, use,
   audit, revoke ([skillctl manual](../referenz/manual-skillctl.md)).
2. The chain verifies offline; a hosted registry, ledger or transparency log
   is complementary, never a prerequisite for verification
   (opening paragraph of the manual).
3. The threat catalogue has referenceable IDs (R01 through R12). Test comments
   cite all twelve; measured on 2026-09-16,
   `grep -rn 'THREAT-R' pkg/ cmd/` matches every one of the twelve IDs R01
   through R12. The convention is in [THREAT_MODEL.md](../../../THREAT_MODEL.md), §6.

## Reading order for a review

| Step | Document | Contents |
|---|---|---|
| 1 | [THREAT_MODEL.md](../../../THREAT_MODEL.md) | Runtime trust chain: threats R01 through R12 with mitigations, tests and the documented closure of earlier GAPs |
| 2 | [SECURITY.md](../../../SECURITY.md) | Reporting channel (private, GitHub Security Advisories), supported versions, supply-chain commitments |
| 3 | [required-checks.txt](../../security/required-checks.txt) | The manifest of intended required checks |
| 4 | [gosec-diff-gate.yml](../../../.github/workflows/gosec-diff-gate.yml) | The no-new-findings gate against the [signature baseline](../../security/gosec-inci-baseline.txt) |
| 5 | [Supply-chain security](../../../SECURITY.md#verifying-a-release) | Verify download signatures and provenance |
| 6 | [Operations runbook: Incident Response](../betrieb/ops-incident-response.en.md) | Compromised key or registry: detect, revoke, rotate, repin |
| 7 | [Operations routine: access tokens](../betrieb/ops-registry-tokens.en.md) | Token lifecycle including departures: the read token ends with the person's account; the write token belongs to the role and is rotated when personnel change |
| 8 | [Runbook: the audit trail](audit-spur.en.md) | Consolidates the three mechanisms: `audit` judges individual skills, `auditlog` reports the audit subsystem (SPEC-0403 §8), `translog` is the L1 transparency log; manual sections are linked there, while the registry timeline (admit, attest, revoke, install) is read in the [incident runbook, section 1](../betrieb/ops-incident-response.en.md) |

## Demonstrate rather than assert

| Format | Resource | Language |
|---|---|---|
| Offline demo with real exit codes: according to the quickstart, a poisoned bundle is rejected with exit 10 and a forced governance action is refused with exit 2 | [Quickstart: skillctl-demo](../nutzer/quickstart-skillctl-demo.md) | EN |
| Reproduce it yourself, offline, without a server | [Quickstart: skillctl](../nutzer/quickstart-skillctl.md) | EN |
| Configure author, reviewer and consumer separately | [Tutorial: first signed skill](../nutzer/tutorial-szenario-02-erster-signierter-skill.en.md) | DE |

## Limits this page states explicitly

1. The threat model covers the runtime trust chain, not the m3c-tools capture
   pipeline; its scope note states that boundary.
2. There are two gosec baselines, and only one has a gate: the blocking
   no-new-findings gate
   ([gosec-diff-gate.yml](../../../.github/workflows/gosec-diff-gate.yml),
   in the CI workflow) checks the signature baseline
   `gosec-inci-baseline.txt`; the SARIF snapshot
   [gosec-baseline.sarif](../../security/gosec-baseline.sarif) is
   not wired into a gate and serves only for triage.
3. A required check is bound to a job NAME; renaming silently disconnects
   enforcement. The explanation is in
   [required-checks.txt](../../security/required-checks.txt) itself.
4. Response times: [SECURITY.md](../../../SECURITY.md) targets acknowledgement
   "within a few working days" and commits to no fixed deadline for a fix
   or disclosure. Decided on 2026-09-16: the soft target is intentional;
   no hard SLA is promised; SECURITY.md records the dated decision.
