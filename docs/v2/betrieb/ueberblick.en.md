# Operations overview: operation and runbooks

Sprachen / Languages: [Deutsch](ueberblick.de.md) | [English](ueberblick.en.md)

Instructions for the person operating a registry, a skill installation or
the capture pipeline. Each runbook describes the procedures and their limits.

Role: Operations · Language: EN

## Which runbook to use

| Situation | Runbook |
|---|---|
| Configure access tokens or renew them after a personnel change | [Access tokens for the registry and skill repository](ops-registry-tokens.en.md) |
| A key or the registry is compromised | [Incident Response](ops-incident-response.en.md) |
| Back up and restore a registry | [Registry backup and restore](ops-registry-backup-restore.en.md) |
| Check health and connect monitoring | [Monitoring and alerting](ops-monitoring.en.md) |
| Uploads fail or wait in the queue | [Capture operations and recovery](runbook-m3c-tools-capture.en.md) |
| Set up a new machine | [Prerequisites](../nutzer/prerequisites.md), [Quickstart: m3c-tools](../nutzer/quickstart-m3c-tools.md), [Quickstart: skillctl](../nutzer/quickstart-skillctl.md) |
| Exchange signed skills between machines | [Scenario 01](../nutzer/tutorial-szenario-01-eigene-skills-mehrere-maschinen.en.md) |
| Author, reviewer and consumer work separately | [Scenario 02](../nutzer/tutorial-szenario-02-erster-signierter-skill.en.md) |

## Before diagnosis

- **Match trust roots to the registry type.** HTTP registries, ER1 `self` and
  Git registries use different configurations. The mapping is in the
  [skillctl manual](../referenz/manual-skillctl.md#trust-roots--registries-which-file-when).
- **Evaluate exit codes.** The [skillctl manual](../referenz/manual-skillctl.md#exit-codes)
  explains refusals and the respective next steps.
- **`skillctl doctor --home` does not isolate every check.** Skills and
  audit logs follow the override; trust roots and the signing key are still
  read from the actual home directory. `--home` alone is therefore insufficient
  for an isolated diagnostic environment.
- **Check the backend and its limits.** The operating instructions distinguish
  Git, HTTP and ER1 registries. Their backup and restoration procedures are
  not interchangeable.
