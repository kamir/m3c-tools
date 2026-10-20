# Ops-Ueberblick: der Betrieb und seine Runbooks

Anleitungen fuer die Person, die ein Registry, eine Skill-Installation oder
die Capture-Pipeline betreibt. Die einzelnen Runbooks beschreiben die
Handgriffe und ihre Grenzen.

Rolle: Betrieb · Sprache: DE

## Wann welches Runbook

| Lage | Runbook |
|---|---|
| Zugangstoken einrichten oder nach einem Personalwechsel erneuern | [Zugangstoken fuer Registry und Skill-Repository](ops-registry-tokens.de.md) |
| Ein Schluessel oder das Registry ist kompromittiert | [Incident Response](ops-incident-response.de.md) |
| Registry sichern und wiederherstellen | [Registry-Backup und Restore](ops-registry-backup-restore.de.md) |
| Zustand pruefen und Ueberwachung anbinden | [Monitoring und Alarmierung](ops-monitoring.de.md) |
| Uploads schlagen fehl oder warten in der Queue | [Capture-Betrieb und Wiederanlauf](runbook-m3c-tools-capture.de.md) |
| Eine neue Maschine einrichten | [Voraussetzungen](../nutzer/prerequisites.md), [Quickstart: m3c-tools](../nutzer/quickstart-m3c-tools.md), [Quickstart: skillctl](../nutzer/quickstart-skillctl.md) |
| Signierte Skills zwischen Maschinen austauschen | [Szenario 01](../nutzer/tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md) |
| Autor, Reviewer und Konsument arbeiten getrennt | [Szenario 02](../nutzer/tutorial-szenario-02-erster-signierter-skill.de.md) |

## Vor der Diagnose

- **Trust Roots dem Registry-Typ zuordnen.** HTTP-Registry, ER1-`self` und
  Git-Registry verwenden unterschiedliche Konfigurationen. Die Zuordnung steht
  im [Manual: skillctl](../referenz/manual-skillctl.md#trust-roots--registries-which-file-when).
- **Exit-Codes auswerten.** Das [Manual: skillctl](../referenz/manual-skillctl.md#exit-codes)
  erklaert Verweigerungen und die jeweils naechsten Schritte.
- **`skillctl doctor --home` isoliert nicht alle Pruefungen.** Skills und
  Audit-Logs folgen dem Override; Trust Roots und Signing-Key werden weiterhin
  aus dem tatsaechlichen Home gelesen. `--home` allein genuegt deshalb nicht
  fuer eine isolierte Diagnoseumgebung.
- **Backend und Grenzen pruefen.** Die Betriebsanleitungen unterscheiden
  Git-, HTTP- und ER1-Registrys. Ihre Sicherungs- und Wiederherstellungsschritte
  sind nicht austauschbar.
