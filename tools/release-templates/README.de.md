# skillctl-Release-Vorlagen

[Deutsch](README.de.md) | [English](README.md)

## Generator für Onboarding-Runbooks (Standard der Release-Vorbereitung)

Jedes skillctl-Release enthält ein **zur Version passendes Onboarding-Runbook**:
ein eigenständiges, CSP-konformes HTML-Arbeitsblatt, das neue Herausgeber für
*genau diese Version* durch install → keygen → login → package → publish → upgrade führt.

- **Vorlage:** `skillctl-publisher-runbook.template.html` ist die maßgebliche
  Quelle. Versionsabhängige Tokens verwenden den Platzhalter `__SKILLCTL_VERSION__`.
- **Generator:** `tools/skillctl-runbook.sh <tag> [out.html]` setzt die Version
  ein und prüft anschließend, dass keine Platzhalter und keine externen Ressourcen
  übrig bleiben; damit bleibt das Ergebnis CSP-konform und offline nutzbar.
- **In die Release-Vorbereitung eingebunden:** `tools/skillctl-release.sh <tag>`
  ruft den Generator automatisch auf und legt `skillctl-publisher-runbook.html`
  neben den Binärdateien in `release/<tag>/` ab. Jedes Release erzeugt dadurch
  ohne manuellen Zusatzschritt das passende Runbook.

## Der Deskriptor: `runbook.meta.json` (BUG-0224)

Menschen arbeiten das HTML durch; der THOH-Katalog speichert `runbook.meta.json`,
damit Arbeit **zugewiesen und verfolgt** werden kann. Dies ist die Begleitdatei
nach SPEC-0275 für `rb-skillctl-publisher`. Sie liegt hier, weil ihre `steps[]`
aus der benachbarten Vorlage abgelesen werden.

- **`steps[].id` muss den `data-step`-Attributen der Vorlage entsprechen**;
  aktuell `s1` bis `s14`. Das Arbeitsblatt verbucht Fortschritt je `data-step`,
  der Server zählt Abschlüsse je `steps[].id`. Abweichende IDs erzeugen
  Fortschritt ohne passenden Empfänger.
- **Neue Schritte in Vorlage und Deskriptor im selben Commit ergänzen.** `s11`
  für erneute Validierung ist der einzige optionale Schritt: `"required": false`.
- Gelesen von `tools/skillctl-runbook-publish.sh` automatisch und von
  `skillctl runbook publish --meta <path>`. Ohne die Datei verwenden beide einen
  eingebauten Deskriptor ohne Schritte; der Katalogeintrag kann dann niemals
  `complete` erreichen. Das war BUG-0224.
- `version`, `source` und `html_url` stehen **nicht** in der Datei. Sie werden
  bei Veröffentlichung ergänzt (SPEC-0275, Abschnitt 4).

### Manuelle Verwendung

```sh
# into the release dir (default)
tools/skillctl-runbook.sh skillctl/v0.2.11-rc1

# into the living onboarding copy (sibling private maintenance plane)
tools/skillctl-runbook.sh skillctl/v0.2.11-rc1 \
  "${M3C_MAINTENANCE_DIR}"/ONBOARDING/skillctl-publisher-runbook.html
```

### Runbook bearbeiten

Bearbeiten Sie die **Vorlage**, niemals eine erzeugte Kopie. Halten Sie sie
vollständig eigenständig, mit eingebettetem CSS/JS und ohne externe Abrufe,
damit die CSP-Prüfung besteht. Die Arbeitsblatt-Engine für Fortschritt,
CLI-Ausgaben und Feedback je Schritt, Kopiersymbole und sitzungsabhängige
Eingabevorlagen liegt im eingebetteten `<script>` der Vorlage.
