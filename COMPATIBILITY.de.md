# Kompatibilitätsrichtlinie

Sprachen / Languages: [Deutsch](COMPATIBILITY.de.md) | [English](COMPATIBILITY.md)

Was stabil bleiben muss und welche älteren Artefakte ein Release unterstützt.
Signierte `.skb`-Bundles und ihre Attestierungsereignisse leben länger als eine CLI-
Version und werden auf fremden Rechnern geprüft. Für `skillctl` hat deshalb
**Formatkompatibilität Vorrang vor API-Kompatibilität**. Aufrufer können auf ein
umbenanntes Flag reagieren; ein im Vorjahr signiertes Bundle muss heute weiter prüfbar sein.
Bei Konflikten hat das Übertragungs-/Bundleformat Vorrang.

Dies sind verbindliche Zusagen aus Entscheidung H8d statt unverbindlicher Ziele.
[Die Prüfung](#wie-die-zusagen-geprüft-werden) nennt vorhandene mechanische Nachweise.

## Unterstützte Versionen

Nur das **neueste** Release jeder Linie wird unterstützt:

- **Produkt:** `vX.Y.Z` für `m3c-tools` und gebündelte Programme;
- **skillctl:** `skillctl/vX.Y.Z` als eigene Versionsreihe der signierten Vertrauens-CLI.

Die Linien verwenden getrennte Tags und versionieren unabhängig. Siehe
[Produktworkflow](.github/workflows/release.yml) und
[skillctl-Workflow](.github/workflows/skillctl-release.yml).
Ältere Tags werden nicht gepflegt; Sicherheitskorrekturen erscheinen in der neuesten
Version jeder Linie. Dies entspricht der in [SECURITY.md](SECURITY.md#supported-versions)
beschriebenen Menge unterstützter und korrigierter Versionen.

## SLA für Sicherheitskorrekturen

| Schweregrad | Ziel |
|----------|--------|
| HIGH / CRITICAL | Korrektur in der neuesten Linie **innerhalb von 7 Tagen** nach bestätigter Meldung |
| andere | nach Möglichkeit im nächsten geplanten Release |

Vertraulich melden: [SECURITY.md](SECURITY.md#reporting-a-vulnerability).
Die Frist beginnt mit der Bestätigung. Eine Korrektur wird als neues Release
veröffentlicht; Backports auf ältere Tags erfolgen nicht.

## Inkompatible Änderungen

Änderungen, die Aufrufer brechen, erscheinen **nur mit MAJOR-Versionsanhebung** und
**immer mit Migrationshinweis** im Release. Inkompatibilität betrifft die Aufrufer
und wird nicht automatisch aus Diffs abgeleitet. MAJOR ist eine bewusste Entscheidung
über `make release-major`; die Ableitungsregel erzeugt MAJOR nie automatisch:
siehe [scripts/derive-bump.sh](scripts/derive-bump.sh).

## `.skb`-Bundleformat

Das Bundleformat ist die zentrale Kompatibilitätsoberfläche. Das Archiv enthält
`bundle.json`; dessen `schema` ist die Formatversion, aktuell `m3c-skill-bundle/v1`,
Konstante `skillbundle.Schema` in
[`pkg/skillbundle/manifest.go`](pkg/skillbundle/manifest.go).
Das Manifest trägt außerdem die Skill-Semver `version` und den Inhaltsdigest
`bundle_digest` als SHA-256 des kanonischen Archivs. Dieser ist die Bundle-Identität.

- Leser akzeptieren Bundles der **aktuellen und vorherigen MINOR-Version N−1** ihrer
  Linie. Ein MINOR-Upgrade macht vertraute Bundles nicht unbrauchbar.
- Jede Änderung der Interpretation vorhandener Bytes ist ein **Formatbruch** und
  verlangt MAJOR sowie eine neue Schema-Version, etwa `m3c-skill-bundle/v1` → `.../v2`.
  Leser prüfen dieses Feld und verweigern inkompatible Bundles ausdrücklich.
  Registry-Trägerformate verfahren ebenso und sperren im Fehlerfall: Ein neueres
  Übertragungsformat führt zu „upgrade skillctl“ statt bestmöglicher Interpretation.

Neue optionale `bundle.json`-Felder innerhalb einer MAJOR-Version brechen das Format
nicht. Alte Leser ignorieren unbekannte Schlüssel; der signierte `bundle_digest` bleibt prüfbar.

## CLI-Flags

Ein entferntes oder umbenanntes Flag muss **mindestens eine MINOR-Version vor Entfernung
als veraltet markiert** sein. Währenddessen funktioniert es weiter, und das Handbuch
nennt die Abkündigung. Damit laufen auf eine MINOR-Version gepinnte Skripte über die
nächste hinaus weiter. Eine inkompatible Entfernung folgt der
[Regel für inkompatible Änderungen](#inkompatible-änderungen).

## Richtlinien- und Konfigurationsschemas

Innerhalb einer MAJOR-Version sind Vertrauenswurzel- und Richtlinienkonfigurationen
**nur additiv**: Optionale neue Schlüssel sind zulässig, bestehende Einstellungen
behalten über MINOR und PATCH ihre Bedeutung. Umdeutung oder Entfernung eines
Schlüssels ist ein Formatbruch mit MAJOR-Anhebung.

## Wie die Zusagen geprüft werden

Wo Prüfungen existieren, beruhen Zusagen nicht nur auf Vertrauen:

- **CLI-Flags:** [`cmd/docaudit`](cmd/docaudit), aufgerufen durch `make check-docs`,
  vergleicht Implementierung und Handbuch in beiden Richtungen je CLI. Echte,
  undokumentierte oder dokumentierte, nicht vorhandene Flags lassen den Build scheitern.
  Abkündigungen bleiben sichtbar, solange das Flag existiert; entfernte Flags dürfen
  keinen verwaisten Handbucheintrag hinterlassen.
- **Versionsanhebung:** Ein zentraler Loose-Semver-Vergleicher in
  [`pkg/skillctl/semver`](pkg/skillctl/semver) prüft Monotonie bei propose, abgesichert
  durch Vergleichs- und Monotonietests. Die höchste nicht widerrufene Version wird
  durch eine gemeinsame Implementierung statt vier abweichender Kopien bestimmt.
- **`.skb`-Format:** Beim Packen wird `schema` ins Bundle geschrieben und explizit auf
  Formatbrüche geprüft. Trägerformate verweigern neuere Versionen ebenfalls ausdrücklich.
- **N−1-Lesezusage:** `TestWireFormatOlderReleaseStillReadable` in
  [`cmd/skillctl/wire_format_compat_test.go`](cmd/skillctl/wire_format_compat_test.go)
  führt vollständigen prüfenden Pull und Offline-Installation des aktuellen Builds gegen
  eine eingecheckte Byte-Fixture eines älteren Releases aus:
  [`cmd/skillctl/testdata/wireformat`](cmd/skillctl/testdata/wireformat).
  Der benachbarte Layout-Freeze in
  [`pkg/skillctl/backend/git/format_test.go`](pkg/skillctl/backend/git/format_test.go)
  schreibt und liest mit demselben Build und sichert damit Selbstkonsistenz.
  Nur die alte Fixture erkennt Änderungen, die Schreiber und Leser gemeinsam verschieben.

Versionsauswahl beschreibt [CONTRIBUTING.md](CONTRIBUTING.md#commit-messages-conventional-commits),
Release-Einstiege das [Makefile](Makefile), Versionsunterstützung und vertrauliche
Meldung [SECURITY.de.md](SECURITY.de.md).
