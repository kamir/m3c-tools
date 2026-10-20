# Sicherheitsrichtlinie

Sprachen / Languages: [Deutsch](SECURITY.de.md) | [English](SECURITY.md)

`skillctl` ist ein Vertrauenswerkzeug. Deshalb gelten für seine Lieferkette dieselben
Maßstäbe wie für andere. Diese Seite beschreibt die vertrauliche Meldung von
Sicherheitslücken und die Prüfung heruntergeladener Programme.

## Eine Sicherheitslücke melden

**Bitte kein öffentliches Issue für ein Sicherheitsproblem eröffnen.** Verwende die
vertraulichen [GitHub Security Advisories](https://github.com/kamir/m3c-tools/security/advisories/new)
über „Report a vulnerability“ im Security-Tab. Gib Folgendes an:

- betroffene Komponente (`m3c-tools`, `skillctl`, Installationsskript, Workflow) und Version oder Commit;
- minimale Reproduktion und beobachtete Auswirkungen;
- mögliche Korrekturvorschläge.

Wir streben eine Bestätigung innerhalb weniger Arbeitstage an und stimmen Korrektur und
Veröffentlichung mit dir ab. Bitte räume vor einer öffentlichen Bekanntgabe angemessene
Zeit zur Behebung ein.

Entschieden am 2026-09-16: Dies bleibt bewusst ein unverbindliches Ziel. Es besteht keine
feste Zusage zur Reaktionszeit; die Aussage ist kein SLA. Diese Entscheidung ist hier
festgehalten, damit das fehlende SLA nicht als Versehen erscheint.

## Unterstützte Versionen

Sicherheitskorrekturen gelten für das **neueste** Release jeder Linie: `vX.Y.Z` für das
Produkt und `skillctl/vX.Y.Z` für die signierte Vertrauens-CLI. Ältere Tags werden nicht
gepflegt; aktualisiere auf das neueste Release.

## Zusagen zur Lieferkette

Jedes Release wird in GitHub Actions gebaut und signiert. Das Repository enthält
**keinen langlebigen Signaturschlüssel**:

- **Schlüssellose cosign-Signaturen** über Release-Prüfsummen mittels GitHub OIDC.
  Der Signaturjob prüft die Signatur selbst; eine fehlerhafte Signatur lässt das Release
  scheitern, statt eine unsignierte Ausgabe auszuliefern.
- **SLSA-Build-Herkunft** (`multiple.intoto.jsonl`), geprüft durch `slsa-verifier`.
  Die signierte `skillctl/v*`-Linie zielt auf SLSA Level 3.
- **ed25519-Fallbacksignatur** der skillctl-`SHA256SUMS`, geprüft gegen den gepinnten
  `skillctl-release.pub`, damit auch Hosts ohne cosign Integrität prüfen können.
- **CycloneDX-SBOM** im skillctl-Release.
- **Gepinnter Bootstrap.** Installations-Einzeiler verwenden einen unveränderlichen
  Commit und SHA-256 je Skript statt des veränderlichen `master`-Branches.

## Ein Release prüfen

**cosign für die Produktlinie:**

```bash
cosign verify-blob checksums.txt \
  --bundle checksums.txt.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/kamir/m3c-tools/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

**SLSA-Herkunft:**

```bash
slsa-verifier verify-artifact <asset> \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/kamir/m3c-tools
```

**Mit `skillctl` installierte Skills** werden **offline** geprüft. Die ed25519-Vertrauenskette
benötigt weder Server noch gehostete CA im Prüfpfad. Widerrufslisten sind signiert, offline
und sperren im Fehlerfall:

```bash
skillctl verify-sig my-skill.skb --pubkey trusted.pub   # no network
```

Der [Produkt-Release-Workflow](.github/workflows/release.yml) und der
[skillctl-Release-Workflow](.github/workflows/skillctl-release.yml) definieren die
Signatur- und Herkunftsschritte der jeweiligen Release-Linie.
