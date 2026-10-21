# Lokale Fallback-Signatur für Releases

[Deutsch](release-fallback.de.md) | [English](release-fallback.en.md)

Der normale Release-Workflow erzeugt einen CI-Entwurf. Der lokale Helfer ergänzt
eine Ed25519-Fallback-Signatur für Installer ohne Cosign aus **bestehenden CI-Bytes**.
Er baut keinen Checkout, erzeugt keine Tags, lädt keine Assets hoch, generiert
kein Runbook und veröffentlicht nichts in THOH. Ein veränderter oder fremder
Checkout kann keine Release-Binärdateien liefern. Den Helfer aus einem
vertrauenswürdigen, geprüften Checkout ausführen; er ist keine Sandbox gegen
bösartigen lokalen Code oder Werkzeuge mit den Rechten des Operators.

```sh
tools/skillctl-release.sh skillctl/v0.5.1
```

Diesen Operator-Helfer unter Linux oder macOS mit Python 3 ausführen (POSIX-Dateigrößenlimits).
Das ändert die unterstützten Kundenplattformen der CLI einschließlich Windows nicht.
Weitere Voraussetzungen: authentifizierter `gh`-Lesezugriff auf Release und Tag,
vertrauenswürdig vorinstallierte `cosign`, `slsa-verifier` (CLI-Vertrag gegen
v2.7.1 geprüft) und OpenSSL mit Ed25519-Unterstützung. Fehlende Werkzeuge oder
Nachweise führen zum Abbruch; es wird nichts installiert. Der CI-Entwurf bzw.
das Release zum exakten Tag muss bereits die fünf Standard-Binärdateien,
`SHA256SUMS`, `SHA256SUMS.cosign.bundle` und genau ein `*.intoto.jsonl`-Provenance-Asset
enthalten. Nicht unterstützte Formate führen zum Abbruch. Asset-Metadaten und heruntergeladene
Größen müssen übereinstimmen; Binärdateien sind auf je 128 MiB, Metadaten auf je
4 MiB und deklarierte Assets insgesamt auf 512 MiB begrenzt. Der Download-Prozess
hat zusätzlich ein Schreiblimit von 128 MiB je Datei. Binärdateien werden
blockweise gehasht statt vollständig in den Speicher geladen. Ein Kopierfehler
entfernt das von diesem Aufruf angelegte Ausgabeverzeichnis.

Vor dem Öffnen von `RELEASE_KEY` (Standard `~/.config/m3c/skill-release.key`) führt
der Helfer folgende Schritte aus:

1. Tag validieren und dessen Remote-Commit auflösen, auch bei annotierten Tags.
2. Ausschließlich benötigte Assets in ein privates temporäres Verzeichnis laden.
3. Das exakte Manifest mit Cosign gegen die genaue Tag-Identität
   `https://github.com/kamir/m3c-tools/.github/workflows/skillctl-release.yml@refs/tags/<tag>`
   und den Aussteller `https://token.actions.githubusercontent.com` prüfen.
4. Genau fünf kanonische Prüfsummeneinträge verlangen und jede Binärdatei prüfen.
5. Jede Binärdatei mit SLSA gegen Repository, exakten Quell-Tag und den in CI
   gepinnten generischen Builder v2.1.0 prüfen. Nur die Ausgabe erfolgreicher
   Verifier-Aufrufe mit `--print-provenance` auswerten: Das signierte v0.2-Statement
   muss genaue Subject-Namen und Digests, Quell-Commit, Release-Workflow sowie
   Commit und Tag der Umgebung binden.
6. Remote-Tag und Manifest-Bytes erneut prüfen.

Anschließend signiert er das unveränderte heruntergeladene Manifest und prüft die
Signatur gegen `INFRA/skillctl-release.pub`, unabhängig gepinnt auf den SHA256-Fingerprint
des rohen Ed25519-Schlüssels
`5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2`.
Ein anderer Signierschlüssel führt zum Fehler. Vorhandene Ausgaben und Symlinks in
den Ausgabeverzeichnissen werden abgelehnt. Lokale Ergebnisse liegen unter
`release/<tag>/`; das Hochladen bleibt ein separater geprüfter Vorgang.
`THOH_PUBLISH` hat für diesen Helfer keine Wirkung. Runbooks separat mit
`tools/skillctl-runbook.sh` erzeugen.

Die Prüfungen belegen Artefaktherkunft und konsistente Bytes innerhalb der
konfigurierten Vertrauensanker. Sie belegen weder Schwachstellenfreiheit noch
aktuelle Kundenfreigabe, vollständige Release-Evidenz oder eine dauerhafte
Fixierung eines veränderlichen GitHub-Tags nach dem letzten Lesen.
CI-Promotion und Evidenz-Gates bleiben separat.

Offline-Tests verwenden gemockte GitHub-/Cosign-/SLSA-Antworten sowie echte
temporäre Ed25519-Schlüssel und OpenSSL. Sie belegen Ablauf, Ablehnungsfälle und
lokale Signaturprüfungen; keine Live-Sigstore-/SLSA-Prüfung eines echten Releases.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/skillctl_release_fallback_test.py
```
