# skillctl-Containerimage und .skb über OCI veröffentlichen (SPEC-0354 D1 und D2)

[Deutsch](README.de.md) · [English](README.md)

Der **P0**-Teil von **SPEC-0354**, Containerized Skill Trust-Plane.
Spezifikation und begleitende Containerisierungsrecherche liegen auf der privaten Maintenance-Ebene.

Containerisiert wird nur die **reine Go-Vertrauensschicht**. Die Erfassungsschicht mit
PortAudio-Recorder und Menüleiste, also cgo und macOS-Funktionen, ist bewusst ausgeschlossen.
Deshalb schließt `.goreleaser.yml` macOS ebenfalls aus. Siehe SPEC-0354 §4.

## D1: das Image

`Dockerfile` baut ein statisches `skillctl` mit `CGO_ENABLED=0` auf
`gcr.io/distroless/static-debian12:nonroot`: keine Shell, kein Root, etwa 16 MB.

```bash
make skillctl-image                      # build with docker (default)
make skillctl-image CONTAINER_ENGINE=podman   # or podman: same CLI
make skillctl-image-smoke                # acceptance checks
```

**Geprüfte Abnahme am 2026-08-14 mit docker 29.3:**

| Prüfung | Ergebnis |
|---|---|
| `skillctl version` im Image | Gibt die über ldflags gesetzte Version aus |
| Image-Nutzer | `nonroot`, ohne Root-Rechte |
| Image-Größe | **16,2 MB**, Ziel höchstens 25 MB |
| Shell vorhanden? | Nein, `/bin/sh` fehlt, distroless |

**Laufzeitvarianten:** k8s Job oder initContainer mit `pull → verify → install` in ein
PVC, sowie Compose-/Pod-Sidecar neben den MCP-Servern, SPEC-0354 D5.
Trust- und Inventarzustand als Volumes einbinden: `~/.claude/skills`, `~/.m3c-tools`,
`~/.cache/m3c`. Secrets stammen aus Umgebungsvariablen oder Secret-Mounts,
**niemals** aus macOS-Keychain oder einer Sitzungsdatei im Home-Verzeichnis.

## D2: ein .skb als OCI-Artefakt veröffentlichen

`../../scripts/publish-skb.sh` überträgt ein signiertes Bundle per **ORAS** in ein
beliebiges OCI-Registry, mit Artefakttyp `application/vnd.m3c.skill.bundle.v1+gzip`,
und signiert die Referenz mit **cosign**. Die Referenz entsteht aus dem Dateinamen:
`<name>@<version>.skb` → `<registry>/skills/<name>:<version>`.

```bash
# Preview exactly what would happen (no oras/registry needed):
make publish-skb SKB=er1-progress-report@1.0.0.skb REGISTRY=ghcr.io/kamir \
     PUBLISH_ARGS="--dry-run"

# Real publish (needs `oras`, a registry login, and a cosign key/OIDC):
COSIGN_KEY=author.key make publish-skb \
     SKB=er1-progress-report@1.0.0.skb REGISTRY=ghcr.io/kamir \
     PUBLISH_ARGS="--verify-after"
```

**Fail-closed-Exit-Codes:** `2` ungültige Eingabe, `3` oras fehlt, `4` cosign fehlt
bei angeforderter Signierung, `5` Push fehlgeschlagen oder Bytes nicht identisch.

**Geprüft am 2026-08-14:** Dry-Run leitet ref, sha256 und mediaType ab und zeigt die
genauen Befehle `oras push` und `cosign sign`. Alle Fail-closed-Pfade liefern die
richtigen Codes. Der echte Push-/Pull-/cosign-Rundlauf benötigt `oras` und ein Registry
und ist der CI-Integrationsschritt nach SPEC-0354 §7 gegen ein lokales Zot.

Konsumentenseite: `oras pull` und `skillctl verify`. Vertrauen liegt in Registry-Metadaten
und Trust Roots, nicht im Artefakt selbst.
