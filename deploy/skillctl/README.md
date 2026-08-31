# skillctl container image + `.skb` OCI publish (SPEC-0354 D1 + D2)

The **P0** slice of **SPEC-0354** (Containerized Skill Trust-Plane) — see the private
maintenance plane for the spec and its companion containerization research.

Only the **reine-Go trust-plane** is containerized. The capture-plane
(portaudio recorder, menubar — cgo + macOS-only) is deliberately excluded;
that is why `.goreleaser.yml` also excludes macOS. See SPEC-0354 §4.

## D1 — the image

`Dockerfile` builds a static (`CGO_ENABLED=0`) `skillctl` on a
`gcr.io/distroless/static-debian12:nonroot` base: no shell, non-root, ~16 MB.

```bash
make skillctl-image                      # build with docker (default)
make skillctl-image CONTAINER_ENGINE=podman   # or podman — same CLI
make skillctl-image-smoke                # acceptance checks
```

**Verified acceptance (2026-08-14, docker 29.3):**

| Check | Result |
|---|---|
| `skillctl version` from inside the image | prints the ldflag-stamped version |
| image user | `nonroot` (non-root) |
| image size | **16.2 MB** (≤ 25 MB target) |
| shell present? | no — `/bin/sh` absent (distroless) |

**Runtime shapes:** k8s Job / initContainer (`pull → verify → install` into a
PVC) and Compose/pod sidecar next to the MCP servers (SPEC-0354 D5). Mount the
trust/inventory state as volumes: `~/.claude/skills`, `~/.m3c-tools`,
`~/.cache/m3c`. Secrets come from env/secret-mounts, **never** the macOS Keychain
or a home-dir session file.

## D2 — publish a `.skb` as an OCI artifact

`../../scripts/publish-skb.sh` pushes a signed bundle into any OCI registry via
**ORAS** (artifact-type `application/vnd.m3c.skill.bundle.v1+gzip`) and signs the
reference with **cosign**. The reference is derived from the bundle filename
(`<name>@<version>.skb` → `<registry>/skills/<name>:<version>`).

```bash
# Preview exactly what would happen (no oras/registry needed):
make publish-skb SKB=er1-progress-report@1.0.0.skb REGISTRY=ghcr.io/kamir \
     PUBLISH_ARGS="--dry-run"

# Real publish (needs `oras`, a registry login, and a cosign key/OIDC):
COSIGN_KEY=author.key make publish-skb \
     SKB=er1-progress-report@1.0.0.skb REGISTRY=ghcr.io/kamir \
     PUBLISH_ARGS="--verify-after"
```

**Fail-closed exit codes:** `2` bad input · `3` oras missing · `4` cosign
missing but signing requested · `5` push failed / byte-identity mismatch.

**Verified (2026-08-14):** dry-run derives ref/sha256/mediaType and prints the
exact `oras push` + `cosign sign` commands; all fail-closed paths return the
right codes. The live push/pull/cosign round-trip needs `oras` + a registry and
is the CI integration step (SPEC-0354 §7, against a local Zot).

Consumer side: `oras pull` + `skillctl verify` — trust lives in the registry
metadata + trust-roots, not inside the artifact.
