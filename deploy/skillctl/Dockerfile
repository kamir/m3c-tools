# deploy/skillctl/Dockerfile: container image for skillctl
# (SPEC-0354 D1, mirrors deploy/thinking-engine/Dockerfile).
#
# skillctl is the skill trust-plane CLI: pack / sign / verify / install /
# pull / attest / revoke / audit. It is pure Go with CGO disabled, so it
# builds to a fully static binary and ships on a `distroless/static` base,
# no shell, non-root, ~20 MB. The intended runtime shapes are:
#   • a k8s Job / initContainer  (pull -> verify -> install into a PVC), and
#   • a Compose/pod sidecar next to the MCP servers (SPEC-0354 D5).
#
# Build (engine-agnostic: docker OR podman):
#   make skillctl-image
#   make skillctl-image CONTAINER_ENGINE=podman
# Or directly:
#   docker build -f deploy/skillctl/Dockerfile -t m3c/skillctl:dev .
#
# NOTE: the capture-plane features (portaudio recorder, menubar) are cgo +
# macOS-only and are deliberately NOT part of any container. See SPEC-0354 §4.
# Only the reine-Go trust-plane is containerized here.

# ---- Stage 1: build ----------------------------------------------------
# CD-T11 / CD-06: base images are DIGEST-PINNED, not tag-floating. A tag like
# `golang:1.26-alpine` is mutable (the registry can repoint it), so pinning the
# tag alone lets an upstream repoint (or a registry compromise) swap the build
# toolchain under us. The @sha256 digest is content-addressed and immutable; the
# tag is kept as a human-readable comment. Refresh with:
#   docker buildx imagetools inspect golang:1.26-alpine   # -> index Digest
# Resolved 2026-09-02: golang:1.26-alpine == 1.26.8-alpine3.24 (>= go.mod
# toolchain go1.26.6, so no toolchain re-download at build time).
FROM golang:1.26-alpine@sha256:b6890e35ded5d19118c2bca3d7754dc4e6f694aac2d0aeb92f9807c2879e4230 AS builder

# git for VCS build metadata; ca-certificates so `go mod download` over
# https module proxies works.
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Prime the module cache first so source-only changes don't invalidate
# the dependency-download layer.
COPY go.mod go.sum ./
RUN go mod download

# Bring the full source in. .dockerignore trims irrelevant paths.
COPY . .

# Static build. -trimpath strips absolute paths; -s -w drops the symbol
# table and DWARF for a smaller binary. VERSION is stamped into
# main.version (printed by `skillctl version`).
ENV CGO_ENABLED=0
ARG VERSION=dev
RUN go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/skillctl \
      ./cmd/skillctl

# ---- Stage 2: runtime --------------------------------------------------
# distroless/static: no shell, no package manager, non-root by default.
# ca-certificates are included in the base, so `pull`/`verify`/`attest`
# can reach an HTTPS registry when a network path is provided.
#
# CD-T11 / CD-06: digest-pinned (see Stage 1). Refresh with:
#   docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot
# Resolved 2026-09-02 (multi-arch index digest).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /out/skillctl /usr/local/bin/skillctl

# The nonroot user's home. Trust/inventory state (~/.claude/skills,
# ~/.m3c-tools, ~/.cache/m3c) is expected to be mounted here as volumes
# for Job/sidecar use; nothing is baked in.
ENV HOME=/home/nonroot
USER nonroot

ENTRYPOINT ["/usr/local/bin/skillctl"]
# No default subcommand: skillctl with no args prints usage and exits
# non-zero, which is the right "you must pick a verb" behavior for a Job.
