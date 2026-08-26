# deploy/skillctl/Dockerfile — container image for skillctl
# (SPEC-0354 D1, mirrors deploy/thinking-engine/Dockerfile).
#
# skillctl is the skill trust-plane CLI: pack / sign / verify / install /
# pull / attest / revoke / audit. It is pure Go with CGO disabled, so it
# builds to a fully static binary and ships on a `distroless/static` base —
# no shell, non-root, ~20 MB. The intended runtime shapes are:
#   • a k8s Job / initContainer  (pull -> verify -> install into a PVC), and
#   • a Compose/pod sidecar next to the MCP servers (SPEC-0354 D5).
#
# Build (engine-agnostic — docker OR podman):
#   make skillctl-image
#   make skillctl-image CONTAINER_ENGINE=podman
# Or directly:
#   docker build -f deploy/skillctl/Dockerfile -t m3c/skillctl:dev .
#
# NOTE: the capture-plane features (portaudio recorder, menubar) are cgo +
# macOS-only and are deliberately NOT part of any container — see SPEC-0354 §4.
# Only the reine-Go trust-plane is containerized here.

# ---- Stage 1: build ----------------------------------------------------
FROM golang:1.25-alpine AS builder

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
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/skillctl /usr/local/bin/skillctl

# The nonroot user's home. Trust/inventory state (~/.claude/skills,
# ~/.m3c-tools, ~/.cache/m3c) is expected to be mounted here as volumes
# for Job/sidecar use; nothing is baked in.
ENV HOME=/home/nonroot
USER nonroot

ENTRYPOINT ["/usr/local/bin/skillctl"]
# No default subcommand: skillctl with no args prints usage and exits
# non-zero, which is the right "you must pick a verb" behavior for a Job.
