# deploy/thinking-engine/Dockerfile: multi-stage build for the m3c
# Thinking Engine (SPEC-0167 Stream 2c).
#
# Stage 1: compile the binary with the `thinking_kafka` tag so the
# real franz-go driver is wired in. CGO disabled → purely static
# binary that runs on a minimal Alpine base.
#
# Stage 2: copy the binary into a fresh Alpine and run as a non-root
# user. Healthcheck curls /v1/health on the default port.
#
# Target image size: <30 MB (thinking-engine binary + alpine + curl).
#
# Build:
#   docker build -f deploy/thinking-engine/Dockerfile \
#     -t m3c/thinking-engine:dev .
# Or via Makefile:
#   make thinking-image

# ---- Stage 1: build ----------------------------------------------------
# CD-T11 / CD-06: base images are DIGEST-PINNED, not tag-floating, exactly as in
# deploy/skillctl/Dockerfile. A tag like `golang:1.25-alpine` is mutable: the
# registry can repoint it, so pinning the tag alone lets an upstream repoint (or
# a registry compromise) swap the build toolchain under us. The @sha256 digest is
# content-addressed and immutable; the tag stays as the human-readable label and
# is what Dependabot keys on when it proposes the next digest. Refresh with:
#   docker buildx imagetools inspect golang:1.25-alpine   # -> index Digest
# Resolved 2026-09-07: golang:1.25-alpine == GOLANG_VERSION 1.25.14. The image
# ships GOTOOLCHAIN=local, and 1.25.14 satisfies the go.mod `go 1.25.0`
# directive, so the build uses the image toolchain and downloads nothing.
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS builder

# Build tooling. git is needed for VCS info when the toolchain pulls
# build metadata; ca-certificates so `go mod download` against
# https:// proxies works.
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Prime the module cache first so source changes don't invalidate
# the dependency download layer.
COPY go.mod go.sum ./
RUN go mod download

# Bring the full source in. .dockerignore trims irrelevant paths.
COPY . .

# Build the thinking-engine binary with the `thinking_kafka` tag.
# -trimpath strips absolute paths; -s -w drops symbol tables and
# DWARF info for a smaller image.
ENV CGO_ENABLED=0
ARG VERSION=0.0.0-dev
RUN go build \
      -tags thinking_kafka \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/thinking-engine \
      ./cmd/thinking-engine

# ---- Stage 2: runtime --------------------------------------------------
# CD-T11 / CD-06: digest-pinned for the same reason as stage 1. Refresh with:
#   docker buildx imagetools inspect alpine:3.20
# Resolved 2026-09-07 (multi-arch index digest).
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# curl for the HTTP healthcheck; ca-certificates so the engine can
# talk to HTTPS (prompt registry, ER1 API). Both are small.
RUN apk add --no-cache curl ca-certificates \
    && addgroup -S m3c \
    && adduser -S -G m3c -h /app m3c

WORKDIR /app

COPY --from=builder /out/thinking-engine /app/thinking-engine

USER m3c

EXPOSE 7140

# The engine refuses to start without --user-context-id, so this is
# NOT a working default. Operators must override CMD or supply the
# flag via compose. Declaring it here is a reminder, not a default.
ENTRYPOINT ["/app/thinking-engine"]
CMD ["--listen", ":7140"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:7140/v1/health || exit 1
