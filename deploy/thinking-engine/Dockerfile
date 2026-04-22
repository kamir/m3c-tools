# deploy/thinking-engine/Dockerfile — multi-stage build for the m3c
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
FROM golang:1.25-alpine AS builder

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
FROM alpine:3.20

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
# NOT a working default — operators must override CMD or supply the
# flag via compose. Declaring it here is a reminder, not a default.
ENTRYPOINT ["/app/thinking-engine"]
CMD ["--listen", ":7140"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:7140/v1/health || exit 1
