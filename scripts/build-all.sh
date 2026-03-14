#!/usr/bin/env bash
# build-all.sh — Build m3c-tools for all supported platforms.
#
# Targets:
#   darwin/arm64  — Full GUI + audio (native on Apple Silicon)
#   darwin/amd64  — Full GUI + audio (requires universal PortAudio)
#   linux/amd64   — CLI only (CGO_ENABLED=0)
#   windows/amd64 — CLI only (CGO_ENABLED=0)
#
# Usage:
#   ./scripts/build-all.sh              # build all targets
#   ./scripts/build-all.sh darwin       # build darwin targets only
#   ./scripts/build-all.sh linux        # build linux target only
#   ./scripts/build-all.sh windows      # build windows target only

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${REPO_ROOT}/build"
mkdir -p "$OUT"

PA_LIB="${REPO_ROOT}/lib/portaudio"
FILTER="${1:-all}"

build_darwin_arm64() {
    echo "==> Building darwin/arm64 (full GUI)..."
    CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
        go build -o "${OUT}/m3c-tools-darwin-arm64" ./cmd/m3c-tools
    echo "    ✓ ${OUT}/m3c-tools-darwin-arm64"
}

build_darwin_amd64() {
    if [ ! -f "${PA_LIB}/libportaudio.a" ]; then
        echo "==> SKIP darwin/amd64: no universal PortAudio at ${PA_LIB}"
        echo "    Run scripts/build-portaudio-universal.sh first"
        return 1
    fi
    echo "==> Building darwin/amd64 (full GUI)..."
    CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
        CGO_CFLAGS="-I${PA_LIB}" \
        CGO_LDFLAGS="-L${PA_LIB} -framework CoreAudio -framework AudioToolbox -framework AudioUnit -framework CoreFoundation -framework CoreServices" \
        go build -o "${OUT}/m3c-tools-darwin-amd64" ./cmd/m3c-tools
    echo "    ✓ ${OUT}/m3c-tools-darwin-amd64"
}

build_linux_amd64() {
    echo "==> Building linux/amd64 (CLI only)..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -o "${OUT}/m3c-tools-linux-amd64" ./cmd/m3c-tools
    echo "    ✓ ${OUT}/m3c-tools-linux-amd64"
}

build_windows_amd64() {
    echo "==> Building windows/amd64 (CLI only)..."
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
        go build -o "${OUT}/m3c-tools-windows-amd64.exe" ./cmd/m3c-tools
    echo "    ✓ ${OUT}/m3c-tools-windows-amd64.exe"
}

cd "$REPO_ROOT"

case "$FILTER" in
    darwin)
        build_darwin_arm64
        build_darwin_amd64
        ;;
    linux)
        build_linux_amd64
        ;;
    windows)
        build_windows_amd64
        ;;
    all)
        build_darwin_arm64
        build_darwin_amd64
        build_linux_amd64
        build_windows_amd64
        ;;
    *)
        echo "Unknown target: $FILTER"
        echo "Usage: $0 [darwin|linux|windows|all]"
        exit 1
        ;;
esac

echo ""
echo "Build complete. Artifacts:"
ls -lh "${OUT}"/m3c-tools-* 2>/dev/null || echo "(none)"
