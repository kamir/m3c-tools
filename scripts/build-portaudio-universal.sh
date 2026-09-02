#!/usr/bin/env bash
# build-portaudio-universal.sh — Build a universal (arm64 + x86_64) PortAudio
# static library for macOS cross-compilation on Apple Silicon.
#
# Output: lib/portaudio/libportaudio.a (fat binary)
#         lib/portaudio/portaudio.h     (header)
#
# Prerequisites: Xcode Command Line Tools

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKDIR="/tmp/portaudio-universal-build"
PA_VERSION="pa_stable_v190700_20210406"
# SHA-256 of the immutable upstream release tarball (matches the Homebrew formula
# and MacPorts). The download below is verified against this and fails closed on
# mismatch — integrity does not depend on which host served the bytes.
PA_SHA256="47efbf42c77c19a05d22e627d42873e991ec0c1357219c0d74ce6a2948cb2def"
# The canonical host files.portaudio.com went offline (DNS no longer resolves),
# which broke this build for everyone. Try it first in case it returns, then fall
# back to the Wayback Machine's immutable snapshot of the exact same tarball. The
# `id_` modifier makes Wayback serve the original raw bytes (no HTML rewriting).
PA_URLS=(
    "https://files.portaudio.com/archives/${PA_VERSION}.tgz"
    "https://web.archive.org/web/20210601000000id_/http://files.portaudio.com/archives/${PA_VERSION}.tgz"
)
OUT="${REPO_ROOT}/lib/portaudio"

echo "==> Downloading PortAudio source..."
mkdir -p "$WORKDIR"
cd "$WORKDIR"
if [ ! -f "${PA_VERSION}.tgz" ]; then
    downloaded=""
    for url in "${PA_URLS[@]}"; do
        echo "    trying ${url%%\?*}"
        if curl -fsSL --retry 3 --connect-timeout 20 -o "${PA_VERSION}.tgz.part" "$url"; then
            mv "${PA_VERSION}.tgz.part" "${PA_VERSION}.tgz"
            downloaded=1
            break
        fi
    done
    if [ -z "$downloaded" ]; then
        echo "ERROR: could not download ${PA_VERSION}.tgz from any known source" >&2
        exit 1
    fi
fi
echo "==> Verifying SHA-256 (fail closed on mismatch)..."
echo "${PA_SHA256}  ${PA_VERSION}.tgz" | shasum -a 256 -c - \
    || { echo "ERROR: SHA-256 mismatch for ${PA_VERSION}.tgz — refusing to build" >&2; exit 1; }
rm -rf portaudio
tar xzf "${PA_VERSION}.tgz"

build_arch() {
    local ARCH="$1"
    local TARGET="$2"
    local HOST="$3"
    echo "==> Building PortAudio for ${ARCH}..."

    cd "$WORKDIR/portaudio"
    rm -rf "build-${ARCH}"
    mkdir "build-${ARCH}"
    cd "build-${ARCH}"

    CC="clang -arch ${ARCH} -target ${TARGET}" \
    CFLAGS="-O2" \
    LDFLAGS="-arch ${ARCH}" \
    ../configure --host="${HOST}" --disable-shared --enable-static 2>&1 | tail -3

    # PortAudio 19.7 uses -Werror but has unused-var warnings on modern clang
    sed -i '' 's/-Werror//g' Makefile

    make -j"$(sysctl -n hw.ncpu)" 2>&1 | tail -1
    echo "    ✓ ${ARCH} built"
}

build_arch "arm64" "aarch64-apple-darwin" "aarch64-apple-darwin"
build_arch "x86_64" "x86_64-apple-darwin" "x86_64-apple-darwin"

echo "==> Creating universal fat library..."
mkdir -p "$OUT"
lipo -create \
    "$WORKDIR/portaudio/build-arm64/lib/.libs/libportaudio.a" \
    "$WORKDIR/portaudio/build-x86_64/lib/.libs/libportaudio.a" \
    -output "$OUT/libportaudio.a"

cp "$WORKDIR/portaudio/include/portaudio.h" "$OUT/"

echo "==> Verifying..."
lipo -info "$OUT/libportaudio.a"
echo ""
echo "Universal PortAudio installed to: $OUT"
echo "  libportaudio.a — $(wc -c < "$OUT/libportaudio.a" | tr -d ' ') bytes"
echo "  portaudio.h"
