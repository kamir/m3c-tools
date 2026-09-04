#!/usr/bin/env bash
# build-portaudio-universal.sh: Build a universal (arm64 + x86_64) PortAudio
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
# and MacPorts). Every download below is verified against this and fails closed on
# mismatch. Integrity does not depend on which host served the bytes.
PA_SHA256="47efbf42c77c19a05d22e627d42873e991ec0c1357219c0d74ce6a2948cb2def"

# CD-16: an ORG-CONTROLLED mirror is the PRIMARY source, so this build does not
# depend on infrastructure we do not control. The canonical host
# files.portaudio.com went offline (DNS no longer resolves), which broke the build
# for everyone; the Wayback Machine is a best-effort community archive, not an SLA
# we can rely on for a release build. Host the exact upstream tarball (~1.5 MB) as
# a GitHub Release asset on our own repo and point PA_MIRROR at it. The SHA-256 gate
# makes the mirror's integrity independent of the source.
#
# PROVISIONED (2026-09-03): the mirror asset is live at the default URL below:
# the 'portaudio-vendor' release on kamir/m3c-tools carries ${PA_VERSION}.tgz
# (sha256 ${PA_SHA256}). No operator action is required for a normal build.
#
#   To RE-PROVISION (new host/repo, or if the asset is ever removed):
#     curl -fL -o "${PA_VERSION}.tgz" \
#       "https://web.archive.org/web/20210601000000id_/http://files.portaudio.com/archives/${PA_VERSION}.tgz"
#     echo "${PA_SHA256}  ${PA_VERSION}.tgz" | shasum -a 256 -c -   # verify before publishing
#     gh release create portaudio-vendor "${PA_VERSION}.tgz" \
#       --repo kamir/m3c-tools --title "PortAudio vendor mirror (build dependency)" \
#       --notes "PortAudio ${PA_VERSION}.tgz mirror: sha256 ${PA_SHA256}"
#   Override at will:  PA_MIRROR=https://my.host/pa.tgz bash scripts/build-portaudio-universal.sh
#   If the mirror is ever unreachable the build still succeeds via the upstream +
#   Wayback fallbacks below (the SHA-256 gate applies to whichever source serves it).
PA_MIRROR="${PA_MIRROR:-https://github.com/kamir/m3c-tools/releases/download/portaudio-vendor/${PA_VERSION}.tgz}"

# Ordered sources: the org-controlled mirror FIRST, then the (currently-dead)
# canonical upstream in case it returns, then the Wayback snapshot as a last
# resort. The `id_` modifier makes Wayback serve the original raw bytes (no HTML
# rewriting). Every source feeds the SAME SHA-256 gate below.
PA_URLS=(
    "${PA_MIRROR}"
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
    || { echo "ERROR: SHA-256 mismatch for ${PA_VERSION}.tgz: refusing to build" >&2; exit 1; }
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
echo "  libportaudio.a: $(wc -c < "$OUT/libportaudio.a" | tr -d ' ') bytes"
echo "  portaudio.h"
