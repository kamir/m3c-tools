#!/bin/bash
# build-windows.sh — Cross-compile m3c-tools for Windows and optionally
# build the NSIS installer.
#
# Usage:
#   ./scripts/build-windows.sh           # compile binaries only
#   ./scripts/build-windows.sh --nsis    # compile + build installer
#
# Prerequisites for --nsis: brew install nsis
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/windows"

echo "=== Cross-compiling for Windows (amd64) ==="
mkdir -p "$BUILD_DIR"

echo "Building m3c-tools.exe..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o "$BUILD_DIR/m3c-tools.exe" "$REPO_ROOT/cmd/m3c-tools"

echo "Building skillctl.exe..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o "$BUILD_DIR/skillctl.exe" "$REPO_ROOT/cmd/skillctl"

echo "Copying icon..."
cp "$REPO_ROOT/design/icons/menubar-icon.png" "$BUILD_DIR/"

echo ""
echo "Windows binaries in $BUILD_DIR/:"
ls -lh "$BUILD_DIR/"

if [[ "${1:-}" == "--nsis" ]]; then
    echo ""
    echo "=== Building NSIS installer ==="
    if ! command -v makensis >/dev/null 2>&1; then
        echo "ERROR: makensis not found. Install with: brew install nsis"
        exit 1
    fi

    # NSIS needs EnvVarUpdate.nsh — check if it's available.
    # If not, use a simplified installer without PATH manipulation.
    makensis "$REPO_ROOT/scripts/installer.nsi"
    echo ""
    echo "Installer: $REPO_ROOT/build/M3C-Tools-Setup.exe"
fi

echo ""
echo "Done."
