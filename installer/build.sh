#!/bin/bash
# Build the M3C Tools Windows installer.
#
# Prerequisites:
#   brew install makensis   (NSIS for macOS, cross-compiles the installer)
#   or: run on Windows with NSIS installed
#
# Usage:
#   cd installer/
#   ./build.sh [path-to-m3c-tools.exe]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXE="${1:-$SCRIPT_DIR/../m3c-tools.exe}"

if [ ! -f "$EXE" ]; then
    echo "Building m3c-tools.exe for Windows..."
    cd "$SCRIPT_DIR/.."
    GOOS=windows GOARCH=amd64 go build -o "$SCRIPT_DIR/m3c-tools.exe" ./cmd/m3c-tools/
    EXE="$SCRIPT_DIR/m3c-tools.exe"
    echo "Built: $EXE"
else
    cp "$EXE" "$SCRIPT_DIR/m3c-tools.exe"
fi

# Copy icon for installer
if [ -f "$SCRIPT_DIR/../pkg/tray/icon.ico" ]; then
    cp "$SCRIPT_DIR/../pkg/tray/icon.ico" "$SCRIPT_DIR/icon.ico"
fi

echo "Building installer..."
cd "$SCRIPT_DIR"

if command -v makensis >/dev/null 2>&1; then
    makensis m3c-tools.nsi
    echo ""
    echo "Installer built: $SCRIPT_DIR/m3c-tools-$(grep PRODUCT_VERSION m3c-tools.nsi | head -1 | sed 's/.*"\(.*\)"/\1/')-setup.exe"
else
    echo "ERROR: makensis not found."
    echo "Install with: brew install makensis"
    echo "Or run this script on Windows with NSIS installed."
    exit 1
fi
