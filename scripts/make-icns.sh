#!/usr/bin/env bash
# make-icns.sh — Convert a source PNG to a macOS .icns file
# Usage: ./scripts/make-icns.sh [source.png] [output.icns]
#
# Requires macOS tools: sips, iconutil
# The source PNG should be at least 512x512 for best results.

set -euo pipefail

SRC="${1:-maindset_icon.png}"
OUT="${2:-build/m3c-tools.icns}"

if [[ ! -f "$SRC" ]]; then
    echo "Error: source PNG not found: $SRC" >&2
    exit 1
fi

# Create temporary iconset directory
ICONSET=$(mktemp -d)/m3c-tools.iconset
mkdir -p "$ICONSET"

# Generate all required icon sizes
# macOS expects these exact filenames in the .iconset
declare -a SIZES=(
    "icon_16x16:16"
    "icon_16x16@2x:32"
    "icon_32x32:32"
    "icon_32x32@2x:64"
    "icon_128x128:128"
    "icon_128x128@2x:256"
    "icon_256x256:256"
    "icon_256x256@2x:512"
    "icon_512x512:512"
)

echo "Generating icon sizes from $SRC..."
for entry in "${SIZES[@]}"; do
    name="${entry%%:*}"
    size="${entry##*:}"
    sips -z "$size" "$size" "$SRC" --out "$ICONSET/${name}.png" >/dev/null 2>&1
    echo "  ${name}.png (${size}x${size})"
done

# Build .icns from iconset
echo "Creating $OUT..."
mkdir -p "$(dirname "$OUT")"
iconutil -c icns "$ICONSET" -o "$OUT"

# Cleanup
rm -rf "$(dirname "$ICONSET")"

echo "Done: $OUT ($(du -h "$OUT" | cut -f1) bytes)"
