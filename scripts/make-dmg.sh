#!/usr/bin/env bash
# make-dmg.sh — Create a distributable macOS DMG from the app bundle
#
# Usage: ./scripts/make-dmg.sh [version]
#   version   Version string (default: derived from git tags)
set -euo pipefail

APP_NAME="M3C-Tools"
BUILD_DIR="./build"
APP_BUNDLE="${BUILD_DIR}/${APP_NAME}.app"

# --- Determine version ---
if [ -n "${1:-}" ]; then
    VERSION="$1"
else
    LATEST_TAG=$(git tag --list 'v*' --sort=-v:refname 2>/dev/null | head -1)
    if [ -n "$LATEST_TAG" ]; then
        VERSION="${LATEST_TAG#v}"
    else
        VERSION="0.0.0"
    fi
fi

DMG_NAME="${APP_NAME}-${VERSION}"
DMG_PATH="${BUILD_DIR}/${DMG_NAME}.dmg"
STAGING_DIR="${BUILD_DIR}/dmg-staging"

echo "Creating ${DMG_NAME}.dmg..."

# --- Verify app bundle exists ---
if [ ! -d "$APP_BUNDLE" ]; then
    echo "Error: App bundle not found at $APP_BUNDLE"
    echo "Run 'make build-app' first."
    exit 1
fi

# --- Copy setup script into app bundle Resources ---
if [ -f "scripts/setup-venv.sh" ]; then
    cp scripts/setup-venv.sh "${APP_BUNDLE}/Contents/Resources/setup-venv.sh"
    chmod +x "${APP_BUNDLE}/Contents/Resources/setup-venv.sh"
    echo "  Bundled setup-venv.sh into app Resources"
fi

# --- Copy .env.example into app bundle Resources ---
if [ -f ".env.example" ]; then
    cp .env.example "${APP_BUNDLE}/Contents/Resources/.env.example"
    echo "  Bundled .env.example into app Resources"
fi

# --- Create staging directory ---
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

# Copy app bundle
cp -r "$APP_BUNDLE" "$STAGING_DIR/"

# Create /Applications symlink
ln -s /Applications "$STAGING_DIR/Applications"

# Create README
cat > "$STAGING_DIR/README.txt" << 'READMEEOF'
M3C-Tools — Multi-Modal-Memory Tools
=====================================

INSTALLATION
1. Drag M3C-Tools.app to the Applications folder.
2. Open Terminal and run first-time setup:

   /Applications/M3C-Tools.app/Contents/MacOS/m3c-tools setup

   This creates a Python virtual environment at ~/.m3c-tools/venv/
   and installs whisper for voice transcription.

3. Grant macOS permissions (Screen Recording, Microphone):

   /Applications/M3C-Tools.app/Contents/MacOS/m3c-tools menubar

   On first launch, macOS will prompt for permissions.

PREREQUISITES
- macOS 13+ (Ventura or later)
- Python 3.9+ (usually pre-installed on macOS)
- ffmpeg: brew install ffmpeg

CONFIGURATION
Copy the included .env.example to ~/.m3c-tools.env and edit:

   cp /Applications/M3C-Tools.app/Contents/Resources/.env.example ~/.m3c-tools.env

Set ER1_API_URL, ER1_API_KEY, and ER1_CONTEXT_ID for your ER1 server.

RUNNING
- Double-click M3C-Tools.app (menu bar icon appears)
- Or from Terminal: m3c-tools menubar
- CLI commands: m3c-tools help

MORE INFO
- https://github.com/kamir/m3c-tools
READMEEOF

echo "  Created staging directory with app + symlink + README"

# --- Remove old DMG ---
rm -f "$DMG_PATH"

# --- Create DMG ---
hdiutil create \
    -volname "$DMG_NAME" \
    -srcfolder "$STAGING_DIR" \
    -ov \
    -format UDZO \
    -imagekey zlib-level=9 \
    "$DMG_PATH" \
    >/dev/null

# --- Cleanup ---
rm -rf "$STAGING_DIR"

# --- Report ---
DMG_SIZE=$(du -h "$DMG_PATH" | awk '{print $1}')
DMG_SHA=$(shasum -a 256 "$DMG_PATH" | awk '{print $1}')

echo ""
echo "DMG created: $DMG_PATH ($DMG_SIZE)"
echo "SHA-256:     $DMG_SHA"
