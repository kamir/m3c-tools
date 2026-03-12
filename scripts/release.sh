#!/usr/bin/env bash
# release.sh — Automated version bumping, tagging, and GitHub release creation
# Usage: ./scripts/release.sh [patch|minor|major]
set -euo pipefail

BUMP_TYPE="${1:-patch}"
BINARY="m3c-tools"
BUILD_DIR="./build"
BASE_VERSION="1.4.1"

# --- Determine current version from git tags ---
LATEST_TAG=$(git tag --list 'v*' --sort=-v:refname | head -1)
if [ -z "$LATEST_TAG" ]; then
    CURRENT_VERSION="$BASE_VERSION"
    echo "No existing version tags found. Starting from v${BASE_VERSION}"
else
    CURRENT_VERSION="${LATEST_TAG#v}"
    echo "Current version: v${CURRENT_VERSION}"
fi

# --- Parse semver components ---
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"
MAJOR=${MAJOR:-0}
MINOR=${MINOR:-0}
PATCH=${PATCH:-0}

# --- Bump version ---
case "$BUMP_TYPE" in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        ;;
    *)
        echo "Error: Invalid bump type '$BUMP_TYPE'. Use: patch, minor, or major"
        exit 1
        ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"
NEW_TAG="v${NEW_VERSION}"
echo "New version: ${NEW_TAG}"

# --- Pre-flight checks ---
if ! command -v gh >/dev/null 2>&1; then
    echo "Error: GitHub CLI (gh) is required. Install: brew install gh"
    exit 1
fi

if ! git remote get-url origin >/dev/null 2>&1; then
    echo "Error: No git remote 'origin' configured."
    echo "  Add one with: git remote add origin https://github.com/<owner>/m3c-tools.git"
    exit 1
fi

# --- Commit all changes if working directory is dirty ---
if [ -n "$(git status --porcelain)" ]; then
    echo ""
    echo "Committing all changes..."
    git add -A
    git commit -m "Release ${NEW_TAG}"
fi

# --- Build binary ---
echo ""
echo "Building ${BINARY}..."
mkdir -p "${BUILD_DIR}"
go build -ldflags "-X main.Version=${NEW_VERSION}" -o "${BUILD_DIR}/${BINARY}" ./cmd/m3c-tools
echo "Built ${BUILD_DIR}/${BINARY}"

# --- Build app bundle + DMG ---
echo ""
echo "Building app bundle..."
APP_VERSION="${NEW_VERSION}" make build-app
echo "Building DMG..."
./scripts/make-dmg.sh "${NEW_VERSION}"
DMG_PATH="${BUILD_DIR}/M3C-Tools-${NEW_VERSION}.dmg"

# --- Push commits to origin ---
echo ""
CURRENT_BRANCH=$(git branch --show-current)
echo "Pushing ${CURRENT_BRANCH} to origin..."
git push origin "${CURRENT_BRANCH}"

# --- Tag ---
echo ""
echo "Creating tag ${NEW_TAG}..."
git tag -a "${NEW_TAG}" -m "Release ${NEW_TAG}"

# --- Push tag ---
echo "Pushing tag to origin..."
git push origin "${NEW_TAG}"

# --- Create GitHub release ---
echo ""
echo "Creating GitHub release ${NEW_TAG}..."
# Build release assets list
RELEASE_ASSETS=("${BUILD_DIR}/${BINARY}")
if [ -f "$DMG_PATH" ]; then
    RELEASE_ASSETS+=("$DMG_PATH")
    DMG_SHA=$(shasum -a 256 "$DMG_PATH" | awk '{print $1}')
    DMG_SIZE=$(du -h "$DMG_PATH" | awk '{print $1}')
    DMG_NOTES="
### macOS Installer
- **${DMG_PATH##*/}** (${DMG_SIZE})
- SHA-256: \`${DMG_SHA}\`

### First-time setup
\`\`\`bash
# After dragging to /Applications:
/Applications/M3C-Tools.app/Contents/MacOS/m3c-tools setup
\`\`\`"
else
    DMG_NOTES=""
fi

gh release create "${NEW_TAG}" \
    "${RELEASE_ASSETS[@]}" \
    --title "Release ${NEW_TAG}" \
    --notes "## ${BINARY} ${NEW_TAG}

### Changes since ${LATEST_TAG:-initial}
$(git log ${LATEST_TAG:+${LATEST_TAG}..}HEAD --oneline --no-decorate 2>/dev/null || echo "- Initial release")
${DMG_NOTES}
" \
    --latest

echo ""
echo "Release ${NEW_TAG} created successfully!"
echo "  View: $(gh release view ${NEW_TAG} --json url -q .url)"
