#!/usr/bin/env bash
# release.sh: leitet die naechste Produktversion ab, taggt origin/master BY HASH
# und schiebt das Tag. Mehr nicht.
#
# Usage: ./scripts/release.sh [patch|minor|major] [--yes]
#
# Publikation findet AUSSCHLIESSLICH in .github/workflows/release.yml statt.
#
# Vorher hat dieses Skript die Working Copy mit `git add -A` committet, lokal auf
# dem Laptop gebaut, eine DMG erzeugt und beides mit `gh release create --latest`
# hochgeladen. Der checksums-Job in release.yml hasht aber nur die CI-Artefakte
# (*.tar.gz, *.zip, *.exe): das nackte Binary und die DMG standen damit weder in
# checksums.txt noch in den SLSA-Subjects. Nachweis: v2.9.0 traegt die Assets
# `m3c-tools` und `M3C-Tools-2.9.0.dmg`, und seine checksums.txt kennt beide
# nicht. Ein signierter Kanal, auf dem unattestierte Assets liegen, ist als
# Ganzes nicht mehr pruefbar: der Nutzer sieht denselben v*-Download und kann an
# der Oberflaeche nicht unterscheiden, was durch die Gates lief.
#
# Was daraus folgt: dieses Skript baut nichts, laedt nichts hoch und committet
# nichts. Es setzt genau einen Zeiger, und alles Weitere entsteht in CI, wo die
# Signatur- und Provenance-Kette haengt.
set -euo pipefail

BUMP_TYPE=""
ASSUME_YES=0

for arg in "$@"; do
    case "$arg" in
        patch|minor|major)
            BUMP_TYPE="$arg"
            ;;
        --yes|-y)
            ASSUME_YES=1
            ;;
        *)
            echo "Error: unknown argument '$arg'"
            echo "Usage: ./scripts/release.sh [patch|minor|major] [--yes]"
            exit 1
            ;;
    esac
done
BUMP_TYPE="${BUMP_TYPE:-patch}"

BASE_VERSION="1.4.1"

# --- Pre-flight: remote + a fresh view of it ---
if ! git remote get-url origin >/dev/null 2>&1; then
    echo "Error: No git remote 'origin' configured."
    echo "  Add one with: git remote add origin https://github.com/<owner>/m3c-tools.git"
    exit 1
fi

echo "Fetching origin (tags + master)..."
git fetch --tags --quiet origin

# Ein schmutziger Baum wird NICHT mehr committet. Frueher hat `git add -A` genau
# das getan und damit unreviewten Inhalt in ein Release gehoben. Getaggt wird
# ohnehin origin/master, also traegt der lokale Stand nichts zum Release bei:
# die Warnung existiert, damit niemand glaubt, seine offenen Aenderungen seien
# mit ausgeliefert worden. Untracked-Dateien blockieren bewusst nicht.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo ""
    echo "Error: tracked files are modified in this working copy."
    echo "  This script tags origin/master, so local changes would NOT be released."
    echo "  Commit them, get them reviewed and merged to master, then run again:"
    git status --short --untracked-files=no | sed 's/^/    /'
    exit 1
fi

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

# --- Refuse to re-tag ---
if git rev-parse -q --verify "refs/tags/${NEW_TAG}" >/dev/null; then
    echo "Error: tag ${NEW_TAG} already exists locally. See docs/releasing.md (Rollback)."
    exit 1
fi
if git ls-remote --exit-code --tags origin "refs/tags/${NEW_TAG}" >/dev/null 2>&1; then
    echo "Error: tag ${NEW_TAG} already exists on origin. See docs/releasing.md (Rollback)."
    exit 1
fi

# --- The commit that will be tagged: origin/master, by hash ---
# Working copies drift onto feature branches and worktrees, deshalb wird nie
# "der aktuelle Branch" getaggt, sondern der reviewte Stand auf master.
if ! HASH=$(git rev-parse -q --verify 'origin/master^{commit}'); then
    echo "Error: origin/master not found after fetch."
    exit 1
fi

echo ""
echo "New version:  ${NEW_TAG}   (bump: ${BUMP_TYPE})"
echo "Tagging:      origin/master @ ${HASH}"
echo "              $(git log -1 --format='%s' "$HASH")"
echo "              $(git log -1 --format='%an, %ad' --date=short "$HASH")"
echo ""
echo "Release approval (docs/releasing.md, 'Release approval'):"
echo "  the tag push is the point of no return. The SPEC-0406 acceptance gate"
echo "  covers the machine half; the two-person half is a human step and is not"
echo "  observable from here. If you are releasing alone, record it as break-glass."
echo ""
echo "This script will NOT build, upload or commit anything."
echo "Publication happens in .github/workflows/release.yml, triggered by this tag."
echo ""

# --- Point of no return: confirm ---
if [ "$ASSUME_YES" -ne 1 ]; then
    if [ ! -t 0 ]; then
        echo "Error: no terminal to confirm on. Re-run with --yes if this is intended."
        exit 1
    fi
    printf 'Push tag %s and start the release workflow? [y/N] ' "$NEW_TAG"
    read -r reply
    case "$reply" in
        y|Y|yes|YES) ;;
        *)
            echo "Aborted. Nothing was tagged or pushed."
            exit 1
            ;;
    esac
fi

# --- Tag + push ---
echo ""
echo "Creating tag ${NEW_TAG} on ${HASH}..."
git tag -a "${NEW_TAG}" "${HASH}" -m "Release ${NEW_TAG}"

echo "Pushing tag to origin..."
git push origin "${NEW_TAG}"

echo ""
echo "Tag ${NEW_TAG} pushed. CI now builds, signs, attests and publishes."
echo "  Watch:  gh run watch \"\$(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId')\""
echo "  Assets: gh release view ${NEW_TAG} --json assets -q '.assets[].name'"
echo "  Undo:   docs/releasing.md, section 'Rollback'"
