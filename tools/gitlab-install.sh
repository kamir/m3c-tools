#!/usr/bin/env bash
# gitlab-install.sh — Universal installer for skillctl & m3c-tools from GitLab
#
# Fetches the appropriate platform binary from a GitLab Generic Package Registry
# or Releases endpoint, verifies its SHA-256 integrity, and installs to PATH.
#
# Usage:
#   # Install skillctl from local Master2 GitLab:
#   curl -fsSL http://192.168.0.135/ai-platform/m3c-tools/-/raw/main/tools/gitlab-install.sh | \
#     GITLAB_URL="http://192.168.0.135" \
#     PROJECT_PATH="ai-platform/m3c-tools" \
#     TOOL="skillctl" \
#     bash
#
#   # Install m3c-tools with private token (if private repo):
#   curl -fsSL ... | GITLAB_TOKEN="glpat-xxx" bash

set -euo pipefail

TOOL="${TOOL:-skillctl}" # "skillctl" or "m3c-tools" or "skillctl-demo"
GITLAB_URL="${GITLAB_URL:-http://192.168.0.135}"
PROJECT_PATH="${PROJECT_PATH:-ai-platform/m3c-tools}"
VERSION="${VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
GITLAB_TOKEN="${GITLAB_TOKEN:-}"

# Platform detection
uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
uname_m=$(uname -m)

case "$uname_s" in
  darwin) os="darwin" ;;
  linux)  os="linux" ;;
  msys*|cygwin*|mingw*) os="windows" ;;
  *) echo "ERROR: Unsupported OS: $uname_s" >&2; exit 1 ;;
esac

case "$uname_m" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "ERROR: Unsupported architecture: $uname_m" >&2; exit 1 ;;
esac

ext=""
[ "$os" = "windows" ] && ext=".exe"
asset="${TOOL}-${os}-${arch}${ext}"

# Tooling check
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required" >&2; exit 1; }

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@"
  else echo "ERROR: No sha256 checksum tool available (need sha256sum or shasum)" >&2; exit 1; fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

AUTH_HEADER=()
if [ -n "$GITLAB_TOKEN" ]; then
  AUTH_HEADER=("-H" "PRIVATE-TOKEN: ${GITLAB_TOKEN}")
fi

# URL encode project path for GitLab API (e.g. ai-platform/m3c-tools -> ai-platform%2Fm3c-tools)
PROJECT_ID_ENCODED=$(echo "$PROJECT_PATH" | sed 's/\//%2F/g')

echo "=== Installing ${TOOL} (${os}/${arch}) from GitLab (${GITLAB_URL}) ==="

DOWNLOAD_URL="${GITLAB_URL}/api/v4/projects/${PROJECT_ID_ENCODED}/packages/generic/${TOOL}/${VERSION}/${asset}"
MANIFEST_URL="${GITLAB_URL}/api/v4/projects/${PROJECT_ID_ENCODED}/packages/generic/${TOOL}/${VERSION}/SHA256SUMS"

echo "Downloading ${asset}..."
if ! curl -fsSL "${AUTH_HEADER[@]}" -o "$tmp/$asset" "$DOWNLOAD_URL"; then
  # Fallback to direct raw release file if package registry path differs
  FALLBACK_URL="${GITLAB_URL}/${PROJECT_PATH}/-/raw/main/dist/${asset}"
  echo "Package registry download failed, attempting raw repository path: ${FALLBACK_URL}..."
  curl -fsSL "${AUTH_HEADER[@]}" -o "$tmp/$asset" "$FALLBACK_URL" || {
    echo "ERROR: Failed to download ${asset} from ${GITLAB_URL}." >&2
    exit 1
  }
fi

# Download and verify checksum if available
echo "Checking integrity..."
if curl -fsSL "${AUTH_HEADER[@]}" -o "$tmp/SHA256SUMS" "$MANIFEST_URL" 2>/dev/null; then
  EXPECTED_HASH=$(grep "${asset}$" "$tmp/SHA256SUMS" | awk '{print $1}' || true)
  if [ -n "$EXPECTED_HASH" ]; then
    ACTUAL_HASH=$(sha256 "$tmp/$asset" | awk '{print $1}')
    if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
      echo "ERROR: SHA256 checksum mismatch for ${asset}!" >&2
      echo "  Expected: $EXPECTED_HASH" >&2
      echo "  Actual:   $ACTUAL_HASH" >&2
      exit 1
    fi
    echo "✓ Checksum verified: ${ACTUAL_HASH}"
  fi
fi

# Install binary
mkdir -p "$INSTALL_DIR"
chmod 755 "$tmp/$asset"
cp "$tmp/$asset" "$INSTALL_DIR/${TOOL}${ext}"

echo ""
echo "✓ Successfully installed ${TOOL} to ${INSTALL_DIR}/${TOOL}${ext}"
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
  echo "NOTE: Add ${INSTALL_DIR} to your PATH to run '${TOOL}' from anywhere:"
  echo "  export PATH=\"\$PATH:${INSTALL_DIR}\""
fi
