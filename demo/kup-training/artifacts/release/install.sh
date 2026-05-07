#!/usr/bin/env bash
# skillctl installer — fetch the right binary for this host from a GitHub
# release, verify SHA-256, install to a user-writable bin directory.
#
# Usage:
#   curl -L https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.1.0-kup/install.sh | bash
#   curl -L .../install.sh | INSTALL_DIR=$HOME/.local/bin bash
#
# Required env (or args): RELEASE_BASE — GitHub raw release URL prefix.
set -euo pipefail

RELEASE_BASE="${RELEASE_BASE:-https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.1.0-kup}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

uname_s=$(uname -s | tr '[:upper:]' '[:lower:]')
uname_m=$(uname -m)
case "$uname_s" in
  darwin) os="darwin" ;;
  linux)  os="linux" ;;
  msys*|cygwin*|mingw*) os="windows" ;;
  *) echo "unsupported OS: $uname_s" >&2; exit 1 ;;
esac
case "$uname_m" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "unsupported arch: $uname_m" >&2; exit 1 ;;
esac
ext=""; [[ "$os" == "windows" ]] && ext=".exe"
asset="skillctl-${os}-${arch}${ext}"

mkdir -p "$INSTALL_DIR"
tmp=$(mktemp -d)
trap "rm -rf $tmp" EXIT

echo "Fetching $asset from $RELEASE_BASE"
curl -fsSL -o "$tmp/$asset"     "$RELEASE_BASE/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$RELEASE_BASE/SHA256SUMS"

echo "Verifying SHA-256"
expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')
[[ -n "$expected" ]] || { echo "$asset not in SHA256SUMS" >&2; exit 1; }
actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
if [[ "$expected" != "$actual" ]]; then
  echo "checksum mismatch: expected $expected, got $actual" >&2
  exit 1
fi
echo "OK: $expected"

chmod +x "$tmp/$asset"
mv "$tmp/$asset" "$INSTALL_DIR/skillctl${ext}"
echo "Installed: $INSTALL_DIR/skillctl${ext}"
echo
echo "Next steps:"
echo "  $INSTALL_DIR/skillctl${ext} --help"
echo "  $INSTALL_DIR/skillctl${ext} keygen --out ~/.claude/skillctl-keys/author"
