#!/usr/bin/env bash
# skillctl installer — fetch the right binary for this host from a GitHub
# release, VERIFY the ed25519 signature over SHA256SUMS (provenance), then
# verify the binary's SHA-256 (integrity), then install to a user bin dir.
#
# Portable across macOS (shasum) and Linux (sha256sum). Requires: curl, openssl.
#
# Usage:
#   curl -fsSL .../install.sh | RELEASE_BASE=.../releases/download/skillctl/v0.2.1 bash
#   curl -fsSL .../install.sh | INSTALL_DIR=$HOME/.local/bin bash
set -euo pipefail

RELEASE_BASE="${RELEASE_BASE:-https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.1}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# sha256: prefer sha256sum (Linux/coreutils), fall back to shasum -a 256 (macOS).
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  elif command -v shasum    >/dev/null 2>&1; then shasum -a 256 "$@"
  else echo "no sha256 tool (need sha256sum or shasum)" >&2; return 1; fi
}

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
ext=""; [ "$os" = "windows" ] && ext=".exe"
asset="skillctl-${os}-${arch}${ext}"

command -v curl    >/dev/null 2>&1 || { echo "curl required" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl required for signature verification" >&2; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fetch() { curl -fsSL -o "$tmp/$1" "$RELEASE_BASE/$1"; }

echo "Fetching manifest + signature + key"
fetch SHA256SUMS
fetch SHA256SUMS.sig
fetch skillctl-release.pub

echo "Verifying ed25519 signature over SHA256SUMS (provenance)"
if ! openssl pkeyutl -verify -pubin -inkey "$tmp/skillctl-release.pub" -rawin \
       -in "$tmp/SHA256SUMS" -sigfile "$tmp/SHA256SUMS.sig" >/dev/null 2>&1; then
  echo "SIGNATURE VERIFICATION FAILED — refusing to install" >&2
  exit 1
fi
fp=$(openssl pkey -pubin -in "$tmp/skillctl-release.pub" -outform DER 2>/dev/null | sha256 | awk '{print "sha256:"$1}')
echo "OK: signed by the skillctl release key ($fp)"

echo "Fetching $asset"
fetch "$asset"

echo "Verifying SHA-256 (integrity)"
expected=$(grep " $asset\$" "$tmp/SHA256SUMS" | awk '{print $1}')
[ -n "$expected" ] || { echo "$asset not in SHA256SUMS" >&2; exit 1; }
actual=$(sha256 "$tmp/$asset" | awk '{print $1}')
[ "$expected" = "$actual" ] || { echo "checksum mismatch: $expected != $actual" >&2; exit 1; }
echo "OK: $expected"

mkdir -p "$INSTALL_DIR"
chmod +x "$tmp/$asset"
mv "$tmp/$asset" "$INSTALL_DIR/skillctl${ext}"
[ "$os" = "darwin" ] && xattr -dr com.apple.quarantine "$INSTALL_DIR/skillctl${ext}" 2>/dev/null || true
echo "Installed: $INSTALL_DIR/skillctl${ext}"
echo
"$INSTALL_DIR/skillctl${ext}" version 2>/dev/null || true
echo "Next: add $INSTALL_DIR to PATH, then: skillctl --help"
