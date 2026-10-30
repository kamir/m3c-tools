#!/usr/bin/env bash
# m3c-tools installer: fetch the right archive for this host from the newest
# m3c-tools release, verify provenance over checksums.txt, verify the archive's
# SHA-256, then install to a user bin dir. No admin rights.
#
# Requires curl, tar and either cosign or openssl.
#
# Usage:
#   curl -fsSL .../m3c-tools-install.sh | bash
#   curl -fsSL .../m3c-tools-install.sh | INSTALL_DIR=$HOME/bin bash
#   curl -fsSL .../m3c-tools-install.sh | RELEASE_BASE=.../releases/download/v2.13.0 bash
set -euo pipefail

[ -n "${RELEASE_BASE:-}" ] && echo "WARNING: RELEASE_BASE overrides the default release origin (${RELEASE_BASE})" >&2

# The newest m3c-tools release comes from the release feed. The /releases/latest
# shortcut is not usable: it names the newest release of the whole repository, and
# that is often a skillctl release.
newest_m3c_tag() {
  curl -fsSL --max-time 20 "https://github.com/kamir/m3c-tools/releases.atom" 2>/dev/null \
    | grep -oE 'releases/tag/v[0-9][^"<]*' \
    | head -1 \
    | sed 's|releases/tag/||'
}

if [ -z "${RELEASE_BASE:-}" ]; then
  tag="$(newest_m3c_tag || true)"
  if [ -z "$tag" ]; then
    echo "m3c-tools-install: could not determine the newest release." >&2
    echo "  No network, or github.com is not reachable from here." >&2
    echo "  Name a release explicitly, for example:" >&2
    echo "    RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/v2.12.0 bash" >&2
    exit 1
  fi
  RELEASE_BASE="https://github.com/kamir/m3c-tools/releases/download/${tag}"
  echo "m3c-tools-install: newest release is ${tag}" >&2
fi
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# Fingerprint of the release key: sha256 of the raw 32-byte ed25519 key.
EXPECTED_FP="sha256:5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2"
COSIGN_ID_REGEX="${M3C_COSIGN_IDENTITY:-^https://github.com/kamir/m3c-tools/\.github/workflows/release\.yml@refs/tags/v}"
COSIGN_ISSUER="https://token.actions.githubusercontent.com"
[ -n "${M3C_COSIGN_IDENTITY:-}" ] && echo "WARNING: M3C_COSIGN_IDENTITY overrides the pinned cosign identity." >&2

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@"
  else echo "no sha256 tool (need sha256sum or shasum)" >&2; return 1; fi
}

case "$(uname -s | tr '[:upper:]' '[:lower:]')" in
  darwin) os=darwin ;;
  linux) os=linux ;;
  *) echo "unsupported OS for this script. On Windows use tools/m3c-tools-install.ps1." >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
asset="m3c-tools-${os}-${arch}.tar.gz"

command -v curl >/dev/null 2>&1 || { echo "curl required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar required" >&2; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fetch() { curl -fsSL -o "$tmp/$1" "$RELEASE_BASE/$1"; }

echo "Fetching manifest"
if ! fetch checksums.txt; then
  echo "Could not fetch checksums.txt from: $RELEASE_BASE" >&2
  echo "The release may not be published yet." >&2
  exit 1
fi

verified=0
if command -v cosign >/dev/null 2>&1 && curl -fsSL -o "$tmp/checksums.txt.cosign.bundle" "$RELEASE_BASE/checksums.txt.cosign.bundle" 2>/dev/null; then
  echo "Verifying cosign keyless provenance over checksums.txt (GitHub OIDC)"
  if cosign verify-blob "$tmp/checksums.txt" \
       --bundle "$tmp/checksums.txt.cosign.bundle" \
       --certificate-identity-regexp "$COSIGN_ID_REGEX" \
       --certificate-oidc-issuer "$COSIGN_ISSUER" >/dev/null 2>&1; then
    echo "OK: cosign keyless provenance verified (signed by the release workflow)"
    verified=1
  else
    echo "COSIGN VERIFICATION FAILED: refusing to install (no silent downgrade to ed25519)." >&2
    exit 1
  fi
fi

if [ "$verified" != 1 ]; then
  command -v openssl >/dev/null 2>&1 || { echo "cosign or openssl required for signature verification" >&2; exit 1; }
  if ! fetch checksums.txt.sig || ! fetch skillctl-release.pub; then
    echo "Could not fetch checksums.txt.sig from: $RELEASE_BASE" >&2
    echo "Cosign did not verify here, and this release carries no fallback signature." >&2
    echo "Install cosign and re-run. Refusing to install unverified binaries." >&2
    exit 1
  fi
  echo "Verifying ed25519 signature over checksums.txt"
  if ! openssl pkeyutl -verify -pubin -inkey "$tmp/skillctl-release.pub" -rawin \
         -in "$tmp/checksums.txt" -sigfile "$tmp/checksums.txt.sig" >/dev/null 2>&1; then
    echo "SIGNATURE VERIFICATION FAILED: refusing to install" >&2
    exit 1
  fi
  fp=$(openssl pkey -pubin -in "$tmp/skillctl-release.pub" -outform DER 2>/dev/null | tail -c 32 | sha256 | awk '{print "sha256:"$1}')
  if [ "$fp" != "$EXPECTED_FP" ]; then
    echo "RELEASE KEY FINGERPRINT MISMATCH, refusing to install" >&2
    echo "  expected: $EXPECTED_FP" >&2
    echo "  got:      $fp" >&2
    exit 1
  fi
  echo "OK: signed by the pinned release key ($fp)"
fi

echo "Fetching $asset"
fetch "$asset"
echo "Verifying SHA-256 (integrity)"
expected=$(grep " $asset\$" "$tmp/checksums.txt" | awk '{print $1}')
[ -n "$expected" ] || { echo "$asset not in checksums.txt" >&2; exit 1; }
actual=$(sha256 "$tmp/$asset" | awk '{print $1}')
[ "$expected" = "$actual" ] || { echo "checksum mismatch: $expected != $actual" >&2; exit 1; }
echo "OK: $expected"

mkdir -p "$tmp/x"
tar xzf "$tmp/$asset" -C "$tmp/x"
binary=""
for candidate in "$tmp/x/m3c-tools" "$tmp/x/m3c-tools-${os}-${arch}"; do
  [ -f "$candidate" ] && binary="$candidate" && break
done
[ -n "$binary" ] || { echo "the archive holds no m3c-tools binary" >&2; exit 1; }

mkdir -p "$INSTALL_DIR"
chmod +x "$binary"
mv "$binary" "$INSTALL_DIR/m3c-tools"
[ "$os" = darwin ] && xattr -dr com.apple.quarantine "$INSTALL_DIR/m3c-tools" 2>/dev/null || true
echo "Installed: $INSTALL_DIR/m3c-tools"
echo
if ! "$INSTALL_DIR/m3c-tools" version; then
  echo "The binary is installed but does not start on this machine." >&2
  exit 1
fi
echo "Next: add $INSTALL_DIR to PATH, then: m3c-tools transcript dQw4w9WgXcQ"
