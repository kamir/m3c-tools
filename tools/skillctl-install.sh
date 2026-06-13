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

RELEASE_BASE="${RELEASE_BASE:-https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.2.10}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# SEC-M2: pin the release-key fingerprint. The signature alone proves only that
# SHA256SUMS was signed by WHATEVER key sits next to it at the same origin — an
# origin compromise can swap key + sig + binaries together and still "verify".
# Pinning the expected fingerprint here (and preferring the in-repo key below)
# closes that hole: the fetched key must match this exact value or we refuse.
# Fingerprint = sha256 of the raw 32-byte ed25519 key (DER SPKI tail).
EXPECTED_FP="sha256:5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2"

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

echo "Fetching manifest"
fetch SHA256SUMS

# === Provenance track 1 (preferred): keyless cosign / GitHub OIDC (SPEC-0253). ===
# When cosign is installed AND the release carries a cosign bundle, verify
# SHA256SUMS against the EXPECTED workflow OIDC identity (no key to trust — the
# signer is the release workflow itself). A present-but-invalid bundle is a HARD
# FAIL (an attacker must not be able to strip it to force a downgrade); a fully
# ABSENT bundle/cosign falls through to the pinned-ed25519 track below, so every
# existing release (which has no cosign bundle) keeps installing unchanged.
COSIGN_ID_REGEX="${SKILLCTL_COSIGN_IDENTITY:-^https://github.com/kamir/m3c-tools/\.github/workflows/skillctl-release\.yml@refs/tags/skillctl/v}"
COSIGN_ISSUER="https://token.actions.githubusercontent.com"
verified=0
if command -v cosign >/dev/null 2>&1 && curl -fsSL -o "$tmp/SHA256SUMS.cosign.bundle" "$RELEASE_BASE/SHA256SUMS.cosign.bundle" 2>/dev/null; then
  echo "Verifying cosign keyless provenance over SHA256SUMS (GitHub OIDC)"
  if cosign verify-blob "$tmp/SHA256SUMS" \
       --bundle "$tmp/SHA256SUMS.cosign.bundle" \
       --certificate-identity-regexp "$COSIGN_ID_REGEX" \
       --certificate-oidc-issuer "$COSIGN_ISSUER" >/dev/null 2>&1; then
    echo "OK: cosign keyless provenance verified (signed by the release workflow)"
    verified=1
  else
    echo "COSIGN VERIFICATION FAILED — a bundle is present but did not verify against the" >&2
    echo "expected workflow identity; refusing to install (no silent downgrade to ed25519)." >&2
    exit 1
  fi
fi
if [ "${SKILLCTL_REQUIRE_COSIGN:-0}" = "1" ] && [ "$verified" != "1" ]; then
  echo "SKILLCTL_REQUIRE_COSIGN=1 but no verifiable cosign provenance was found — refusing." >&2
  exit 1
fi

# === Provenance track 2 (fallback / current default): pinned ed25519 (SEC-M2). ===
# Reached when cosign is absent or the release carries no cosign bundle.
if [ "$verified" != "1" ]; then
  fetch SHA256SUMS.sig
  fetch skillctl-release.pub

  # SEC-M2: prefer the in-repo, version-controlled release key when this script
  # runs from a checkout — it is reviewed and cannot be swapped by an origin
  # compromise. Search a few likely roots relative to the script location.
  script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd 2>/dev/null || echo "")
  pubkey="$tmp/skillctl-release.pub"
  for cand in \
    "$script_dir/../INFRA/skillctl-release.pub" \
    "$script_dir/INFRA/skillctl-release.pub" \
    "$script_dir/skillctl-release.pub"; do
    if [ -f "$cand" ]; then
      echo "Using in-repo release key: $cand"
      pubkey="$cand"
      break
    fi
  done

  echo "Verifying ed25519 signature over SHA256SUMS (provenance)"
  if ! openssl pkeyutl -verify -pubin -inkey "$pubkey" -rawin \
         -in "$tmp/SHA256SUMS" -sigfile "$tmp/SHA256SUMS.sig" >/dev/null 2>&1; then
    echo "SIGNATURE VERIFICATION FAILED — refusing to install" >&2
    exit 1
  fi
  # Fingerprint = sha256 of the raw 32-byte ed25519 key (DER SPKI tail) — the
  # same derivation used for trust-roots + the published K-release fingerprint.
  fp=$(openssl pkey -pubin -in "$pubkey" -outform DER 2>/dev/null | tail -c 32 | sha256 | awk '{print "sha256:"$1}')
  # SEC-M2: fail closed unless the key's fingerprint matches the pinned value.
  # Without this, a signature that merely verifies against a co-located key would
  # pass — defeating the point of signing.
  if [ "$fp" != "$EXPECTED_FP" ]; then
    echo "RELEASE KEY FINGERPRINT MISMATCH — refusing to install" >&2
    echo "  expected: $EXPECTED_FP" >&2
    echo "  got:      $fp" >&2
    exit 1
  fi
  echo "OK: signed by the pinned skillctl release key ($fp)"
fi

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
