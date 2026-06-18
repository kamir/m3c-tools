#!/usr/bin/env bash
# Build, checksum, and SIGN a multi-arch skillctl release (SPEC-0246 distribution).
#
# Produces, under release/<tag>/ :
#   skillctl-{darwin,linux}-{amd64,arm64}, skillctl-windows-amd64.exe
#   SHA256SUMS            — sha256 of every binary (integrity)
#   SHA256SUMS.sig        — detached ed25519 signature over SHA256SUMS (provenance, K-release)
#   skillctl-release.pub  — the K-release public key (also pinned at INFRA/)
#   install.sh            — curl|bash installer (verifies sig + sha256)
#   RELEASE_NOTES.md
#
# Usage:
#   tools/skillctl-release.sh skillctl/v0.2.0
#
# Env:
#   RELEASE_KEY  ed25519 private key (PEM). Default: ~/.config/m3c/skill-release.key
set -euo pipefail

TAG="${1:?usage: skillctl-release.sh <tag>  e.g. skillctl/v0.2.0}"
VERSION="${TAG##*/}"                      # v0.2.0
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_KEY="${RELEASE_KEY:-$HOME/.config/m3c/skill-release.key}"
OUT="${REPO_ROOT}/release/${TAG}"

[ -f "${RELEASE_KEY}" ] || { echo "release key not found: ${RELEASE_KEY}" >&2; exit 1; }
mkdir -p "${OUT}"

# Portable sha256 (Linux sha256sum / macOS shasum).
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"
  else shasum -a 256 "$@"; fi
}

echo "==> building skillctl ${TAG} (5 targets, -trimpath, version-stamped)"
build() {
  local os="$1" arch="$2" ext="${3:-}"
  local out="${OUT}/skillctl-${os}-${arch}${ext}"
  GOOS="${os}" GOARCH="${arch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -X main.version=${TAG}" \
    -o "${out}" ./cmd/skillctl
  echo "    $(basename "${out}")"
}
( cd "${REPO_ROOT}"
  build darwin  arm64
  build darwin  amd64
  build linux   amd64
  build linux   arm64
  build windows amd64 .exe )

echo "==> SHA256SUMS"
( cd "${OUT}" && sha256 skillctl-* > SHA256SUMS && cat SHA256SUMS )

echo "==> sign SHA256SUMS with K-release (ed25519)"
openssl pkeyutl -sign -inkey "${RELEASE_KEY}" -rawin \
  -in "${OUT}/SHA256SUMS" -out "${OUT}/SHA256SUMS.sig"
openssl pkey -in "${RELEASE_KEY}" -pubout -out "${OUT}/skillctl-release.pub"

echo "==> verify signature locally (gate)"
openssl pkeyutl -verify -pubin -inkey "${OUT}/skillctl-release.pub" -rawin \
  -in "${OUT}/SHA256SUMS" -sigfile "${OUT}/SHA256SUMS.sig" \
  || { echo "SIGNATURE VERIFY FAILED" >&2; exit 1; }

cp "${REPO_ROOT}/tools/skillctl-install.sh" "${OUT}/install.sh"
# Stamp the installer's default RELEASE_BASE to THIS release, so
# `curl …/${TAG}/install.sh | bash` (no env override) installs THIS version.
# Without this the copied default points at whatever tag was committed, and a
# no-override install silently fetches the wrong (older) binary.
sed "s#download/skillctl/[^\"}]*#download/${TAG}#" "${OUT}/install.sh" > "${OUT}/install.sh.tmp" && mv "${OUT}/install.sh.tmp" "${OUT}/install.sh"
echo "==> install.sh RELEASE_BASE default → ${TAG}"
grep 'RELEASE_BASE:-' "${OUT}/install.sh" | head -1
FP="sha256:$(openssl pkey -in "${RELEASE_KEY}" -pubout -outform DER 2>/dev/null | tail -c 32 | sha256 | awk '{print $1}')"

cat > "${OUT}/RELEASE_NOTES.md" <<EOF
# skillctl ${VERSION}

Trust-and-governance CLI for AI-agent skills. Single static Go binary — no Node.

## Install (verifies signature + checksum)

\`\`\`sh
curl -fsSL https://github.com/kamir/m3c-tools/releases/download/${TAG}/install.sh \\
  | RELEASE_BASE=https://github.com/kamir/m3c-tools/releases/download/${TAG} bash
\`\`\`

## What's new
- \`skillctl publish --share-room <label>\` — map a bundle into a SPEC-0096
  co-learning room at admit time (repeatable; \`\$SKILL_SHARE_ROOMS\`).
- \`skillctl room share|unshare <skill> --room <label>\` — back-fill / remove the
  room mapping on already-published bundles.
- \`skillctl version\` — prints the stamped release tag.

## Provenance
Binaries are checksummed (\`SHA256SUMS\`) and the manifest is ed25519-signed
(\`SHA256SUMS.sig\`) by the skillctl **release key** (separate from skill-author
keys). Verify against the pinned public key:

- \`skillctl-release.pub\` (also at \`INFRA/skillctl-release.pub\` in the repo)
- K-release fingerprint: \`${FP}\`

\`\`\`sh
openssl pkeyutl -verify -pubin -inkey skillctl-release.pub -rawin \\
  -in SHA256SUMS -sigfile SHA256SUMS.sig
\`\`\`
EOF

echo "==> generate onboarding runbook (release-prep standard)"
"${REPO_ROOT}/tools/skillctl-runbook.sh" "${TAG}" "${OUT}/skillctl-publisher-runbook.html"

echo
echo "==> assembled: ${OUT}"
ls -1 "${OUT}"
echo "K-release fingerprint: ${FP}"
echo
echo "Publish (draft) with:"
echo "  gh release create ${TAG} --draft --title \"skillctl ${VERSION}\" \\"
echo "     --notes-file ${OUT}/RELEASE_NOTES.md ${OUT}/skillctl-* ${OUT}/SHA256SUMS ${OUT}/SHA256SUMS.sig ${OUT}/skillctl-release.pub ${OUT}/install.sh"
