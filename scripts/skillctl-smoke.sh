#!/usr/bin/env bash
# skillctl-smoke.sh — Smoke-test a PUBLISHED skillctl release build.
#
# Downloads the shipped binary for this host from the GitHub release, verifies its
# integrity (SHA-256 against the signed SHA256SUMS, plus cosign provenance when
# cosign is present), then runs a minimal offline lifecycle (version → keygen →
# pack → sign → verify-sig) to prove the artifact users actually download works.
#
# This is Phase 4 of the skillctl release chain (see docs/releasing.md and the
# /release-skillctl skill). Windows is smoke-tested separately by
# .github/workflows/skillctl-windows-smoke.yml (install from the published release).
#
# Usage:  scripts/skillctl-smoke.sh [skillctl/vX.Y.Z]   (defaults to the latest skillctl tag)
set -euo pipefail

REPO="${REPO:-kamir/m3c-tools}"
TAG="${1:-$(git tag --list 'skillctl/v*' --sort=-v:refname 2>/dev/null | head -1)}"
[ -n "$TAG" ] || { echo "skillctl-smoke: no skillctl/v* tag given or found" >&2; exit 2; }
VER="${TAG#skillctl/}"          # v0.4.0
VER_NUM="${VER#v}"              # 0.4.0

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
ASSET="skillctl-${os}-${arch}"
BASE="https://github.com/${REPO}/releases/download/${TAG}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[0;33m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; FAILED=1; }
warn() { echo -e "  ${YEL}!${NC} $1"; }
FAILED=0

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "=== skillctl smoke: ${TAG} (${ASSET}) ==="

# ── 1. Download the published artifact + its signed checksums ────────────────
echo "1. Download from the release"
if ! curl -fsSLO "${BASE}/${ASSET}" || ! curl -fsSLO "${BASE}/SHA256SUMS"; then
  fail "could not download ${ASSET} / SHA256SUMS from ${TAG} (is the release published?)"
  exit 1
fi
curl -fsSLO "${BASE}/SHA256SUMS.cosign.bundle" 2>/dev/null || true
pass "downloaded ${ASSET} + SHA256SUMS"

# ── 2. Integrity: the binary's digest must be in the signed SHA256SUMS ───────
echo "2. Integrity (SHA-256 against SHA256SUMS)"
sumtool() { command -v sha256sum >/dev/null 2>&1 && sha256sum "$@" || shasum -a 256 "$@"; }
want=$(grep " ${ASSET}\$" SHA256SUMS | awk '{print $1}' || true)
got=$(sumtool "${ASSET}" | awk '{print $1}')
if [ -n "$want" ] && [ "$want" = "$got" ]; then
  pass "SHA-256 matches the signed SHA256SUMS"
else
  fail "SHA-256 mismatch (want=${want:-<absent>} got=${got})"
fi

# ── 3. Provenance: cosign (keyless OIDC) when available ─────────────────────
echo "3. Provenance"
if command -v cosign >/dev/null 2>&1 && [ -f SHA256SUMS.cosign.bundle ]; then
  if cosign verify-blob SHA256SUMS --bundle SHA256SUMS.cosign.bundle \
       --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/skillctl-release\.yml@refs/tags/skillctl/v" \
       --certificate-oidc-issuer "https://token.actions.githubusercontent.com" >/dev/null 2>&1; then
    pass "cosign provenance verified (keyless OIDC)"
  else
    fail "cosign verify-blob FAILED for SHA256SUMS"
  fi
else
  warn "cosign not available — skipped provenance check (SHA-256 above is the integrity anchor)"
fi

# ── 4. The shipped binary runs, end to end, offline ─────────────────────────
echo "4. Lifecycle on the shipped binary"
chmod +x "${ASSET}"
BIN="./${ASSET}"
if out=$("$BIN" version 2>&1); then
  if echo "$out" | grep -q "$VER_NUM"; then pass "version reports ${VER_NUM}"; else warn "version output does not mention ${VER_NUM}: ${out}"; fi
else
  fail "\`skillctl version\` did not run"
fi

mkdir -p smoke-skill
printf -- '---\nname: smoke\ndescription: skillctl release smoke-test skill.\n---\n# smoke\n' > smoke-skill/SKILL.md
# Note: sign/verify-sig use the Go flag package, which stops at the first
# positional — so flags MUST precede the BUNDLE.skb positional.
if "$BIN" keygen --out ./smk >/dev/null 2>&1 \
   && "$BIN" pack --skill ./smoke-skill -o ./s.skb --name smoke --version 1.0.0 >/dev/null 2>&1 \
   && "$BIN" sign --key ./smk.priv ./s.skb >/dev/null 2>&1 \
   && "$BIN" verify-sig --pubkey ./smk.pub ./s.skb >/dev/null 2>&1; then
  pass "keygen → pack → sign → verify-sig (offline) succeeded"
else
  fail "offline lifecycle failed on the shipped binary"
fi

echo "─────────────────────────────"
if [ "$FAILED" -eq 0 ]; then
  echo -e "${GREEN}SMOKE PASS${NC}: ${TAG} — the published build downloads, verifies and runs."
else
  echo -e "${RED}SMOKE FAIL${NC}: ${TAG} — the published build is broken; roll it back (see /release-skillctl Phase 6)."
  exit 1
fi
