#!/usr/bin/env bash
# skillctl-smoke.sh — Smoke-test a PUBLISHED skillctl release build.
#
# Runs the full install → verify → execute → uninstall lifecycle against the
# artifact users actually download:
#   install    download the shipped binary for this host from the GitHub release
#   verify     SHA-256 against the signed SHA256SUMS (+ cosign provenance if cosign)
#   execute    a minimal offline lifecycle (version → keygen → pack → sign → verify-sig)
#   uninstall  remove the installed binary and confirm it is gone
#
# This is Phase 4 of the skillctl release chain (see docs/releasing.md and the
# /release-skillctl skill) AND the per-leg body of the H9 Tier-1 platform smoke
# gate (.github/workflows/skillctl-smoke-matrix.yml), which runs it on macOS
# arm64/amd64 + Linux amd64/arm64 (Windows is covered by a parallel matrix leg).
#
# Where the assets come from (checked in order, per asset):
#   1. SMOKE_ASSET_DIR   a locally-staged dir holding the release assets. The H9
#                        release gate stages the SAME-RUN build artifacts here
#                        (the exact bytes the release attaches) via
#                        actions/download-artifact — so the gate needs only
#                        contents:read and never has to read a DRAFT release.
#   2. gh                authenticated GitHub API (GH_TOKEN/GITHUB_TOKEN) — resolves
#                        a published release's assets for standalone/manual runs.
#   3. curl              the public download URL — local dev against a published tag.
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

# Fetch a single release asset into the CWD. Tries, per asset: (1) a locally-staged
# SMOKE_ASSET_DIR (the release gate stages the same-run build artifacts there —
# contents:read, no draft read needed), (2) the authenticated `gh` API for a
# published release, (3) the public download URL via curl.
dl() {
  local asset="$1"
  if [ -n "${SMOKE_ASSET_DIR:-}" ] && [ -f "${SMOKE_ASSET_DIR}/${asset}" ]; then
    cp "${SMOKE_ASSET_DIR}/${asset}" .
  elif [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ] && command -v gh >/dev/null 2>&1; then
    GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}" gh release download "$TAG" \
      --repo "$REPO" --pattern "$asset" --dir . --clobber
  else
    curl -fsSLO "${BASE}/${asset}"
  fi
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "=== skillctl smoke: ${TAG} (${ASSET}) ==="

# ── 1. Install: download the published artifact + its signed checksums ───────
echo "1. Install (download ${ASSET} from the release)"
if ! dl "$ASSET" || ! dl SHA256SUMS; then
  fail "could not download ${ASSET} / SHA256SUMS from ${TAG} (is the release published or drafted?)"
  exit 1
fi
dl SHA256SUMS.cosign.bundle 2>/dev/null || true
pass "downloaded ${ASSET} + SHA256SUMS"

# ── 2. Verify (integrity): the binary's digest must be in the signed SHA256SUMS ─
echo "2. Verify (SHA-256 against SHA256SUMS)"
sumtool() { command -v sha256sum >/dev/null 2>&1 && sha256sum "$@" || shasum -a 256 "$@"; }
want=$(grep " ${ASSET}\$" SHA256SUMS | awk '{print $1}' || true)
got=$(sumtool "${ASSET}" | awk '{print $1}')
if [ -n "$want" ] && [ "$want" = "$got" ]; then
  pass "SHA-256 matches the signed SHA256SUMS"
else
  fail "SHA-256 mismatch (want=${want:-<absent>} got=${got})"
fi

# ── 3. Verify (provenance): cosign (keyless OIDC) when available ─────────────
echo "3. Verify (cosign provenance)"
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

# ── 4. Execute: the shipped binary runs, end to end, offline ─────────────────
echo "4. Execute (offline lifecycle on the shipped binary)"
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

# ── 5. Uninstall: remove the installed binary and confirm it is gone ─────────
echo "5. Uninstall (remove the binary, verify it is gone)"
rm -f "${BIN}"
if [ ! -e "${BIN}" ]; then
  pass "uninstalled — ${ASSET} removed"
else
  fail "uninstall failed — ${ASSET} still present"
fi

echo "─────────────────────────────"
if [ "$FAILED" -eq 0 ]; then
  echo -e "${GREEN}SMOKE PASS${NC}: ${TAG} — the published build downloads, verifies and runs."
else
  echo -e "${RED}SMOKE FAIL${NC}: ${TAG} — the published build is broken; roll it back (see /release-skillctl Phase 6)."
  exit 1
fi
