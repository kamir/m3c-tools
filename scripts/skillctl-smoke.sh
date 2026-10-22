#!/usr/bin/env bash
# skillctl-smoke.sh: Smoke-test a PUBLISHED skillctl release build.
#
# Runs the full install → verify → execute → uninstall lifecycle against the
# artifact users actually download:
#   install    download the shipped binary for this host from the GitHub release
#   verify     SHA-256 against the signed SHA256SUMS (+ cosign provenance if cosign)
#   execute    a minimal offline lifecycle (version → keygen → pack → sign → verify-sig)
#   uninstall  remove the installed binary and confirm it is gone
#
# This is the published-artifact check for .github/workflows/skillctl-release.yml
# and the per-leg body of the H9 Tier-1 platform smoke
# gate (.github/workflows/skillctl-smoke-matrix.yml), which runs it on macOS
# arm64/amd64 + Linux amd64/arm64 (Windows is covered by a parallel matrix leg).
#
# Required mode is the default: missing cosign/bundle and wrong version fail.
# SMOKE_REQUIRED=0 explicitly selects a manual integrity-only compatibility run.
# SMOKE_STAGED_REQUIRED=1 forbids download fallback for same-run release assets.
# SMOKE_TARGET explicitly selects darwin/arm64, darwin/amd64, linux/amd64 or linux/arm64.
# Selecting darwin/amd64 on Apple silicon exercises Rosetta, not native Intel.
# Where optional/manual assets come from (checked in order, per asset):
#   1. SMOKE_ASSET_DIR   a locally-staged dir holding the release assets. The H9
#                        release gate stages the SAME-RUN build artifacts here
#                        (the exact bytes the release attaches) via
#                        actions/download-artifact, so the gate needs only
#                        contents:read and never has to read a DRAFT release.
#   2. gh                authenticated GitHub API (GH_TOKEN/GITHUB_TOKEN): resolves
#                        a published release's assets for standalone/manual runs.
#   3. curl              the public download URL: local dev against a published tag.
#
# Usage:  scripts/skillctl-smoke.sh [skillctl/vX.Y.Z]   (defaults to the latest skillctl tag)
set -euo pipefail

REPO="${REPO:-kamir/m3c-tools}"
TAG="${1:-$(git tag --list 'skillctl/v*' --sort=-v:refname 2>/dev/null | head -1)}"
[ -n "$TAG" ] || { echo "skillctl-smoke: no skillctl/v* tag given or found" >&2; exit 2; }
VER="${TAG#skillctl/}"          # v0.4.0
VER_NUM="${VER#v}"              # 0.4.0

REQUIRED="${SMOKE_REQUIRED:-1}"
STAGED_REQUIRED="${SMOKE_STAGED_REQUIRED:-0}"
case "$REQUIRED:$STAGED_REQUIRED" in 0:0|0:1|1:0|1:1) ;; *) echo "invalid smoke mode" >&2; exit 2 ;; esac

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
TARGET="${SMOKE_TARGET:-${os}/${arch}}"
case "$TARGET" in
  darwin/arm64|darwin/amd64|linux/amd64|linux/arm64) ;;
  *) echo "unsupported SMOKE_TARGET: $TARGET" >&2; exit 2 ;;
esac
ASSET="skillctl-${TARGET/\//-}"
BASE="https://github.com/${REPO}/releases/download/${TAG}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YEL='\033[0;33m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; FAILED=1; }
warn() { echo -e "  ${YEL}!${NC} $1"; }
FAILED=0

# Fetch a single release asset into the CWD. Tries, per asset: (1) a locally-staged
# SMOKE_ASSET_DIR (the release gate stages the same-run build artifacts there:
# contents:read, no draft read needed), (2) the authenticated `gh` API for a
# published release, (3) the public download URL via curl.
dl() {
  local asset="$1"
  if [ -n "${SMOKE_ASSET_DIR:-}" ] && [ -f "${SMOKE_ASSET_DIR}/${asset}" ]; then
    cp "${SMOKE_ASSET_DIR}/${asset}" .
  elif [ "$STAGED_REQUIRED" = "1" ]; then
    echo "required staged asset absent: $asset" >&2
    return 1
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
# These controls suppress native credential operations in the lifecycle. They do
# not isolate arbitrary skill execution or prove native credential integration.
mkdir -p "$WORK/home"
export HOME="$WORK/home" USERPROFILE="$WORK/home"
export M3C_TOKEN_STORE=file M3C_TEST_KEYCHAIN=0 M3C_ER1_KEYCHAIN=off

echo "=== skillctl smoke: ${TAG} (${ASSET}) ==="

# ── 1. Install: download the published artifact + its signed checksums ───────
echo "1. Install (download ${ASSET} from the release)"
if ! dl "$ASSET" || ! dl SHA256SUMS; then
  fail "could not download ${ASSET} / SHA256SUMS from ${TAG} (is the release published or drafted?)"
  exit 1
fi
if ! dl SHA256SUMS.cosign.bundle; then
  if [ "$REQUIRED" = "1" ]; then
    fail "required cosign bundle missing"
    exit 1
  fi
fi
pass "downloaded ${ASSET} + SHA256SUMS"

# ── 2. Verify (integrity): the binary's digest must be in the signed SHA256SUMS ─
echo "2. Verify (SHA-256 against SHA256SUMS)"
sumtool() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}
want=$(awk -v asset="$ASSET" '$2 == asset && NF == 2 {count++; digest=$1} END {if (count == 1) print digest}' SHA256SUMS)
if [[ ! "$want" =~ ^[[:xdigit:]]{64}$ ]]; then
  fail "missing, duplicate or invalid SHA256SUMS entry for $ASSET"
  exit 1
fi
got=$(sumtool "${ASSET}" | awk '{print $1}')
if [ -n "$want" ] && [ "$want" = "$got" ]; then
  pass "SHA-256 matches the signed SHA256SUMS"
else
  fail "SHA-256 mismatch (want=${want:-<absent>} got=${got})"
  exit 1
fi

# ── 3. Verify (provenance): cosign (keyless OIDC) when available ─────────────
echo "3. Verify (cosign provenance)"
if command -v cosign >/dev/null 2>&1 && [ -f SHA256SUMS.cosign.bundle ]; then
  if cosign verify-blob SHA256SUMS --bundle SHA256SUMS.cosign.bundle \
       --certificate-identity "https://github.com/${REPO}/.github/workflows/skillctl-release.yml@refs/tags/${TAG}" \
       --certificate-oidc-issuer "https://token.actions.githubusercontent.com" >/dev/null 2>&1; then
    pass "cosign provenance verified (keyless OIDC)"
  else
    fail "cosign verify-blob FAILED for SHA256SUMS"
    exit 1
  fi
else
  if [ "$REQUIRED" = "1" ]; then
    fail "required cosign verifier or bundle missing"
    exit 1
  fi
  warn "MANUAL OPTIONAL MODE: provenance not checked; no release acceptance"
fi

# ── 4. Execute: the shipped binary runs, end to end, offline ─────────────────
echo "4. Execute (offline lifecycle on the shipped binary)"
chmod +x "${ASSET}"
BIN="./${ASSET}"
if out=$("$BIN" version 2>&1); then
  case "$out" in
    "$TAG"|"$VER"|"$VER_NUM") pass "version reports ${VER_NUM}" ;;
    *)
      if [ "$REQUIRED" = "1" ]; then
        fail "version does not exactly match $TAG"
        exit 1
      fi
      warn "MANUAL OPTIONAL MODE: version does not match $TAG"
      ;;
  esac
else
  fail "\`skillctl version\` did not run"
  exit 1
fi

mkdir -p smoke-skill
printf -- '---\nname: smoke\ndescription: skillctl release smoke-test skill.\n---\n# smoke\n' > smoke-skill/SKILL.md
# Note: sign/verify-sig use the Go flag package, which stops at the first
# positional, so flags MUST precede the BUNDLE.skb positional.
if "$BIN" keygen --out ./smk >/dev/null 2>&1 \
   && "$BIN" pack --skill ./smoke-skill -o ./s.skb --name smoke --version 1.0.0 >/dev/null 2>&1 \
   && "$BIN" sign --key ./smk.priv ./s.skb >/dev/null 2>&1 \
   && "$BIN" verify-sig --pubkey ./smk.pub ./s.skb >/dev/null 2>&1; then
  pass "keygen → pack → sign → verify-sig (offline) succeeded"
else
  fail "offline lifecycle failed on the shipped binary"
fi

# ── 4b. Execute: the trust-freeze chain on the shipped binary, offline ─────
# capture → approve → verify → diff against the walking-skeleton profile, which
# requires only the portable common.identity probe and therefore completes on
# every platform this smoke runs on. HOME is a throwaway directory on purpose: a
# capture reads the host and must write nothing outside its own output directory,
# and a smoke that let it scribble in the runner's home would hide exactly that.
# The Windows leg of the release workflow runs `skillctl version` inline and does
# not reach this script, so Windows coverage of these verbs is the unit suite and
# the Windows Gate, not this step.
echo "4b. Execute (trust-freeze capture → approve → verify → diff, offline)"
TFHOME="${WORK}/tf-home"
mkdir -p "$TFHOME"
if HOME="$TFHOME" USERPROFILE="$TFHOME" "$BIN" trust-freeze doctor --output "${WORK}/tf-cap" >/dev/null 2>&1 \
   && HOME="$TFHOME" USERPROFILE="$TFHOME" "$BIN" trust-freeze capture --profile walking-skeleton \
        --output "${WORK}/tf-cap" --actor release-smoke >/dev/null 2>&1 \
   && HOME="$TFHOME" USERPROFILE="$TFHOME" "$BIN" keygen --out "${WORK}/tfkey" >/dev/null 2>&1 \
   && HOME="$TFHOME" USERPROFILE="$TFHOME" "$BIN" trust-freeze baseline approve --capture "${WORK}/tf-cap" \
        --output "${WORK}/tf-base" --reviewer release-smoke --change-id SMOKE \
        --reason "release smoke test" --key "${WORK}/tfkey.priv" \
        --self-approval allow >/dev/null 2>&1 \
   && HOME="$TFHOME" USERPROFILE="$TFHOME" "$BIN" trust-freeze verify --bundle "${WORK}/tf-base" \
        --trusted-key "${WORK}/tfkey.pub" >/dev/null 2>&1 \
   && HOME="$TFHOME" USERPROFILE="$TFHOME" "$BIN" trust-freeze diff --baseline "${WORK}/tf-base" \
        --current "${WORK}/tf-cap" --trusted-key "${WORK}/tfkey.pub" >/dev/null 2>&1; then
  pass "trust-freeze capture → approve → verify → diff (offline) succeeded"
else
  fail "the trust-freeze chain failed on the shipped binary"
fi

# ── 5. Uninstall: remove the installed binary and confirm it is gone ─────────
echo "5. Uninstall (remove the binary, verify it is gone)"
rm -f "${BIN}"
if [ ! -e "${BIN}" ]; then
  pass "uninstalled, ${ASSET} removed"
else
  fail "uninstall failed, ${ASSET} still present"
fi

echo "─────────────────────────────"
if [ "$FAILED" -eq 0 ]; then
  if [ "$REQUIRED" = "1" ]; then
    echo -e "${GREEN}SMOKE PASS${NC}: ${TAG} (${TARGET}, required checks passed)"
  else
    echo -e "${YEL}MANUAL OPTIONAL SMOKE COMPLETE${NC}: no release acceptance"
  fi
else
  echo -e "${RED}SMOKE FAIL${NC}: ${TAG}) the published build is broken; roll it back (see /release-skillctl Phase 6)."
  exit 1
fi
