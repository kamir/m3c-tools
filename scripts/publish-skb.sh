#!/usr/bin/env bash
# scripts/publish-skb.sh — publish a signed .skb skill bundle as an OCI
# artifact (SPEC-0354 D2).
#
# A .skb is a deterministic, portable, signed skill bundle. This script
# pushes it into any OCI registry as a first-class artifact (via ORAS,
# with a dedicated artifact-type) and then signs the resulting reference
# with cosign — so image, bundle, and signature can live in one registry
# (Zot / Harbor / GHCR / GAR). The consumer side is `oras pull` +
# `skillctl verify`; the trust lives in the registry metadata + trust
# roots, never inside the artifact.
#
# The reference is derived from the bundle filename, which by convention
# is  <name>@<version>.skb :
#     er1-progress-report@1.0.0.skb
#        -> <registry>/skills/er1-progress-report:1.0.0
#
# Usage:
#   scripts/publish-skb.sh --skb <file.skb> --registry <host/namespace> \
#       [--sign|--no-sign] [--key <cosign.key>] [--verify-after] [--dry-run]
#
# Examples:
#   scripts/publish-skb.sh --skb er1-progress-report@1.0.0.skb \
#       --registry ghcr.io/kamir --dry-run
#   COSIGN_KEY=author.key scripts/publish-skb.sh \
#       --skb er1-progress-report@1.0.0.skb --registry ghcr.io/kamir --verify-after
#
# Exit codes (fail-closed):
#   0  success
#   2  usage / bad input (missing/misnamed .skb, missing --registry)
#   3  oras not installed
#   4  cosign not installed but signing requested
#   5  push failed / digest mismatch on verify-after
set -euo pipefail

ARTIFACT_TYPE="application/vnd.m3c.skill.bundle.v1+gzip"

SKB=""
REGISTRY="${REGISTRY:-}"
SIGN=1
COSIGN_KEY="${COSIGN_KEY:-}"
VERIFY_AFTER=0
DRY_RUN=0

die()  { echo "publish-skb: $*" >&2; exit "${2:-2}"; }
note() { echo "publish-skb: $*" >&2; }
run()  { if [ "$DRY_RUN" -eq 1 ]; then echo "  + $*"; else "$@"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --skb)          SKB="${2:-}"; shift 2;;
    --registry)     REGISTRY="${2:-}"; shift 2;;
    --sign)         SIGN=1; shift;;
    --no-sign)      SIGN=0; shift;;
    --key)          COSIGN_KEY="${2:-}"; shift 2;;
    --verify-after) VERIFY_AFTER=1; shift;;
    --dry-run)      DRY_RUN=1; shift;;
    -h|--help)      sed -n '2,40p' "$0"; exit 0;;
    *)              die "unknown argument: $1";;
  esac
done

# ---- input validation (fail-closed) -----------------------------------
[ -n "$SKB" ]      || die "missing --skb <file.skb>"
[ -n "$REGISTRY" ] || die "missing --registry <host/namespace> (or set REGISTRY)"
[ -f "$SKB" ]      || die "bundle not found: $SKB"

base="$(basename "$SKB" .skb)"
case "$base" in
  *@*) NAME="${base%@*}"; VERSION="${base##*@}";;
  *)   die "bundle filename must be <name>@<version>.skb, got: $(basename "$SKB")";;
esac
[ -n "$NAME" ] && [ -n "$VERSION" ] || die "could not derive name/version from: $(basename "$SKB")"

REF="${REGISTRY%/}/skills/${NAME}:${VERSION}"

# ---- tool preflight (fail-closed) -------------------------------------
if ! command -v oras >/dev/null 2>&1; then
  note "oras is required but not installed."
  note "  install: https://oras.land/docs/installation  (brew install oras)"
  [ "$DRY_RUN" -eq 1 ] || die "oras not installed" 3
fi
if [ "$SIGN" -eq 1 ] && ! command -v cosign >/dev/null 2>&1; then
  note "cosign requested but not installed (use --no-sign to skip signing)."
  [ "$DRY_RUN" -eq 1 ] || die "cosign not installed" 4
fi

# ---- transport integrity marker ---------------------------------------
# sha256 of the .skb bytes; used to prove byte-identity after --verify-after.
# (This is the transport digest, distinct from skillctl's canonical bundle
# digest — that one is recomputed by `skillctl verify` from the archive.)
if command -v shasum >/dev/null 2>&1; then
  SRC_SHA="$(shasum -a 256 "$SKB" | awk '{print $1}')"
else
  SRC_SHA="$(sha256sum "$SKB" | awk '{print $1}')"
fi

note "bundle : $SKB"
note "name   : $NAME"
note "version: $VERSION"
note "ref    : $REF"
note "sha256 : $SRC_SHA"
note "type   : $ARTIFACT_TYPE"
[ "$DRY_RUN" -eq 1 ] && note "(dry-run — no registry calls will be made)"

# ---- push -------------------------------------------------------------
run oras push "$REF" \
  --artifact-type "$ARTIFACT_TYPE" \
  "${SKB}:${ARTIFACT_TYPE}" || die "oras push failed" 5

# ---- sign -------------------------------------------------------------
if [ "$SIGN" -eq 1 ]; then
  if [ -n "$COSIGN_KEY" ]; then
    run cosign sign --yes --key "$COSIGN_KEY" "$REF"
  else
    note "no --key/COSIGN_KEY given — attempting keyless (OIDC) cosign sign"
    run cosign sign --yes "$REF"
  fi
else
  note "signing skipped (--no-sign)"
fi

# ---- verify-after (byte-identity round-trip) --------------------------
if [ "$VERIFY_AFTER" -eq 1 ] && [ "$DRY_RUN" -eq 0 ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  note "verify-after: pulling $REF back to check byte-identity"
  ( cd "$tmp" && oras pull "$REF" )
  pulled="$tmp/$(basename "$SKB")"
  [ -f "$pulled" ] || die "verify-after: pulled artifact missing $(basename "$SKB")" 5
  if command -v shasum >/dev/null 2>&1; then
    GOT_SHA="$(shasum -a 256 "$pulled" | awk '{print $1}')"
  else
    GOT_SHA="$(sha256sum "$pulled" | awk '{print $1}')"
  fi
  [ "$GOT_SHA" = "$SRC_SHA" ] || die "verify-after: digest mismatch ($GOT_SHA != $SRC_SHA)" 5
  note "verify-after: OK — byte-identical ($GOT_SHA)"
  if [ "$SIGN" -eq 1 ] && [ -n "$COSIGN_KEY" ]; then
    run cosign verify --key "${COSIGN_KEY}.pub" "$REF" >/dev/null 2>&1 \
      && note "cosign verify: OK" || note "cosign verify: skipped/failed (check pubkey)"
  fi
fi

note "done."
