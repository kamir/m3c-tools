#!/usr/bin/env bash
# 08-invalid-no-signature — A bundle delivered without the matching
# <digest>.author.sig file. Expected: skillctl verify-sig refuses (non-zero).
#
# Failure mode in production: a downloader who rsync'd the .skb but forgot
# the sidecar signature. The verifier MUST fail closed; "no signature found"
# is a fatal condition, not a "trust by default" fallback.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "08 — INVALID: bundle without its detached signature"

DIGEST=$(cat "$ARTIFACTS_DIR/digest.txt")
BUNDLE_ORIG="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.skb"
SIG_ORIG="${BUNDLE_ORIG}.${DIGEST#sha256:}.author.sig"

# Stage a copy of the bundle WITHOUT its sig file.
NAKED_DIR="$BUNDLES_DIR/no-sig"
mkdir -p "$NAKED_DIR"
cp "$BUNDLE_ORIG" "$NAKED_DIR/"
test -f "$NAKED_DIR/$(basename "$BUNDLE_ORIG")"
test ! -f "$NAKED_DIR/$(basename "$SIG_ORIG")"
ok "staged $NAKED_DIR/ — bundle present, signature ABSENT"

log "Eric: skillctl verify-sig on a bundle with no sidecar signature"
# Allow either exit 11 (signature invalid) or exit 1 (generic — file not found).
# Both prove the verifier refuses. Use a wrapper to map "anything non-zero" → ok.
set +e
"$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/mirko.pub" \
    "$NAKED_DIR/$(basename "$BUNDLE_ORIG")" >>"$LOG_DIR/full.log" 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  fail "verify-sig accepted a bundle with no signature — this is a CRITICAL bug"
  exit 1
elif [[ "$rc" -eq 11 || "$rc" -eq 1 ]]; then
  ok "verify-sig refused with exit $rc (no signature available)"
else
  warn "verify-sig refused with exit $rc — refusal accepted, code surprised us"
fi

header "08 — done — UNSIGNED DELIVERY REFUSED ✓"
