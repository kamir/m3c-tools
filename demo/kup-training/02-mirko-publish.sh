#!/usr/bin/env bash
# 02-mirko-publish — Mirko publishes the bundle to the registry (online).
# This step is BEST-EFFORT. If the registry isn't reachable or
# ER1_API_KEY isn't set, the demo continues offline (the cryptographic
# chain is fully provable without it).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "02 — Mirko publishes to the ER1 self registry"

if ! online_mode_available; then
  warn "online mode not available — skipping the ER1 self publish"
  warn "the chain proof in steps 03–09 still runs end-to-end (offline)"
  exit 0
fi

BUNDLE="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.skb"

# Re-pointed (SPEC-0246 convergence) from the HTTP /api/skills registry to the
# ER1 `self` transport: `skillctl publish --registry self`. This exercises the
# real ER1 publish code path (POST /upload_2, envelope-signing, tag schema).
#
# SINGLE-MACHINE SMOKE: the runner's ER1 login acts as the author, publishing
# into their own <sub>___skills context. A true TWO-PERSON cross-principal run
# (SPEC-0246 AC3) needs two ER1 accounts and is validated manually (§11).
# Best-effort: any failure warns; the offline chain proof in 05 proves the trust
# core regardless. Targets `local` by default so demo items never land in prod
# ER1 — set ER1_TARGET=prod for a real run.
ER1_TARGET="${ER1_TARGET:-local}"
log "Mirko: skillctl publish $SKILL_NAME@$SKILL_VERSION --registry self --er1-target $ER1_TARGET"
set +e
HOME="$INSTALL_HOME" "$SKILLCTL" publish "$SKILL_NAME@$SKILL_VERSION" \
    --bundle "$BUNDLE" --registry self \
    --er1-target "$ER1_TARGET" --er1-context skills \
    --key "$KEYS_DIR/mirko.priv" --identity "$MIRKO_ID" --yes \
    >>"$LOG_DIR/full.log" 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  ok "published to ER1 self ($ER1_TARGET)"
else
  warn "publish --registry self exit $rc — ER1 transport not exercised"
  warn "(needs an ER1 login + a reachable '$ER1_TARGET' target); offline chain in 05 is unaffected"
fi

header "02 — done (ER1 self publish attempted)"
