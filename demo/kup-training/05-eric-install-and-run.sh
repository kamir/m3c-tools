#!/usr/bin/env bash
# 05-eric-install-and-run — Eric pulls + verifies + installs + runs the skill.
#
# Online (registry reachable): full SPEC-0188 §7 chain check via `skillctl install`.
# Offline:                      proves the same primitives via verify-sig + manual
#                               extract + run (the cryptographic proof is the same).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "05 — Eric installs and runs kup-hello"

DIGEST=$(cat "$ARTIFACTS_DIR/digest.txt")
BUNDLE="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.skb"
SIG="${BUNDLE}.${DIGEST#sha256:}.author.sig"

if online_mode_available; then
  # Re-pointed (SPEC-0246 AC3 convergence) from `skillctl install --registry
  # .../api/skills` to the ER1 `self` pull path. Single-machine smoke (see 02's
  # note). Eric pins Mirko's key via a HAND-WRITTEN self trust-roots.yaml — the
  # ER1 `self` path uses ~/.claude/trust-roots.yaml, NOT `trust add`.
  ER1_TARGET="${ER1_TARGET:-local}"
  mkdir -p "$INSTALL_HOME/.claude"
  PUB_B64=$(openssl pkey -pubin -in "$KEYS_DIR/mirko.pub" -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n')
  cat > "$INSTALL_HOME/.claude/trust-roots.yaml" <<YAML
registry: self
pubkey_b64: $PUB_B64
governance_minimum: green
YAML
  log "Eric: skillctl pull --registry self --er1-target $ER1_TARGET (G-23 dry-run then confirm)"
  set +e
  TOKEN=$(HOME="$INSTALL_HOME" "$SKILLCTL" pull --registry self \
       --er1-target "$ER1_TARGET" --er1-context skills --skill "$SKILL_NAME" \
       --install --trust-mode --dry-run-install --no-checkpoint 2>>"$LOG_DIR/full.log" \
       | sed -n 's/.*dry-run-install token (5-minute TTL): //p' | head -1)
  if [[ -n "${TOKEN:-}" ]]; then
    HOME="$INSTALL_HOME" "$SKILLCTL" pull --registry self \
       --er1-target "$ER1_TARGET" --er1-context skills --skill "$SKILL_NAME" \
       --install --trust-mode --confirm-install --dry-run-install-token "$TOKEN" \
       --no-checkpoint >>"$LOG_DIR/full.log" 2>&1 \
      && ok "pulled + installed via ER1 self ($ER1_TARGET) — full chain verified by pull's 5 gates" \
      || warn "pull --confirm-install failed — ER1 transport not fully exercised"
  else
    warn "pull --registry self did not yield an install token — ER1 transport not exercised"
    warn "(needs a live '$ER1_TARGET' ER1 with the skill published in step 02); falling back to offline proof"
  fi
  set -e
fi

# OFFLINE / FALLBACK CHAIN PROOF — this is the load-bearing demonstration:
#   1) Eric verifies the author signature against the pinned pubkey.
#   2) On success, Eric extracts the bundle to ~/.claude/skills/<name>/.
#   3) Eric runs the skill.
header "05a — Offline chain proof (always runs)"

log "Eric: skillctl verify-sig --pubkey mirko.pub $BUNDLE"
assert_exit 0 -- "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/mirko.pub" "$BUNDLE"

# Extract (mirroring what `skillctl install`'s atomic-move step does)
INSTALL_TARGET="$INSTALL_HOME/.claude/skills/$SKILL_NAME"
rm -rf "$INSTALL_TARGET"
mkdir -p "$INSTALL_TARGET"
tar -xzf "$BUNDLE" -C "$INSTALL_TARGET"
ok "extracted to $INSTALL_TARGET"

# Confirm the install reflects the bundle (CHECKSUMS exist + SKILL.md has frontmatter)
test -f "$INSTALL_TARGET/SKILL.md" || { fail "missing SKILL.md after install"; exit 1; }
test -f "$INSTALL_TARGET/CHECKSUMS" || { fail "missing CHECKSUMS after install"; exit 1; }
ok "SKILL.md + CHECKSUMS present"

# Run the skill itself (the skill is deliberately trivial; the point is provenance).
header "05b — Eric runs the skill"
log "Eric: bash $INSTALL_TARGET/scripts/hello.sh"
( cd "$INSTALL_HOME" && bash "$INSTALL_TARGET/scripts/hello.sh" ) | tee -a "$LOG_DIR/full.log" | sed 's/^/      /'
test -f "$INSTALL_HOME/output/hello.txt"
ok "skill produced $INSTALL_HOME/output/hello.txt"
note "$(cat "$INSTALL_HOME/output/hello.txt")"

header "05 — done — VALID SKILL WORKS FOR ERIC ✓"
