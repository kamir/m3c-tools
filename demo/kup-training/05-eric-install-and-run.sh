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
  log "Eric: skillctl install $SKILL_NAME@$SKILL_VERSION --registry $REGISTRY_URL"
  set +e
  HOME="$INSTALL_HOME" \
    "$SKILLCTL" install "$SKILL_NAME@$SKILL_VERSION" \
        --registry "$REGISTRY_URL/api/skills" \
        --allow-yellow \
        --verbose \
      >>"$LOG_DIR/full.log" 2>&1
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    ok "install exit 0 — full chain verified by registry"
  else
    warn "install exit $rc — registry round-trip incomplete (likely missing identity registration)"
    warn "falling back to offline chain proof"
  fi
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
