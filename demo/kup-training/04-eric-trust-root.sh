#!/usr/bin/env bash
# 04-eric-trust-root — Eric pins Mirko's pubkey as a trust root in HIS home.
# This is the "operator distributes the registry pubkey to consumer machines"
# step from USER-MANUAL §5.6.1, scoped to the local demo workspace.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "04 — Eric pins Mirko as trust root"

# Use Eric's isolated $HOME so the demo never touches the host user's
# ~/.claude. The skillctl trust command writes to $HOME/.claude/skill-trust-roots.yaml.
log "Eric: skillctl trust add --registry $REGISTRY_URL --pubkey mirko.pub"
HOME="$INSTALL_HOME" \
  "$SKILLCTL" trust add \
    --registry "$REGISTRY_URL" \
    --pubkey "$KEYS_DIR/mirko.pub" \
    --id mirko-author-key \
    >>"$LOG_DIR/full.log" 2>&1
ok "trust root pinned in $INSTALL_HOME/.claude/skill-trust-roots.yaml"

log "Eric: skillctl trust list"
HOME="$INSTALL_HOME" "$SKILLCTL" trust list 2>&1 | tee -a "$LOG_DIR/full.log" | sed 's/^/      /'

header "04 — done"
note "Trust roots file: $INSTALL_HOME/.claude/skill-trust-roots.yaml"
