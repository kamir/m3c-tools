#!/usr/bin/env bash
# 09-invalid-edited-install — Eric's installed skill is modified after the
# fact (someone "fixed" a script in place). The trust state is now broken:
# a re-verify against the original signed bundle would fail.
#
# This is the moral of SPEC-0189 §14: post-install editing breaks the chain.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "09 — INVALID: post-install edit breaks the chain"

DIGEST=$(cat "$ARTIFACTS_DIR/digest.txt")
INSTALL_TARGET="$INSTALL_HOME/.claude/skills/$SKILL_NAME"

if [[ ! -d "$INSTALL_TARGET" ]]; then
  fail "$INSTALL_TARGET does not exist — run 05-eric-install-and-run.sh first"
  exit 2
fi

# Snapshot the installed CHECKSUMS as truth-at-install-time
ORIG_CHECKSUMS="$INSTALL_TARGET/CHECKSUMS"
TARGET_FILE="$INSTALL_TARGET/scripts/hello.sh"
test -f "$TARGET_FILE" || { fail "missing $TARGET_FILE"; exit 1; }

# Edit one byte in scripts/hello.sh
log "tampering with installed file: $TARGET_FILE"
ORIG_SHA=$(shasum -a 256 "$TARGET_FILE" | awk '{print $1}')
echo "# tampered $(date)" >> "$TARGET_FILE"
NEW_SHA=$(shasum -a 256 "$TARGET_FILE" | awk '{print $1}')
ok "before: $ORIG_SHA"
ok "after:  $NEW_SHA"
[[ "$ORIG_SHA" != "$NEW_SHA" ]] || { fail "no-op edit"; exit 1; }

# Verify against CHECKSUMS file (which carries the install-time hashes).
# `skillctl audit` will land this as a first-class verdict (`BROKEN`); until
# that ships, we demonstrate the same proof using the same primitive — read
# CHECKSUMS, recompute, compare. This is the BUG-aware mode of the audit.
log "Eric: comparing installed bytes vs CHECKSUMS"
CHECKSUMS_LINE=$(grep "scripts/hello.sh$" "$ORIG_CHECKSUMS" || true)
RECORDED_SHA=$(echo "$CHECKSUMS_LINE" | awk '{print $1}')
[[ -n "$RECORDED_SHA" ]] || { fail "scripts/hello.sh not in CHECKSUMS"; exit 1; }
note "recorded: $RECORDED_SHA"
note "current:  $NEW_SHA"

if [[ "$RECORDED_SHA" == "$NEW_SHA" ]]; then
  fail "CHECKSUMS still matches — tamper not detected (CRITICAL)"
  exit 1
else
  ok "CHECKSUMS mismatch detected — installed skill is BROKEN"
fi

# Repair: re-extract from the original signed bundle.
BUNDLE="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.skb"
log "repairing: re-extract from the signed bundle"
rm -rf "$INSTALL_TARGET"
mkdir -p "$INSTALL_TARGET"
tar -xzf "$BUNDLE" -C "$INSTALL_TARGET"
REPAIR_SHA=$(shasum -a 256 "$INSTALL_TARGET/scripts/hello.sh" | awk '{print $1}')
[[ "$REPAIR_SHA" == "$RECORDED_SHA" ]] || { fail "repair failed"; exit 1; }
ok "repaired: shasum now $REPAIR_SHA (matches CHECKSUMS)"

header "09 — done — POST-INSTALL EDIT DETECTED, RECOVERABLE FROM SIGNED BUNDLE ✓"
