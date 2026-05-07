#!/usr/bin/env bash
# 01-mirko-author — Mirko writes a skill, packs it, signs it.
# Proves: keygen → pack → sign → verify-sig (local round-trip).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
require_skillctl

header "01 — Mirko authors and signs the skill"

# 1) Generate Mirko's signing key (idempotent: remove leftovers from prior runs)
rm -f "$KEYS_DIR/mirko.priv" "$KEYS_DIR/mirko.pub"
log "Mirko: skillctl keygen --out $KEYS_DIR/mirko"
run_ok "$SKILLCTL" keygen --out "$KEYS_DIR/mirko" >/dev/null
test -f "$KEYS_DIR/mirko.priv" && test -f "$KEYS_DIR/mirko.pub"
ok "wrote mirko.priv (mode 0600) and mirko.pub (mode 0644)"

# 2) Stage the skill source as a clean copy under bundles/src/
SRC="$BUNDLES_DIR/src/$SKILL_NAME"
rm -rf "$SRC"
mkdir -p "$(dirname "$SRC")"
cp -r "$SCRIPT_DIR/fixtures/valid-skill" "$SRC"
chmod +x "$SRC/scripts/hello.sh"
ok "staged skill source: $SRC"

# 3) Pack into a deterministic .skb
BUNDLE="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.skb"
log "Mirko: skillctl pack --skill $SRC -o $BUNDLE --name $SKILL_NAME --version $SKILL_VERSION"
run_ok "$SKILLCTL" pack \
    --skill "$SRC" \
    -o "$BUNDLE" \
    --name "$SKILL_NAME" \
    --version "$SKILL_VERSION" \
    --summary "KuP training demo skill — writes a hello.txt." \
    --source-repo "kamir/m3c-tools" \
    --source-path "demo/kup-training/fixtures/valid-skill" \
    --author-intent yellow \
    --author-intent-rationale "Writes one local file under ./output/. No network. No subprocess." \
    >/dev/null

# 4) Determinism check — re-pack and compare
BUNDLE2="$BUNDLES_DIR/${SKILL_NAME}-${SKILL_VERSION}.repack.skb"
"$SKILLCTL" pack \
    --skill "$SRC" \
    -o "$BUNDLE2" \
    --name "$SKILL_NAME" \
    --version "$SKILL_VERSION" \
    --summary "KuP training demo skill — writes a hello.txt." \
    --source-repo "kamir/m3c-tools" \
    --source-path "demo/kup-training/fixtures/valid-skill" \
    --author-intent yellow \
    --author-intent-rationale "Writes one local file under ./output/. No network. No subprocess." \
    >>"$LOG_DIR/full.log" 2>&1
if cmp -s "$BUNDLE" "$BUNDLE2"; then
  ok "determinism: two packs of the same input are byte-identical"
  rm -f "$BUNDLE2"
else
  fail "non-deterministic pack output (digests differ)"
  exit 1
fi

# 5) Sign the bundle with Mirko's key (clear any prior .author.sig leftovers)
#    NOTE: skillctl sign requires flags BEFORE the bundle positional arg
rm -f "${BUNDLE}".*.author.sig
log "Mirko: skillctl sign --key mirko.priv --identity-id $MIRKO_ID $BUNDLE"
SIGN_OUT=$("$SKILLCTL" sign --key "$KEYS_DIR/mirko.priv" --identity-id "$MIRKO_ID" "$BUNDLE" 2>>"$LOG_DIR/full.log")
echo "$SIGN_OUT" | tee -a "$LOG_DIR/full.log" | head -5 | sed 's/^/      /'
DIGEST=$(echo "$SIGN_OUT" | awk '/^digest:/ {print $2}')
[[ -n "$DIGEST" ]] || { fail "could not parse digest from sign output"; exit 1; }
# The sign output emits raw hex; the rest of the demo expects sha256:<hex>.
case "$DIGEST" in sha256:*) ;; *) DIGEST="sha256:$DIGEST" ;; esac
echo "$DIGEST" > "$ARTIFACTS_DIR/digest.txt"
ok "bundle digest: $DIGEST"

# 6) Verify the signature locally (closes the loop without touching the registry)
log "Mirko: skillctl verify-sig --pubkey mirko.pub $BUNDLE"
assert_exit 0 -- "$SKILLCTL" verify-sig --pubkey "$KEYS_DIR/mirko.pub" "$BUNDLE"

header "01 — done"
note "Bundle:    $BUNDLE"
note "Digest:    $DIGEST"
note "Signature: ${BUNDLE}.${DIGEST#sha256:}.author.sig"
note "Pubkey:    $KEYS_DIR/mirko.pub  (this is what Eric will pin)"
