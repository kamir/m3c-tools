#!/usr/bin/env bash
# 00-preflight — build skillctl, set up the demo workspace, sanity-check tools.
# Idempotent: safe to re-run.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

header "00 — Preflight"

# 1) Required tools
log "checking host tools"
for tool in go curl shasum tar gzip; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool: $(command -v "$tool")"
  else
    fail "missing required tool: $tool"
    exit 2
  fi
done

# 2) Locate skillctl source
SOURCE_DIR=""
for cand in \
    "/Users/kamir/wt/spec-0189/s2-integration" \
    "/Users/kamir/GITHUB.kamir/m3c-tools" \
    "$(cd "$SCRIPT_DIR/../.." && pwd)" ; do
  if [[ -d "$cand/cmd/skillctl" ]]; then
    SOURCE_DIR="$cand"; break
  fi
done
if [[ -z "$SOURCE_DIR" ]]; then
  fail "could not locate skillctl source (cmd/skillctl)"
  exit 2
fi
ok "skillctl source: $SOURCE_DIR"

# 3) Build the binary into the demo workspace
mkdir -p "$ARTIFACTS_DIR/bin"
log "building skillctl → $SKILLCTL"
( cd "$SOURCE_DIR" && go build -o "$SKILLCTL" ./cmd/skillctl )
ok "built $(file "$SKILLCTL" | sed 's/.*: //')"

# 4) Check it runs
"$SKILLCTL" --help >>"$LOG_DIR/full.log" 2>&1
ok "skillctl --help works"

# 5) Online-mode probe — auto-resolve ER1_API_KEY from macOS keychain if unset.
# Same convention used by register-identity.sh and push-to-er1.sh:
#   service = aims-core-er1 ,  account = $USER
if [[ -z "${ER1_API_KEY:-}" ]] && command -v security >/dev/null 2>&1; then
  _kc_key=$(security find-generic-password -s aims-core-er1 -a "$USER" -w 2>/dev/null || true)
  if [[ -n "$_kc_key" ]]; then
    export ER1_API_KEY="$_kc_key"
    ok "ER1_API_KEY auto-resolved from macOS keychain (service=aims-core-er1, account=$USER)"
  fi
fi

if online_mode_available; then
  ok "registry reachable at $REGISTRY_URL — online stretch goal will run"
else
  warn "online stretch goal will be skipped"
  if [[ -z "${ER1_API_KEY:-}" ]]; then
    note "ER1_API_KEY not set and not in keychain. Add it once with:"
    note "  security add-generic-password -s aims-core-er1 -a \"\$USER\" -w"
    note "Or export it inline:"
    note "  export ER1_API_KEY=\$(security find-generic-password -s aims-core-er1 -a \"\$USER\" -w)"
  else
    note "ER1_API_KEY is set but $REGISTRY_URL/api/skills/health did not return 200."
    note "Check the local stack: docker ps | grep aims-core-local"
  fi
fi

# 6) Clean previous demo state (artifacts/ only — we never touch the host)
# Keys are preserved by default so registered identities (Mirko, reviewer)
# stay valid across runs. The registry persists identities forever; if the
# local key changes, signature_invalid is the resulting error class.
# Pass --reset-all to wipe keys too (for first-run-from-scratch test).
KEEP_KEYS=1
for arg in "$@"; do
  case "$arg" in
    --reset-all|--wipe-keys) KEEP_KEYS=0 ;;
  esac
done
log "resetting demo workspace under $ARTIFACTS_DIR (keeping bin/$([ "$KEEP_KEYS" -eq 1 ] && echo ' + keys/'))"
if [ "$KEEP_KEYS" -eq 0 ]; then
  rm -rf "$KEYS_DIR"
  mkdir -p "$KEYS_DIR"
fi
rm -rf "$BUNDLES_DIR" "$TRUST_DIR" "$INSTALL_HOME"
mkdir -p "$KEYS_DIR" "$BUNDLES_DIR" "$TRUST_DIR" "$INSTALL_HOME/.claude"
: > "$LOG_DIR/full.log"
ok "workspace clean$([ "$KEEP_KEYS" -eq 1 ] && [ -f "$KEYS_DIR/mirko.priv" ] && echo " (kept $(ls "$KEYS_DIR" | wc -l | tr -d ' ') existing key files)")"

header "Preflight complete"
note "Source:   $SOURCE_DIR"
note "Binary:   $SKILLCTL"
note "Workdir:  $ARTIFACTS_DIR"
note "Eric \$HOME: $INSTALL_HOME"
note "Online:   $(online_mode_available && echo yes || echo no)"
