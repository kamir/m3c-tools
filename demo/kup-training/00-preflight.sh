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

# 5) Online-mode probe (informational only)
if online_mode_available; then
  ok "registry reachable at $REGISTRY_URL — online stretch goal will run"
else
  warn "registry not reachable or ER1_API_KEY not set — online stretch goal will be skipped"
  note "to enable: export ER1_API_KEY=... and ensure $REGISTRY_URL/api/skills/health returns 200"
fi

# 6) Clean previous demo state (artifacts/ only — we never touch the host)
log "resetting demo workspace under $ARTIFACTS_DIR (keeping bin/)"
rm -rf "$KEYS_DIR" "$BUNDLES_DIR" "$TRUST_DIR" "$INSTALL_HOME"
mkdir -p "$KEYS_DIR" "$BUNDLES_DIR" "$TRUST_DIR" "$INSTALL_HOME/.claude"
: > "$LOG_DIR/full.log"
ok "workspace clean"

header "Preflight complete"
note "Source:   $SOURCE_DIR"
note "Binary:   $SKILLCTL"
note "Workdir:  $ARTIFACTS_DIR"
note "Eric \$HOME: $INSTALL_HOME"
note "Online:   $(online_mode_available && echo yes || echo no)"
