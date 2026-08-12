#!/usr/bin/env bash
# plaud-e2e-check.sh — end-to-end proof that Plaud login → capture works.
#
# Two paths, checked in priority order:
#   DURABLE  — official OAuth token (tools/plaud-mcp-login.mjs → ~/.plaud/tokens-mcp.json)
#              → developer API → `plaud dev sync`.   ← recommended, hands-off.
#   LEGACY   — ephemeral consumer token (`plaud auth paste`/scrape) → `plaud list/sync`.
#
# Exits 0 only if a WORKING capture path is proven. Read-only (dry-run; `dev list`
# does not upload). A one-item real upload proof is `plaud dev sync --limit 1`.
#
#   Usage:  tools/plaud-e2e-check.sh
#   Env:    BIN=./build/m3c-tools   TOKEN_FILE=~/.m3c-tools/plaud-session.json
set -uo pipefail

BIN="${BIN:-./build/m3c-tools}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.m3c-tools/plaud-session.json}"
DEVTOK="$HOME/.plaud/tokens-mcp.json"
pass=0; fail=0; DURABLE_OK=0
ok(){   printf '  \033[32m✅ PASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
no(){   printf '  \033[31m❌ FAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
info(){ printf '  \033[36mℹ\033[0m       %s\n' "$1"; }
# soft() hard-fails only when the durable path is NOT already working.
soft(){ if (( DURABLE_OK == 1 )); then info "$1"; else no "$1"; fi; }

echo
echo "  Plaud login → capture — end-to-end validation"
echo "  binary: $BIN"
echo "  ────────────────────────────────────────────────────────────"

# ── DURABLE path (recommended): official OAuth token → developer API ──
if [[ -f "$DEVTOK" ]]; then
  DEV="$("$BIN" plaud dev list 2>&1)"
  DC="$(grep -oE "developer API \(([0-9]+)\)" <<<"$DEV" | grep -oE '[0-9]+' | head -1)"
  if [[ -n "$DC" && "$DC" -gt 0 ]]; then
    ok "DURABLE path works — 'plaud dev' lists $DC recordings via the official OAuth token"; DURABLE_OK=1
  elif grep -qiE "expired|rejected|refresh" <<<"$DEV"; then
    no "durable token present but stale — refresh: node tools/plaud-mcp-login.mjs"
  else
    no "durable dev-API path failed: $(grep -iE 'error|http' <<<"$DEV" | head -1)"
  fi
else
  info "no durable token yet — for hands-off capture: node tools/plaud-mcp-login.mjs  (then 'plaud dev sync --all')"
fi

echo "  ── legacy consumer path (ephemeral) ─────────────────────────"

# ── L1. A consumer token is saved ────────────────────────────────────
if [[ -f "$TOKEN_FILE" ]]; then ok "consumer token file present"; else
  soft "no consumer token file (fine if you use the durable path)"; fi

# ── L2. Consumer token lifetime (durable vs ephemeral) ───────────────
LIFE="$(python3 - "$TOKEN_FILE" <<'PY' 2>/dev/null
import json,sys,base64,time,re
try:
    d=json.load(open(sys.argv[1])); tok=d.get("token","").strip()
except Exception: print("ERR"); sys.exit()
if tok[:1] in "\"'" and tok[-1:] in "\"'": tok=tok[1:-1]
m=re.match(r'^eyJ[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.',tok)
if not m: print("NOJWT"); sys.exit()
try:
    p=m.group(1); p+='='*(-len(p)%4)
    exp=json.loads(base64.urlsafe_b64decode(p.encode())).get("exp")
    print(f"{(exp-time.time())/3600:.1f}" if exp else "NOEXP")
except Exception: print("NOEXP")
PY
)"
case "$LIFE" in
  ERR|NOJWT) info "no consumer JWT saved";;
  NOEXP)     info "consumer token lifetime unknown";;
  *) h="${LIFE%.*}"
     if   (( h < 0 ));  then info "consumer token past its exp"
     elif (( h < 48 )); then info "consumer token is EPHEMERAL (~${LIFE}h ≈ 1 day) — the durable path avoids this"
     else                    info "consumer token exp ~$(( h/24 ))d"; fi;;
esac

# ── L3. Consumer token authenticates + capture→ER1 resolves ──────────
LIST="$("$BIN" plaud list 2>&1)"
COUNT="$(grep -oE "Plaud recordings \(([0-9]+)\)" <<<"$LIST" | grep -oE '[0-9]+' | head -1)"
if [[ -n "$COUNT" && "$COUNT" -gt 0 ]]; then
  ok "consumer API authenticated — listed $COUNT recordings"
  SYNC="$("$BIN" plaud sync --all --dry-run 2>&1)"
  if REG="$(grep -oE "region redirect: \S+ -> \S+" <<<"$SYNC" | head -1)"; then info "region: ${REG#region redirect: }"; fi
  if grep -qiE "found [0-9]+ recordings" <<<"$SYNC"; then
    N="$(grep -oE "Syncing ([0-9]+) new" <<<"$SYNC" | grep -oE '[0-9]+' | head -1)"
    ok "consumer capture→ER1 resolved (dry-run)${N:+ — ${N} new would upload}"
  else soft "consumer sync dry-run did not resolve: $(grep -iE 'error|fail' <<<"$SYNC" | head -1)"; fi
elif grep -qiE "invalid auth header|status=-3900" <<<"$LIST"; then
  soft "consumer API rejected the saved token (stale/dev token) — use the durable 'plaud dev' path"
else
  soft "consumer path could not list: $(grep -iE 'error|expired' <<<"$LIST" | head -1)"; fi

# ── verdict ──────────────────────────────────────────────────────────
echo "  ────────────────────────────────────────────────────────────"
if (( fail == 0 )); then
  printf '  \033[1;32mVERDICT: PASS\033[0m — %d checks green. A working capture path is proven.\n' "$pass"
  (( DURABLE_OK == 1 )) && printf '  \033[32m✔ durable path ready:\033[0m  %s plaud dev sync --all\n' "$BIN"
  echo; exit 0
else
  printf '  \033[1;31mVERDICT: FAIL\033[0m — %d passed, %d failed. Do NOT claim it works.\n' "$pass" "$fail"
  (( DURABLE_OK == 0 )) && printf '  \033[33m→ for a durable, hands-off login:\033[0m  node tools/plaud-mcp-login.mjs  &&  %s plaud dev sync --all\n' "$BIN"
  echo; exit 1
fi
