#!/usr/bin/env bash
# plaud-e2e-check.sh — end-to-end proof that Plaud login → capture works.
#
# Validates whatever token is currently saved (from ANY login method:
# `plaud auth mcp`, `plaud auth paste`, `plaud auth login`, `--from-er1`).
# Exits 0 only if EVERY check passes, so it is a real gate — not a claim.
#
#   Usage:  tools/plaud-e2e-check.sh
#   Env:    BIN=./build/m3c-tools   TOKEN_FILE=~/.m3c-tools/plaud-session.json
#
# Read-only: `plaud list` and `plaud sync --dry-run` never upload or mutate.
set -uo pipefail

BIN="${BIN:-./build/m3c-tools}"
TOKEN_FILE="${TOKEN_FILE:-$HOME/.m3c-tools/plaud-session.json}"
pass=0; fail=0; EPHEMERAL=0
ok(){   printf '  \033[32m✅ PASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
no(){   printf '  \033[31m❌ FAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
info(){ printf '  \033[36mℹ\033[0m       %s\n' "$1"; }

echo
echo "  Plaud login → capture — end-to-end validation"
echo "  binary: $BIN"
echo "  ────────────────────────────────────────────────────────────"

# ── 1. A token is saved ──────────────────────────────────────────────
if [[ -f "$TOKEN_FILE" ]]; then ok "token file present ($TOKEN_FILE)"; else
  no "no token file — run a login first: '$BIN plaud auth mcp' (or 'paste')"; fi

# ── 2. Token shape + real lifetime (durable vs ephemeral) ────────────
LIFETIME_HOURS="$(python3 - "$TOKEN_FILE" <<'PY' 2>/dev/null
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
case "$LIFETIME_HOURS" in
  ERR|NOJWT) no "saved token is not a JWT (login did not store a bearer)";;
  NOEXP)     info "token has no exp claim (lifetime unknown)";;
  *) h="${LIFETIME_HOURS%.*}"
     if   (( h < 0 ));   then no   "token already past its exp (${LIFETIME_HOURS}h) — re-login"
     elif (( h < 48 ));  then info "token is EPHEMERAL (~${LIFETIME_HOURS}h left ≈ 1 day) — a browser/paste token that WILL fail tomorrow; run 'plaud auth mcp' for a ~300-day durable token"; EPHEMERAL=1
     else                     ok   "token is DURABLE (~$(( h/24 ))d left)"; fi;;
esac

# ── 3. Token LOADS and is not treated as expired (catches margin bug) ─
LIST="$("$BIN" plaud list 2>&1)"; RC=$?
if grep -qiE "token expired|no token|error loading token" <<<"$LIST"; then
  no "LoadToken rejected the saved token: $(grep -iE 'expired|no token|error loading' <<<"$LIST" | head -1 | sed 's/^ *//')"
else ok "saved token loads and is accepted by LoadToken"; fi

# ── 4. Token AUTHENTICATES against the live API ──────────────────────
# Positive-first: a recording count > 0 IS proof of auth. Only fall back to
# error-matching on Plaud-specific strings (never generic "401" — that matches
# hex recording IDs and unrelated ER1 sync-state auth).
COUNT="$(grep -oE "Plaud recordings \(([0-9]+)\)" <<<"$LIST" | grep -oE '[0-9]+' | head -1)"
if [[ -n "$COUNT" && "$COUNT" -gt 0 ]]; then
  ok "Plaud API authenticated — listed $COUNT recordings"
elif grep -qE "invalid auth header|status=-3900" <<<"$LIST"; then
  no "Plaud API rejected the token (invalid/expired bearer)"
else
  no "could not list recordings (rc=$RC): $(grep -iE 'error|expired' <<<"$LIST" | head -1)"; fi

# ── 5. Region resolved correctly (EU/US redirect handled) ────────────
SYNC="$("$BIN" plaud sync --all --dry-run 2>&1)"
if REG="$(grep -oE "region redirect: \S+ -> \S+" <<<"$SYNC" | head -1)"; then info "region: ${REG#region redirect: }"; fi

# ── 6. Capture→ER1 pipeline resolves (dry-run, NO upload) ────────────
if grep -qiE "found [0-9]+ recordings" <<<"$SYNC" && grep -qiE "WOULD be synced|Syncing [0-9]+ new|already synced|0 new recordings" <<<"$SYNC"; then
  N="$(grep -oE "Syncing ([0-9]+) new" <<<"$SYNC" | grep -oE '[0-9]+' | head -1)"
  ok "capture→ER1 pipeline resolved (dry-run)${N:+ — ${N} new would upload}"
else
  no "sync dry-run did not resolve items: $(grep -iE 'error|fail' <<<"$SYNC" | head -1)"; fi

# ── verdict ──────────────────────────────────────────────────────────
echo "  ────────────────────────────────────────────────────────────"
if (( fail == 0 )); then
  printf '  \033[1;32mVERDICT: PASS\033[0m — %d checks green. Login → capture works end-to-end.\n' "$pass"
  (( EPHEMERAL == 1 )) && printf '  \033[33m⚠ but the current token is EPHEMERAL (~1 day).\033[0m For a durable login, run:\n      node tools/plaud-mcp-login.mjs   &&   %s plaud auth mcp   &&   %s\n' "$BIN" "$0"
  echo; exit 0
else
  printf '  \033[1;31mVERDICT: FAIL\033[0m — %d passed, %d failed. Do NOT claim it works.\n\n' "$pass" "$fail"; exit 1
fi
