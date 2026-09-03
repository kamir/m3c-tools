#!/usr/bin/env bash
#
# tools/boundary-gate.test.sh — fixtures for tools/boundary-gate.sh (SPEC-0358).
#
# A leak gate that stops flagging is worse than no gate, because it still reads
# green. These fixtures assert the gate from the FAILING side: each pattern in
# tools/leak-patterns.txt must actually block, the scope split must hold, and a
# clean tree must pass. Written when the patterns moved into a shared table read
# by both this gate and scripts/bugtracker.sh.
#
# Builds a throwaway git repo; no network. Exit 0 = all assertions passed.
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GATE="$HERE/boundary-gate.sh"
PATTERNS="$HERE/leak-patterns.txt"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

REPO="$TMP/repo"
mkdir -p "$REPO/tools" "$REPO/cmd" "$REPO/docs"
cp "$GATE" "$REPO/tools/boundary-gate.sh"
cp "$PATTERNS" "$REPO/tools/leak-patterns.txt"
cd "$REPO"
git init -q; git config user.email t@t; git config user.name t

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }

# run_gate -> prints output, returns the gate's exit code
run_gate() { git add -A >/dev/null 2>&1; bash tools/boundary-gate.sh >"$TMP/out" 2>&1; }

# blocks DESC FILE CONTENT   — the gate must FAIL and name the file
blocks() {
  local d=$1 f=$2 c=$3
  printf '%s\n' "$c" > "$f"
  if run_gate; then bad "$d (the gate passed)"; else
    grep -q "^$f:" "$TMP/out" && ok "$d" || bad "$d (failed, but did not name $f)"
  fi
  rm -f "$f"
}

# allows DESC FILE CONTENT   — the gate must PASS
allows() {
  local d=$1 f=$2 c=$3
  printf '%s\n' "$c" > "$f"
  if run_gate; then ok "$d"; else bad "$d (the gate blocked: $(head -1 "$TMP/out"))"; fi
  rm -f "$f"
}

# --- a clean tree passes -------------------------------------------------------
printf '# widget\n\nImplements SPEC-1234 and follows ADR-0007.\n' > README.md
if run_gate; then ok "a clean tree passes"; else bad "a clean tree passes ($(head -1 "$TMP/out"))"; fi

# --- every pattern in the table actually blocks --------------------------------
# Each fixture is written into a NON-exempt path (README-like), where both scopes apply.
blocks "always-scope: a private-repo path is blocked" \
  "docs.md" 'see m3c-tools-maintenance/bug-reports/BUG-0001-x.md for the analysis'
blocks "ops-exempt scope: an internal endpoint is blocked outside the tool surface" \
  "NOTES.md" 'the server runs on 127.0.0.1:8081 locally'
blocks "ops-exempt scope: an ER1 context-id is blocked" \
  "NOTES.md" 'context 123456789012345678901___skills holds it'
blocks "ops-exempt scope: a secret header is blocked" \
  "NOTES.md" 'authenticate with X-API-KEY: <token>'
blocks "ops-exempt scope: an internal API path is blocked" \
  "NOTES.md" 'POST /upload_2 with the payload'
blocks "ops-exempt scope: the PLM API path is blocked" \
  "NOTES.md" 'GET /api/plm/projects/1'

# --- the scope split holds -----------------------------------------------------
allows "ops-exempt scope is skipped on the tool's own surface" \
  "cmd/client.go" 'const defaultURL = "http://127.0.0.1:8081" // the ER1 client ships this'
blocks "always scope is NOT skipped there — a private path is blocked everywhere" \
  "cmd/notes.go" '// see m3c-tools-maintenance/SPEC/SPEC-0001-x.md'

# --- ID-only references stay legal (the point of the rule) ---------------------
allows "an ID-only private reference is allowed" \
  "docs/design.md" 'This implements SPEC-0358 and closes BUG-0213.'

# --- the table is the source of truth ------------------------------------------
n_patterns=$(grep -cvE '^[[:space:]]*(#|$)' tools/leak-patterns.txt)
[ "$n_patterns" -ge 5 ] && ok "the pattern table is loaded ($n_patterns patterns)" \
                        || bad "the pattern table looks empty ($n_patterns patterns)"

: > tools/leak-patterns.txt
if run_gate; then bad "an empty pattern table must not pass silently"; else
  grep -q 'no patterns loaded' "$TMP/out" && ok "an empty pattern table fails loudly" \
    || bad "an empty pattern table failed, but not with the expected message"
fi
cp "$PATTERNS" tools/leak-patterns.txt

rm -f tools/leak-patterns.txt
if run_gate; then bad "a missing pattern table must not pass silently"; else
  grep -q 'missing tools/leak-patterns.txt' "$TMP/out" && ok "a missing pattern table fails loudly" \
    || bad "a missing pattern table failed, but not with the expected message"
fi
cp "$PATTERNS" tools/leak-patterns.txt

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
