#!/usr/bin/env bash
#
# tools/id-xref-lint.test.sh: self-contained fixtures for tools/id-xref-lint.sh
# (SPEC-0358 WF-001 W4). Builds a throwaway git repo + a fake private registry, then
# asserts the lint's three behaviours: resolvable→pass, dangling→fail, path-glued→fail,
# plus the public-CI degrade mode (registry absent → resolution skipped).
#
# No network, no deps beyond git + grep. Exit 0 = all assertions passed.
#
set -euo pipefail

LINT="$(cd "$(dirname "$0")" && pwd)/id-xref-lint.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- a fake private registry: real ids are SPEC-0001, SPEC-0342, ADR-0007 -----------
mkdir -p "$TMP/registry/SPEC" "$TMP/registry/ADR"
: > "$TMP/registry/SPEC/SPEC-0001-alpha.md"
: > "$TMP/registry/SPEC/SPEC-0342-content-topology.md"
: > "$TMP/registry/ADR/ADR-0007-example-decision.md"

# --- a throwaway public repo with fixtures ------------------------------------------
REPO="$TMP/repo"
mkdir -p "$REPO/docs"
cd "$REPO"
git init -q
git config user.email t@t; git config user.name t

# resolvable + id-only + benign compounds/sub-refs  -> PASS (no finding)
cat > docs/good.md <<'EOF'
This module implements SPEC-0342 and follows ADR-0007.
It also builds on SPEC-0342/0001 (compound), SPEC-0001/ADR-0007 (two ids)
and the SPEC-0342/RC2 sub-requirement. Prose like a SPEC-0342-style guard is fine.
EOF

# dangling id -> FAIL (resolution)
cat > docs/dangling.md <<'EOF'
This references SPEC-9999 which does not exist, and a typo SPEC-0432.
EOF

# path-glued + private filename -> FAIL (id-not-alone, even with no registry)
cat > docs/pathglued.md <<'EOF'
See SPEC-0342/SPEC-0342-content-topology.md for the detail.
Also see ../registry/SPEC/SPEC-0342-content-topology.md.
EOF

git add -A

pass=0; failc=0
ok()  { printf '  ok   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL %s\n' "$1"; failc=$((failc+1)); }
contains()   { printf '%s' "$1" | grep -q "$2"; }

# ============ 1. full run: registry present ==========================================
echo "[1] registry present (full run)"
set +e
OUT="$(M3C_MAINTENANCE_DIR="$TMP/registry" bash "$LINT" 2>/dev/null)"; RC=$?
set -e
[ "$RC" -eq 1 ]                                   && ok "exit 1 (violations found)"        || bad "expected exit 1, got $RC"
contains "$OUT" 'docs/dangling.md:.*SPEC-9999'    && ok "flags dangling SPEC-9999"          || bad "missed SPEC-9999"
contains "$OUT" 'docs/dangling.md:.*SPEC-0432'    && ok "flags typo SPEC-0432"              || bad "missed SPEC-0432"
contains "$OUT" 'docs/pathglued.md:.*id-not-alone' && ok "flags path-glued reference"       || bad "missed path-glued ref"
! contains "$OUT" 'docs/good.md:'                 && ok "resolvable/id-only file is clean"  || bad "false positive on good.md"

# ============ 2. degrade mode: registry absent (public CI) ===========================
echo "[2] registry absent (public-CI degrade)"
set +e
OUT2="$(M3C_MAINTENANCE_DIR="$TMP/does-not-exist" bash "$LINT" 2>&1)"; RC2=$?
set -e
contains "$OUT2" 'resolution skipped'             && ok "prints resolution-skipped notice" || bad "no skip notice"
[ "$RC2" -eq 1 ]                                  && ok "still exit 1 (format-only caught path-glued)" || bad "expected exit 1, got $RC2"
contains "$OUT2" 'docs/pathglued.md:.*id-not-alone' && ok "path-glued still caught with no registry" || bad "missed path-glued in degrade"
! contains "$OUT2" 'SPEC-9999'                    && ok "dangling NOT flagged (resolution skipped)"   || bad "flagged dangling without registry"

echo
if [ "$failc" -ne 0 ]; then
  echo "id-xref-lint.test: FAIL ($pass passed, $failc failed)"; exit 1
fi
echo "id-xref-lint.test: OK ($pass assertions passed)"
