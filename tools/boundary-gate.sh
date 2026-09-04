#!/usr/bin/env bash
#
# tools/boundary-gate.sh: SPEC-0358 content-plane leak gate
# ("ship the code, keep the reasoning")
#
# m3c-tools is the PUBLIC / open-source plane. Its private sibling plane holds the
# reasoning artefacts (SPECs, ARCH, ADR, OPS/CISO, FR/Bug/CR, onboarding-guide
# material) and lives in the maintenance repo + PLM + ER1. This gate fails CI when a
# public-plane file embeds private-plane content.
#
# It iterates the tracked files (git ls-files), skips binary files and an allowlist,
# and flags any line matching a leak pattern as:
#
#     file:line: <reason>: <matched text>
#
# Exit 1 if any hit, else print "boundary-gate: clean" and exit 0.
#
# Leak patterns
# -------------
# Defined ONCE in tools/leak-patterns.txt (scope TAB reason TAB regex) and read by
# this gate AND by scripts/bugtracker.sh, which applies the same rules to GitHub
# issue bodies. Text no CI job would ever see. Adding a pattern there tightens
# both; that is the whole point of not writing them out twice.
#
#   scope "always"      checked everywhere, no exceptions (the private-repo path).
#   scope "ops-exempt"  skipped on the public tool's own operational surface.
#
# ID-only markers are fine on purpose: a bare "SPEC-1234" / "ADR-1234" matches no
# pattern here, so referencing the private reasoning plane by identifier never trips
# the gate, only a concrete private path/endpoint/secret/context does.
#
# Two scoped allowlists (see arrays below), both documented and reviewable:
#   * OPS_EXEMPT: the public tool's own operational surface (its source, tests,
#     config, API/user docs, demo, templates). Per SPEC-0358 "ship the code", the ER1
#     client legitimately carries its own localhost endpoint, header name, API paths
#     and default context there, so patterns 2-5 are not checked on those paths.
#     Pattern 1 (a path into the private repo) is ALWAYS checked, everywhere.
#   * PRIV_BASELINE: now EMPTY. Former machine-local bridges were resolved for real:
#     .claude/settings.json is git-ignored, and the skills + demo build resolve the
#     private plane via $M3C_MAINTENANCE_DIR. Rule 1 has no exceptions.
#
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
emit() { printf '%s\n' "$1"; fail=1; }

# ---- Load the shared pattern table --------------------------------------------
PATTERNS_FILE="tools/leak-patterns.txt"
[ -f "$PATTERNS_FILE" ] || { echo "boundary-gate: missing $PATTERNS_FILE" >&2; exit 2; }
P_SCOPE=(); P_REASON=(); P_RE=()
while IFS=$'\t' read -r scope reason re; do
  case "$scope" in ''|\#*) continue ;; esac
  [ -n "$re" ] || continue
  P_SCOPE+=("$scope"); P_REASON+=("$reason"); P_RE+=("$re")
done < "$PATTERNS_FILE"
[ "${#P_RE[@]}" -gt 0 ] || { echo "boundary-gate: no patterns loaded from $PATTERNS_FILE" >&2; exit 2; }

# match_prefix PATH PREFIX...  -> 0 if PATH starts with any PREFIX
match_prefix() { local p=$1; shift; local x; for x in "$@"; do [ "${p#"$x"}" != "$p" ] && return 0; done; return 1; }
# match_exact  PATH ITEM...    -> 0 if PATH equals any ITEM
match_exact()  { local p=$1; shift; local x; for x in "$@"; do [ "$p" = "$x" ] && return 0; done; return 1; }

# ---- Base allowlist: skipped by every rule -------------------------------------
# Files that DEFINE or EXERCISE the leak rules necessarily contain the literals
# themselves: the pattern table and the two fixture suites, exactly like this
# gate's own source. Nothing else belongs on this list: an exemption here is a
# blind spot, so it is granted only to files whose whole purpose is the rule.
BASE_EXACT=(
  tools/boundary-gate.sh
  tools/boundary-gate.test.sh
  tools/leak-patterns.txt
  scripts/bugtracker.test.sh
  CONTENT-TOPOLOGY.md
)
BASE_PREFIX=(CHANGELOG .git)          # CHANGELOG*, .gitignore/.gitattributes/.github/...

# ---- Operational-surface exemption: patterns 2-5 only --------------------------
OPS_EXEMPT_PREFIX=(cmd/ pkg/ e2e/ docs/ demo/ installer/ mcp-skill-server/ rag-mcp-server/ release/ scripts/ tools/ .claude/)
OPS_EXEMPT_EXACT=(.env.example)

# ---- Private-path baseline: pattern 1 only (documented local bridges) ----------
# EMPTY: every former bridge has been resolved for real. .claude/settings.json is
# now git-ignored (machine-local), and the skills + demo build resolve the private
# plane via $M3C_MAINTENANCE_DIR instead of a literal path. Keep this empty; the
# private-repo-path rule now applies to every tracked file with no exceptions.
PRIV_BASELINE=()

# scan_pattern FILE REASON PATTERN: emit "file:line: reason: text" per match
scan_pattern() {
  local f=$1 reason=$2 pat=$3 m ln txt
  while IFS= read -r m; do
    [ -z "$m" ] && continue
    ln=${m%%:*}
    txt=${m#*:}
    txt=${txt#"${txt%%[![:space:]]*}"}          # left-trim
    emit "$f:$ln: $reason: $txt"
  done < <(grep -InE "$pat" "$f" 2>/dev/null || true)
}

check() {
  local f=$1
  match_exact  "$f" "${BASE_EXACT[@]}"  && return 0
  match_prefix "$f" "${BASE_PREFIX[@]}" && return 0
  grep -Iq . "$f" 2>/dev/null || return 0        # skip binary / empty files

  local ops_exempt=0 baselined=0 i
  match_prefix "$f" "${OPS_EXEMPT_PREFIX[@]}" && ops_exempt=1
  match_exact  "$f" "${OPS_EXEMPT_EXACT[@]}"  && ops_exempt=1
  if [ "${#PRIV_BASELINE[@]}" -gt 0 ] && match_exact "$f" "${PRIV_BASELINE[@]}"; then baselined=1; fi

  for i in "${!P_RE[@]}"; do
    case "${P_SCOPE[$i]}" in
      always)     [ "$baselined"  -eq 1 ] && continue ;;
      ops-exempt) [ "$ops_exempt" -eq 1 ] && continue ;;
      *) emit "$PATTERNS_FILE: unknown scope '${P_SCOPE[$i]}'"; continue ;;
    esac
    scan_pattern "$f" "${P_REASON[$i]}" "${P_RE[$i]}"
  done
}

while IFS= read -r f; do
  [ -n "$f" ] && check "$f"
done < <(git ls-files)

if [ "$fail" -ne 0 ]; then
  echo "boundary-gate: FAIL: public-plane file(s) embed private-plane content (SPEC-0358)" >&2
  exit 1
fi
echo "boundary-gate: clean"
exit 0
