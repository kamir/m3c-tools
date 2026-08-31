#!/usr/bin/env bash
#
# tools/boundary-gate.sh — SPEC-0358 content-plane leak gate
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
#   1. private-repo path reference  m3c-tools-maintenance/   (a PATH into the private
#      repo; public->private references must be ID-ONLY, e.g. "implements SPEC-1234")
#   2. internal endpoint            127.0.0.1:8081
#   3. ER1 context-id               [0-9]{18,25}___[a-z0-9]+
#   4. secret header                X-API-KEY
#   5. internal API path            /upload_2  or  /api/plm/
#
# ID-only markers are fine on purpose: a bare "SPEC-1234" / "ADR-1234" matches no
# pattern here, so referencing the private reasoning plane by identifier never trips
# the gate — only a concrete private path/endpoint/secret/context does.
#
# Two scoped allowlists (see arrays below), both documented and reviewable:
#   * OPS_EXEMPT — the public tool's own operational surface (its source, tests,
#     config, API/user docs, demo, templates). Per SPEC-0358 "ship the code", the ER1
#     client legitimately carries its own localhost endpoint, header name, API paths
#     and default context there, so patterns 2-5 are not checked on those paths.
#     Pattern 1 (a path into the private repo) is ALWAYS checked, everywhere.
#   * PRIV_BASELINE — a small, explicit baseline of machine-local agent config and a
#     local demo build that intentionally bridge to the maintenance plane and cannot
#     be de-pathed without breaking a local workflow. Tracked for follow-up; NOT a way
#     to hide a real product leak (the shipped code/docs are all checked).
#
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
emit() { printf '%s\n' "$1"; fail=1; }

# match_prefix PATH PREFIX...  -> 0 if PATH starts with any PREFIX
match_prefix() { local p=$1; shift; local x; for x in "$@"; do [ "${p#"$x"}" != "$p" ] && return 0; done; return 1; }
# match_exact  PATH ITEM...    -> 0 if PATH equals any ITEM
match_exact()  { local p=$1; shift; local x; for x in "$@"; do [ "$p" = "$x" ] && return 0; done; return 1; }

# ---- Base allowlist: skipped by every rule -------------------------------------
BASE_EXACT=(tools/boundary-gate.sh CONTENT-TOPOLOGY.md)
BASE_PREFIX=(CHANGELOG .git)          # CHANGELOG*, .gitignore/.gitattributes/.github/...

# ---- Operational-surface exemption: patterns 2-5 only --------------------------
OPS_EXEMPT_PREFIX=(cmd/ pkg/ e2e/ docs/ demo/ installer/ mcp-skill-server/ rag-mcp-server/ release/ scripts/ tools/ .claude/)
OPS_EXEMPT_EXACT=(.env.example)

# ---- Private-path baseline: pattern 1 only (documented local bridges) ----------
PRIV_BASELINE=(.claude/settings.json \
               .claude/skills/bug-fix/SKILL.md \
               .claude/skills/bug-report/SKILL.md \
               .claude/skills/release-aims/skill.md \
               demo/kup-training/make-pdf.sh)

# scan_pattern FILE REASON PATTERN — emit "file:line: reason: text" per match
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

  # Rule 1 — reference into the PRIVATE repo (always checked, minus the baseline)
  if ! match_exact "$f" "${PRIV_BASELINE[@]}"; then
    scan_pattern "$f" 'private-repo path reference' 'm3c-tools-maintenance/'
  fi

  # Rules 2-5 — internal endpoint / ER1 context-id / secret header / internal API path
  if ! match_prefix "$f" "${OPS_EXEMPT_PREFIX[@]}" && ! match_exact "$f" "${OPS_EXEMPT_EXACT[@]}"; then
    scan_pattern "$f" 'internal endpoint' '127\.0\.0\.1:8081'
    scan_pattern "$f" 'ER1 context-id'    '[0-9]{18,25}___[a-z0-9]+'
    scan_pattern "$f" 'secret header'     'X-API-KEY'
    scan_pattern "$f" 'internal API path' '/upload_2|/api/plm/'
  fi
}

while IFS= read -r f; do
  [ -n "$f" ] && check "$f"
done < <(git ls-files)

if [ "$fail" -ne 0 ]; then
  echo "boundary-gate: FAIL — public-plane file(s) embed private-plane content (SPEC-0358)" >&2
  exit 1
fi
echo "boundary-gate: clean"
exit 0
