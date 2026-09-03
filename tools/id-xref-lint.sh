#!/usr/bin/env bash
#
# tools/id-xref-lint.sh — SPEC-0358 id-only cross-reference lint (WF-001 W4)
# The companion to tools/boundary-gate.sh ("ship the code, keep the reasoning").
#
# The boundary-gate blocks private PATHS + secrets + internal endpoints from leaking
# into the public plane. This lint enforces the OTHER half of SPEC-0358 §3.2 / §4:
#
#     A public-plane file may cite the private intent plane ONLY by a bare id-marker
#     (`implements SPEC-0342`, `see ADR-0007`) — never a path or URL into the private
#     repo, and the id must actually RESOLVE to a real SPEC/ADR on the private plane.
#
# It catches typos (`SPEC-0432` for `SPEC-0342`), dangling refs (a SPEC that was never
# written / was renumbered), private-only ids pasted as text, and the "id-not-alone"
# leak where an identifier is glued into a path/URL or embeds the private doc filename.
#
# Two checks
# ----------
#   A. id-not-alone  (format-only — ALWAYS runs, no registry needed)
#        A marker glued to a path or URL, or one that embeds a private doc filename:
#            SPEC-0342/SPEC-0342-foo.md   see ../SPEC/SPEC-0342-x.md   SPEC-0167-slug.md
#        A bare compound shorthand (`SPEC-0279/0278`), a second id after a slash
#        (`SPEC-0247/SPEC-0251`) or an intra-spec sub-ref (`SPEC-0246/RC2`) is NOT a
#        path — the identifier still stands alone — and passes.
#
#   B. resolution    (needs the private SPEC/ADR registry)
#        Every `SPEC-NNNN` / `ADR-NNNN` marker must resolve to a real registry file in
#        the maintenance repo's SPEC/ and ADR/ directories. A non-resolving marker is a
#        typo, a dangling/renumbered ref, or a private-only id leaking as text.
#
# Locating the private registry
# -----------------------------
#   $M3C_MAINTENANCE_DIR   (same convention the demo build + skills use), else the
#   sibling checkout ../m3c-tools-maintenance. When the registry is ABSENT — the normal
#   case in the PUBLIC repo's CI, where the private plane is never checked out — check B
#   is SKIPPED with a clear notice and only the format-only check A runs. The lint is
#   therefore safe to wire into open-source CI: it degrades, it does not error.
#
# Output (identical shape to boundary-gate):  file:line: <reason>: <text>
# Exit 1 on any violation, else print a clean line and exit 0.
#
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
emit() { printf '%s\n' "$1"; fail=1; }

# match_exact PATH ITEM...  -> 0 if PATH equals any ITEM
match_exact() { local p=$1; shift; local x; for x in "$@"; do [ "$p" = "$x" ] && return 0; done; return 1; }

# ---- Allowlist: files that DEFINE / DOCUMENT the convention itself, with placeholder
#      ids (SPEC-1234) and deliberately-bad path examples. Skipped by BOTH checks —
#      they are reviewed on purpose and their example markers must not resolve. -------
XREF_EXEMPT_EXACT=(
  tools/id-xref-lint.sh          # this lint — its comments carry example bad patterns
  tools/id-xref-lint.test.sh     # its self-test — fixtures embed dangling + glued ids
  tools/boundary-gate.sh         # docstring cites SPEC-1234 / ADR-1234 as placeholders
  CONTENT-TOPOLOGY.md            # the public topology doc: placeholder ids + rule examples
)

# ---- Marker + violation patterns (ERE) -----------------------------------------
# NOTE: scope is SPEC + ADR per SPEC-0358 §4 (the resolvable design/decision plane).
# FR / CR / BUG live in PLM/ER1 (no file registry) and are an explicit non-goal here;
# add them to MARKER + a registry source when a file registry for them exists.
MARKER='(SPEC|ADR)-[0-9]{4}'

# A marker glued to a real path/URL: a separator (/ or :) followed by a tail that
# still contains a further path char (. or /). The trailing "[./]" is what separates a
# genuine path/URL/filename from a bare compound id or a sub-ref:
#   SPEC-0342/SPEC-0342-foo.md  -> tail "SPEC-0342-foo.md" has a "." -> HIT
#   SPEC-0342/a/b               -> tail "a/b"              has a "/" -> HIT
#   SPEC-0342:../SPEC/x.md      -> tail "../SPEC/x.md"     has "." /  -> HIT
#   SPEC-0279/0278 (compound)   -> tail "0278"            no "." "/" -> ok
#   SPEC-0247/SPEC-0251 (2 ids) -> tail "SPEC-0251"       no "." "/" -> ok
#   SPEC-0246/RC2  (sub-ref)    -> tail "RC2"             no "." "/" -> ok
PAT_PATH='(SPEC|ADR)-[0-9]{4}[/:][^[:space:]),]*[./][^[:space:]),]*'

# A marker used as the HEAD of a PRIVATE doc filename (SPEC-0167-thinking-engine.md).
# The extension anchor keeps prose compounds ("a SPEC-0276-style list") from matching.
PAT_FILE='(SPEC|ADR)-[0-9]{4}-[A-Za-z0-9._-]*\.(md|markdown|txt|adoc|rst|pdf|html|htm|yaml|yml|json)'

# ---- Locate the private registry (env, else sibling checkout) -------------------
MAINT="${M3C_MAINTENANCE_DIR:-$(dirname "$PWD")/m3c-tools-maintenance}"
REGISTRY_PRESENT=0
REAL_SET="|"
n_spec=0 n_adr=0
if [ -d "$MAINT/SPEC" ]; then
  REGISTRY_PRESENT=1
  # Enumerate real ids from the registry filenames (SPEC-NNNN-*.md / ADR-NNNN-*.md).
  # Globs (not ls|grep) so odd filenames can't break the parse; the id is the fixed
  # "<PREFIX>-NNNN" head of the basename (SPEC-=9 chars, ADR-=8).
  for p in "$MAINT"/SPEC/SPEC-[0-9][0-9][0-9][0-9]*; do
    [ -e "$p" ] || continue
    b=${p##*/}; id=${b:0:9}
    case "$REAL_SET" in *"|$id|"*) : ;; *) REAL_SET="${REAL_SET}${id}|"; n_spec=$((n_spec + 1)) ;; esac
  done
  for p in "$MAINT"/ADR/ADR-[0-9][0-9][0-9][0-9]*; do
    [ -e "$p" ] || continue
    b=${p##*/}; id=${b:0:8}
    case "$REAL_SET" in *"|$id|"*) : ;; *) REAL_SET="${REAL_SET}${id}|"; n_adr=$((n_adr + 1)) ;; esac
  done
fi

# scan_pattern FILE REASON PATTERN — emit "file:line: reason: text" per matching line
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

# resolve_scan FILE — emit one finding per marker that does not resolve in the registry
resolve_scan() {
  local f=$1 m ln mk
  while IFS= read -r m; do
    [ -z "$m" ] && continue
    ln=${m%%:*}
    mk=${m#*:}
    case "$REAL_SET" in
      *"|$mk|"*) : ;;                                   # resolves — fine
      *) emit "$f:$ln: dangling reference (no such id in private registry): $mk" ;;
    esac
  done < <(grep -InoE "$MARKER" "$f" 2>/dev/null || true)
}

check() {
  local f=$1
  match_exact "$f" "${XREF_EXEMPT_EXACT[@]}" && return 0
  grep -Iq . "$f" 2>/dev/null || return 0             # skip binary / empty files

  # A — id-not-alone (always checked; no registry needed)
  scan_pattern "$f" 'id-not-alone (id glued to a path/URL)'      "$PAT_PATH"
  scan_pattern "$f" 'id-not-alone (embeds private doc filename)' "$PAT_FILE"

  # B — resolution (only when the private registry is present)
  if [ "$REGISTRY_PRESENT" -eq 1 ]; then resolve_scan "$f"; fi
  return 0                                              # never let set -e kill the loop
}

if [ "$REGISTRY_PRESENT" -eq 1 ]; then
  printf 'id-xref-lint: registry %s (%d SPEC, %d ADR)\n' "$MAINT" "$n_spec" "$n_adr" >&2
else
  printf 'id-xref-lint: resolution skipped (private registry not present at %s); format-only checks running\n' "$MAINT" >&2
fi

while IFS= read -r f; do
  [ -n "$f" ] && check "$f"
done < <(git ls-files)

if [ "$fail" -ne 0 ]; then
  echo "id-xref-lint: FAIL — public-plane cross-reference violates SPEC-0358 (id-only + resolvable)" >&2
  exit 1
fi
echo "id-xref-lint: clean"
exit 0
