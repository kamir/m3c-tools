#!/usr/bin/env bash
#############################################################################
# gosec-diff-gate.sh — in-CI "no-new-findings" diff gate for gosec.
#
# WHY THIS EXISTS
#   gosec.yml uploads SARIF to GitHub Code Scanning and does the new-vs-baseline
#   diff NATIVELY — but that only BLOCKS a PR once the repo-level branch
#   protection "Require the code scanning results check to pass" is enabled
#   (Settings, admin-only). This script blocks a PR DIRECTLY from CI, without
#   that toggle: it exits non-zero the moment a change introduces a gosec
#   finding that is NEW relative to a committed signature baseline.
#
# DEFEATING THE BRITTLENESS OBJECTION (why a self-contained diff is safe here)
#   A raw SARIF/JSON diff is brittle because (a) gosec's SARIF carries no
#   partialFingerprints and (b) line/column move on every unrelated edit. We
#   sidestep both:
#     * gosec is PINNED at v2.29.0 (same as gosec.yml), so rule ids and the
#       code-snippet rendering do not drift under us.
#     * the per-finding SIGNATURE is  rule_id <TAB> repo-relative-file <TAB>
#       normalized-code-snippet  — it deliberately EXCLUDES line and column, and
#       strips the "<lineno>: " prefix gosec embeds on every snippet line, so a
#       finding that merely SHIFTS DOWN (an edit elsewhere in the file) keeps the
#       exact same signature and is NOT reported as new.
#
# MODES
#   (default / check)  run gosec, compute current signatures, compare to the
#                      committed baseline; exit 1 iff a NEW signature appeared
#                      (naming each new finding). Removed findings never fail.
#   --update           regenerate + overwrite the baseline from the current tree
#                      (for a maintainer who intentionally accepts a finding).
#
# DEPENDENCIES: gosec (v2.29.0, on PATH), jq. jq is pre-installed on the
#   macos-latest GitHub runner; gosec is installed by the workflow via
#   `go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0`.
#
# NOTE ON SCOPE: findings whose file is OUTSIDE the repo (cgo-generated code in
#   the go-build cache, whose path is a machine-specific hash) are excluded — they
#   are not repo source and cannot be relativized deterministically, so keeping
#   them would make the baseline machine-dependent. They are dropped identically
#   from both the baseline and every run, so the gate stays sound.
#############################################################################
set -euo pipefail

# --- locations -------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd -P)"
BASELINE="$REPO_ROOT/docs/security/gosec-inci-baseline.txt"
GOSEC_JSON="$REPO_ROOT/gosec.json"

# The root prefix stripped from absolute file paths to make signatures
# machine-independent. gosec emits absolute paths anchored at the working
# directory; we scan from the repo root, so that is the prefix to strip.
PWD_PREFIX="$REPO_ROOT"

MODE="check"
if [ "${1:-}" = "--update" ]; then
  MODE="update"
elif [ -n "${1:-}" ]; then
  echo "usage: $(basename "$0") [--update]" >&2
  exit 2
fi

command -v gosec >/dev/null 2>&1 || { echo "ERROR: gosec not on PATH (go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0)" >&2; exit 2; }
command -v jq    >/dev/null 2>&1 || { echo "ERROR: jq not on PATH" >&2; exit 2; }

# --- jq: one detail row per finding ---------------------------------------
# Emits TAB-separated:  rule_id  relfile  snippet  line  details
# The first three fields ARE the signature; line+details are for human output.
# `snippet` = code with per-line "<n>: " prefixes stripped, all whitespace
# collapsed to single spaces, trimmed — so it is single-line and TSV-safe.
# shellcheck disable=SC2016  # $pwd/$rel/$snip/$det are jq variables, not shell
JQ_DETAIL='
  (.Issues // [])[]
  | select(.file | startswith($pwd + "/"))
  | ( .file | ltrimstr($pwd + "/") ) as $rel
  | ( .code
      | split("\n")
      | map( sub("^[0-9]+:"; "") )
      | join(" ")
      | gsub("[ \t\r\n]+"; " ")
      | gsub("^ +| +$"; "")
    ) as $snip
  | ( (.details // "") | gsub("[ \t\r\n]+"; " ") | gsub("^ +| +$"; "") ) as $det
  | [ .rule_id, $rel, $snip, (.line // ""), $det ]
  | @tsv
'

# --- run gosec + build the current detail/signature sets -------------------
run_gosec() {
  echo "Running gosec (pinned v2.29.0) over ./... ..." >&2
  # -no-fail: gosec exits 0 even with findings, so this never trips `set -e`.
  # No -track-suppressions: #nosec-annotated sites are already dropped as active
  # findings, exactly what we want the signature set to reflect.
  ( cd "$REPO_ROOT" && gosec -no-fail -fmt json -out "$GOSEC_JSON" ./... ) >&2 2>&1 || {
    echo "ERROR: gosec run failed" >&2; exit 2;
  }
}

# writes detail rows (5 cols) to $1
build_detail() {
  jq -r --arg pwd "$PWD_PREFIX" "$JQ_DETAIL" "$GOSEC_JSON" > "$1"
}

# signatures (first 3 cols, sorted -u) from a detail file $1 -> stdout
sigs_from_detail() {
  cut -f1-3 "$1" | LC_ALL=C sort -u
}

# committed baseline signatures (strip header comments), sorted -u -> stdout
baseline_sigs() {
  # awk drops comment/blank lines and exits 0 even if everything is filtered
  # (grep -v would exit 1 on an all-comment file and trip `set -e`).
  awk 'NF && $0 !~ /^[[:space:]]*#/' "$BASELINE" | LC_ALL=C sort -u
}

# --- update mode -----------------------------------------------------------
if [ "$MODE" = "update" ]; then
  run_gosec
  tmp_detail="$(mktemp)"
  trap 'rm -f "$tmp_detail"' EXIT
  build_detail "$tmp_detail"
  count="$(sigs_from_detail "$tmp_detail" | wc -l | tr -d ' ')"
  {
    echo "# gosec in-CI diff-gate signature baseline — pinned gosec@v2.29.0."
    echo "# One signature per line:  rule_id <TAB> repo-relative-file <TAB> normalized-code-snippet"
    echo "# (line/column deliberately excluded; snippet line-number prefixes stripped)."
    echo "# Regenerate after intentionally accepting a finding:  scripts/gosec-diff-gate.sh --update"
    sigs_from_detail "$tmp_detail"
  } > "$BASELINE"
  echo "Wrote $count signature(s) to ${BASELINE#"$REPO_ROOT"/}"
  exit 0
fi

# --- check mode ------------------------------------------------------------
if [ ! -f "$BASELINE" ]; then
  echo "ERROR: baseline not found: $BASELINE" >&2
  echo "       generate it once with: scripts/gosec-diff-gate.sh --update" >&2
  exit 2
fi

run_gosec
detail="$(mktemp)"
cur_sigs="$(mktemp)"
base_sigs="$(mktemp)"
new_sigs="$(mktemp)"
removed_sigs="$(mktemp)"
trap 'rm -f "$detail" "$cur_sigs" "$base_sigs" "$new_sigs" "$removed_sigs"' EXIT

build_detail "$detail"
sigs_from_detail "$detail" > "$cur_sigs"
baseline_sigs > "$base_sigs"

# comm needs sorted inputs (both already LC_ALL=C sort -u).
comm -13 "$base_sigs" "$cur_sigs" > "$new_sigs"      # in current, not baseline = NEW
comm -23 "$base_sigs" "$cur_sigs" > "$removed_sigs"  # in baseline, not current = REMOVED

base_n="$(wc -l < "$base_sigs" | tr -d ' ')"
cur_n="$(wc -l  < "$cur_sigs"  | tr -d ' ')"
new_n="$(wc -l  < "$new_sigs"  | tr -d ' ')"
removed_n="$(wc -l < "$removed_sigs" | tr -d ' ')"

echo "gosec no-new-findings diff gate (pinned v2.29.0)"
echo "  baseline signatures : $base_n"
echo "  current  signatures : $cur_n"
echo "  new vs baseline     : $new_n"
echo "  removed vs baseline : $removed_n"

if [ "$removed_n" -gt 0 ]; then
  echo ""
  echo "NOTE: $removed_n baseline finding(s) no longer present — nice. Once merged,"
  echo "      shrink the baseline so it keeps blocking their reintroduction:"
  echo "        scripts/gosec-diff-gate.sh --update"
fi

if [ "$new_n" -eq 0 ]; then
  echo ""
  echo "PASS: no new gosec findings vs the committed baseline."
  exit 0
fi

echo ""
echo "FAIL: $new_n NEW gosec finding(s) not in the baseline:"
echo ""
# For each new signature, print every matching finding (rule, file:line, details, code).
awk -F'\t' '
  NR==FNR { key[$1 FS $2 FS $3]=1; next }
  { k=$1 FS $2 FS $3;
    if (k in key)
      printf "  [%s] %s:%s\n      %s\n      %s\n\n", $1, $2, $4, $5, $3 }
' "$new_sigs" "$detail"

echo "If a new finding is intentional and accepted, add a justified #nosec"
echo "annotation, OR (maintainer) accept it into the baseline:"
echo "  scripts/gosec-diff-gate.sh --update"
exit 1
