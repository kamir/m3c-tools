#!/usr/bin/env bash
# make-pdf — Render the canonical Skill-Manager user manual as a branded PDF.
# Output: $ARTIFACTS_DIR/USER-MANUAL.pdf
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"

header "G1 — Render USER-MANUAL.md → PDF"

USER_MANUAL_MD="/Users/kamir/GITHUB.kamir/m3c-tools-maintenance/PROJECTS/Skill-Manager/USER-MANUAL.md"
SKILLCTL_MANUAL_MD="/Users/kamir/GITHUB.kamir/m3c-tools-maintenance/PROJECTS/Skill-Manager/SKILLCTL-MANUAL.md"
OUT_USER="$ARTIFACTS_DIR/USER-MANUAL.pdf"
OUT_CLI="$ARTIFACTS_DIR/SKILLCTL-MANUAL.pdf"
OUT_BUNDLE="$ARTIFACTS_DIR/KuP-skill-manager-handbook.pdf"

for f in "$USER_MANUAL_MD" "$SKILLCTL_MANUAL_MD"; do
  test -f "$f" || { fail "missing $f"; exit 2; }
done
command -v pandoc >/dev/null   || { fail "pandoc not found"; exit 2; }
command -v xelatex >/dev/null  || { fail "xelatex not found"; exit 2; }

PANDOC_FLAGS=(
  --pdf-engine=xelatex
  --toc --toc-depth=2
  --variable=geometry:margin=1in
  --variable=mainfont:"Helvetica Neue"
  --variable=monofont:"Menlo"
  --variable=fontsize:10pt
  --variable=colorlinks:true
  --variable=linkcolor:NavyBlue
  --variable=urlcolor:NavyBlue
  --highlight-style=tango
  --metadata=date:"$(date +%Y-%m-%d)"
  --metadata=author:"m3c · Scalytics — KuP Berlin training"
)

# Substitute glyphs that Helvetica Neue lacks with print-friendly ASCII so
# the rendered PDF is clean. Live emoji/arrows survive in the source MD.
preprocess() {
  local in="$1" out="$2"
  # Use perl for portable inline UTF-8 substitution (sed on macOS chokes
  # on multi-byte literals in certain locales).
  perl -CSD -pe '
    s/\x{1F7E2}/(G)/g;   # 🟢 → (G)
    s/\x{1F7E1}/(Y)/g;   # 🟡 → (Y)
    s/\x{1F534}/(R)/g;   # 🔴 → (R)
    s/\x{2192}/->/g;     # → → ->
    s/\x{21B5}/<-/g;     # ↵
    s/\x{2713}/[ok]/g;   # ✓ → [ok]
    s/\x{2717}/[X]/g;    # ✗ → [X]
    s/\x{2705}/[ok]/g;   # ✅
    s/\x{274C}/[X]/g;    # ❌
    s/\x{2026}/.../g;    # … → ...
    s/\x{2014}/--/g;     # — → --
    s/\x{2013}/-/g;      # – → -
    s/\x{00A0}/ /g;      # NBSP → space
    s/\x{2022}/*/g;      # • → *
    s/\x{272D}/[*]/g;    # ✭
  ' "$in" > "$out"
}

PRE_USER="$ARTIFACTS_DIR/_pre-USER.md"
PRE_CLI="$ARTIFACTS_DIR/_pre-CLI.md"
preprocess "$USER_MANUAL_MD"     "$PRE_USER"
preprocess "$SKILLCTL_MANUAL_MD" "$PRE_CLI"
ok "preprocessed source MDs (emoji/arrows → ASCII)"

log "rendering $OUT_USER"
pandoc "$PRE_USER" "${PANDOC_FLAGS[@]}" \
  --metadata=title:"Skill-Manager User Manual" \
  --metadata=subtitle:"Operating the m3c Skill Lifecycle Management stack" \
  -o "$OUT_USER" 2>>"$LOG_DIR/full.log"
ok "wrote $OUT_USER ($(du -h "$OUT_USER" | awk '{print $1}'))"

log "rendering $OUT_CLI"
pandoc "$PRE_CLI" "${PANDOC_FLAGS[@]}" \
  --metadata=title:"skillctl Command Reference" \
  --metadata=subtitle:"Every subcommand, every flag, every exit code" \
  -o "$OUT_CLI" 2>>"$LOG_DIR/full.log"
ok "wrote $OUT_CLI ($(du -h "$OUT_CLI" | awk '{print $1}'))"

# Combined handbook (one PDF, both manuals concatenated)
log "rendering combined handbook → $OUT_BUNDLE"
pandoc "$PRE_USER" "$PRE_CLI" "${PANDOC_FLAGS[@]}" \
  --metadata=title:"KuP Skill-Manager Handbook" \
  --metadata=subtitle:"User Manual + skillctl Reference" \
  -o "$OUT_BUNDLE" 2>>"$LOG_DIR/full.log"
ok "wrote $OUT_BUNDLE ($(du -h "$OUT_BUNDLE" | awk '{print $1}'))"

# Tidy intermediate files
rm -f "$PRE_USER" "$PRE_CLI"

header "G1 — done"
note "Standalone: $OUT_USER"
note "Standalone: $OUT_CLI"
note "Combined:   $OUT_BUNDLE  ←  hand this to KuP attendees"
