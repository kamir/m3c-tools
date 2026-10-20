#!/usr/bin/env bash
#
# tools/boundary-gate.test.sh: fixtures for tools/boundary-gate.sh (SPEC-0358).
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

# Fixtures legen Wegwerf-git-Repos an. Als Hook geerbte GIT_*-Variablen wuerden
# jeden git-Aufruf hier auf das AUFRUFENDE Repo umlenken. In
# m3c-tools-maintenance hat genau das 3076 Loeschungen in einen echten Index
# geschrieben (BUG-0213, zurueckgenommen, kein Datenverlust). Ein Fixture, das
# ein echtes Repo anfassen kann, ist eine Waffe, kein Test.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
      GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_PREFIX

# in_throwaway DIR: bricht ab, wenn git auf ein FREMDES Repo zeigt. Muss VOR
# dem ersten Schreibbefehl laufen: schon `git init` und `git config` schreiben,
# und `git config user.email` landete beim ersten Anlauf in der Config des
# echten Repos. "Noch kein Repo" ist in Ordnung; das ist der Normalfall vor
# `git init`. Pfade aufgeloest vergleichen (macOS: /var -> /private/var).
in_throwaway() {
  local want have
  want=$(cd "$1" 2>/dev/null && pwd -P) || { echo "FATAL: $1 fehlt" >&2; exit 2; }
  have=$(git rev-parse --show-toplevel 2>/dev/null) || return 0
  [ "$have" = "$want" ] || { echo "FATAL: git zeigt auf $have, nicht auf $want" >&2; exit 2; }
}


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
in_throwaway "$REPO"          # VOR dem ersten Schreibbefehl
git init -q; git config user.email t@t; git config user.name t
in_throwaway "$REPO"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }

# run_gate -> prints output, returns the gate's exit code
run_gate() { git add -A >/dev/null 2>&1; bash tools/boundary-gate.sh >"$TMP/out" 2>&1; }

# blocks DESC FILE CONTENT: the gate must FAIL and name the file
blocks() {
  local d=$1 f=$2 c=$3
  mkdir -p "$(dirname "$f")"
  printf '%s\n' "$c" > "$f"
  if run_gate; then bad "$d (the gate passed)"; else
    if grep -q "^$f:" "$TMP/out"; then ok "$d"; else bad "$d (failed, but did not name $f)"; fi
  fi
  rm -f "$f"
}

# allows DESC FILE CONTENT: the gate must PASS
allows() {
  local d=$1 f=$2 c=$3
  mkdir -p "$(dirname "$f")"
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
blocks "always scope is NOT skipped there. A private path is blocked everywhere" \
  "cmd/notes.go" '// see m3c-tools-maintenance/SPEC/SPEC-0001-x.md'

# --- ID-only references stay legal (the point of the rule) ---------------------
allows "an ID-only private reference is allowed" \
  "docs/design.md" 'This implements SPEC-0358 and closes BUG-0213.'

# --- narrative document boundaries do not depend on operational exemptions ----
blocks "mixed-case nested specification directory is blocked" \
  "pkg/example/SpEcS/overview.md" '# Protocol design'
blocks "nested architecture decision document is blocked" \
  "notes/decisions/ADR-0123-choice.MD" '# Decision'
blocks "nested planning directory is blocked" \
  "nested/Planning/release.txt" 'Release sequence'
blocks "planning filename is blocked" \
  "docs/release-plan.md" '# Release sequence'
blocks "case-insensitive obsolete docs are blocked" \
  "nested/DoCs/OlD/manual.md" '# User manual'
blocks "obsolete docs cannot hide behind the github exemption" \
  ".github/Docs/Old/usage.md" '# Usage'
blocks "specification title with a neutral filename is blocked" \
  "docs/protocol.md" '# Specification: capture protocol'
blocks "numbered specification title is blocked" \
  "docs/protocol.md" '# SPEC-1234: Capture protocol'
blocks "ADR title with a neutral filename is blocked" \
  "docs/choice.md" '# Architecture Decision Record: storage'
blocks "requirements document title is blocked" \
  "docs/capture.md" '# Requirements Specification: capture'
blocks "German requirements document title is blocked" \
  "docs/capture.md" '# Anforderungsspezifikation: Erfassung'
blocks "setext document title is blocked" \
  "docs/storage.rst" $'Specification: storage\n======================'
blocks "bold Markdown specification title is blocked" \
  "docs/protocol.md" '# **Specification**: internal design'
blocks "italic Markdown decision title is blocked" \
  "docs/protocol.md" '# _ADR-1234_: internal decision'
blocks "RST dashed specification title is blocked" \
  "docs/protocol.rst" $'Specification: internal design\n------------------------------'
blocks "HTML h1 specification title is blocked" \
  "docs/protocol.html" '<h1>Specification: internal design</h1>'
blocks "HTML document title is blocked" \
  "docs/protocol.html" '<html><head><title>Requirements: internal design</title></head></html>'
blocks "multiline HTML title with nested markup is blocked" \
  "docs/protocol.html" $'<H1 class="document-title">\n<strong>Specification</strong>: internal design\n</H1>'
blocks "AsciiDoc specification title is blocked" \
  "docs/protocol.adoc" '= Specification: protocol'
blocks "Org requirements title is blocked" \
  "docs/protocol.org" '* Requirements: protocol'
blocks "specification ID without a separator is blocked" \
  "docs/SPEC0188.md" '# Capture design'
blocks "nested specification package is blocked" \
  "nested/Spec-1234/overview.md" '# Capture design'
blocks "obsolete documentation assets are blocked" \
  "asset-check/Docs/Old/assets/diagram.svg" '<svg></svg>'
blocks "neutral filename with a release plan title is blocked" \
  "docs/work.md" '# Release Plan: rollout'
blocks "generic plan title is blocked" \
  "docs/work.md" '# Plan: release work'
blocks "top-level implementation plan is blocked" \
  "docs/work.md" '# Implementation Plan: rollout'

allows "source file named for a specification remains legal" \
  "tests/test_spec0188_tools.py" 'def test_spec0188_tools(): pass'
allows "test fixture containing a specification title remains legal" \
  "pkg/parser/testdata/SPEC-1234.md" '# Specification: parser fixture'
allows "nested fixture containing an ADR remains legal" \
  "tests/fixtures/ADR-1234.md" '# Architecture Decision Record: parser fixture'
allows "skill instructions remain legal" \
  ".claude/skills/spec-review/SKILL.md" '# Specification review'
allows "OpenAPI contract remains legal" \
  "api/specs/openapi.yaml" $'openapi: 3.1.0\ninfo: {title: API, version: 1.0.0}'
allows "JSON schema remains legal" \
  "api/specs/capture.schema.json" '{"type":"object"}'
allows "runtime dependency requirements remain legal" \
  "requirements.txt" 'requests==2.32.0'
allows "test dependency requirements remain legal" \
  "tests/requirements.txt" 'pytest==8.0.0'
allows "user manual requirements section remains legal" \
  "docs/user-manual.md" $'# User Manual\n\n## Requirements\nInstall the client. Implementation follows SPEC-1234.'
allows "manual with an implementation plan subsection remains legal" \
  "docs/user-manual.md" $'# User Manual\n\n## Implementation Plan\nSee the separately managed deployment plan.'
allows "API reference with inline references remains legal" \
  "docs/api-reference.md" $'# API Reference\n\nThe endpoint implements SPEC-1234 and ADR-0123.'
allows "normal HTML API reference remains legal" \
  "docs/protocol.html" '<html><head><title>API Reference</title></head><body><h1>API Reference</h1><p>Implements SPEC-1234.</p></body></html>'
allows "HTML lower-level requirements section remains legal" \
  "docs/protocol.html" '<title>User Manual</title><h1>User Manual</h1><h2>Requirements</h2>'
allows "RST API reference remains legal" \
  "docs/protocol.rst" $'API Reference\n-------------\nImplements SPEC-1234.'
allows "Markdown requirements subsection stays legal" \
  "docs/protocol.md" $'# User Manual\n\nRequirements\n------------\nInstall the client.'
allows "documented heading examples remain legal" \
  "docs/user-manual.md" $'# User Manual\n\n```markdown\n# Specification: example heading\n```'

# --- the table is the source of truth ------------------------------------------
n_patterns=$(grep -cvE '^[[:space:]]*(#|$)' tools/leak-patterns.txt)
if [ "$n_patterns" -ge 5 ]; then ok "the pattern table is loaded ($n_patterns patterns)";
else bad "the pattern table looks empty ($n_patterns patterns)"; fi

: > tools/leak-patterns.txt
if run_gate; then bad "an empty pattern table must not pass silently"; else
  if grep -q 'no patterns loaded' "$TMP/out"; then ok "an empty pattern table fails loudly";
  else bad "an empty pattern table failed, but not with the expected message"; fi
fi
cp "$PATTERNS" tools/leak-patterns.txt

rm -f tools/leak-patterns.txt
if run_gate; then bad "a missing pattern table must not pass silently"; else
  if grep -q 'missing tools/leak-patterns.txt' "$TMP/out"; then ok "a missing pattern table fails loudly";
  else bad "a missing pattern table failed, but not with the expected message"; fi
fi
cp "$PATTERNS" tools/leak-patterns.txt

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
