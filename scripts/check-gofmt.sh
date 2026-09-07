#!/usr/bin/env bash
# check-gofmt.sh: refuse a tree that gofmt would change.
#
# AUDIT-0001 Befund 1.11. Gemessen am 2026-09-07: 111 von 778 .go-Dateien waren
# nicht gofmt-konform, und durchgesetzt wurde Formatierung nirgends: kein
# Workflow, kein Makefile-Ziel, kein formatters-Block in .golangci.yml. Die
# Drift war deshalb nicht bloss Kosmetik, sie hat gekostet: ein `gofmt -w` auf
# ein Verzeichnis zog acht unbeteiligte Dateien in einen fremden Commit, weil
# sie vorher schon unformatiert waren.
#
# Das Muster ist bewusst dasselbe wie in check-no-emdash.sh: reines Shell ueber
# den verfolgten Baum, ein Ziel in `make ci`, ein blockierender CI-Job.
#
# Usage:
#   ./scripts/check-gofmt.sh            # ganzer Baum, exit 1 bei jedem Treffer
#   ./scripts/check-gofmt.sh --staged   # nur was gerade gestaged ist
#   ./scripts/check-gofmt.sh --fix      # schreibt die Formatierung
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

mode="${1:-all}"

case "$mode" in
  --fix)
    files=$(git ls-files '*.go')
    ;;
  --staged)
    # Nur gestagte Go-Dateien, und nur solche, die es noch gibt.
    files=$(git diff --cached --name-only --diff-filter=ACMR -- '*.go' || true)
    ;;
  all|"")
    files=$(git ls-files '*.go')
    ;;
  -h|--help)
    sed -n '2,20p' "$0"; exit 0
    ;;
  *)
    echo "check-gofmt: unbekanntes Argument $mode" >&2; exit 2
    ;;
esac

if [ -z "$files" ]; then
  echo "check-gofmt: keine Go-Dateien zu pruefen"
  exit 0
fi

if [ "$mode" = "--fix" ]; then
  # shellcheck disable=SC2086
  gofmt -w $files
  echo "check-gofmt: formatiert"
  exit 0
fi

# shellcheck disable=SC2086
bad=$(gofmt -l $files)

if [ -n "$bad" ]; then
  n=$(printf '%s\n' "$bad" | wc -l | tr -d ' ')
  total=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
  echo "check-gofmt: FAIL, $n von $total Datei(en) sind nicht gofmt-konform:" >&2
  printf '  %s\n' $bad >&2
  echo "" >&2
  echo "  Beheben: ./scripts/check-gofmt.sh --fix   (oder gofmt -w auf die Dateien oben)" >&2
  echo "  Nur die eigenen Dateien formatieren, nie ein ganzes Verzeichnis:" >&2
  echo "  ein gofmt -w auf ein Verzeichnis nimmt fremde Dateien in den Commit." >&2
  exit 1
fi

n=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
echo "check-gofmt: $n Datei(en) gofmt-konform"
