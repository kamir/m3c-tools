#!/usr/bin/env bash
# check-python.sh: Linter und Tests fuer den Python-Anteil des Repos.
#
# AUDIT-0001 Befund N.2. Gemessen am 2026-09-07: mcp-skill-server/server.py sind
# 1379 Zeilen, die den kompletten Skill-Lifecycle als Claude-Code-Werkzeuge
# anbieten, und daneben liegen 25 Tests. Ein grep ueber alle 16 Workflows, das
# Makefile und scripts/ nach "mcp-skill-server" oder "rag-mcp-server" fand
# genau 0 Treffer: die Tests sind nie gelaufen, gelintet wurde nie.
#
# Abgedeckt wird alles, was `git ls-files '*.py'` findet: die beiden
# MCP-Server und die Hilfsskripte unter scripts/.
#
# Zwei Tore, beide blockierend:
#   lint  ruff mit Standardregeln (siehe ruff.toml)
#   test  pytest fuer mcp-skill-server
#
# Ein drittes ist bewusst OFFEN: rag-mcp-server/test_sync_drift.py braucht
# turbovec, und dafuer gibt es auf PyPI nur ein macOS-arm64-Rad, kein
# manylinux-Rad. Auf einem Ubuntu-Runner ist der Test also nicht ausfuehrbar.
# Dieses Skript fuehrt ihn aus, wenn turbovec importierbar ist, und sagt sonst
# laut, dass er uebersprungen wurde. Es faerbt ihn nicht gruen.
#
# Usage:
#   ./scripts/check-python.sh            # lint + test
#   ./scripts/check-python.sh --lint     # nur Linter
#   ./scripts/check-python.sh --test     # nur Tests
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON="${PYTHON:-python3}"

mode="${1:-all}"
case "$mode" in
  --lint|--test|all|"") ;;
  -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
  *) echo "check-python: unbekanntes Argument $mode" >&2; exit 2 ;;
esac

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "check-python: FAIL, $PYTHON nicht gefunden. PYTHON=<pfad> setzen." >&2
  exit 1
fi

run_lint() {
  local files
  files=$(git ls-files '*.py')
  if [ -z "$files" ]; then
    echo "check-python: keine Python-Dateien im verfolgten Baum"
    return 0
  fi

  local ruff_cmd
  if command -v ruff >/dev/null 2>&1; then
    ruff_cmd=(ruff)
  elif "$PYTHON" -m ruff --version >/dev/null 2>&1; then
    ruff_cmd=("$PYTHON" -m ruff)
  else
    echo "check-python: FAIL, ruff nicht gefunden." >&2
    echo "  Beheben: $PYTHON -m pip install ruff" >&2
    return 1
  fi

  # shellcheck disable=SC2086
  "${ruff_cmd[@]}" check --output-format concise $files
  local n
  n=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
  echo "check-python: $n Python-Datei(en) ruff-sauber"
}

run_tests() {
  if ! "$PYTHON" -m pytest --version >/dev/null 2>&1; then
    echo "check-python: FAIL, pytest nicht gefunden." >&2
    echo "  Beheben: $PYTHON -m pip install pytest" >&2
    return 1
  fi

  if ! "$PYTHON" -c "import mcp" >/dev/null 2>&1; then
    echo "check-python: FAIL, das Paket mcp fehlt, mcp-skill-server/server.py ist ohne es nicht importierbar." >&2
    echo "  Beheben: $PYTHON -m pip install mcp" >&2
    return 1
  fi

  ( cd mcp-skill-server && "$PYTHON" -m pytest -q )

  # rag-mcp-server: siehe Kopf dieser Datei. Kein manylinux-Rad fuer turbovec.
  if "$PYTHON" -c "import turbovec" >/dev/null 2>&1; then
    ( cd rag-mcp-server && "$PYTHON" -m pytest -q test_sync_drift.py )
  else
    echo "check-python: UEBERSPRUNGEN, rag-mcp-server/test_sync_drift.py (turbovec fehlt)."
    echo "  Das ist eine bekannte Luecke, kein bestandener Test."
    echo "  Nachholen: $PYTHON -m pip install turbovec numpy PyYAML  (nur macOS arm64)"
  fi
}

case "$mode" in
  --lint) run_lint ;;
  --test) run_tests ;;
  all|"") run_lint; run_tests ;;
esac
