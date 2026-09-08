#!/usr/bin/env bash
# check-python.sh: Linter und Tests fuer den Python-Anteil des Repos.
#
# AUDIT-0001 Befund N.2. Der Befund beschreibt den Stand VOR diesem Zweig. Auf
# origin/master gemessen: mcp-skill-server/server.py hat dort 1379 Zeilen, die
# den kompletten Skill-Lifecycle als Claude-Code-Werkzeuge anbieten, und daneben
# liegen 25 Tests. Ein grep ueber alle 16 Workflows, das Makefile und scripts/
# nach "mcp-skill-server" oder "rag-mcp-server" fand genau 0 Treffer: die Tests
# sind nie gelaufen, und kein Linter hat den Python-Baum je angefasst.
#
# Diese beiden Zahlen gelten NICHT mehr fuer den Baum, in dem dieser Kommentar
# steht: der erste Commit dieses Zweigs hat die ruff-Funde in server.py behoben
# und Tests ergaenzt. Auf diesem Stand gemessen am 2026-09-07 sind es 1420
# Zeilen und 31 gesammelte Tests, 22 in test_spec0188_tools.py und 9 in
# test_spec0189_tools.py.
#
# Praezisierung dazu, denn "ungeprueft" waere zu absolut: CodeQL laeuft auf
# diesem Repo im default setup, python steht in seiner Sprachliste, und
# "Analyze (python)" ist ein required check auf master. Gemessen:
#   gh api repos/kamir/m3c-tools/code-scanning/default-setup
#     -> "state":"configured", "languages":[...,"python",...]
# Der grep oben konnte das nicht sehen, weil default setup ohne Workflow-Datei
# im Baum laeuft. Der Kern des Befundes bleibt trotzdem stehen: SAST ist weder
# ein Linter noch ein Testlauf. CodeQL sucht Sicherheitsmuster; es faellt nicht
# ueber ein ungenutztes Import, eine ueberschriebene Funktionsdefinition oder
# einen roten Test. Genau diese Luecke schliesst dieses Skript.
#
# Abgedeckt wird alles, was `git ls-files '*.py'` findet: die beiden
# MCP-Server und die drei Hilfsskripte unter scripts/.
#
# Zwei Tore:
#   lint  ruff mit Standardregeln (siehe ruff.toml), alle verfolgten .py
#   test  pytest fuer mcp-skill-server UND rag-mcp-server
#
# Beide Testverzeichnisse laufen unbedingt. Fehlt eine Abhaengigkeit, bricht
# dieses Skript mit einer Handlungsanweisung ab; es faerbt nichts gruen und
# ueberspringt nichts still. Ein frueherer Stand hat
# rag-mcp-server/test_sync_drift.py uebersprungen, mit der Begruendung, fuer
# turbovec gebe es nur ein macOS-arm64-Rad. Das war eine Fehlmessung: die
# Sonde lief mit dem Plattform-Tag manylinux2014_x86_64, das Rad traegt aber
# manylinux_2_28_x86_64, und pip gleicht diese Tags nicht aufeinander ab.
# Gemessen am 2026-09-07:
#   pip download turbovec --platform manylinux_2_28_x86_64 \
#     --python-version 3.12 --only-binary=:all: -d /tmp/x
#   -> Saved turbovec-1.0.0-cp39-abi3-manylinux_2_28_x86_64.whl
# Der Test braucht ausserdem weder sentence-transformers noch torch: er
# reicht ueber den Konstruktor einen _FakeEmbedder herein.
#
# Wie weit "blockierend" traegt: der CI-Job "Python servers (ruff + pytest)"
# laeuft bei jedem Push und jedem Pull Request und wird rot, wenn dieses Skript
# rot wird. Seit dem 2026-09-08 steht er auch in der
# required-status-checks-Liste von master, haelt also einen Merge auf. Gemessen:
#   gh api repos/kamir/m3c-tools/branches/master/protection \
#     --jq '.required_status_checks.contexts' | grep -c "Python servers"
#   -> 1
# Am 2026-09-07 war dieselbe Messung 0, und dieser Absatz sagte das mit Datum,
# damit er auffaellt, sobald die Einstellung nachgezogen ist.
#
# Usage:
#   ./scripts/check-python.sh            # lint + test
#   ./scripts/check-python.sh --lint     # nur Linter
#   ./scripts/check-python.sh --test     # nur Tests
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON="${PYTHON:-python3}"

# Hilfe = der Kopfkommentar selbst, damit beides nicht auseinanderlaufen kann.
# Ein fester Zeilenbereich driftet, sobald jemand oben einen Absatz einfuegt.
print_help() {
  awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

mode="${1:-all}"
case "$mode" in
  --lint|--test|all|"") ;;
  -h|--help) print_help; exit 0 ;;
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

# require_modules <hinweis> <pip-name-liste> <modul> [modul ...]
# Meldet ALLE fehlenden Module auf einmal, nicht das erste; wer eine venv
# frisch aufsetzt, soll nicht dreimal nacheinander scheitern.
#
# Regel fuer die Modulliste: sondiert wird das TIEFSTE Modul, das der Code
# wirklich importiert, nicht der Paketname und nicht das Wurzelpaket. Ein
# Paket kann installiert sein, waehrend genau das Untermodul fehlt, an dem der
# Server haengt; die Sonde ist dann gruen und der Fehler faellt erst als
# pytest-Sammelfehler auf, also ohne die Handlungsanweisung, fuer die diese
# Funktion da ist. Umgekehrt gilt die Regel nur bis zur Modulgrenze: ein
# importierter NAME (eine Klasse, eine Funktion) laesst sich mit `import`
# nicht sondieren.
require_modules() {
  local what="$1" pip_line="$2"; shift 2
  local missing="" mod
  for mod in "$@"; do
    "$PYTHON" -c "import $mod" >/dev/null 2>&1 || missing="$missing $mod"
  done
  if [ -n "$missing" ]; then
    echo "check-python: FAIL, $what fehlt/fehlen:${missing}." >&2
    echo "  Beheben: $PYTHON -m pip install $pip_line" >&2
    return 1
  fi
}

run_tests() {
  if ! "$PYTHON" -m pytest --version >/dev/null 2>&1; then
    echo "check-python: FAIL, pytest nicht gefunden." >&2
    echo "  Beheben: $PYTHON -m pip install pytest" >&2
    return 1
  fi

  # mcp-skill-server/server.py:24 macht `from mcp.server.fastmcp import FastMCP`.
  # Sondiert wird deshalb mcp.server.fastmcp und nicht mcp: in mcp 2.x wurde
  # FastMCP zu MCPServer umbenannt und dieses Modul entfernt, waehrend
  # `import mcp` weiterhin gelingt. Gemessen am 2026-09-07 in zwei
  # Wegwerf-venvs:
  #   mcp==2.1.1   `import mcp` gruen, `import mcp.server.fastmcp` faellt mit
  #                ModuleNotFoundError
  #   mcp==1.30.0  beide gruen
  # Mit der frueheren Sonde auf mcp waere diese Vorbedingung unter 2.x also
  # gruen gewesen und pytest danach mit einem Sammelfehler gefallen. Der
  # pip-Hinweis nennt 'mcp<2', weil `pip install mcp` erneut 2.x holen wuerde;
  # 'mcp<2' loeste am 2026-09-07 zu 1.30.0 auf, und dort ist die Sonde gruen.
  require_modules "fuer mcp-skill-server" "'mcp<2'" mcp.server.fastmcp

  # rag-mcp-server/test_sync_drift.py fuehrt Indexer.build() und .sync() aus;
  # beide importieren turbovec lazy in der Funktion. numpy kommt aus indexer.py,
  # yaml (PyYAML) laedt config.default.yaml in der Fixture.
  #
  # Hier fallen Sonde und tatsaechlicher Import bereits zusammen. indexer.py
  # macht `from turbovec import IdMapIndex`, und IdMapIndex ist eine Klasse,
  # kein Modul; `import turbovec.IdMapIndex` scheitert auch bei heiler
  # Installation, gemessen am 2026-09-07 gegen turbovec 1.0.0. turbovec ist
  # damit schon das tiefste sondierbare Modul, numpy und yaml ebenso. Der
  # Unterschied zwischen Paketname und Modulname steht ebenfalls richtig:
  # installiert wird PyYAML, importiert wird yaml.
  require_modules "fuer rag-mcp-server" "turbovec numpy PyYAML" turbovec numpy yaml

  ( cd mcp-skill-server && "$PYTHON" -m pytest -q )
  ( cd rag-mcp-server && "$PYTHON" -m pytest -q )
}

case "$mode" in
  --lint) run_lint ;;
  --test) run_tests ;;
  all|"") run_lint; run_tests ;;
esac
