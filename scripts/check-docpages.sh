#!/usr/bin/env bash
# check-docpages.sh: jede erzeugte Doku-Seite unter docs/pages/ und
# docs/v2/pages/ muss zu ihrer Markdown-Quelle passen.
#
# Warum ein Tor und keine Gewohnheit: die Seite traegt eine Kopie der Markdown
# in sich. Eine Kopie, die niemand vergleicht, ist nach der zweiten Aenderung
# eine andere Aussage als das Original, und der Leser sieht nicht, welche der
# beiden aelter ist. Dieses Skript erzeugt jede Seite neu und vergleicht sie
# Byte fuer Byte mit dem, was im Baum liegt.
#
# Die Paare stehen unten in REGISTER, eine Zeile je Seite. Eine neue Doku-Seite
# einzutragen ist Teil des Erzeugens, nicht ein spaeterer Gedanke: eine Seite
# ohne Registerzeile wird von diesem Tor nie geprueft, und dann ist das Tor
# gruen, ohne etwas gemessen zu haben.
#
# Aufruf: ./scripts/check-docpages.sh
# Exit:   0 alle Seiten passen · 1 mindestens eine ist veraltet · 2 Aufbaufehler
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# markdown-quelle -> erzeugte seite
REGISTER='
docs/v2/betrieb/ops-human-agent-team.de.md|docs/v2/pages/ops-human-agent-team.html
docs/v2/index.md|docs/v2/pages/wegweiser.html
docs/v2/nutzer/einstieg.de.md|docs/v2/pages/nutzer-einstieg.html
docs/v2/entwickler/architecture.md|docs/v2/pages/entwickler-architecture.html
docs/v2/entwickler/getting-started.md|docs/v2/pages/entwickler-getting-started.html
docs/v2/betrieb/ueberblick.de.md|docs/v2/pages/betrieb-ueberblick.html
docs/v2/betrieb/runbook-m3c-tools-capture.de.md|docs/v2/pages/betrieb-runbook-m3c-tools-capture.html
docs/v2/sicherheit/ueberblick.de.md|docs/v2/pages/sicherheit-ueberblick.html
docs/v2/entwickler/skillctl-sim.md|docs/v2/pages/entwickler-skillctl-sim.html
docs/v2/sicherheit/audit-spur.de.md|docs/v2/pages/sicherheit-audit-spur.html
docs/v2/entwickler/secretctl.md|docs/v2/pages/entwickler-secretctl.html
docs/v2/betrieb/QA-abnahme-skillctl-windows.de.md|docs/v2/pages/betrieb-qa-abnahme-skillctl-windows.html
'

command -v python3 >/dev/null || { echo "check-docpages: python3 fehlt" >&2; exit 2; }
[ -x tools/docpage.sh ] || { echo "check-docpages: tools/docpage.sh fehlt oder ist nicht ausfuehrbar" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
seen=0
while IFS='|' read -r src out; do
  [ -n "$src" ] || continue
  seen=$((seen + 1))
  if [ ! -f "$src" ]; then
    echo "  FEHLT   Quelle $src (im Register, aber nicht im Baum)"
    fail=1
    continue
  fi
  if [ ! -f "$out" ]; then
    echo "  FEHLT   Seite $out; erzeuge sie mit: tools/docpage.sh $src $out"
    fail=1
    continue
  fi
  ./tools/docpage.sh "$src" "$TMP/neu.html" >/dev/null
  if cmp -s "$TMP/neu.html" "$out"; then
    echo "  ok      $out"
  else
    echo "  VERALTET $out"
    echo "          Die Seite und $src sagen Verschiedenes."
    echo "          Erzeuge sie neu:  tools/docpage.sh $src $out"
    fail=1
  fi
done <<< "$(printf '%s\n' "$REGISTER" | sed '/^[[:space:]]*$/d')"

# Eine Seite im Baum, die in keiner Registerzeile steht, wuerde nie geprueft.
for dir in docs/pages docs/v2/pages; do
  [ -d "$dir" ] || continue
  for page in "$dir"/*.html; do
    [ -e "$page" ] || continue
    case "$REGISTER" in
      *"|$page"*) ;;
      *) echo "  UNGEPRUEFT $page steht in keiner Registerzeile"; fail=1 ;;
    esac
  done
done

echo ""
if [ "$fail" -eq 0 ]; then
  echo "check-docpages: $seen Seite(n) stimmen mit ihrer Quelle ueberein"
else
  echo "check-docpages: mindestens eine Seite ist veraltet oder ungeprueft" >&2
fi
exit "$fail"
