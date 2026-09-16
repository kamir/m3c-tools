#!/usr/bin/env bash
#
# check-installer-version.sh: die Vorgabe der beiden Installer muss die
# NEUESTE skillctl-Fassung sein, die dieses Repositorium kennt.
#
# Warum es das gibt. docs/releasing-skillctl-windows.md fuehrt als Release-
# Schritt: "tools/skillctl-install.sh RELEASE_BASE default raised to
# skillctl/vX.Y.Z". Beim Schnitt von skillctl/v0.5.0 am 2026-09-10 ist dieser
# Handgriff ausgefallen, und nichts hat es gemerkt. Die Folge, am 2026-09-16
# gemessen: der in README.md und drei Doku-Dateien gepinnte Einzeiler lieferte
# eine install.ps1, deren Vorgabe auf skillctl/v0.4.0 zeigte, sechs Tage nach
# der Veroeffentlichung von v0.5.0. Gegen v0.4.0 fiel die Akzeptanzprobe in
# 6 von 14 Schritten durch.
#
# Warum das vorhandene Tor es nicht fing. scripts/check-install-pins.sh prueft,
# ob ein Pin AUFLOEST und ob die Pruefsumme daneben zu den Bytes passt. Beides
# war korrekt. Die Frage "liefert dieser Pin die AKTUELLE Fassung" hat es nie
# gestellt, und eine Frage, die kein Werkzeug stellt, beantwortet auch niemand.
#
# Die Fassung kommt aus den git-Tags, nicht aus der API: das Tor ist damit
# offline, deterministisch in CI, und kann nicht gruen werden, weil ein Proxy
# eine alte Release-Liste zwischengespeichert hat.
#
# Zwei Stellen bleiben absichtlich unberuehrt:
#   - tools/skillctl-install.sh Zeile 9 ist ein BEISPIEL fuer den
#     Ueberschreibweg und darf eine beliebige alte Fassung nennen.
#   - Runbooks, die einen historischen Schnitt beschreiben.
#
# Usage: ./scripts/check-installer-version.sh
# Exit:  0 die Vorgaben sind aktuell; 1 ein Befund; 2 Einrichtungsfehler
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; NC=$'\033[0m'

newest=$(git tag --list 'skillctl/v*' | sed 's#^skillctl/v##' | sort -V | tail -1)
[ -n "$newest" ] || { echo "check-installer-version: keine skillctl-Tags gefunden" >&2; exit 2; }

fail=0
check() {   # <datei> <zeilennummer>
  local f=$1 ln=$2 got
  [ -f "$f" ] || { echo "check-installer-version: $f fehlt" >&2; exit 2; }
  got=$(sed -n "${ln}p" "$f" | grep -oE 'download/skillctl/v[0-9]+\.[0-9]+\.[0-9]+' | sed 's#.*/v##' || true)
  if [ -z "$got" ]; then
    printf '%s' "$RED"
    echo "FEHLER  $f:$ln traegt keine Fassungsvorgabe mehr."
    echo "        Diese Pruefung haengt an der Zeilennummer. Wurde die Datei"
    echo "        umgebaut, ist die Zeilennummer hier nachzuziehen."
    printf '%s' "$NC"; fail=1; return
  fi
  if [ "$got" != "$newest" ]; then
    printf '%s' "$RED"
    echo "FEHLER  $f:$ln zeigt auf skillctl/v$got, neuester Tag ist skillctl/v$newest."
    echo "        Wer dem dokumentierten Einzeiler folgt, installiert damit die"
    echo "        aeltere Fassung. Das ist der Release-Schritt aus"
    echo "        docs/releasing-skillctl-windows.md, der beim Schnitt ausfaellt."
    echo "        Beheben: die Zeile auf skillctl/v$newest ziehen."
    printf '%s' "$NC"; fail=1; return
  fi
  echo "  ok    $f:$ln -> skillctl/v$got"
}

echo "check-installer-version: neuester skillctl-Tag ist v$newest"
check tools/skillctl-install.sh 16
check tools/skillctl-install.ps1 25
check tools/skillctl-install.ps1 101

if [ "$fail" -ne 0 ]; then
  echo "${RED}FAIL${NC}: die Installer-Vorgabe ist aelter als der neueste Tag."
  exit 1
fi
echo "${GREEN}OK${NC}: beide Installer geben skillctl/v$newest vor."
echo "     NICHT geprueft: ob dieser Tag auch VEROEFFENTLICHT ist (ein Entwurf"
echo "     zaehlt hier mit), und ob die Release-Seite dieselbe Datei traegt."
