#!/usr/bin/env bash
#
# check-installer-version.sh: die Installer duerfen KEINE Fassung einbacken.
#
# Warum es dieses Tor gibt, und das gilt unveraendert weiter.
# docs/v2/betrieb/releasing-skillctl-windows.md fuehrte als Release-Schritt: "tools/
# skillctl-install.sh RELEASE_BASE default raised to skillctl/vX.Y.Z". Beim
# Schnitt von skillctl/v0.5.0 am 2026-09-10 ist dieser Handgriff ausgefallen,
# und nichts hat es gemerkt. Die Folge, am 2026-09-16 gemessen: der in README.md
# und drei Doku-Dateien gepinnte Einzeiler lieferte eine install.ps1, deren
# Vorgabe auf skillctl/v0.4.0 zeigte, sechs Tage nach der Veroeffentlichung von
# v0.5.0. Gegen v0.4.0 fiel die Akzeptanzprobe in 6 von 14 Schritten durch, und
# die Bezugszahlen zeigten es offen: 61 Windows-Bezuege auf v0.3.1, 27 auf
# v0.4.0, null auf v0.5.0.
#
# WAS SICH AM 2026-09-16 GEAENDERT HAT, und warum dieses Tor jetzt das Gegenteil
# prueft. Die erste Fassung dieses Skripts verlangte, dass die eingebackene
# Vorgabe dem neuesten Tag ENTSPRICHT. Das ist die richtige Frage an das falsche
# Mittel: es haelt einen Handgriff am Leben und prueft nur, ob er ausgefuehrt
# wurde. Die Entscheidung vom selben Tag war, den Handgriff abzuschaffen: beide
# Installer loesen die neueste Marke zur LAUFZEIT auf.
#
# Damit ist die zu schuetzende Eigenschaft eine andere und eine staerkere: es
# darf gar keine Fassung mehr eingebacken sein. Eine Vorgabe, die es nicht gibt,
# kann nicht veralten. Dieses Tor prueft deshalb ab jetzt auf ABWESENHEIT.
#
# Nebenbei faellt damit ein Mangel weg, den die erste Fassung selbst benannte:
# sie haftete an ZEILENNUMMERN und meldete beim kleinsten Umbau einen Fehler,
# der keiner war. Hier wird die ganze Datei gelesen.
#
# Zwei Stellen bleiben absichtlich unberuehrt:
#   - Zeilen, die eine Fassung als BEISPIEL fuer den Ueberschreibweg nennen
#     (RELEASE_BASE=... in der Verwendungszeile, -ReleaseBase in der Hilfe).
#   - Die Abbruchmeldung, die dem Menschen einen ausdruecklichen Aufruf zeigt.
# Beide erkennt man daran, dass sie NICHT der Zuweisung eines Vorgabewerts sind.
#
# Usage: ./scripts/check-installer-version.sh
# Exit:  0 keine eingebackene Fassung; 1 ein Befund; 2 Einrichtungsfehler
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; NC=$'\033[0m'

fail=0

# Eine eingebackene Vorgabe ist eine ZUWEISUNG an RELEASE_BASE bzw.
# $ReleaseBase, deren rechte Seite eine Marke enthaelt. Ein Beispiel in einem
# Kommentar oder eine Hilfezeile ist das nicht.
pruefe_keine_vorgabe() {   # <datei>
  local f=$1 treffer
  [ -f "$f" ] || { echo "check-installer-version: $f fehlt" >&2; exit 2; }

  # Am Zeilenanfang verankert, denn nur dort steht eine ZUWEISUNG. Die erste
  # Fassung dieses Musters war nicht verankert und hielt prompt die eigene
  # Hilfezeile (echo "  RELEASE_BASE=... bash") fuer eine Vorgabe. Eine
  # Meldung, die dem Menschen den ausdruecklichen Aufruf zeigt, ist das
  # Gegenteil einer eingebackenen Vorgabe.
  treffer=$(grep -nE '^[[:space:]]*(RELEASE_BASE=|\$ReleaseBase[[:space:]]*=)[^=]*download/skillctl/v[0-9]' "$f" || true)
  if [ -n "$treffer" ]; then
    printf '%s' "$RED"
    echo "FEHLER  $f backt eine Fassung als Vorgabe ein:"
    echo "$treffer" | sed 's/^/          /'
    echo "        Eine eingebackene Vorgabe veraltet beim naechsten Release, und"
    echo "        genau das ist am 2026-09-10 passiert. Der Installer soll die"
    echo "        neueste Marke zur Laufzeit aufloesen."
    printf '%s' "$NC"; fail=1; return
  fi
  echo "  ok    $f backt keine Fassung ein"
}

# Gegenprobe, und sie ist der Grund, warum dieses Tor nicht blind gruen meldet:
# Abwesenheit allein ist kein Beweis. Waere der Aufloeser entfernt worden,
# faende die Suche oben ebenfalls nichts, und das Tor meldete OK fuer einen
# Installer, der gar keine Fassung mehr bezieht.
pruefe_aufloeser_vorhanden() {   # <datei> <muster>
  local f=$1 muster=$2
  if ! grep -qE "$muster" "$f"; then
    printf '%s' "$RED"
    echo "FEHLER  $f hat keinen Aufloeser fuer die neueste Marke ($muster)."
    echo "        Ohne ihn bezieht der Installer gar keine Fassung mehr."
    printf '%s' "$NC"; fail=1; return
  fi
  echo "  ok    $f loest die neueste Marke auf"
}

echo "check-installer-version: die Installer duerfen keine Fassung einbacken"
pruefe_keine_vorgabe tools/skillctl-install.sh
pruefe_keine_vorgabe tools/skillctl-install.ps1
# Auf die DEFINITION gepruefft, nicht auf den Namen irgendwo. Die erste Fassung
# suchte den blossen Namen, und ein Mutationstest hat sie entwaffnet: benennt man
# die Funktion um, findet der Name sich immer noch an der Aufrufstelle, und das
# Tor meldete gruen fuer einen Installer ohne Aufloeser.
pruefe_aufloeser_vorhanden tools/skillctl-install.sh  '^neueste_skillctl_marke\(\)'
pruefe_aufloeser_vorhanden tools/skillctl-install.ps1 '^function Get-NeuesteSkillctlMarke'

if [ "$fail" -ne 0 ]; then
  echo "${RED}FAIL${NC}: ein Installer traegt eine eingebackene Fassung oder keinen Aufloeser."
  exit 1
fi
echo "${GREEN}OK${NC}: beide Installer loesen die Fassung zur Laufzeit auf."
echo "     NICHT geprueft: ob der Aufloeser auch FUNKTIONIERT. Das braucht Netz"
echo "     und steht deshalb nicht in diesem Tor, sondern im Rauchtest."
