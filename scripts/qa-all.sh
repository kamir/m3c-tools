#!/usr/bin/env bash
# qa-all.sh: ein Lauf, der jede lokale Pruefung dieses Baums faehrt und am Ende
# sagt, ob alles so lief wie erwartet.
#
# Warum es das gibt, obwohl es 22 Pruefskripte und 27 Make-Ziele schon gibt: wer
# sie einzeln aufruft, vergisst eines, und `make ci` haelt beim ersten Fehler an
# und deckt die restlichen zu. Dieses Skript laeuft weiter, sammelt, und gibt
# eine Zeile Urteil.
#
# Drei Eigenschaften, die es von einem Sammelaufruf unterscheiden:
#
#   1. Eine Pruefung, die NICHT laufen konnte, gilt nicht als bestanden. Sie ist
#      `uebersprungen` mit Grund, und die Urteilszeile nennt ihre Anzahl. Eine
#      PFLICHT-Pruefung, die nicht laufen konnte, ist ein Fehlschlag.
#   2. Die Testschritte zaehlen, wie viele Tests wirklich liefen, und der Lauf
#      faellt, wenn es null waren. Ein Testaufruf, dessen Muster nichts trifft,
#      endet auf 0 und sagt nichts; genau dieser Fall soll hier auffallen.
#   3. `--selbsttest` beweist, dass dieses Skript ueberhaupt rot werden kann. Ein
#      Tor, das noch nie gefallen ist, hat nichts gemessen.
#
# Aufruf:
#   scripts/qa-all.sh              alles
#   scripts/qa-all.sh --schnell    ohne die beiden langen Abnahmeskripte
#   scripts/qa-all.sh --selbsttest die Gegenprobe: pflanzt einen Fehler
#
# Exit: 0 alles wie erwartet - 1 mindestens eine Abweichung - 2 Aufrufproblem
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCHNELL=0
SELBSTTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --schnell) SCHNELL=1; shift ;;
    --selbsttest) SELBSTTEST=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "qa-all: unbekanntes Argument: $1" >&2; exit 2 ;;
  esac
done

command -v go >/dev/null || { echo "qa-all: go fehlt" >&2; exit 2; }
command -v python3 >/dev/null || { echo "qa-all: python3 fehlt (wird zum Zaehlen der Tests gebraucht)" >&2; exit 2; }

LOG="$(mktemp -d)"
trap 'rm -rf "$LOG"' EXIT

# Die Toolchain, gegen die gemessen wird. Das ist keine Kosmetik: go.mod nennt
# `toolchain go1.26.6`, und das ist fuer Go eine UNTERGRENZE, kein Pin. Wer ein
# neueres Go hat, benutzt sein eigenes, waehrend die CI genau die genannte
# Fassung installiert. Gemessen am 2026-09-25: der Bundle-Digest von
# pkg/skillbundle entsteht ueber den gzip-Strom, dessen Ausgabe sich zwischen
# Go-Fassungen aendert, also faellt TestDigestStability mit go1.27.1 und besteht
# mit go1.26.6. Ein Lauf mit einer anderen Fassung als die CI sagt weniger ueber
# die CI, darum wird sie hier festgelegt, und wenn das nicht geht, gesagt.
TOOLCHAIN="$(sed -n 's/^toolchain \(go[0-9.]*\)$/\1/p' go.mod | head -1)"
TOOLCHAIN_HINWEIS=""
if [ -n "$TOOLCHAIN" ]; then
  if GOTOOLCHAIN="$TOOLCHAIN" go version >/dev/null 2>&1; then
    export GOTOOLCHAIN="$TOOLCHAIN"
    TOOLCHAIN_HINWEIS="Toolchain $TOOLCHAIN, wie go.mod sie nennt"
  else
    TOOLCHAIN_HINWEIS="ACHTUNG: $TOOLCHAIN ist hier nicht verfuegbar, gemessen wird mit $(go version | awk '{print $3}'). Ein Ergebnis dieses Laufs sagt weniger ueber die CI."
  fi
else
  TOOLCHAIN_HINWEIS="go.mod nennt keine Toolchain, gemessen wird mit $(go version | awk '{print $3}')"
fi

GRUEN='\033[0;32m'; ROT='\033[0;31m'; GELB='\033[0;33m'; GRAU='\033[2m'; AUS='\033[0m'
[ -t 1 ] || { GRUEN=''; ROT=''; GELB=''; GRAU=''; AUS=''; }

BESTANDEN=0; GEFALLEN=0; UEBERSPRUNGEN=0; PFLICHT_FEHLT=0
ZEILEN="$LOG/zeilen"; : > "$ZEILEN"
NOTIZ="$LOG/notiz"

# notiz setzt den Zusatztext, den die Zeile eines Schrittes mitfuehrt.
notiz() { printf '%s' "$*" > "$NOTIZ"; }

# ueberspringen sagt, warum ein Schritt nicht laufen konnte. Rueckgabe 77 ist die
# Verabredung zwischen den Schrittfunktionen und dem Laeufer.
ueberspringen() { notiz "$*"; return 77; }

# lauf fuehrt einen Schritt aus: id, klasse (pflicht|bedingt), Name, Funktion.
lauf() {
  local id="$1" klasse="$2" name="$3" fn="$4"
  : > "$NOTIZ"
  local t0 rc dauer zusatz
  t0=$(date +%s)
  "$fn" > "$LOG/$id.out" 2>&1
  rc=$?
  dauer=$(( $(date +%s) - t0 ))
  zusatz="$(cat "$NOTIZ" 2>/dev/null)"
  case "$rc" in
    0)
      BESTANDEN=$((BESTANDEN + 1))
      printf "${GRUEN}ok${AUS}       %-26s %3ss %s\n" "$id" "$dauer" "$zusatz"
      printf 'ok|%s|%s|%s\n' "$id" "$name" "$zusatz" >> "$ZEILEN"
      ;;
    77)
      UEBERSPRUNGEN=$((UEBERSPRUNGEN + 1))
      if [ "$klasse" = "pflicht" ]; then
        PFLICHT_FEHLT=$((PFLICHT_FEHLT + 1))
        printf "${ROT}FEHLT${AUS}    %-26s %3ss %s ${ROT}(Pflicht)${AUS}\n" "$id" "$dauer" "$zusatz"
        printf 'fehlt|%s|%s|%s\n' "$id" "$name" "$zusatz" >> "$ZEILEN"
      else
        printf "${GELB}uebersp.${AUS} %-26s %3ss %s\n" "$id" "$dauer" "$zusatz"
        printf 'uebersprungen|%s|%s|%s\n' "$id" "$name" "$zusatz" >> "$ZEILEN"
      fi
      ;;
    *)
      GEFALLEN=$((GEFALLEN + 1))
      printf "${ROT}FEHLER${AUS}   %-26s %3ss exit=%s %s\n" "$id" "$dauer" "$rc" "$zusatz"
      printf 'fehler|%s|%s|exit=%s %s\n' "$id" "$name" "$rc" "$zusatz" >> "$ZEILEN"
      printf "${GRAU}"; tail -n 12 "$LOG/$id.out" | sed 's/^/         /'; printf "${AUS}"
      ;;
  esac
}

# --- die Schritte -----------------------------------------------------------

qa_build() {
  go build ./... || return 1
  mkdir -p build
  go build -o build/skillctl ./cmd/skillctl || return 1
  notiz "alle Pakete, plus build/skillctl"
}

qa_vet() { go vet ./...; }

qa_gofmt() { ./scripts/check-gofmt.sh; }

qa_lint() {
  command -v golangci-lint >/dev/null || ueberspringen "golangci-lint nicht installiert" || return 77
  golangci-lint run ./...
}

# Die Testflaeche ist genau die, die die CI faehrt, damit ein gruener Lauf hier
# etwas ueber die CI aussagt. ./... waere falsch: darin stecken die
# Netz-Tests von ./e2e/, die offline nichts beweisen.
qa_tests() {
  go test -json -race -count=1 \
    ./pkg/... ./cmd/m3c-tools/... ./cmd/skillctl-demo/... ./cmd/secretctl/... \
    ./cmd/skillctl/... ./cmd/docaudit/ ./cmd/verbaudit/ ./cmd/exitaudit/ \
    > "$LOG/tests.json" 2>&1
  local rc=$?
  local zahlen
  zahlen="$(python3 - "$LOG/tests.json" <<'PY'
import json, sys
p = f = s = 0
with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
    for line in fh:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not ev.get("Test"):
            continue
        a = ev.get("Action")
        if a == "pass":
            p += 1
        elif a == "fail":
            f += 1
        elif a == "skip":
            s += 1
print(f"{p} {f} {s}")
PY
)"
  local bestanden gefallen uebersprungen
  bestanden="$(echo "$zahlen" | awk '{print $1}')"
  gefallen="$(echo "$zahlen" | awk '{print $2}')"
  uebersprungen="$(echo "$zahlen" | awk '{print $3}')"
  notiz "${bestanden} Tests bestanden, ${gefallen} gefallen, ${uebersprungen} uebersprungen"
  # Ein Lauf ohne einen einzigen Test ist kein gruener Lauf, sondern ein
  # Testaufruf, dessen Muster nichts getroffen hat.
  if [ "${bestanden:-0}" -eq 0 ]; then
    notiz "kein einziger Test lief, das Muster hat nichts getroffen"
    return 1
  fi
  return $rc
}

qa_tests_e2e() {
  make test-unit > "$LOG/e2e.txt" 2>&1
  local rc=$?
  local n
  n="$(grep -c '^--- PASS' "$LOG/e2e.txt" 2>/dev/null || true)"
  notiz "${n:-0} Tests der Offline-Liste"
  if [ "${n:-0}" -eq 0 ]; then
    notiz "kein einziger Test der Offline-Liste lief"
    return 1
  fi
  return $rc
}

qa_windows() { make test-gate-windows-quick; }

qa_docs() { make check-docs; }

qa_docpages() { ./scripts/check-docpages.sh; }

qa_prosa() { ./scripts/check-no-emdash.sh; }

qa_namen() { ./scripts/check-no-real-names.sh; }

qa_pins() { ./scripts/check-install-pins.sh; }

qa_installer_fassung() { ./scripts/check-installer-version.sh; }

qa_redirect() { ./scripts/check-redirect-guard.sh; }

qa_make_ziele() { ./scripts/check-makefile-targets.sh; }

qa_pflicht_checks() { ./scripts/check-required-checks.sh; }

qa_boundary() { ./tools/boundary-gate.sh; }

qa_id_xref() { ./tools/id-xref-lint.sh; }

qa_python() {
  command -v ruff >/dev/null || ueberspringen "ruff nicht installiert" || return 77
  ./scripts/check-python.sh
}

qa_gosec() {
  command -v gosec >/dev/null || ueberspringen "gosec nicht installiert" || return 77
  ./scripts/gosec-diff-gate.sh
}

qa_freeze_abnahme() {
  [ "$SCHNELL" -eq 0 ] || ueberspringen "--schnell" || return 77
  ./scripts/trustfreeze-acceptance.sh
}

qa_lebenszyklus_abnahme() {
  [ "$SCHNELL" -eq 0 ] || ueberspringen "--schnell" || return 77
  [ -x ./build/skillctl ] || ueberspringen "build/skillctl fehlt, der Bauschritt ist gefallen" || return 77
  ./scripts/skillctl-acceptance.sh --skillctl ./build/skillctl
}

# Die Tore, die sich selbst pruefen. Ein Tor, das nie gefallen ist, hat nichts
# gemessen, und diese drei koennen das von sich beweisen.
qa_tor_selbsttests() {
  ./tools/boundary-gate.test.sh > "$LOG/st1" 2>&1 || return 1
  ./tools/id-xref-lint.test.sh > "$LOG/st2" 2>&1 || return 1
  ./scripts/check-makefile-targets.sh --selftest > "$LOG/st3" 2>&1 || return 1
  notiz "boundary-gate, id-xref-lint und check-makefile-targets fallen auf Kommando"
}

# Nur im Selbsttest: ein Schritt, der fallen MUSS, und einer, der uebersprungen
# werden MUSS. Damit zeigt der Lauf, dass er beide Faelle sieht.
qa_gepflanzter_fehler() { return 3; }
qa_gepflanztes_werkzeug() { ueberspringen "ein Werkzeug, das es nicht gibt" || return 77; }

# --- Lauf -------------------------------------------------------------------

echo ""
echo "QA-Gesamtlauf, $(git rev-parse --short HEAD 2>/dev/null || echo 'kein git') auf $(uname -s)"
echo "$TOOLCHAIN_HINWEIS"
[ "$SCHNELL" -eq 1 ] && echo "Modus: --schnell, die langen Abnahmeskripte bleiben aus"
[ "$SELBSTTEST" -eq 1 ] && echo "Modus: --selbsttest, ein Fehler und ein Werkzeugmangel sind gepflanzt"
echo "-----------------------------------------------------------------------"

lauf build           pflicht "Baut jedes Paket und skillctl"          qa_build
lauf vet             pflicht "go vet"                                  qa_vet
lauf gofmt           pflicht "gofmt-Konformitaet"                      qa_gofmt
lauf lint            bedingt "golangci-lint"                           qa_lint
lauf tests           pflicht "Testflaeche der CI, mit -race"           qa_tests
lauf tests-e2e       pflicht "Offline-Liste aus dem Makefile"          qa_tests_e2e
lauf windows         pflicht "Cross-Kompilat und Windows-Tor"          qa_windows
lauf docs            pflicht "Doku gegen Implementierung"              qa_docs
lauf docpages        pflicht "Erzeugte Doku-Seiten"                    qa_docpages
lauf prosa           pflicht "Kein Em-Dash im Baum"                    qa_prosa
lauf namen           pflicht "Keine Personennamen im Baum"             qa_namen
lauf pins            pflicht "Installer-Pins und Digests"              qa_pins
lauf installer       pflicht "Fassung des Installers"                  qa_installer_fassung
lauf redirect        pflicht "Redirect-Guard"                          qa_redirect
lauf make-ziele      pflicht "Jedes cmd/ hat ein Make-Ziel"            qa_make_ziele
lauf pflicht-checks  pflicht "Namensbindung der Pflicht-Checks"        qa_pflicht_checks
lauf boundary        pflicht "Keine privaten Verweise"                 qa_boundary
lauf id-xref         pflicht "SPEC-, FR- und BUG-Verweise"             qa_id_xref
lauf python          bedingt "Python-Linter"                           qa_python
lauf gosec           bedingt "Keine neuen gosec-Befunde"               qa_gosec
# Unter --schnell sind die beiden Abnahmeskripte ausdruecklich abgewaehlt, nicht
# ausgefallen. Als Pflicht deklariert koennte ein schneller Lauf nie bestehen,
# und ein Modus, der nie gruen werden kann, wird nicht benutzt. Die Einschraenkung
# bleibt sichtbar: sie stehen in der Liste der nicht gelaufenen Pruefungen, und
# die Urteilszeile sagt, dass sie nicht belegt sind.
ABNAHME_KLASSE=pflicht
[ "$SCHNELL" -eq 1 ] && ABNAHME_KLASSE=bedingt

lauf freeze-abnahme  "$ABNAHME_KLASSE" "Trust-Freeze-Abnahme, 62 Schritte"    qa_freeze_abnahme
lauf lebenszyklus    "$ABNAHME_KLASSE" "Zwei-Parteien-Probe des Lebenszyklus" qa_lebenszyklus_abnahme
lauf tor-selbsttests pflicht "Die Tore fallen auf Kommando"            qa_tor_selbsttests

if [ "$SELBSTTEST" -eq 1 ]; then
  lauf gepflanzt-fehler   pflicht "Gepflanzter Fehler"        qa_gepflanzter_fehler
  lauf gepflanzt-werkzeug bedingt "Gepflanzter Werkzeugmangel" qa_gepflanztes_werkzeug
fi

GESAMT=$((BESTANDEN + GEFALLEN + UEBERSPRUNGEN))
echo "-----------------------------------------------------------------------"
printf "%s Pruefungen: %s bestanden, %s gefallen, %s uebersprungen" \
  "$GESAMT" "$BESTANDEN" "$GEFALLEN" "$UEBERSPRUNGEN"
[ "$PFLICHT_FEHLT" -gt 0 ] && printf " (davon %s Pflicht)" "$PFLICHT_FEHLT"
echo ""

if [ "$UEBERSPRUNGEN" -gt 0 ]; then
  echo ""
  echo "Nicht gelaufen, und darum nicht bestanden:"
  grep -E '^(uebersprungen|fehlt)\|' "$ZEILEN" | while IFS='|' read -r zustand id name grund; do
    printf "  %-22s %s (%s)\n" "$id" "$grund" "$name"
  done
fi

echo ""
if [ "$SELBSTTEST" -eq 1 ]; then
  # Die Gegenprobe urteilt umgekehrt: der Lauf MUSS den gepflanzten Fehler
  # gesehen und den Werkzeugmangel als uebersprungen gemeldet haben.
  if [ "$GEFALLEN" -ge 1 ] && [ "$UEBERSPRUNGEN" -ge 1 ]; then
    printf "${GRUEN}SELBSTTEST BESTANDEN${AUS}: der Lauf sieht einen Fehler und einen Werkzeugmangel.\n"
    exit 0
  fi
  printf "${ROT}SELBSTTEST GEFALLEN${AUS}: der gepflanzte Fehler oder der Werkzeugmangel wurde nicht gemeldet.\n"
  exit 1
fi

if [ "$GEFALLEN" -eq 0 ] && [ "$PFLICHT_FEHLT" -eq 0 ]; then
  if [ "$UEBERSPRUNGEN" -eq 0 ]; then
    printf "${GRUEN}QA BESTANDEN${AUS}: alle %s Pruefungen liefen und verhielten sich wie erwartet.\n" "$GESAMT"
  else
    printf "${GRUEN}QA BESTANDEN${AUS}, mit Einschraenkung: %s von %s Pruefungen liefen und verhielten sich wie\n" "$BESTANDEN" "$GESAMT"
    printf "erwartet. Nicht gelaufen und darum nicht belegt: %s (siehe oben).\n" "$UEBERSPRUNGEN"
  fi
  exit 0
fi

printf "${ROT}QA GEFALLEN${AUS}: %s Pruefung(en) verhielten sich nicht wie erwartet" "$GEFALLEN"
[ "$PFLICHT_FEHLT" -gt 0 ] && printf ", und %s Pflichtpruefung(en) liefen nicht" "$PFLICHT_FEHLT"
printf ".\n"
exit 1
