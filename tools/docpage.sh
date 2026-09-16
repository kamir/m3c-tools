#!/usr/bin/env bash
# docpage.sh: aus einer Markdown-Datei unter docs/ eine lesbare, druckbare
# Doku-Seite erzeugen.
#
# Warum es diesen Schritt gibt: eine 900-Zeilen-Anleitung liest niemand in
# einem Texteditor, und die Jekyll-Standardform der Seite traegt weder
# Abschnittsschiene noch Kopierknoepfe noch einen Druck-Flavor. Die Markdown
# bleibt die Quelle; diese Seite ist eine zweite Darstellung davon und sagt
# das in ihrer eigenen Fusszeile.
#
# Die Markdown wird in die Seite GESTEMPELT, nicht dorthin uebersetzt. Damit
# kann der Inhalt nicht durch einen selbstgebauten Uebersetzer verformt
# werden, und die Seite bleibt lesbar, auch wenn zur Laufzeit gar nichts
# laedt: faellt die Rendering-Bibliothek aus, zeigt die Seite den Rohtext.
#
# Dass die erzeugte Datei zur Quelle passt, ist NICHT Vertrauenssache:
# scripts/check-docpages.sh erzeugt sie neu und vergleicht. Wer die Markdown
# aendert und das Erzeugen vergisst, faellt dort auf.
#
# Aufruf:
#   tools/docpage.sh <markdown> [ausgabe.html]
#   tools/docpage.sh docs/ops-human-agent-team.de.md
#
# Vorgabe fuer die Ausgabe: docs/pages/<basisname-ohne-sprachsuffix>.html
# Der eigene Ordner ist Absicht: Jekyll uebersetzt docs/x.md nach x.html, eine
# erzeugte docs/x.html wuerde also mit der Uebersetzung kollidieren.
#
# Der Titel kommt aus der ersten H1 der Markdown, ohne die Gattungsangabe
# davor: "# Ops-Runbook: ein Mensch-Agent-Team einrichten" wird zu
# "Ein Mensch-Agent-Team einrichten". Mit --title laesst sich das ueberschreiben.
#
# Exit: 0 erzeugt · 1 ein Fehler · 2 Aufrufproblem
set -euo pipefail

TITLE=""
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --title) TITLE="${2:?--title braucht einen Text}"; shift 2 ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unbekannte Option: $1" >&2; exit 2 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

SRC="${ARGS[0]:-}"
[ -n "$SRC" ] || { echo "Aufruf: tools/docpage.sh <markdown> [ausgabe.html]" >&2; exit 2; }
[ -f "$SRC" ] || { echo "keine solche Datei: $SRC" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TPL="${ROOT}/tools/release-templates/docpage.template.html"
[ -f "$TPL" ] || { echo "Vorlage fehlt: $TPL" >&2; exit 1; }

BASE="$(basename "$SRC" .md)"
BASE="${BASE%.de}"
OUT="${ARGS[1]:-${ROOT}/docs/pages/${BASE}.html}"

# Titel aus der ersten H1, die Gattungsangabe vor dem Doppelpunkt faellt weg.
if [ -z "$TITLE" ]; then
  TITLE="$(grep -m1 '^# ' "$SRC" | sed 's/^# //')"
  case "$TITLE" in
    *:*) TITLE="${TITLE#*: }" ;;
  esac
  # Erster Buchstabe gross, weil die Ueberschrift im Original klein weitergeht.
  TITLE="$(printf '%s' "$TITLE" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
fi

# Der Quellverweis ist repo-relativ, damit er auf jeder Maschine gleich lautet.
REL="${SRC#"${ROOT}/"}"
REL="${REL#./}"

mkdir -p "$(dirname "$OUT")"

# Der Platzhalter steht in einem script-Block, der Rohtext aufnimmt. Nur eine
# Zeichenfolge koennte ihn beenden, und genau die wird vorher abgelehnt.
if grep -qi '</script' "$SRC"; then
  echo "FEHLER: $SRC enthaelt '</script'; das wuerde die Seite zerreissen." >&2
  exit 1
fi

python3 - "$TPL" "$SRC" "$OUT" "$TITLE" "$REL" <<'PY'
import io, sys
tpl, src, out, title, rel = sys.argv[1:6]
page = io.open(tpl, encoding="utf-8").read()
md = io.open(src, encoding="utf-8").read()
for name, value in (("__TITLE__", title), ("__SOURCE__", rel)):
    if name not in page:
        sys.exit("Platzhalter %s fehlt in der Vorlage" % name)
    page = page.replace(name, value)
page = page.replace("__MARKDOWN__", md)
io.open(out, "w", encoding="utf-8").write(page)
PY

# Tore auf dem Ergebnis. Ein nicht ersetzter Platzhalter waere im Browser erst
# sichtbar, wenn jemand die Seite oeffnet, und das ist zu spaet.
for ph in __TITLE__ __SOURCE__ __MARKDOWN__; do
  if grep -q "$ph" "$OUT"; then
    echo "FEHLER: Platzhalter $ph steht noch in $OUT" >&2
    exit 1
  fi
done

echo "==> Doku-Seite erzeugt: ${OUT#"${ROOT}/"}"
echo "    Quelle: $REL"
echo "    Titel:  $TITLE"
echo "    Groesse: $(wc -c < "$OUT" | tr -d ' ') Bytes"
