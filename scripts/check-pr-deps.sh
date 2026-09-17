#!/usr/bin/env bash
# check-pr-deps.sh: die Depends-on-Zeilen im Body eines Pull Requests gegen
# den echten Zustand der Pull Requests, die sie nennen.
#
# WARUM: "merge #316 zuerst" stand bisher als Prosa in PR-Kommentaren, und auf
# der PR-Uebersicht sind vier gruene PRs ununterscheidbar. Eine Reihenfolge,
# die nur ein Mensch im Kopf traegt, ist keine Reihenfolge (Pruefrage aus der
# Arbeitsregel: woher weiss das Werkzeug davon?). Dieses Skript macht den
# PR-Body zum Traeger und misst ihn.
#
# TRAEGER: NUR der PR-Body, nie ein Kommentar. Ein Kommentar ist Konversation,
# der Body ist der Vertrag. Gezaehlt werden Zeilen der Form
#
#     Depends-on: #316
#     depends-on: #316, #321
#
# Gross- und Kleinschreibung ist egal, mehrere Zeilen sind erlaubt, mehrere
# Referenzen je Zeile auch. Eine Depends-on-Zeile OHNE lesbare #N-Referenz
# blockiert ebenfalls: "Depends-on: PR 316" darf nicht als "keine
# Abhaengigkeit" durchgehen (fail-closed).
#
# ZUSTAENDE: MERGED und CLOSED erfuellen die Abhaengigkeit (CLOSED heisst: der
# Plan hat sich geaendert, und die Ausgabezeile sagt das sichtbar). OPEN
# blockiert. Eine Referenz, die sich nicht aufloesen laesst (Tippfehler,
# geloeschter PR, Netzfehler), blockiert ebenfalls, mit eigener Meldung: ein
# Tippfehler darf nicht als erfuellt durchgehen. Ein Selbstbezug blockiert.
#
# Aufruf: ./scripts/check-pr-deps.sh <pr-nummer> [<owner/repo>]
#         (Vorgabe fuer das Repo: kamir/m3c-tools, wie in
#         scripts/check-required-checks.sh)
# Exit:   0 keine Abhaengigkeit, oder jede ist MERGED oder CLOSED
#         1 mindestens eine blockiert (OPEN, nicht aufloesbar, Selbstbezug,
#           oder eine Depends-on-Zeile ohne lesbare Referenz)
#         2 Aufruffehler: Argumente, gh fehlt, oder der PR selbst ist nicht
#           lesbar. Exit 2 ist eine Aussage ueber den AUFRUF, Exit 1 eine
#           ueber den PR; die Trennung folgt check-required-checks.sh.
set -euo pipefail

PR_NUM="${1:-}"
REPO="${2:-kamir/m3c-tools}"

if [ -z "$PR_NUM" ] || ! [[ "$PR_NUM" =~ ^[0-9]+$ ]]; then
  echo "usage: $0 <pr-nummer> [<owner/repo>]" >&2
  echo "  pr-nummer muss eine Zahl sein, bekommen: '${PR_NUM}'" >&2
  exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "check-pr-deps: gh fehlt auf dem PATH; ohne gh ist der Body nicht lesbar" >&2
  exit 2
fi

# Der Body des zu pruefenden PRs. Scheitert das, ist der AUFRUF kaputt
# (falsche Nummer, falsches Repo, keine Rechte), nicht die Abhaengigkeit.
if ! BODY="$(gh pr view "$PR_NUM" --repo "$REPO" --json body --jq '.body' 2>&1)"; then
  echo "check-pr-deps: PR #$PR_NUM in $REPO ist nicht lesbar:" >&2
  printf '%s\n' "$BODY" >&2
  exit 2
fi

# gh liefert Bodys mit CRLF-Zeilenenden; das \r wuerde sonst am Zeilenanker
# der grep-Muster haengen.
BODY="${BODY//$'\r'/}"

# Nur Zeilen, die mit Depends-on beginnen (fuehrender Leerraum erlaubt).
# `|| true`: keine Treffer ist der Normalfall, kein Fehler.
DEP_LINES="$(printf '%s\n' "$BODY" \
  | grep -iE '^[[:space:]]*depends-on[[:space:]]*:' || true)"

if [ -z "$DEP_LINES" ]; then
  echo "check-pr-deps: PR #$PR_NUM hat keine Depends-on-Zeile im Body; nichts zu pruefen"
  exit 0
fi

# Alle #N-Referenzen aus den Depends-on-Zeilen, numerisch dedupliziert.
REFS="$(printf '%s\n' "$DEP_LINES" \
  | grep -oE '#[0-9]+' | tr -d '#' | sort -n -u || true)"

if [ -z "$REFS" ]; then
  echo "check-pr-deps: PR #$PR_NUM traegt Depends-on-Zeile(n) ohne lesbare #N-Referenz:"
  printf '%s\n' "$DEP_LINES" | sed 's/^/  /'
  echo "Eine Abhaengigkeit, die das Werkzeug nicht lesen kann, gilt als"
  echo "blockierend, nicht als abwesend (fail-closed). Form: Depends-on: #123"
  exit 1
fi

BLOCKERS=""
block() { BLOCKERS="${BLOCKERS:+$BLOCKERS, }$1"; }
while IFS= read -r ref; do
  if [ "$ref" = "$PR_NUM" ]; then
    echo "  #$ref SELBSTBEZUG"
    block "#$ref (verweist auf sich selbst)"
    continue
  fi
  if ! STATE="$(gh pr view "$ref" --repo "$REPO" --json state --jq '.state' 2>&1)"; then
    echo "  #$ref NICHT AUFLOESBAR"
    printf '%s\n' "$STATE" | sed 's/^/    gh: /'
    block "#$ref (kein Pull Request dieser Nummer in $REPO, oder nicht lesbar)"
    continue
  fi
  case "$STATE" in
    MERGED|CLOSED)
      echo "  #$ref $STATE"
      ;;
    OPEN)
      echo "  #$ref OPEN"
      block "#$ref (noch OPEN)"
      ;;
    *)
      # Ein Zustand, den dieses Skript nicht kennt, ist kein erfuellter
      # Zustand: fail-closed statt raten.
      echo "  #$ref UNBEKANNTER ZUSTAND '$STATE'"
      block "#$ref (unbekannter Zustand '$STATE')"
      ;;
  esac
done <<< "$REFS"

if [ -n "$BLOCKERS" ]; then
  echo "check-pr-deps: PR #$PR_NUM ist blockiert durch $BLOCKERS"
  echo "Erst mergen (oder die Depends-on-Zeile im Body korrigieren), dann"
  echo "laeuft das Tor beim naechsten Body- oder Branch-Ereignis neu."
  exit 1
fi

echo "check-pr-deps: jede Abhaengigkeit von PR #$PR_NUM ist MERGED oder CLOSED"
exit 0
