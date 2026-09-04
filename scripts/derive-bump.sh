#!/usr/bin/env bash
#############################################################################
# derive-bump.sh: leitet die Semver-Stufe aus den COMMITS ab, statt sie zu
# raten. Gibt `major`, `minor` oder `patch` auf stdout aus.
#
# Warum es das gibt: `make release` war fest auf `release-patch` verdrahtet,
# und der /ship-Skill entschied nach DIFF-GROESSE ("50+ Zeilen -> patch"). So
# ist der Fleet-Kill-Switch (FR-0045) als v2.8.1 ausgeliefert worden: eine
# Patch-Nummer fuer ein Feature. Die Information, welche Stufe richtig ist,
# lag die ganze Zeit vor: die Commits tragen konsequent feat:/fix:-Praefixe.
#
# Regel (hoechste gefundene Stufe gewinnt):
#   `!` nach dem Typ (feat!:, fix!:) oder ein BREAKING CHANGE: -Trailer  -> major
#   irgendein feat:                                                      -> minor
#   sonst                                                                -> patch
#
# Ein feat: unter zwanzig fix: ergibt weiterhin minor. Zeilenzahl ist KEIN
# Signal: ein einzeiliges Feature bleibt ein Feature, ein tausendzeiliges
# Refactoring ohne Verhaltensaenderung bleibt ein Patch.
#############################################################################
set -euo pipefail

LATEST_TAG=$(git tag --list 'v*' --sort=-v:refname | head -1)
RANGE="${LATEST_TAG:+$LATEST_TAG..}HEAD"

LOG=$(git log "$RANGE" --format='%s%n%b' 2>/dev/null || git log --format='%s%n%b')

if grep -qE '^[a-z]+(\([^)]*\))?!:' <<<"$LOG" || grep -q 'BREAKING CHANGE:' <<<"$LOG"; then
  echo major
elif grep -qE '^feat(\([^)]*\))?:' <<<"$LOG"; then
  echo minor
else
  echo patch
fi
