#!/usr/bin/env bash
#
# check-install-pins.sh: every pinned raw.githubusercontent URL in the docs must
# point at a real, published COMMIT, and the SHA-256 next to it must match the
# bytes at that pin.
#
# Why this exists (BUG-0215): the install one-liners were pinned to
# 82c8328..., which is the object id of the ANNOTATED TAG skillctl/v0.4.0, not
# of the commit it points at. `git rev-parse <tag>` hands you the tag object;
# raw.githubusercontent.com only serves commits. Every published install
# one-liner returned 404, on Windows and Unix alike, and nothing noticed: the
# release runbook says to pin `git rev-parse origin/master`, but no check ever
# read what was actually written.
#
# A rule nobody checks is a request. This is the check.
#
# It is deliberately OFFLINE: it reads git objects, not the network, so it is
# deterministic in CI and cannot pass because a proxy cached a 200. It needs the
# full history (fetch-depth: 0), because a pin is by definition an older commit.
#
# Usage: ./scripts/check-install-pins.sh
# Exit:  0 every pin resolves and every digest matches - 1 a finding - 2 setup error
#
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; NC=$'\033[0m'
fail=0
emit() { printf '%s%s\n' "$1" "$NC"; fail=1; }

# owner/repo of this checkout, so a fork does not check the upstream pins.
origin=$(git config --get remote.origin.url 2>/dev/null || true)
origin=${origin%.git}; origin=${origin#git@github.com:}; origin=${origin#https://github.com/}
[ -n "$origin" ] || { echo "check-install-pins: no origin remote" >&2; exit 2; }

pins=$(git grep -hoE "raw\.githubusercontent\.com/$origin/[0-9a-f]{40}/[^ )\"'\`]+" -- '*.md' \
       | sort -u || true)
if [ -z "$pins" ]; then
  echo "check-install-pins: no pinned URLs found (nothing to check)"
  exit 0
fi

# --- Durchgang 1: Pins aufloesen, Digests sammeln ---------------------------
#
# Zwei Durchgaenge, weil Regel (b) unten die Digests ALLER gepinnten Dateien
# braucht: die beiden Einzeiler stehen in den Dokumenten direkt untereinander,
# und ein Fenster um die eine URL sieht zwangslaeufig den Digest der anderen.
# Die erste Fassung dieser Pruefung meldete genau das als Fehler.
n=0
ALLWANT=""
PINS=""
while IFS= read -r pin; do
  [ -n "$pin" ] || continue
  rest=${pin#raw.githubusercontent.com/$origin/}
  sha=${rest%%/*}
  path=${rest#*/}
  n=$((n + 1))

  # 1. Der Pin muss ein COMMIT sein. Genau das ging in Produktion schief: ein
  #    Tag-Objekt hat eine gueltige 40-Hex-Id und wird von niemandem serviert.
  type=$(git cat-file -t "$sha" 2>/dev/null || echo missing)
  case "$type" in
    commit) ;;
    tag)
      emit "${RED}FAIL $path: pinned to a TAG object ($sha)"
      emit "${RED}     raw.githubusercontent serves commits only. Use: git rev-parse ${sha}^{commit}"
      continue ;;
    missing)
      emit "${RED}FAIL $path: pinned object $sha is not in this clone"
      emit "${RED}     A pin is an older commit; this check needs the full history (fetch-depth: 0)."
      continue ;;
    *)
      emit "${RED}FAIL $path: pinned object $sha is a $type, not a commit"
      continue ;;
  esac

  # 2. Der Commit muss veroeffentlicht sein, sonst 404 fuer alle ausser dir.
  if git rev-parse --verify -q origin/master >/dev/null 2>&1; then
    git merge-base --is-ancestor "$sha" origin/master 2>/dev/null \
      || emit "${RED}FAIL $path: $sha is not reachable from origin/master (unpublished pin)"
  fi

  # 3. Die Datei muss es an diesem Commit geben.
  git cat-file -e "$sha:$path" 2>/dev/null \
    || { emit "${RED}FAIL $path: does not exist at $sha"; continue; }

  want=$(git show "$sha:$path" | shasum -a 256 | cut -d' ' -f1)
  ALLWANT="$ALLWANT $want"
  PINS="$PINS$sha/$path|$want"$'\n'
done <<<"$pins"

# --- Durchgang 2: die veroeffentlichten Digests pruefen ----------------------
while IFS='|' read -r url want; do
  [ -n "$url" ] || continue
  path=${url#*/}
  want_up=$(printf '%s' "$want" | tr 'a-f' 'A-F')

  # (a) Eine Zeile, die den Pfad nennt UND einen Digest traegt, muss DIESEN tragen.
  #     Das ist die Tabellenzeile.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    got=$(printf '%s' "$line" | grep -oE '[0-9a-fA-F]{64}' | head -1 | tr 'A-F' 'a-f')
    [ "$got" = "$want" ] || emit "${RED}FAIL $path: a line publishes SHA-256 $got, the pin has $want"
  done < <(git grep -hE "$path" -- '*.md' | grep -E '[0-9a-fA-F]{64}' || true)

  # (b) In den verify-then-run-Bloecken steht der Digest auf einer EIGENEN Zeile,
  #     fuer PowerShell in Grossbuchstaben. Regel (a) sieht ihn dort nicht. Ein
  #     Fenster von 8 Zeilen nach der URL ist, was so ein Block umspannt; erlaubt
  #     ist jeder Digest einer gepinnten Datei, verboten jeder fremde.
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    emit "${RED}FAIL a verify block near the pin publishes a foreign digest: $hit"
  done < <(
    git grep -l "$url" -- '*.md' 2>/dev/null | while IFS= read -r doc; do
      [ -n "$doc" ] || continue
      awk -v u="$url" -v ok="$ALLWANT" -v d="$doc" '
        index($0, u) { win = 8; next }
        win > 0 {
          win--
          if (match($0, /[0-9a-fA-F]{64}/)) {
            h = tolower(substr($0, RSTART, RLENGTH))
            if (index(ok, h) == 0) printf "%s:%d: %s\n", d, NR, h
          }
        }' "$doc"
    done
  )

  # (c) Der echte Digest muss im pinnenden Dokument ueberhaupt vorkommen, sonst
  #     kann ein Pin-Bump ohne Digest-Bump still durchgehen.
  while IFS= read -r doc; do
    [ -n "$doc" ] || continue
    grep -qE "$want|$want_up" "$doc" \
      || emit "${RED}FAIL $doc pins $path at ${url%%/*} but never publishes its digest $want"
  done < <(git grep -l "$url" -- '*.md' 2>/dev/null || true)
done <<<"$PINS"

if [ "$fail" -ne 0 ]; then
  printf '%scheck-install-pins: FAIL%s - a published install one-liner is broken\n' "$RED" "$NC" >&2
  exit 1
fi
printf '%scheck-install-pins: %d pin(s) resolve, digests match%s\n' "$GREEN" "$n" "$NC"
