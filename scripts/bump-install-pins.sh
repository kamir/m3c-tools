#!/usr/bin/env bash
#
# bump-install-pins.sh: move the install one-liners to a new release commit and
# recompute the SHA-256 digests published next to them.
#
# This automates the one manual step that broke the installers (BUG-0215). The
# release runbook said to pin `git rev-parse origin/master`; somebody pinned a
# tag instead, and `git rev-parse <annotated-tag>` returns the TAG OBJECT, which
# raw.githubusercontent.com does not serve. Every published one-liner 404'd.
#
# So the first thing this script does, and the reason it exists, is
# `<ref>^{commit}`. A tag, a branch or a commit all resolve to the commit.
#
# It only rewrites; it verifies nothing. scripts/check-install-pins.sh is the
# gate, and the caller runs it afterwards: a bumper that also judged its own
# work would be the same trust boundary problem as a self-signed attestation.
#
# Usage:
#   scripts/bump-install-pins.sh <ref>            # rewrite in place
#   scripts/bump-install-pins.sh <ref> --check    # report only, exit 1 if stale
#
# Exit: 0 nothing to do (or done) - 1 --check found drift - 2 usage/setup error
#
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

ref=${1:-}
mode=${2:-}
[ -n "$ref" ] || { echo "usage: $0 <ref> [--check]" >&2; exit 2; }

# THE line this whole script exists for.
commit=$(git rev-parse --verify -q "${ref}^{commit}") \
  || { echo "bump-install-pins: cannot resolve $ref to a commit" >&2; exit 2; }

origin=$(git config --get remote.origin.url 2>/dev/null || true)
origin=${origin%.git}; origin=${origin#git@github.com:}; origin=${origin#https://github.com/}
[ -n "$origin" ] || { echo "bump-install-pins: no origin remote" >&2; exit 2; }

# Current pins, as written in the docs.
old_shas=$(git grep -hoE "raw\.githubusercontent\.com/$origin/[0-9a-f]{40}/" -- '*.md' \
           | grep -oE '[0-9a-f]{40}' | sort -u || true)
paths=$(git grep -hoE "raw\.githubusercontent\.com/$origin/[0-9a-f]{40}/[^ )\"'\`]+" -- '*.md' \
        | sed -E 's#.*/[0-9a-f]{40}/##' | sort -u || true)
[ -n "$paths" ] || { echo "bump-install-pins: no pinned URLs found"; exit 0; }

changed=0
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT

apply() {                      # apply FROM TO  -- rewrite every tracked .md
  local from=$1 to=$2 f
  [ "$from" = "$to" ] && return 0
  while IFS= read -r f; do
    grep -q "$from" "$f" || continue
    changed=1
    if [ "$mode" = "--check" ]; then
      printf '  %s: %s -> %s\n' "$f" "${from:0:12}" "${to:0:12}"
    else
      sed "s/$from/$to/g" "$f" > "$tmp" && mv "$tmp" "$f" && tmp=$(mktemp)
    fi
  done < <(git ls-files '*.md')
}

# 1. the pinned commit, long form and the short form used in prose
while IFS= read -r old; do
  [ -n "$old" ] || continue
  apply "$old" "$commit"
  apply "${old:0:7}" "${commit:0:7}"
done <<<"$old_shas"

# 2. the digests published beside them, in both cases (PowerShell uppercases)
while IFS= read -r path; do
  [ -n "$path" ] || continue
  git cat-file -e "$commit:$path" 2>/dev/null || {
    echo "bump-install-pins: $path does not exist at ${commit:0:12}" >&2; exit 2; }
  new=$(git show "$commit:$path" | shasum -a 256 | cut -d' ' -f1)
  while IFS= read -r old; do
    [ -n "$old" ] || continue
    git cat-file -e "$old:$path" 2>/dev/null || continue
    prev=$(git show "$old:$path" | shasum -a 256 | cut -d' ' -f1)
    apply "$prev" "$new"
    apply "$(printf '%s' "$prev" | tr 'a-f' 'A-F')" "$(printf '%s' "$new" | tr 'a-f' 'A-F')"
  done <<<"$old_shas"
done <<<"$paths"

if [ "$mode" = "--check" ]; then
  [ "$changed" -eq 0 ] && { echo "bump-install-pins: docs already pin ${commit:0:12}"; exit 0; }
  echo "bump-install-pins: docs are stale for ${commit:0:12}" >&2
  exit 1
fi
[ "$changed" -eq 0 ] && echo "bump-install-pins: docs already pin ${commit:0:12}" \
                     || echo "bump-install-pins: pinned to ${commit:0:12}"
