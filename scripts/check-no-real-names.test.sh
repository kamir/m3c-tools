#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
name=$(sed -n "s/^NAMES='\([^|]*\).*/\1/p" "$root/scripts/check-no-real-names.sh")
fingerprint=$(awk -v name="$name" 'index($0, "/keys/" tolower(name) ".priv:private-key:1") { print; exit }' "$root/.gitleaksignore")
[ -n "$name" ] && [ -n "$fingerprint" ] || { echo 'fixture inputs missing' >&2; exit 1; }
mkdir -p "$fixture/scripts"
cp "$root/scripts/check-no-real-names.sh" "$fixture/scripts/"
git -C "$fixture" init -q
cd -- "$fixture"
git add scripts/check-no-real-names.sh
check() {
  local expected=$1 label=$2 actual=0
  shift 2
  bash scripts/check-no-real-names.sh "$@" > gate-output.log 2>&1 || actual=$?
  rm -f gate-output.log
  [ "$actual" -eq "$expected" ] || { echo "FAIL: $label (exit $actual, want $expected)" >&2; exit 1; }
  echo "ok: $label"
}
printf '%s\n' "$fingerprint" > .gitleaksignore
check 0 'exact historical fingerprint'
check 1 'all mode reports the exemption' --all
printf '0%s\n' "${fingerprint:1}" > .gitleaksignore
check 1 'different historical commit'
printf '%s extra\n' "$fingerprint" > .gitleaksignore
check 1 'additional content on the same line'
printf '%s\n' "$fingerprint" > another.txt
rm .gitleaksignore
check 1 'same pointer in another file'
rm another.txt
printf '%s\nexample %s\n' "$fingerprint" "$name" > .gitleaksignore
check 1 'new name in the same machine file'
