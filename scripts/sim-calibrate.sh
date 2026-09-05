#!/usr/bin/env bash
# sim-calibrate.sh: measure whether the simulation can actually SEE a defect.
#
# EV-4 of the empirical-validation framework. A benchmark that cannot fail is not
# an instrument, it is decoration, and the only way to know which one you have is
# to break the system on purpose and check that the needle moves.
#
# The method is mutation testing, used here as calibration rather than as a
# coverage metric: for each mutant, one gate of the trust chain is disabled in a
# throwaway git worktree, the binary is rebuilt, and the simulation is run against
# it. A mutant that the simulation does NOT catch is a hole in the corpus, and the
# script reports the DETECTION RATE, which is the sensitivity of the instrument.
#
# Nothing here touches the working tree: every mutant lives in its own worktree
# and is removed afterwards, whether the run succeeds or not.
#
# Usage:  ./scripts/sim-calibrate.sh [-n <scenarios>]
# Exit:   0 when every mutant was detected, 1 otherwise.

set -uo pipefail

N=100
while [ $# -gt 0 ]; do
  case "$1" in
    -n) N="${2:-100}"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "sim-calibrate: unknown flag $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "sim-calibrate: the working tree has uncommitted changes." >&2
  echo "  Mutants are built from a worktree of HEAD, so uncommitted work would not" >&2
  echo "  be measured. Commit or stash first." >&2
  exit 2
fi

WORK="$(mktemp -d)"
cleanup() {
  for wt in "$WORK"/mutant-*; do
    [ -d "$wt" ] && git worktree remove "$wt" --force >/dev/null 2>&1
  done
  git worktree prune >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

# Each mutant is a name, a file, and a sed expression that disables one control.
# They are deliberately CRUDE: the question is not whether the simulation notices a
# subtle refactor, it is whether it notices that a gate stopped gating.
MUTANTS=(
  "gate5-revocation|pkg/skillctl/registry/backend_pull.go|s|if acc.IsRevoked(digest) {|if false \&\& acc.IsRevoked(digest) {|"
  "gate4-governance|pkg/skillctl/registry/backend_pull.go|s|if len(qual) < tr.quorum() {|if false \&\& len(qual) < tr.quorum() {|"
)

echo "sim-calibrate: building the simulator"
go build -o "$WORK/skillctl-sim" ./cmd/skillctl-sim || exit 1

detected=0
total=0
declare -a MISSED=()

for m in "${MUTANTS[@]}"; do
  name="${m%%|*}"; rest="${m#*|}"
  file="${rest%%|*}"; expr="${rest#*|}"
  total=$((total + 1))

  wt="$WORK/mutant-$name"
  git worktree add --detach "$wt" HEAD >/dev/null 2>&1 || { echo "  $name: worktree failed"; continue; }

  if ! sed -i '' "$expr" "$wt/$file" 2>/dev/null && ! sed -i "$expr" "$wt/$file" 2>/dev/null; then
    echo "  $name: the mutation did not apply (the code moved); treating as MISSED"
    MISSED+=("$name (mutation no longer applies)")
    continue
  fi
  if ! git -C "$wt" diff --quiet -- "$file"; then
    :
  else
    echo "  $name: the mutation changed nothing; treating as MISSED"
    MISSED+=("$name (no textual change)")
    continue
  fi

  if ! (cd "$wt" && go build -o "$WORK/skillctl-$name" ./cmd/skillctl 2>/dev/null); then
    echo "  $name: the mutant does not compile; treating as MISSED"
    MISSED+=("$name (does not compile)")
    continue
  fi

  # The instrument reading: a non-zero exit means the simulation refused to accept
  # this build. That is exactly what detection means here.
  if "$WORK/skillctl-sim" run -n "$N" -jobs 8 -skillctl "$WORK/skillctl-$name" >"$WORK/$name.log" 2>&1; then
    echo "  $name: NOT DETECTED"
    MISSED+=("$name")
  else
    conflicts=$(grep -oE '[0-9]+ conflicts' "$WORK/$name.log" | head -1)
    viol=$(grep -oE 'INVARIANT VIOLATIONS \([0-9]+\)' "$WORK/$name.log" | head -1)
    echo "  $name: detected  ($conflicts, $viol)"
    detected=$((detected + 1))
  fi
done

echo ""
echo "detection rate: $detected of $total"
if [ ${#MISSED[@]} -gt 0 ]; then
  echo "MISSED mutants, each one a hole in the corpus:"
  for m in "${MISSED[@]}"; do echo "  $m"; done
  echo ""
  echo "A missed mutant means the simulation would stay green while that control is"
  echo "dead. Add the scenario that would have caught it before trusting the next run."
  exit 1
fi
echo "Every disabled control was caught. The instrument has sensitivity on this corpus."
