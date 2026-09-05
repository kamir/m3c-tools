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
# Usage:  ./scripts/sim-calibrate.sh [-t <strength>] [-n <scenarios>]
#
# The default is the same covering array the CI gate runs, so a detection rate
# measured here is a statement about the gate and not about some other corpus.
# Calibrating a broader corpus than the one that actually guards the branch would
# report a sensitivity nobody ever gets.
# Exit:   0 when every mutant was detected, 1 otherwise.

set -uo pipefail

N=100
T=2
while [ $# -gt 0 ]; do
  case "$1" in
    -n) N="${2:-100}"; T=0; shift 2 ;;
    -t) T="${2:-2}"; shift 2 ;;
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
  "gate1-envelope|pkg/skillctl/registry/backend_pull.go|s|if err := VerifyEnvelopeSignature(pub, event); err != nil {|if err := VerifyEnvelopeSignature(pub, event); false \&\& err != nil {|"
  "gate2-digest|pkg/skillctl/registry/backend_pull.go|s|if gotDigest != digest {|if false \&\& gotDigest != digest {|"
  "silent-noop-install|pkg/skillctl/registry/install_trust_mode.go|s|if err := os.Rename(tmp, target); err != nil {|if err := func() error { _ = tmp; _ = target; return nil }(); err != nil {|"
  "early-fetch|pkg/skillctl/registry/backend_pull.go|s|if acc.IsRevoked(digest) {|if _, ferr := be.Fetch(ctx, artifact.ArtifactRef{Name: name, Version: ver, Digest: digest}); ferr != nil { res.Skipped = append(res.Skipped, \&PullSkip{Name: name, Version: ver, Digest: digest, Gate: ErrGateDigest, Detail: ferr.Error()}); continue } else if acc.IsRevoked(digest) {|"
)

# The last two are not disabled gates. They are the two SIDE-EFFECT requirements,
# and each exists because the defect it models is invisible to everything that
# reads an exit code or a gate name.
#
#   silent-noop-install  reports success and writes nothing        -> caught by INV-7
#   early-fetch          fetches the artifact BEFORE deciding      -> caught by INV-8
#
# early-fetch is the calibration for FR-0119 D3, decided 2026-09-05. You cannot
# observe a fetch that did not happen, so the corpus withholds the artifact and
# checks that the revocation and governance decisions are still reached. This
# mutant is the proof that the check has teeth: it fetches first, the fetch fails
# because the bytes are gone, and the pull reports the digest gate for a bundle it
# should have refused on signed metadata alone.

# The last one is not a gate. It is the defect class an external reviewer named on
# 2026-09-05: report success, write nothing. Every check that reads an exit code or
# a printed gate passes it, which is why INV-7 had to stop asking the tool how it
# went and read the consumer's disk instead. If this mutant is ever NOT detected,
# the disk-based invariants have stopped working and every accept bin in every
# report on this project is unbacked.

echo "sim-calibrate: building the simulator"
go build -o "$WORK/skillctl-sim" ./cmd/skillctl-sim || exit 1

# THE BASELINE, and it comes first on purpose.
#
# Every statement below is of the form "the mutant was rejected". That is only
# evidence if the UNMUTATED build is accepted: otherwise the run rejects
# everything, every mutant looks detected, and the detection rate is 100 percent
# of nothing. Measure the zero before measuring the deflection.
echo "sim-calibrate: baseline, the unmutated build must PASS"
if ! go build -o "$WORK/skillctl-base" ./cmd/skillctl; then
  echo "sim-calibrate: the unmutated build does not compile; nothing can be calibrated" >&2
  exit 1
fi
if ! "$WORK/skillctl-sim" run -t "$T" -n "$N" -jobs 8 -skillctl "$WORK/skillctl-base" >"$WORK/baseline.log" 2>&1; then
  echo "sim-calibrate: the BASELINE run failed. Calibration is meaningless until it passes." >&2
  echo "  A run that rejects the unmutated build rejects every mutant too, and would" >&2
  echo "  report perfect sensitivity while measuring nothing." >&2
  tail -20 "$WORK/baseline.log" >&2
  exit 1
fi
echo "  baseline: PASS"

detected=0
total=0
declare -a MISSED=()

for m in "${MUTANTS[@]}"; do
  name="${m%%|*}"; rest="${m#*|}"
  file="${rest%%|*}"; expr="${rest#*|}"
  total=$((total + 1))

  wt="$WORK/mutant-$name"
  # A worktree that never came up is a mutant that never ran. It used to `continue`
  # without a trace, so the final success branch could be reached with mutants that
  # were never tested. An untested control is not a passed one.
  if ! git worktree add --detach "$wt" HEAD >/dev/null 2>&1; then
    echo "  $name: worktree failed; the mutant never ran, counting as MISSED"
    MISSED+=("$name (worktree could not be created)")
    continue
  fi

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

  # THE READING, and it is deliberately not the exit code.
  #
  # It used to be: non-zero exit means detected. That is wrong in the most
  # dangerous direction, and an external reviewer found it on 2026-09-05. The
  # simulator also exits non-zero when its own harness breaks, so a mutant whose
  # build merely fails to run scored as CAUGHT. A calibration that counts its own
  # breakage as sensitivity is precisely the false green this whole exercise
  # exists to prevent, sitting inside the instrument that is supposed to rule it
  # out.
  #
  # Detection now requires a POSITIVE, behavioural reading: at least one conflict
  # or one invariant violation, AND no harness failure. Anything else is reported
  # under its own name and counts as MISSED, because "we could not tell" is not
  # "we caught it".
  "$WORK/skillctl-sim" run -t "$T" -n "$N" -jobs 8 -skillctl "$WORK/skillctl-$name" >"$WORK/$name.log" 2>&1
  rc=$?

  nconf=$(grep -oE '[0-9]+ conflicts' "$WORK/$name.log" | head -1 | grep -oE '^[0-9]+')
  nviol=$(grep -oE 'INVARIANT VIOLATIONS \(([0-9]+)\)' "$WORK/$name.log" | grep -oE '[0-9]+' | head -1)
  nharn=$(grep -oE '[0-9]+ harness failure' "$WORK/$name.log" | head -1 | grep -oE '^[0-9]+')
  nconf=${nconf:-0}; nviol=${nviol:-0}; nharn=${nharn:-0}

  # ORDER MATTERS HERE, and getting it wrong in either direction is a bug.
  #
  # A behavioural finding comes FIRST: a mutant that breaks the product will often
  # also make a later step fail, and that follow-on failure must not erase the
  # finding that preceded it. The silent-noop-install mutant is exactly this shape,
  # it raises ten INV-7 violations and then two later verifies cannot run.
  #
  # But a harness failure WITHOUT any behavioural finding is not detection. That
  # was the old bug: every non-zero exit counted, so a mutant that merely failed to
  # run scored as caught.
  if [ "$nconf" -gt 0 ] || [ "$nviol" -gt 0 ]; then
    extra=""
    [ "$nharn" -gt 0 ] && extra=", $nharn follow-on harness failure(s)"
    echo "  $name: detected  ($nconf conflicts, $nviol invariant violations, exit $rc$extra)"
    detected=$((detected + 1))
  elif [ "$nharn" -gt 0 ]; then
    echo "  $name: HARNESS FAILURE ($nharn) and no behavioural finding; nothing was measured, counting as MISSED"
    MISSED+=("$name (harness failure, not a behavioural reading)")
  elif [ "$rc" -ne 0 ]; then
    echo "  $name: exit $rc but NO conflict and NO invariant violation; that is not a reading, counting as MISSED"
    MISSED+=("$name (non-zero exit without a behavioural finding)")
  else
    echo "  $name: NOT DETECTED"
    MISSED+=("$name")
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
