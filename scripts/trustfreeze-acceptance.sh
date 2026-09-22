#!/usr/bin/env bash
# trustfreeze-acceptance.sh: the Trust Freeze walking-skeleton acceptance path
# (SPEC-0466 to SPEC-0471), run against a built skillctl on the real host.
#
#   capture, explicit approval, baseline, offline verify PASS, one flipped
#   byte, verify FAIL, restore, the baseline diffed against itself, a changed
#   capture, a deterministic diff with a stable finding, --fail-on exit codes,
#   deterministic reports that evaluate no signature, refusals.
#
# The same path runs hermetically in cmd/skillctl/trustfreeze_acceptance_test.go
# with a fake host. This script is the real-host counterpart: it reads the
# host's own identity (os-release or sw_vers or the registry, and uname). It
# prints the fields of a SPEC-0471 section 6 evidence record around the
# steps: the commit (or "uncommitted tree at <sha>"), how the binary was
# obtained, the toolchain, the platform class (OS family, architecture, OS
# name and version from the capture), and the capture and baseline content
# digests. With --skillctl the binary's commit is not checked: the record
# then says so. A run is a smoke run on one host; it becomes evidence only
# together with that record. No workflow runs it; it is run by hand.
#
# The "changed capture" is produced by leaving out the one required probe
# (--exclude-probe common.identity): a real host cannot be made to report
# another OS version, and a missing required probe is a real, deterministic
# change that the default policy must block (critical collection gap).
#
# Everything happens in a throwaway directory with a throwaway HOME and a
# throwaway key from `skillctl keygen`; nothing is committed and the directory
# is removed at exit unless --keep is given. The bundles contain the host name
# (device/host): only exit codes, result classes and step names are printed.
#
# Usage:
#   ./scripts/trustfreeze-acceptance.sh [--skillctl <path>] [--keep]
#
# Exit: 0 every step behaved as expected, 1 at least one did not, 2 usage.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

SKILLCTL=""
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --skillctl) SKILLCTL="${2:-}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "trustfreeze-acceptance: unknown argument $1" >&2; exit 2 ;;
    esac
done

WORK="$(mktemp -d)"
cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo "kept: $WORK (its bundles contain this host's name)"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# Evidence record, part 1: what was run (read-only git queries only).
COMMIT="unknown (not a git checkout)"
if HEAD_SHA="$(git rev-parse --verify HEAD 2>/dev/null)"; then
    if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
        COMMIT="uncommitted tree at $HEAD_SHA"
    else
        COMMIT="$HEAD_SHA"
    fi
fi
TOOLCHAIN="$(go version 2>/dev/null || echo unknown)"
if [ -z "$SKILLCTL" ]; then
    BINARY="built from this checkout"
    SKILLCTL="$WORK/skillctl"
    go build -o "$SKILLCTL" ./cmd/skillctl
else
    BINARY="given with --skillctl (its commit is not checked by this script)"
fi
SKILLCTL="$(cd "$(dirname "$SKILLCTL")" && pwd)/$(basename "$SKILLCTL")"
[ -x "$SKILLCTL" ] || { echo "trustfreeze-acceptance: $SKILLCTL is not executable" >&2; exit 2; }
echo "evidence: commit      $COMMIT"
echo "evidence: binary      $BINARY"
echo "evidence: toolchain   $TOOLCHAIN"
echo "evidence: platform    $(uname -s 2>/dev/null || echo unknown)/$(uname -m 2>/dev/null || echo unknown)"

mkdir -p "$WORK/home" "$WORK/keys" "$WORK/tf"
export HOME="$WORK/home"
cd "$WORK"

STEP=0
BAD=0
OUT=""

# step <want-exit> <want-class|-> <label> <command...>
# Runs the command, keeps its stdout in $OUT, and checks the exit code and,
# unless "-", the result_class of the JSON output.
step() {
    local want="$1" class="$2" label="$3" code got verdict
    shift 3
    STEP=$((STEP + 1))
    set +e
    OUT="$("$@" 2>"$WORK/stderr.txt")"
    code=$?
    set -e
    got="$(printf '%s\n' "$OUT" | sed -n 's/^  "result_class": "\([a-z_]*\)",*$/\1/p' | head -1)"
    verdict="ok"
    if [ "$code" -ne "$want" ] || { [ "$class" != "-" ] && [ "$got" != "$class" ]; }; then
        verdict="UNEXPECTED"
        BAD=$((BAD + 1))
    fi
    printf 'step %02d  %-58s exit %d (want %d)  %-24s %s\n' "$STEP" "$label" "$code" "$want" "${got:--}" "$verdict"
}

# check <label> <command...>: a plain assertion, counted like a step.
check() {
    local label="$1" verdict="ok"
    shift
    STEP=$((STEP + 1))
    if ! "$@" >/dev/null 2>&1; then
        verdict="UNEXPECTED"
        BAD=$((BAD + 1))
    fi
    printf 'step %02d  %-58s %s\n' "$STEP" "$label" "$verdict"
}

absent() { [ ! -e "$1" ]; }
contains() { printf '%s' "$OUT" | grep -q -- "$1"; }
lacks() { ! contains "$1"; }
# field <name>: a top-level string field of the last JSON output.
field() { printf '%s\n' "$OUT" | sed -n "s/^  \"$1\": \"\([^\"]*\)\",*\$/\1/p" | head -1; }
# attr <name>: a device/os attribute of the first capture (never the host
# name, which lives in device/host and is not printed).
attr() { sed -n "s/^ *\"$1\": \"\([^\"]*\)\",*\$/\1/p" tf/capture-1/state/device.json | head -1; }

tf() { "$SKILLCTL" trust-freeze "$@"; }
PUB="$WORK/keys/reviewer.pub"

step 0 - "keygen (throwaway key)" "$SKILLCTL" keygen --out "$WORK/keys/reviewer"
step 0 ok "doctor" tf doctor --format json
check "doctor: full platform support not established" contains '"platform_support": "not_established"'

# 1. Capture, approve, verify.
step 0 ok "capture (walking-skeleton)" tf capture --profile walking-skeleton --output tf/capture-1 --format json
CAPTURE_DIGEST="$(field content_digest)"
check "capture has no approval and no signature" absent tf/capture-1/approval.json
printf 'Walking skeleton baseline.\r\nReviewed by the acceptance script.\r\n' >reason.txt
step 2 usage_error "approve without --reviewer is refused" tf baseline approve --capture tf/capture-1 --output tf/baseline-x \
    --change-id CHG-0001 --reason @reason.txt --key keys/reviewer.priv --format json
check "  ... and writes nothing" absent tf/baseline-x
step 2 usage_error "approve with an unreadable --key is refused" tf baseline approve --capture tf/capture-1 --output tf/baseline-y \
    --reviewer alice --change-id CHG-0001 --reason @reason.txt --key keys/absent.priv --format json
check "  ... and writes nothing" absent tf/baseline-y
step 0 ok "baseline approve" tf baseline approve --capture tf/capture-1 --output tf/baseline-1 \
    --reviewer alice --change-id CHG-0001 --reason @reason.txt --key keys/reviewer.priv --format json
check "approval reason normalized to LF" contains '"reason": "Walking skeleton baseline.\\nReviewed by the acceptance script."'
BASELINE_DIGEST="$(field content_digest)"
step 0 ok "verify baseline with the trusted key: PASS" tf verify --bundle tf/baseline-1 --trusted-key "$PUB" --format json
step 1 verification_failure "verify baseline without trust material" tf verify --bundle tf/baseline-1 --format json
check "  ... signature still reported valid" contains '"signature_valid": true'

# 2. One flipped byte, FAIL; diff refuses; restore, PASS.
flip() { cp tf/baseline-1/state/device.json device.json.orig && perl -0pi -e 's/device\/os/device\/oS/' tf/baseline-1/state/device.json; }
restore() { cp device.json.orig tf/baseline-1/state/device.json; }
check "flip one byte in state/device.json" flip
step 1 verification_failure "verify after one flipped byte: FAIL" tf verify --bundle tf/baseline-1 --trusted-key "$PUB" --format json
check "  ... reported as digest_mismatch" contains '"integrity_reason": "digest_mismatch"'
step 1 verification_failure "diff refuses the tampered baseline" tf diff --baseline tf/baseline-1 --current tf/capture-1 \
    --trusted-key "$PUB" --output tf/diff-refused --format json
check "  ... and writes nothing" absent tf/diff-refused
check "restore state/device.json" restore
step 0 ok "verify after restore: PASS" tf verify --bundle tf/baseline-1 --trusted-key "$PUB" --format json

# 3. The baseline against itself, then the same host again: no drift that
# reaches the default threshold.
step 0 ok "diff baseline vs itself" tf diff --baseline tf/baseline-1 --current tf/baseline-1 --trusted-key "$PUB" --format json
step 0 ok "capture again" tf capture --profile walking-skeleton --output tf/capture-2 --format json
step 0 ok "diff baseline vs same-host capture" tf diff --baseline tf/baseline-1 --current tf/capture-2 --trusted-key "$PUB" --format json

# 4. A changed capture: the required probe left out.
step 1 incomplete_capture "capture without the required probe" tf capture --profile walking-skeleton \
    --exclude-probe common.identity --output tf/capture-3 --format json
step 1 drift_threshold_exceeded "diff: required collection gap blocks" tf diff --baseline tf/baseline-1 --current tf/capture-3 \
    --trusted-key "$PUB" --format json
FIRST="$OUT"
check "  ... finding TF-POL-GAP-REQUIRED, critical" contains '"rule_id": "TF-POL-GAP-REQUIRED"'
check "  ... its artifacts are not_observed" contains '"kind": "not_observed"'
check "  ... and never removed" lacks '"kind": "removed"'
step 1 drift_threshold_exceeded "diff again" tf diff --baseline tf/baseline-1 --current tf/capture-3 --trusted-key "$PUB" --format json
check "  ... byte-identical output" test "$FIRST" = "$OUT"
step 0 ok "diff --fail-on none" tf diff --baseline tf/baseline-1 --current tf/capture-3 --trusted-key "$PUB" --fail-on none --format json
step 1 drift_threshold_exceeded "diff --fail-on critical" tf diff --baseline tf/baseline-1 --current tf/capture-3 --trusted-key "$PUB" --fail-on critical --format json
step 0 ok "diff --output (bundle 1)" tf diff --baseline tf/baseline-1 --current tf/capture-3 --trusted-key "$PUB" --fail-on none --output tf/diff-1 --format json
step 0 ok "diff --output (bundle 2)" tf diff --baseline tf/baseline-1 --current tf/capture-3 --trusted-key "$PUB" --fail-on none --output tf/diff-2 --format json
check "  ... diff.json byte-identical" cmp tf/diff-1/diff.json tf/diff-2/diff.json
check "  ... verdict.json byte-identical" cmp tf/diff-1/verdict.json tf/diff-2/verdict.json
step 0 ok "verify diff bundle (integrity scope)" tf verify --bundle tf/diff-1 --format json

# 5. Reports: a projection, the signature is evaluated by verify only.
step 0 ok "report baseline (1)" tf report --input tf/baseline-1 --output tf/report-b1.json
check "  ... signature not_evaluated (report is a projection)" contains '"result": "not_evaluated"'
step 0 ok "report baseline (2)" tf report --input tf/baseline-1 --output tf/report-b2.json
check "  ... byte-identical" cmp tf/report-b1.json tf/report-b2.json
step 0 ok "report diff bundle" tf report --input tf/diff-1 --output tf/report-d1.json
step 1 execution_error "report never overwrites" tf report --input tf/diff-1 --output tf/report-d1.json
step 2 - "report --format sarif: not implemented" tf report --input tf/diff-1 --output tf/report-x.sarif --format sarif

# 6. Usage refusals and key material.
step 2 - "capture without --output" tf capture --profile walking-skeleton
step 2 - "diff --format markdown: not implemented" tf diff --baseline tf/baseline-1 --current tf/capture-2 --format markdown
check "no private key material in any bundle or report" sh -c '! grep -rq "PRIVATE KEY" tf'

# Evidence record, part 2: what the run observed (no host name).
echo ""
echo "evidence: os          $(attr os_family)/$(attr arch) $(attr os_name) $(attr os_version)"
echo "evidence: capture     ${CAPTURE_DIGEST:-unknown}"
echo "evidence: baseline    ${BASELINE_DIGEST:-unknown}"
echo ""
if [ "$BAD" -gt 0 ]; then
    echo "FAIL: $BAD of $STEP steps behaved unexpectedly"
    exit 1
fi
echo "PASS: all $STEP steps behaved as expected"
