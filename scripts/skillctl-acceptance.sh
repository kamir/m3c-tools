#!/usr/bin/env bash
#
# skillctl-acceptance.sh: the SPEC-0406 acceptance rehearsal, by hand.
#
# The twin of scripts/skillctl-acceptance.ps1, same steps, same report, so a run
# from a Mac and a run from a Windows box compare line by line.
#
# It sits one level above scripts/skillctl-test.sh. That one asks "can this
# machine build and test skillctl". This one asks "does this machine REFUSE
# correctly", which is the only half of the question a machine can answer alone.
#
# ---------------------------------------------------------------------------
# WHAT IT RUNS, and why it stops where it does.
#
# Two parties live in two separate HOME directories with two separate keys, and
# a third directory stands in for the untrusted transport. The script drives the
# real binary through:
#
#   R1   this machine is usable                                (doctor)
#   R2   the build under test is named in the report            (version)
#   R3a  the sender packs a skill                               (pack)
#   R3b  the sender signs it                                    (sign)
#   R3c  the sender checks their OWN work before sending        (verify-sig)
#   R3d  the artifact travels, unaltered, and still verifies    (verify-sig)
#   R3e  an artifact ALTERED after signing is refused           (verify-sig, exit 10)
#   R3f  the refusal names the cause, not a missing file        (AC-08)
#   R4a..R4f  the same in the other direction                   (symmetry)
#
# It stops before install. `install --bundle` needs the BundleMeta envelope, and
# that envelope carries author, registry AND governance signatures: a script that
# minted it would have to hold every key, and a run in which one actor holds
# every key demonstrates nothing about two actors. The install half therefore
# lives in the automated regression, which builds each party's keys in isolation:
#
#     go test ./cmd/skillctl/ -run TestAcceptance_TwoParty -v
#
# and in the real two-machine run, SPEC-0406 §4.
# ---------------------------------------------------------------------------
#
# Usage:
#   ./scripts/skillctl-acceptance.sh [--skillctl PATH] [--work DIR] [--keep]
#
# Exit: 0 every step passed; 1 a step failed; 2 usage or setup error.

set -uo pipefail

SKILLCTL=""
WORK=""
KEEP=0

usage() {
  cat <<'USAGE'
skillctl-acceptance.sh: the SPEC-0406 acceptance rehearsal.

  --skillctl PATH   the binary under test (default: ./build/skillctl, then PATH)
  --work DIR        workspace (default: a temp dir, removed unless --keep)
  --keep            keep the workspace so the artifacts can be inspected
  -h, --help        this text

A rehearsal exercises the commands and the refusals on ONE machine. It does not
establish that two machines, two people, or an out-of-band fingerprint check
were involved. The summary says so; please do not report it as an acceptance.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skillctl) SKILLCTL="${2:?--skillctl needs a path}"; shift 2 ;;
    --work)     WORK="${2:?--work needs a path}";         shift 2 ;;
    --keep)     KEEP=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
[ -t 1 ] || { RED=""; GREEN=""; YELLOW=""; NC=""; }

IDS=(); STATES=(); NOTES=(); FAILED=0; LAST_OUT=""

record() {                           # record <id> <PASS|FAIL|SKIP> <note>
  IDS+=("$1"); STATES+=("$2"); NOTES+=("$3")
  [ "$2" = "FAIL" ] && FAILED=1
  return 0
}

# step runs a command and compares the exit code against the one SPEC-0406
# predicts. A step that fails for the WRONG reason is a failure: "non-zero" is
# not a result, it is the absence of one.
step() {                             # step <id> <want-exit> <label> -- cmd...
  local id="$1" want="$2" label="$3"; shift 4
  LAST_OUT="$("$@" 2>&1)"; local rc=$?
  if [ "$rc" -eq "$want" ]; then
    record "$id" PASS "$label"
    printf '  %s%-4s PASS%s  %s (exit %d)\n' "$GREEN" "$id" "$NC" "$label" "$rc"
  else
    record "$id" FAIL "$label: wanted exit $want, got $rc"
    printf '  %s%-4s FAIL%s  %s: wanted exit %d, got %d\n' "$RED" "$id" "$NC" "$label" "$want" "$rc"
    printf '%s\n' "$LAST_OUT" | sed 's/^/          /'
  fi
}

# says checks the PREVIOUS step's output for a phrase. This is the AC-08 check:
# a refusal that exits correctly and explains the wrong thing still sends its
# reader after the wrong problem.
says() {                             # says <id> <needle> <label>
  local id="$1" needle="$2" label="$3"
  if printf '%s' "$LAST_OUT" | grep -qiF -- "$needle"; then
    record "$id" PASS "$label"
    printf '  %s%-4s PASS%s  %s\n' "$GREEN" "$id" "$NC" "$label"
  else
    record "$id" FAIL "$label: output never mentioned '$needle'"
    printf '  %s%-4s FAIL%s  %s: output never mentioned %s\n' "$RED" "$id" "$NC" "$label" "$needle"
    printf '%s\n' "$LAST_OUT" | sed 's/^/          /'
  fi
}

# ---- setup ---------------------------------------------------------------

if [ -z "$SKILLCTL" ]; then
  if [ -x "./build/skillctl" ]; then SKILLCTL="./build/skillctl"
  elif command -v skillctl >/dev/null 2>&1; then SKILLCTL="$(command -v skillctl)"
  else echo "no skillctl found: build it (make build-skillctl) or pass --skillctl" >&2; exit 2; fi
fi
SKILLCTL="$(cd "$(dirname "$SKILLCTL")" && pwd)/$(basename "$SKILLCTL")"

if [ -z "$WORK" ]; then
  WORK="$(mktemp -d)"
  [ "$KEEP" -eq 1 ] || trap 'rm -rf "$WORK"' EXIT
fi
mkdir -p "$WORK"

VERSION="$("$SKILLCTL" version 2>/dev/null | head -1)"
[ -n "$VERSION" ] || { echo "the binary at $SKILLCTL does not answer 'version'" >&2; exit 2; }

echo "skillctl acceptance rehearsal (SPEC-0406)"
echo "binary  : $SKILLCTL"
echo "version : $VERSION"
echo "platform: $(uname -s) $(uname -m)"
echo "work    : $WORK"
echo ""

TRANSPORT="$WORK/transport"; mkdir -p "$TRANSPORT"

# one_party sets up a home, a key and a demo skill. Each party gets its own of
# everything: a shared value here would quietly weaken the whole exercise.
one_party() {                        # one_party <name> <skill> <greeting>
  local who="$1" skill="$2" greet="$3"
  mkdir -p "$WORK/$who/src/$skill" "$WORK/$who/keys"
  printf '# %s\n\n%s\n' "$skill" "$greet" > "$WORK/$who/src/$skill/SKILL.md"
  env HOME="$WORK/$who" "$SKILLCTL" keygen --out "$WORK/$who/keys/$who" >/dev/null 2>&1
}

echo "== Phase 1: both sides check their installation =="
one_party bob bob-demo-skill "Hello from Bob"
one_party alice  alice-demo-skill  "Hello from Alice"

# doctor is asked ONCE, about THIS machine, and deliberately not twice as if it
# were two of them.
#
# Two reasons. It reports the real environment, which is the point of the
# command, and a sandboxed answer would say nothing useful. And on Windows a
# SHIPPING build ignores $HOME for the trust-root path by design (WIN-09
# confinement), so a per-party sandbox would silently collapse into one machine
# there while still looking like two here. A check whose meaning changes between
# the twins is worse than a check that only runs once.
step R1 0 "this machine is usable (doctor)" -- \
  "$SKILLCTL" doctor
says R2 "$VERSION" "the build under test is named in the report"

# exchange plays one direction: sender seals, the artifact travels, the
# recipient checks it, then a tampered copy is checked too.
exchange() {                         # exchange <sender> <skill> <prefix>
  local who="$1" skill="$2" px="$3"
  local key="$WORK/$who/keys/$who"
  local skb="$WORK/$who/$skill@1.0.0.skb"

  step "${px}a" 0 "$who: packs the skill" -- \
    env HOME="$WORK/$who" "$SKILLCTL" pack --skill "$WORK/$who/src/$skill" \
      -o "$skb" --name "$skill" --version 1.0.0
  step "${px}b" 0 "$who: signs it" -- \
    env HOME="$WORK/$who" "$SKILLCTL" sign --key "$key.priv" "$skb"
  step "${px}c" 0 "$who: checks their OWN work before sending" -- \
    env HOME="$WORK/$who" "$SKILLCTL" verify-sig --pubkey "$key.pub" "$skb"

  # The artifact travels. Its signature travels with it, which is what actually
  # happens when someone sends you a signed file.
  cp "$skb" "$TRANSPORT/"
  local sig
  for sig in "$skb".*.author.sig; do
    [ -e "$sig" ] && cp "$sig" "$TRANSPORT/$(basename "$sig")"
  done
  local arrived="$TRANSPORT/$(basename "$skb")"

  step "${px}d" 0 "the unaltered artifact still verifies after transport" -- \
    env HOME="$WORK/$who" "$SKILLCTL" verify-sig --pubkey "$key.pub" "$arrived"

  # Now the tamper: a copy, altered, with the signature NOT re-made.
  local bad="$TRANSPORT/${skill}-tampered.skb"
  cp "$arrived" "$bad"
  for sig in "$arrived".*.author.sig; do
    [ -e "$sig" ] && cp "$sig" "$bad.$(basename "$sig" | sed "s|^$(basename "$arrived")\.||")"
  done
  printf '\xff' | dd of="$bad" bs=1 seek=200 count=1 conv=notrunc 2>/dev/null

  step "${px}e" 10 "the altered artifact is REFUSED" -- \
    env HOME="$WORK/$who" "$SKILLCTL" verify-sig --pubkey "$key.pub" "$bad"
  says "${px}f" "changed after signing" "the refusal names the cause, not a missing file"
}

echo ""
echo "== Alice to Bob =="
exchange alice alice-demo-skill R3

echo ""
echo "== Bob to Alice (symmetry: neither side has a privileged role) =="
exchange bob bob-demo-skill R4

# ---- summary -------------------------------------------------------------

echo ""
echo "========================================"
if [ "$FAILED" -ne 0 ]; then echo " FAIL"; else echo " PASS (rehearsal)"; fi
echo "========================================"
echo ""
echo "Platform : $(uname -s) $(uname -m)"
echo "Binary   : $SKILLCTL"
echo "Version  : $VERSION"
echo ""
for i in "${!IDS[@]}"; do
  case "${STATES[$i]}" in
    PASS) c="$GREEN" ;; FAIL) c="$RED" ;; *) c="$YELLOW" ;;
  esac
  printf '  %s%-5s %-5s%s %s\n' "$c" "${IDS[$i]}" "${STATES[$i]}" "$NC" "${NOTES[$i]}"
done

cat <<'CAVEAT'

WHAT THIS RUN DID NOT ESTABLISH
  * that two machines and two people were involved: both parties ran here,
  * that a fingerprint was compared over a SECOND channel (SPEC-0406 §3.2),
    which is what makes "the recipient need not trust the transport" TRUE
    rather than merely asserted,
  * that a human understood any of the output,
  * the install half (T05, T09, T12, T14, T15). That needs the BundleMeta
    envelope, which carries author, registry AND governance signatures; a
    script that minted it would hold every key, and a run where one actor
    holds every key demonstrates nothing about two actors.

  For the install half:  go test ./cmd/skillctl/ -run TestAcceptance_TwoParty -v
  For the acceptance:    SPEC-0406 §4, with a person on each end.

  A rehearsal reported as a passed acceptance is the failure this note exists
  to prevent.
CAVEAT

[ "$KEEP" -eq 1 ] && echo "" && echo "workspace kept: $WORK"
[ "$FAILED" -ne 0 ] && exit 1
exit 0
