#!/usr/bin/env bash
# katas-smoke.sh: run what the Katas tutorial promises, and assert it, so the
# tutorial cannot go stale without CI noticing.
#
#   docs/v2/nutzer/tutorial-katas-und-test-ride.de.md
#
# Sibling of scripts/tutorial-smoke.sh (which gates the two scenario tutorials);
# wired into scripts/check-docs.sh the same way. Everything here is offline,
# non-interactive and hermetic: kata progress lands in a throwaway HOME, the web
# mirror is never started (--no-web), and the Test Ride writes only under
# demo/kup-training/artifacts/ (gitignored; its own 00-preflight resets it).
#
# What is RUN, and what is only name-checked. Two kinds of assertion, labelled:
#
#   RUN         the tutorial's own commands are executed against the real
#               binaries and the documented exit codes and outputs are compared:
#               the Kata board (--kata-list), one non-interactive rep of each of
#               the five Katas (closed stdin ends the coach loop after one rep),
#               the selftest, and both Test Ride entry commands (run-all.sh and
#               run-and-prove.sh, with exactly the flags the tutorial quotes).
#
#   NAME-CHECK  a file, make target or flag the tutorial names is looked up by
#               that name (ls / grep). This proves the name still resolves, not
#               that the thing behind it works. Used only where running it needs
#               a server (the online half, steps 10-12), a human (--walk, kiosk)
#               or the private maintenance plane (make-pdf.sh).
#
# The interactive coach loop (--mode kata with a human), kiosk mode and the
# browser board are NOT exercised beyond their flag names: no claim about them
# is made here.
#
# Exit: 0 every assertion held; 1 at least one drifted (the failure names it).

set -uo pipefail

# ---------------------------------------------------------------- options ----
KEEP=0
SKILLCTL=""
DEMO=""
WS=""

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/katas-smoke.sh [--skillctl <path>] [--skillctl-demo <path>] [--keep] [--workspace <dir>]

  --skillctl <path>       real skillctl binary. Default: ./build/skillctl.
  --skillctl-demo <path>  skillctl-demo binary. Default: ./build/skillctl-demo.
  --keep                  do not delete the workspace at the end; print its path.
  --workspace <dir>       where to build the sandbox. Default: a mktemp dir.
  -h, --help              this text.

There is deliberately no $PATH fallback: a binary from $PATH was built from
some other tree, and asserting this tree's tutorial against it measures the
wrong subject (see the note in tutorial-smoke.sh). Build with
'make build-skillctl-demo' (it builds skillctl too), or pass both paths.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1; shift ;;
    --skillctl) SKILLCTL="${2:-}"; shift 2 ;;
    --skillctl-demo) DEMO="${2:-}"; shift 2 ;;
    --workspace) WS="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "katas-smoke: unknown flag $1" >&2; usage; exit 2 ;;
  esac
done

# ------------------------------------------------------------------ setup ----
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUTORIAL="docs/v2/nutzer/tutorial-katas-und-test-ride.de.md"

abspath() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *)
      local d
      d="$(cd "$(dirname "$1")" 2>/dev/null && pwd)" || return 1
      printf '%s/%s' "$d" "$(basename "$1")"
      ;;
  esac
}

[ -n "$SKILLCTL" ] || SKILLCTL="$REPO_ROOT/build/skillctl"
[ -n "$DEMO" ]     || DEMO="$REPO_ROOT/build/skillctl-demo"
SKILLCTL="$(abspath "$SKILLCTL")" || { echo "katas-smoke: --skillctl path does not resolve" >&2; exit 1; }
DEMO="$(abspath "$DEMO")"         || { echo "katas-smoke: --skillctl-demo path does not resolve" >&2; exit 1; }

for bin in "$SKILLCTL" "$DEMO"; do
  if [ ! -x "$bin" ]; then
    echo "katas-smoke: '$bin' is not an executable file." >&2
    echo "             Build both with 'make build-skillctl-demo', or pass" >&2
    echo "             --skillctl / --skillctl-demo." >&2
    exit 1
  fi
done

if [ -z "$WS" ]; then
  WS="$(mktemp -d "${TMPDIR:-/tmp}/katas-smoke.XXXXXX")"
else
  mkdir -p "$WS"
fi
SMOKE_HOME="$WS/home"
mkdir -p "$SMOKE_HOME"
LOG="$WS/full.log"

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    echo ""
    echo "workspace kept: $WS"
  else
    rm -rf "$WS"
  fi
}
trap cleanup EXIT

# ------------------------------------------------------------------ output ---
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G='\033[0;32m'; R='\033[0;31m'; B='\033[1m'; D='\033[2m'; N='\033[0m'
else
  G=''; R=''; B=''; D=''; N=''
fi

STEP=0
FAILURES=0
LAST_OUT=""
LAST_RC=0

step() { STEP=$((STEP + 1)); echo ""; printf "${B}%s. %s${N}\n" "$STEP" "$1"; }
ok()   { printf "   ${G}ok${N}    %s\n" "$1"; }
bad()  { printf "   ${R}DRIFT${N} %s\n" "$1"; FAILURES=$((FAILURES + 1)); }
note() { printf "   ${D}%s${N}\n" "$1"; }

# run <label> <expected-exit> <cmd...>: run it, compare the exit code, keep
# going. Not fail-fast: one drift should not hide the next. Commands that need
# the throwaway HOME say so themselves (env HOME=...), the Test Ride runs with
# the ambient one: its go build would otherwise start from a cold cache.
run() {
  local label="$1" want="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  printf '%s\n' "=== $label (want exit $want, got $rc)" "$out" >> "$LOG"
  if [ "$rc" -eq "$want" ]; then
    ok "$label (exit $rc)"
  else
    bad "$label: expected exit $want, got $rc"
    printf '%s\n' "$out" | sed 's/^/         /' | tail -12
  fi
  LAST_OUT="$out"
  LAST_RC="$rc"
  return 0
}

# expect_in <label> <needle>: assert the last output carried a documented string.
# The tutorial quotes these, so a changed line is drift even at exit 0.
expect_in() {
  if printf '%s' "$LAST_OUT" | grep -q -- "$2"; then
    ok "$1"
  else
    bad "$1: expected output to contain '$2'"
    printf '%s\n' "$LAST_OUT" | sed 's/^/         /' | tail -8
  fi
}

# name_check_file <label> <path>: NAME-CHECK, the tutorial names this file.
name_check_file() {
  if [ -e "$2" ]; then ok "$1 (name-check)"; else bad "$1: '$2' does not exist"; fi
}

# name_check_grep <label> <pattern> <file>: NAME-CHECK, the name appears in code.
name_check_grep() {
  if grep -q -- "$2" "$3" 2>/dev/null; then
    ok "$1 (name-check)"
  else
    bad "$1: '$2' not found in $3"
  fi
}

echo ""
printf "${B}Katas tutorial smoke${N}\n"
note "tutorial:      $TUTORIAL"
note "skillctl:      $SKILLCTL"
note "skillctl-demo: $DEMO"
note "workspace:     $WS (throwaway HOME: $SMOKE_HOME)"

# ------------------------------------------------------- 0. the subject ------
step "The tutorial file itself"
name_check_file "the Katas tutorial exists where this gate points" "$REPO_ROOT/$TUTORIAL"

# ------------------------------------------- 1. the flags the tutorial quotes
step "skillctl-demo knows every flag the tutorial quotes (RUN: its own -h)"
# docaudit gates the flag surface of m3c-tools and skillctl, not skillctl-demo,
# so a renamed demo flag would strand the tutorial silently without this.
run "skillctl-demo -h" 0 "$DEMO" -h
for f in -mode -kata -kata-list -selftest -kiosk-delay; do
  expect_in "usage names $f" "$f"
done

# --------------------------------------------------------- 2. the Kata board
step "Das Brett: --kata-list zeigt die fuenf Katas der Tabelle in 2.2 (RUN)"
run "skillctl-demo --kata-list (fresh HOME)" 0 env HOME="$SMOKE_HOME" "$DEMO" --kata-list --no-color
expect_in "K1 Seal & prove"           "K1.*Seal & prove"
expect_in "K2 Detect tamper"          "K2.*Detect tamper"
expect_in "K3 Govern reversibly"      "K3.*Govern reversibly"
expect_in "K4 Trust roots & install"  "K4.*Trust roots & install"
expect_in "K5 Revoke & fail-closed"   "K5.*Revoke & fail-closed"
# 2.4: "das Fenster steuert KATA_STALL_DAYS (Standard 5)". Both halves:
expect_in "default rust window is 5 days (KATA_STALL_DAYS)" "rust window 5d (KATA_STALL_DAYS)"
run "KATA_STALL_DAYS=9 overrides the window" 0 env HOME="$SMOKE_HOME" KATA_STALL_DAYS=9 "$DEMO" --kata-list --no-color
expect_in "the board reports the 9d window" "rust window 9d"

# ------------------------------------- 3. one rep per Kata, real exit codes --
step "Fuenf Katas, je ein Durchgang: die Exit-Codes der Tabelle in 2.2 (RUN)"
# A closed stdin makes the coach run exactly one rep and pause (documented
# behaviour), so each documented target exit is observed against the real
# skillctl: K2's per-skill verdict 10, K3's G-23 refusal 2, K5's offline
# revocation 17, and 0 for K1/K4. A missed target prints "no beat recorded"
# instead of the beat line, which turns the assertion red.
for pair in "K1 0" "K2 10" "K3 2" "K4 0" "K5 17"; do
  K="${pair% *}"; want="${pair#* }"
  run "one rep of $K" 0 env HOME="$SMOKE_HOME" "$DEMO" --kata "$K" --no-web --no-color --skillctl "$SKILLCTL" < /dev/null
  expect_in "$K observed its documented target exit $want" "$K beat: exit $want = target"
done

# ------------------------------------------------- 4. progress and mastery ---
step "Fortschritt: einmal ueben ergibt 1/3, nicht gruen (2.4) (RUN)"
run "skillctl-demo --kata-list (after one rep each)" 0 env HOME="$SMOKE_HOME" "$DEMO" --kata-list --no-color
expect_in "K1 stands at 1/3 and gelb, not gruen" "K1 *\[gelb\] *1/3"
expect_in "K5 (1 rep required) is gruen at 1/1"  "K5 *\[gruen\] *1/1"
if [ -f "$SMOKE_HOME/.skillctl-demo/kata-progress.json" ]; then
  ok "progress lives at ~/.skillctl-demo/kata-progress.json, as 2.4 states"
else
  bad "no progress file at \$HOME/.skillctl-demo/kata-progress.json"
fi

# ----------------------------------------------------------- 5. the selftest
step "Der Selbsttest aus 2.5 (RUN)"
run "skillctl-demo --selftest" 0 env HOME="$SMOKE_HOME" "$DEMO" --selftest --no-color --skillctl "$SKILLCTL" < /dev/null
expect_in "the selftest reports its exit-code assertions" "exit-code assertions passed (real skillctl)"

# ------------------------------------------------------ 6. the Test Ride -----
step "Der Test Ride, beide Einstiegskommandos aus 1.1 und 1.4 (RUN)"
# Exactly the two commands the tutorial quotes. Both write only under
# demo/kup-training/artifacts/ (gitignored); 00-preflight resets that itself.
# run() executes the function in a subshell, so the cd stays local.
RIDE_JSON="$WS/ride-report.json"
ride_all()   { cd "$REPO_ROOT/demo/kup-training" && ./run-all.sh --offline-only --no-pdf --no-release; }
ride_prove() { cd "$REPO_ROOT/demo/kup-training" && ./run-and-prove.sh --skip-online --chain-only --json "$RIDE_JSON"; }
run "run-all.sh --offline-only --no-pdf --no-release" 0 ride_all
run "run-and-prove.sh --skip-online --chain-only --json" 0 ride_prove
if [ -f "$RIDE_JSON" ]; then
  ok "ride-report.json written (1.4: der Nachweis)"
  LAST_OUT="$(cat "$RIDE_JSON")"
  expect_in "overall verdict green" '"overall_verdict": "green"'
  # The exits the table in 1.2 pins: steps 06 and 07 refuse with exit 11.
  expect_in "step 06 refused the tampered bundle with exit 11" '"id": "06".*exit 11 (expected 11)'
  expect_in "step 07 refused the wrong key against the pin, exit 11" '"id": "07".*exit 11 (expected 11)'
  expect_in "step 09 repaired the edited install from the bundle" '"id": "09".*drift recoverable'
else
  bad "run-and-prove.sh did not write $RIDE_JSON"
fi

# -------------------------------- 7. what a server or a human would need -----
step "Nur namensgeprueft: Online-Haelfte, Trainerteil, Verweise (NAME-CHECK)"
for s in 10-scan-and-sync.sh 11-use-skill.sh 12-decay.sh make-pdf.sh; do
  name_check_file "demo/kup-training/$s (1.5, Teil 3)" "$REPO_ROOT/demo/kup-training/$s"
done
name_check_grep "10-scan-and-sync.sh knows --operator (1.5)" '--operator)' "$REPO_ROOT/demo/kup-training/10-scan-and-sync.sh"
name_check_grep "tutorial-smoke.sh knows --walk (1b)" '--walk)' "$REPO_ROOT/scripts/tutorial-smoke.sh"
name_check_grep "Makefile has build-skillctl (1b)" '^build-skillctl:' "$REPO_ROOT/Makefile"
name_check_grep "Makefile has build-skillctl-demo (2.1)" '^build-skillctl-demo:' "$REPO_ROOT/Makefile"
for s in skillctl-test.sh skillctl-test.ps1 skillctl-enterprise-test.sh skillctl-enterprise-test.ps1; do
  name_check_file "scripts/$s (Landkarte, Stufen 1+2)" "$REPO_ROOT/scripts/$s"
done
for d in docs/old/quickstart-skillctl.md docs/old/quickstart-skillctl-demo.md \
         docs/v2/referenz/manual-skillctl.md \
         docs/v2/nutzer/tutorial-szenario-01-eigene-skills-mehrere-maschinen.de.md \
         docs/v2/nutzer/tutorial-szenario-02-erster-signierter-skill.de.md; do
  name_check_file "link target $d" "$REPO_ROOT/$d"
done

# ----------------------------------------------------------------- Bericht ---
echo ""
echo "─────────────────────────────"
if [ "$FAILURES" -eq 0 ]; then
  printf "${G}PASS${N}: %s Abschnitte, jede gepruefte Zusage des Katas-Tutorials gehalten.\n" "$STEP"
  exit 0
else
  printf "${R}FAIL${N}: %s Abweichung(en). Das Katas-Tutorial verspricht etwas, das der Baum nicht mehr tut.\n" "$FAILURES"
  echo "Volles Protokoll: $LOG (mit --keep bleibt es liegen)"
  exit 1
fi
