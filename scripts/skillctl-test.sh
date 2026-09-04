#!/usr/bin/env bash
#
# skillctl-test.sh: quick local skillctl verification for macOS and Linux.
#
# The twin of scripts/skillctl-test.ps1, same six steps, same summary, so a
# report from a Mac, a Linux box and a Windows box can be compared line by line.
# It answers one practical question:
#
#   "Can this machine reproducibly build the current master, and does the
#    skillctl test suite pass here?"
#
#   1. prerequisites   git + go present, Go new enough for this module
#   2. repository      clone, or fetch and fast-forward an existing checkout
#   3. dependencies    go mod download + go mod verify
#   4. build           go build ./cmd/skillctl, then skillctl version
#   5. tests           go test [-race] over the skillctl packages
#   6. smoke           skillctl --help exits 0
#
# This is deliberately NOT the full trust/release suite (no lint, no
# govulncheck, no gosec, no coverage gate, no e2e). Those come in stage 2.
#
# Scope of step 5: by default the same package set the release gate runs
# (./cmd/skillctl/... ./pkg/skillctl/...). A bare `go test ./...` in this repo
# also builds packages that need the network, an ER1 server, whisper, or a
# microphone (on macOS, PortAudio via cgo), and their failures say nothing
# about skillctl. Use --full to run everything anyway.
#
# Race detector: needs cgo and a C toolchain (clang from the Xcode command line
# tools on macOS, gcc on Linux). If none is found the tests still run and the
# race step reports SKIP rather than silently passing.
#
# Nothing here touches your real trust roots: no skillctl subcommand that
# writes state is invoked.
#
# Usage:
#   ./scripts/skillctl-test.sh [--repo-dir DIR] [--ref BRANCH] [--full] [--no-race]
#   curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-test.sh | bash
#
# Exit: 0 every required step passed - 1 a step failed or the setup is unusable.
#
set -uo pipefail

REPO_URL="${REPO_URL:-https://github.com/kamir/m3c-tools.git}"
REPO_DIR="${REPO_DIR:-$HOME/m3c-tools}"
REF="${REF:-master}"          # master is the active branch; main is abandoned
FULL=0
NO_RACE=0
MIN_GO="1.25.0"               # kept in step with the `go` directive in go.mod

usage() {
  cat <<'USAGE'
skillctl-test.sh: quick local skillctl verification for macOS and Linux.

  --repo-dir DIR   where the checkout lives (default: $HOME/m3c-tools)
  --repo-url URL   clone URL (default: the public GitHub repository)
  --ref BRANCH     branch to test (default: master)
  --full           run `go test ./...` instead of only the skillctl packages
  --no-race        never use the race detector
  -h, --help       this text

Six steps: prerequisites, repository, dependencies, build, tests, smoke.
Exit 0 only if every required step passed.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --repo-dir) REPO_DIR="${2:?--repo-dir needs a path}"; shift 2 ;;
    --repo-url) REPO_URL="${2:?--repo-url needs a URL}";  shift 2 ;;
    --ref)      REF="${2:?--ref needs a branch}";         shift 2 ;;
    --full)     FULL=1;    shift ;;
    --no-race)  NO_RACE=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
[ -t 1 ] || { RED=""; GREEN=""; YELLOW=""; NC=""; }

NAMES=(); STATES=(); FAILED=0
COMMIT=""; BINARY=""; VERSION=""

set_result() {                       # set_result <name> <PASS|FAIL|SKIP>
  NAMES+=("$1"); STATES+=("$2")
  [ "$2" = "FAIL" ] && FAILED=1
  return 0
}

summary() {
  echo ""
  echo "========================================"
  if [ "$FAILED" -ne 0 ]; then echo " FAIL"; else echo " PASS"; fi
  echo "========================================"
  echo ""
  echo "Platform   : $(uname -s) $(uname -m)"
  echo "Repository : $REPO_DIR"
  echo "Ref        : $REF"
  [ -n "$COMMIT" ]  && echo "Commit     : $COMMIT"
  [ -n "$BINARY" ]  && echo "Binary     : $BINARY"
  [ -n "$VERSION" ] && echo "Version    : $VERSION"
  echo ""
  local i c
  for i in "${!NAMES[@]}"; do
    case "${STATES[$i]}" in
      PASS) c="$GREEN" ;; FAIL) c="$RED" ;; *) c="$YELLOW" ;;
    esac
    printf '  %s%-12s %s%s\n' "$c" "${NAMES[$i]}" "${STATES[$i]}" "$NC"
  done
  echo ""
}

# Stop with the summary printed, never with a bare shell error: a half-finished
# run that says which step died is more useful than a stray exit code.
die() {
  echo ""
  printf '%sERROR: %s%s\n' "$RED" "$1" "$NC" >&2
  FAILED=1
  summary
  exit 1
}

echo ""
echo "========================================"
echo " skillctl: $(uname -s) test run"
echo "========================================"
echo ""

# 1. Prerequisites ----------------------------------------------------------
echo "[1/6] Checking prerequisites..."

command -v git >/dev/null 2>&1 || die "git is not installed or not on PATH."
command -v go  >/dev/null 2>&1 || die "Go is not installed or not on PATH. See https://go.dev/dl/"

echo "  $(git --version)"
GO_VERSION_RAW="$(go version)"
echo "  $GO_VERSION_RAW"

# "go version go1.25.1 darwin/arm64": take the number, pad "1.26" to "1.26.0"
# so a plain sort -V comparison is well defined.
GO_VER="$(printf '%s' "$GO_VERSION_RAW" | sed -nE 's/.*go([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p')"
case "$GO_VER" in *.*.*) ;; *.*) GO_VER="$GO_VER.0" ;; esac
if [ -n "$GO_VER" ]; then
  lowest="$(printf '%s\n%s\n' "$GO_VER" "$MIN_GO" | sort -V | head -1)"
  [ "$lowest" = "$MIN_GO" ] \
    || die "Go $GO_VER is older than the $MIN_GO this module requires. Upgrade from https://go.dev/dl/"
fi

CC_BIN=""
for c in cc clang gcc; do
  if command -v "$c" >/dev/null 2>&1; then CC_BIN="$(command -v "$c")"; break; fi
done
USE_RACE=0
if [ "$NO_RACE" -eq 1 ]; then
  echo "  race detector: disabled by --no-race"
elif [ -n "$CC_BIN" ]; then
  USE_RACE=1
  echo "  C toolchain: $CC_BIN (race detector available)"
else
  echo "  race detector: unavailable (no C compiler on PATH)"
  [ "$(uname -s)" = "Darwin" ] && echo "                install it with: xcode-select --install"
fi
set_result "Prereqs" "PASS"

# 2. Repository -------------------------------------------------------------
echo ""
echo "[2/6] Getting current m3c-tools ($REF)..."

if [ -d "$REPO_DIR/.git" ]; then
  cd "$REPO_DIR" || die "cannot enter $REPO_DIR"
  [ -z "$(git status --porcelain)" ] \
    || die "the checkout at $REPO_DIR has local changes. Commit, stash, or pass --repo-dir."
  git fetch origin "$REF"           || die "git fetch failed."
  git checkout "$REF"               || die "git checkout $REF failed."
  git merge --ff-only "origin/$REF" || die "git merge --ff-only failed."
else
  git clone --branch "$REF" "$REPO_URL" "$REPO_DIR" || die "git clone failed."
  cd "$REPO_DIR" || die "cannot enter $REPO_DIR"
fi

COMMIT="$(git rev-parse HEAD)"
echo "  Testing commit: $COMMIT"
set_result "Repo" "PASS"

# 3. Dependencies -----------------------------------------------------------
echo ""
echo "[3/6] Verifying dependencies..."
go mod download || die "go mod download failed."
go mod verify   || die "go mod verify failed (a module in the cache does not match its checksum)."
set_result "Deps" "PASS"

# 4. Build ------------------------------------------------------------------
echo ""
echo "[4/6] Building skillctl..."

# build/ is git-ignored, so a test run never dirties the checkout.
BIN_DIR="$REPO_DIR/build"
mkdir -p "$BIN_DIR"
BINARY="$BIN_DIR/skillctl"

go build -o "$BINARY" ./cmd/skillctl || die "go build ./cmd/skillctl failed."
[ -x "$BINARY" ] || die "$BINARY was not created."
echo "  Build OK: $BINARY"

VERSION="$("$BINARY" version)" || die "skillctl version failed."
[ -n "$VERSION" ] || die "skillctl version printed nothing."
echo "  Version: $VERSION"
set_result "Build" "PASS"

# 5. Tests ------------------------------------------------------------------
echo ""
echo "[5/6] Running Go tests..."
echo "      This can take a few minutes."
echo ""

if [ "$FULL" -eq 1 ]; then
  PKGS=("./...")
  echo "  --full: the whole module, including packages that need network or hardware."
else
  PKGS=("./cmd/skillctl/..." "./pkg/skillctl/...")
fi

TEST_ARGS=(test -count=1)
[ "$USE_RACE" -eq 1 ] && TEST_ARGS+=(-race)
TEST_ARGS+=("${PKGS[@]}")

echo "  go ${TEST_ARGS[*]}"
echo ""
# The race detector is a cgo runtime; be explicit rather than relying on
# whatever CGO_ENABLED the toolchain defaulted to on this machine.
[ "$USE_RACE" -eq 1 ] && export CGO_ENABLED=1
if ! go "${TEST_ARGS[@]}"; then
  set_result "Tests" "FAIL"
  if [ "$USE_RACE" -eq 1 ]; then set_result "Race" "FAIL"; else set_result "Race" "SKIP"; fi
  summary
  exit 1
fi
set_result "Tests" "PASS"
if [ "$USE_RACE" -eq 1 ]; then set_result "Race" "PASS"; else set_result "Race" "SKIP"; fi

# 6. Smoke ------------------------------------------------------------------
echo ""
echo "[6/6] Running skillctl smoke test..."
if ! "$BINARY" --help >/dev/null; then
  set_result "CLI smoke" "FAIL"
  summary
  exit 1
fi
set_result "CLI smoke" "PASS"

summary
[ "$FAILED" -eq 0 ] || exit 1
echo "skillctl builds and tests clean on this machine."
echo "Next: the stage 2 enterprise gate (lint, govulncheck, gosec, coverage, e2e)."
echo ""
exit 0
