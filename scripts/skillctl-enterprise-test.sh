#!/usr/bin/env bash
#
# skillctl-enterprise-test.sh: the local, offline-capable twin of our CI, for
# macOS and Linux. Stage 2 of the trust check. Stage 1
# (scripts/skillctl-test.sh) answers "does it build and do the tests pass here";
# this answers the harder question:
#
#   "Would this tree pass the gates we actually merge and release on?"
#
# It runs every gate CI runs that can honestly run on a laptop, one after the
# other, never fail-fast, and prints a PASS / FAIL / SKIP trust report at the
# end. Exit 0 iff no gate FAILED (with --strict, iff none was skipped either).
#
#   stage1        build + tests + CLI smoke (scripts/skillctl-test.sh)
#   vet           go vet
#   lint          golangci-lint (pinned v2.13.2, as in ci.yml)
#   mod-tidy      go mod tidy must be a no-op (go.mod/go.sum restored after)
#   docaudit      every real CLI flag documented, every documented flag real
#   prose         no U+2014 em dash in the tracked tree
#   pins          every pinned install one-liner resolves, digests match
#   boundary      the public/private plane boundary gate
#   coverage      the .testcoverage.yml ratchet over the skillctl trust surface
#   govulncheck   CVEs reachable from our code (pinned v1.7.0)
#   gosec         SAST, judged against docs/security/gosec-inci-baseline.txt
#   gitleaks      secret scan over the full history (config-aware)
#   trust-surface the windows-gate.yml parity run, whole-package, no allow-list
#   lifecycle     offline author/sign/verify/trust/tamper proof, fail-closed
#
# WHAT IT IS NOT. It is not the release: no tagging, no signing, no publish, no
# provenance. Some gates only exist server-side (SLSA provenance, cosign/OIDC,
# Code Scanning ingestion, the Windows matrix); those stay in CI, and a green
# report here is not a substitute for a green PR.
#
# TOOLS. golangci-lint, gosec and go-test-coverage are installed on demand at
# the versions CI pins, into $(go env GOPATH)/bin. Pass --no-install to forbid
# that: a missing tool then reports SKIP instead. govulncheck is run via
# `go run …@v1.7.0` and needs no install. gitleaks is never auto-installed (its
# release tarball is hash-verified in CI, which a convenience script should not
# fake); if it is not on PATH the gate reports SKIP. Anything that installs or
# downloads needs the network; the rest is offline.
#
# SCOPE. The Go gates default to the skillctl trust surface
# (./cmd/skillctl/... ./pkg/skillctl/...), the same scope the coverage gate
# uses. --full widens them to ./..., which on macOS also needs PortAudio
# (brew install portaudio pkg-config) for the cgo audio packages; without it
# those gates report SKIP rather than a misleading red.
#
# Usage:
#   ./scripts/skillctl-enterprise-test.sh [--repo-dir DIR] [--ref BRANCH]
#                                         [--full] [--no-install] [--strict]
#                                         [--skip-stage1]
#   curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/master/scripts/skillctl-enterprise-test.sh | bash
#
# Exit: 0 no gate failed - 1 a gate failed (or, with --strict, was skipped)
#       2 the setup is unusable (no git, no Go, dirty checkout)
#
set -uo pipefail

REPO_URL="${REPO_URL:-https://github.com/kamir/m3c-tools.git}"
REPO_DIR="${REPO_DIR:-$HOME/m3c-tools}"
REF="${REF:-master}"
FULL=0; NO_INSTALL=0; STRICT=0; SKIP_STAGE1=0

# Pinned exactly as .github/workflows/{ci,coverage-gate,gosec}.yml pin them.
GOLANGCI_VERSION="v2.13.2"
GOVULNCHECK_VERSION="v1.7.0"
GOSEC_VERSION="v2.29.0"
COVERAGE_VERSION="v2.19.0"

usage() {
  cat <<'USAGE'
skillctl-enterprise-test.sh: the local twin of our CI (stage 2).

  --repo-dir DIR   where the checkout lives (default: $HOME/m3c-tools)
  --repo-url URL   clone URL (default: the public GitHub repository)
  --ref BRANCH     branch to test (default: master)
  --full           widen the Go gates from the skillctl trust surface to ./...
  --no-install     never install a missing tool; report SKIP instead
  --strict         a SKIPPED gate also fails the run
  --skip-stage1    do not re-run scripts/skillctl-test.sh (build + tests)
  -h, --help       this text

Exit 0 iff no gate failed (with --strict, iff none was skipped either).
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --repo-dir) REPO_DIR="${2:?--repo-dir needs a path}"; shift 2 ;;
    --repo-url) REPO_URL="${2:?--repo-url needs a URL}";  shift 2 ;;
    --ref)      REF="${2:?--ref needs a branch}";         shift 2 ;;
    --full)         FULL=1;        shift ;;
    --no-install)   NO_INSTALL=1;  shift ;;
    --strict)       STRICT=1;      shift ;;
    --skip-stage1)  SKIP_STAGE1=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; DIM=$'\033[2m'; NC=$'\033[0m'
[ -t 1 ] || { RED=""; GREEN=""; YELLOW=""; DIM=""; NC=""; }

NAMES=(); STATES=(); NOTES=()
N_FAIL=0; N_SKIP=0; N_PASS=0

record() {                      # record <name> <PASS|FAIL|SKIP> [note]
  NAMES+=("$1"); STATES+=("$2"); NOTES+=("${3:-}")
  case "$2" in
    PASS) N_PASS=$((N_PASS + 1)) ;;
    FAIL) N_FAIL=$((N_FAIL + 1)) ;;
    SKIP) N_SKIP=$((N_SKIP + 1)) ;;
  esac
  return 0
}

gate_head() { printf '\n%s\n%s>>> %s%s\n' "----------------------------------------" "$DIM" "$1" "$NC"; }

# run_gate <name> <command...>: run it, stream its output, record the verdict.
run_gate() {
  local name="$1"; shift
  gate_head "$name"
  if "$@"; then
    printf '  %s[PASS]%s %s\n' "$GREEN" "$NC" "$name"
    record "$name" PASS
  else
    printf '  %s[FAIL]%s %s (exit %d)\n' "$RED" "$NC" "$name" "$?"
    record "$name" FAIL
  fi
}

skip_gate() {                   # skip_gate <name> <reason>
  gate_head "$1"
  printf '  %s[SKIP]%s %s (%s)\n' "$YELLOW" "$NC" "$1" "$2"
  record "$1" SKIP "$2"
}

die() { printf '\n%sERROR: %s%s\n' "$RED" "$1" "$NC" >&2; exit 2; }

echo ""
echo "========================================"
echo " skillctl: enterprise gate ($(uname -s))"
echo "========================================"
echo ""
echo "  This runs the CI gates locally and takes several minutes."
echo ""

# --- setup ------------------------------------------------------------------
command -v git >/dev/null 2>&1 || die "git is not installed or not on PATH."
command -v go  >/dev/null 2>&1 || die "Go is not installed or not on PATH. See https://go.dev/dl/"

if [ -d "$REPO_DIR/.git" ]; then
  cd "$REPO_DIR" || die "cannot enter $REPO_DIR"
  [ -z "$(git status --porcelain)" ] \
    || die "the checkout at $REPO_DIR has local changes. Commit, stash, or pass --repo-dir."
else
  git clone --branch "$REF" "$REPO_URL" "$REPO_DIR" || die "git clone failed."
  cd "$REPO_DIR" || die "cannot enter $REPO_DIR"
fi

GOBIN_DIR="$(go env GOPATH)/bin"
export PATH="$GOBIN_DIR:$PATH"

# ensure_tool <command> <module@version>: 0 if usable, 1 if not.
ensure_tool() {
  command -v "$1" >/dev/null 2>&1 && return 0
  [ "$NO_INSTALL" -eq 1 ] && return 1
  echo "  installing $2 into $GOBIN_DIR (needs the network) ..."
  go install "$2" >/dev/null 2>&1 || return 1
  command -v "$1" >/dev/null 2>&1
}

if [ "$FULL" -eq 1 ]; then SCOPE=("./...")
else SCOPE=("./cmd/skillctl/..." "./pkg/skillctl/..."); fi

# Do the cgo audio packages typecheck here? On macOS they need PortAudio, and
# without it every ./... gate would go red for a reason that has nothing to do
# with the code under test. Probe once, report SKIP where it matters.
CGO_FULL_OK=1
if ! go build -o /dev/null ./pkg/recorder/ >/dev/null 2>&1; then
  CGO_FULL_OK=0
  echo "  note: the cgo audio packages do not build here"
  [ "$(uname -s)" = "Darwin" ] && echo "        (brew install portaudio pkg-config enables the ./... gates)"
fi
if [ "$FULL" -eq 1 ] && [ "$CGO_FULL_OK" -eq 0 ]; then
  echo "  note: --full requested but ./... does not build; falling back to the trust surface"
  SCOPE=("./cmd/skillctl/..." "./pkg/skillctl/...")
fi

echo "  repo   : $REPO_DIR"
echo "  scope  : ${SCOPE[*]}"

# --- 1. stage 1: build + tests + smoke --------------------------------------
if [ "$SKIP_STAGE1" -eq 1 ]; then
  skip_gate "stage1" "--skip-stage1"
else
  run_gate "stage1" bash ./scripts/skillctl-test.sh --repo-dir "$REPO_DIR" --ref "$REF"
fi

# The gates below want a binary; stage 1 leaves one in build/, but not if it was
# skipped or failed.
[ -x "$REPO_DIR/build/skillctl" ] || go build -o "$REPO_DIR/build/skillctl" ./cmd/skillctl >/dev/null 2>&1

# --- 2. vet -----------------------------------------------------------------
run_gate "vet" go vet "${SCOPE[@]}"

# --- 3. golangci-lint -------------------------------------------------------
if ensure_tool golangci-lint "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$GOLANGCI_VERSION"; then
  run_gate "lint" golangci-lint run --timeout=5m "${SCOPE[@]}"
else
  skip_gate "lint" "golangci-lint $GOLANGCI_VERSION not installed"
fi

# --- 4. go mod tidy is a no-op ----------------------------------------------
# CD-T4 in ci.yml. `go mod tidy` MUTATES go.mod/go.sum, so restore them
# afterwards either way: a QA run must not leave the checkout rewritten.
gate_head "mod-tidy"
if go mod tidy >/dev/null 2>&1 && git diff --exit-code go.mod go.sum >/dev/null 2>&1; then
  printf '  %s[PASS]%s mod-tidy\n' "$GREEN" "$NC"; record "mod-tidy" PASS
else
  printf '  %s[FAIL]%s mod-tidy (go mod tidy changed go.mod/go.sum)\n' "$RED" "$NC"
  git diff --stat go.mod go.sum
  record "mod-tidy" FAIL
fi
git checkout -- go.mod go.sum 2>/dev/null || true

# --- 5. docaudit ------------------------------------------------------------
gate_head "docaudit"
if go test -count=1 ./cmd/docaudit/ >/dev/null 2>&1 && go run ./cmd/docaudit -cli all; then
  printf '  %s[PASS]%s docaudit\n' "$GREEN" "$NC"; record "docaudit" PASS
else
  printf '  %s[FAIL]%s docaudit\n' "$RED" "$NC"; record "docaudit" FAIL
fi

# --- 6-8. the shell gates ---------------------------------------------------
run_gate "prose"    ./scripts/check-no-emdash.sh
run_gate "pins"     ./scripts/check-install-pins.sh
run_gate "boundary" ./tools/boundary-gate.sh

# --- 9. coverage ratchet ----------------------------------------------------
# .testcoverage.yml reads `profile: cover.out` at the repo root. *.out is
# git-ignored, and it is removed again below.
if ensure_tool go-test-coverage "github.com/vladopajic/go-test-coverage/v2@$COVERAGE_VERSION"; then
  gate_head "coverage"
  if go test ./pkg/skillctl/... ./cmd/skillctl/... -covermode=atomic -coverprofile=cover.out >/dev/null \
     && go-test-coverage --config .testcoverage.yml; then
    printf '  %s[PASS]%s coverage\n' "$GREEN" "$NC"; record "coverage" PASS
  else
    printf '  %s[FAIL]%s coverage (a package fell below its ratchet floor)\n' "$RED" "$NC"
    record "coverage" FAIL
  fi
  rm -f cover.out
else
  skip_gate "coverage" "go-test-coverage $COVERAGE_VERSION not installed"
fi

# --- 10. govulncheck --------------------------------------------------------
# Fails only on vulnerabilities REACHABLE from our code. Needs the network for
# the vulnerability database (and for `go run` to fetch the tool).
run_gate "govulncheck" go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" "${SCOPE[@]}"

# --- 11. gosec, judged against the committed baseline -----------------------
# The diff gate is the honest form: this tree has ~500 triaged pre-existing
# findings (docs/security/gosec-baseline.md), so an absolute count says nothing.
# What must never happen is a NEW finding.
if [ "$CGO_FULL_OK" -eq 0 ]; then
  skip_gate "gosec" "gosec type-checks ./..., and the cgo packages do not build here"
elif ! command -v jq >/dev/null 2>&1; then
  skip_gate "gosec" "jq is not installed (the diff gate needs it)"
elif ensure_tool gosec "github.com/securego/gosec/v2/cmd/gosec@$GOSEC_VERSION"; then
  run_gate "gosec" ./scripts/gosec-diff-gate.sh
else
  skip_gate "gosec" "gosec $GOSEC_VERSION not installed"
fi

# --- 12. gitleaks -----------------------------------------------------------
# Deliberately never auto-installed: CI verifies the release tarball against a
# pinned SHA-256 before it runs it, and a convenience script should not pretend
# to do that.
if command -v gitleaks >/dev/null 2>&1; then
  run_gate "gitleaks" gitleaks git . --config .gitleaks.toml --no-banner --redact
else
  skip_gate "gitleaks" "not on PATH; see the pinned install in .github/workflows/ci.yml"
fi

# --- 13. trust surface, the windows-gate.yml parity run ---------------------
# The same package set the Windows gate runs, whole-package, no -run allow-list
# (both are deliberate in CI), and including ./evaluation/... which stage 1 does
# not cover. On Windows this run needs -tags allow_home_override_test, because a
# shipping Windows build ignores $HOME for the trust-root paths and the hermetic
# trust tests inject it; outside Windows $HOME is always honored, so no tag.
run_gate "trust-surface" go test -count=1 -timeout=300s ./pkg/skillctl/... ./cmd/skillctl/... ./evaluation/...

# --- 14. lifecycle smoke (offline, sandboxed) -------------------------------
run_gate "lifecycle" ./scripts/skillctl-quickstart-unix.sh --bin "$REPO_DIR/build/skillctl"

# --- trust report -----------------------------------------------------------
echo ""
echo "========================================"
if [ "$N_FAIL" -gt 0 ]; then
  printf ' %sTRUST REPORT: FAIL%s\n' "$RED" "$NC"
elif [ "$N_SKIP" -gt 0 ] && [ "$STRICT" -eq 1 ]; then
  printf ' %sTRUST REPORT: FAIL (strict: a gate was skipped)%s\n' "$RED" "$NC"
elif [ "$N_SKIP" -gt 0 ]; then
  printf ' %sTRUST REPORT: PASS with %d skipped%s\n' "$YELLOW" "$N_SKIP" "$NC"
else
  printf ' %sTRUST REPORT: PASS%s\n' "$GREEN" "$NC"
fi
echo "========================================"
echo ""
echo "Platform   : $(uname -s) $(uname -m)"
echo "Repository : $REPO_DIR"
echo "Commit     : $(git rev-parse HEAD)"
echo "Scope      : ${SCOPE[*]}"
echo "Go         : $(go version | sed -E 's/^go version //')"
echo ""
for i in "${!NAMES[@]}"; do
  case "${STATES[$i]}" in
    PASS) c="$GREEN" ;; FAIL) c="$RED" ;; *) c="$YELLOW" ;;
  esac
  printf '  %s%-14s %-4s%s %s\n' "$c" "${NAMES[$i]}" "${STATES[$i]}" "$NC" "${NOTES[$i]}"
done
echo ""
printf '  %d passed, %d failed, %d skipped\n' "$N_PASS" "$N_FAIL" "$N_SKIP"
echo ""
if [ "$N_SKIP" -gt 0 ]; then
  echo "A skipped gate is not a passed gate. Each one is listed above with its"
  echo "reason, so a missing local tool is never read as evidence."
  echo ""
fi
echo "Server-side only, never covered here: SLSA provenance, cosign/OIDC signing,"
echo "Code Scanning ingestion, and the Windows/cross-compile matrix. Read the PR."
echo ""

[ "$N_FAIL" -eq 0 ] || exit 1
[ "$STRICT" -eq 1 ] && [ "$N_SKIP" -gt 0 ] && exit 1
exit 0
