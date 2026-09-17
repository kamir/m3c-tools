#!/usr/bin/env bash
# ci-classify.sh: does this change touch code at all, or only prose.
#
# WHY THIS EXISTS
#
# Measured on 2026-09-17 over the last 60 merged pull requests of this
# repository:
#
#     go, no workflow     28   47%
#     other               10   17%
#     workflow only        9   15%
#     go + workflow        7   12%
#     docs/text only       6   10%
#
# One pull request in ten changes nothing but prose, and pays for the macOS
# jobs anyway: Lint & Vet, Unit Tests, skillctl Security Tests, Build macOS and
# Ratchet coverage together measured 894 seconds, billed at the macOS rate.
# A file ending in .md cannot change what a Go test does.
#
# WHAT IT REFUSES TO DO, and this is the whole design
#
# It never causes a required check to be SKIPPED. A job skipped by an `if:`
# reports the conclusion "skipped", and GitHub's branch protection counts that
# as satisfied: gating a required job on a path filter therefore switches the
# gate off for those paths without anything turning red. So the JOB always runs
# and always reports; only its expensive STEPS are conditional. A docs-only
# pull request still gets a real green tick from a job that really ran.
#
# It is FAIL-CLOSED in every direction. If the base cannot be determined, if
# the file list comes back empty, if git errors, if the event is not a pull
# request: the answer is code=true and everything runs. The only path to
# code=false is a complete file list in which every single entry is prose.
#
# It does not touch the security gates. gosec, the gosec diff gate and
# govulncheck run unconditionally, because "a documentation change cannot
# introduce a vulnerability" is an argument, and a security gate should not
# rest on an argument when it can rest on having run.
#
# USAGE
#
#     ./scripts/ci-classify.sh                 prints "code=true" or "code=false"
#     ./scripts/ci-classify.sh --github-output appends it to $GITHUB_OUTPUT too
#     ./scripts/ci-classify.sh --selftest      plants known inputs, checks answers
#
# In a workflow it needs `fetch-depth: 2` on the checkout, because on a pull
# request GitHub checks out the MERGE commit, whose first parent is the base.

set -euo pipefail

# A path is prose only if it matches one of these WHOLE. Everything else, named
# or not, is code. New directories are therefore code until somebody decides
# otherwise in a reviewed diff, which is the correct default for a list like
# this one.
is_prose() {
  case "$1" in
    *.md)            return 0 ;;
    docs/*.html)     return 0 ;;
    docs/*.png|docs/*.jpg|docs/*.svg) return 0 ;;
    LICENSE|AUTHORS) return 0 ;;
    *)               return 1 ;;
  esac
}

classify() {
  local files="$1"
  [ -n "$files" ] || { echo "true"; return; }
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    is_prose "$f" || { echo "true"; return; }
  done <<< "$files"
  echo "false"
}

selftest() {
  local fails=0
  check() { # name expected files
    local got; got="$(classify "$3")"
    if [ "$got" = "$2" ]; then
      echo "  ok    $1 (code=$got)"
    else
      echo "  FAIL  $1: expected code=$2, got code=$got"; fails=$((fails + 1))
    fi
  }

  echo "ci-classify selftest"
  check "prose only"            false "README.md
docs/manual-skillctl.md"
  check "empty file list"       true  ""
  # Rule 4 of .claude/rules/claims.md: a search that finds nothing proves
  # nothing until it has found something. Each of these plants ONE code file in
  # an otherwise prose-only list, and the answer has to flip.
  check "planted .go"           true  "README.md
pkg/skillctl/verify.go"
  check "planted go.sum"        true  "README.md
go.sum"
  check "planted workflow"      true  "README.md
.github/workflows/ci.yml"
  check "planted script"        true  "docs/index.md
scripts/check-no-emdash.sh"
  check "planted Makefile"      true  "README.md
Makefile"
  check "planted docs .txt"     true  "README.md
docs/security/required-checks.txt"
  check "planted dotfile"       true  "README.md
.golangci.yml"
  echo ""
  if [ "$fails" -ne 0 ]; then
    echo "$fails selftest failure(s)"; return 1
  fi
  echo "all selftests pass"
}

changed_files() {
  # Fail-closed: any step that cannot answer prints nothing, and an empty list
  # classifies as code.
  [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] || return 0
  git rev-parse --verify --quiet HEAD^1 >/dev/null 2>&1 || return 0
  git rev-parse --verify --quiet HEAD^2 >/dev/null 2>&1 || return 0
  git diff --name-only HEAD^1 HEAD 2>/dev/null || true
}

main() {
  case "${1:-}" in
    --selftest) selftest; return $? ;;
  esac

  local files code
  files="$(changed_files)"
  code="$(classify "$files")"

  echo "event      ${GITHUB_EVENT_NAME:-none}"
  echo "files      $(printf '%s' "$files" | grep -c . || true)"
  if [ -n "$files" ]; then
    printf '%s\n' "$files" | sed 's/^/           /'
  fi
  echo "code=$code"

  if [ "${1:-}" = "--github-output" ] && [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "code=$code" >> "$GITHUB_OUTPUT"
  fi
}

main "$@"
