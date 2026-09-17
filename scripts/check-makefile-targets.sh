#!/usr/bin/env bash
#
# Build-coverage gate: every directory under cmd/ must be reachable from
# `make build-all`.
#
# Why a gate and not a convention. cmd/secretctl entered the tree with no Make
# target and nothing said so, because a missing line has no reviewer: the
# Makefile is not wrong in any way a reader notices, it is simply short. The
# same had happened twice before without anyone writing it down, which is the
# part that made a gate worth the fifty lines.
#
# What it measures, and why that is not the Makefile's text. It reads the
# EXPANSION of `make -n build-all`. A target can exist and still build nothing,
# because it hangs off no dependency chain: on 2026-09-17 both build-skillctl-sim
# and the since-removed thinking-build were in that state, and a grep for "cmd/skillctl-sim"
# over the Makefile would have reported both as fine. The expansion answers
# "would this command be built", which is the question; the text answers "is this
# string present", which is a neighbouring one.
#
# Usage:
#   ./scripts/check-makefile-targets.sh             # the gate
#   ./scripts/check-makefile-targets.sh --selftest  # prove it can fail
#
# Exit: 0 every command is covered, 1 something is not (or make itself failed).

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

# A search that finds nothing proves nothing until it has found something
# (.claude/rules/claims.md, rule 4). --selftest plants an uncovered command and
# requires the gate to fail on it.
if [[ "${1:-}" == "--selftest" ]]; then
    probe="cmd/zz-makefile-gate-probe"
    if [[ -e "$probe" ]]; then
        echo "SELFTEST: $probe already exists; refusing to touch it." >&2
        exit 1
    fi
    mkdir -p "$probe"
    trap 'rm -rf "${repo_root:?}/$probe"' EXIT
    if "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
        echo "SELFTEST FAIL: the gate passed while $probe was uncovered."
        echo "  It is not measuring what it claims to measure."
        exit 1
    fi
    echo "SELFTEST PASS: a planted uncovered command ($probe) makes the gate exit 1."
    exit 0
fi

if ! plan=$(make -n build-all 2>&1); then
    echo "check-makefile-targets: FAIL, 'make -n build-all' did not succeed." >&2
    echo "$plan" | tail -5 >&2
    exit 1
fi

missing=()
covered=0
total=0

for dir in cmd/*/; do
    [[ -d "$dir" ]] || continue
    name=$(basename "$dir")
    total=$((total + 1))
    # The trailing (space|end) matters: ./cmd/skillctl is a prefix of
    # ./cmd/skillctl-sim, and without it the shorter name would absorb the
    # longer one's coverage.
    if grep -qE "\./cmd/${name}([[:space:]]|\$)" <<<"$plan"; then
        covered=$((covered + 1))
    else
        missing+=("$name")
    fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "check-makefile-targets: FAIL"
    echo "  $covered of $total directories under cmd/ are reachable from 'make build-all'."
    echo "  These are not:"
    for name in "${missing[@]}"; do
        echo "      cmd/$name"
    done
    echo
    echo "  Add a target for each and hang it off build-all, e.g."
    echo "      .PHONY: build-<name>"
    echo "      build-<name>:"
    echo "      	go build -o \$(BUILD_DIR)/<name> ./cmd/<name>"
    echo "  then add build-<name> to the build-all prerequisites."
    echo "  Also give it a row in docs/program-index.md; check-index.sh wants one."
    exit 1
fi

echo "check-makefile-targets: PASS, all $total directories under cmd/ are reachable from 'make build-all'."
