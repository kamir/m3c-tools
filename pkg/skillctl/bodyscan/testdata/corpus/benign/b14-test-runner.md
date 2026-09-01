---
name: go-test-runner
version: 1.0.0
description: Run the Go test suite for a package and summarise pass/fail counts.
allowed-tools:
  - Bash
  - Read
governance_level: green
---

# go-test-runner

Run tests and report the result.

The skill runs `go test ./...` with `-count=1` so results are never cached,
then summarises how many packages passed and failed. It always *runs* the
tests — it will never skip or disable them. A failing suite is reported as a
failure, not hidden.
