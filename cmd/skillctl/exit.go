package main

// Centralised exit-code translation for SPEC-0188 §11 numbered codes.
//
// runWithExit is the single audit point that sits between a runner function
// (runInstall, runVerify, ...) and os.Exit: the runner returns an integer exit
// code and runWithExit passes it to os.Exit verbatim — so usage errors (2),
// generic errors (1), and ok (0) flow through unchanged.
//
// Why a single helper: SPEC-0188 §11 mandates that `skillctl install` and
// `skillctl verify` MUST surface the numbered code. Threading that through
// every subcommand by hand is brittle; one helper, one audit point, no
// chance of an exit code getting silently re-mapped to 1 mid-flight.

import "os"

// runWithExit invokes fn (an existing runner that returns a numeric exit
// code) and calls os.Exit with that code. This is the wiring shim main.go
// uses for `install` and `verify` so the SPEC-0188 §11 numbered codes
// surface verbatim through the process boundary.
//
// The runner is responsible for printing diagnostics to stderr; this helper
// does NOT print anything additional — it just translates int → os.Exit.
func runWithExit(fn func() int) {
	os.Exit(fn())
}
