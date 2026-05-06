package main

// Centralised exit-code translation for SPEC-0188 §11 numbered codes.
//
// runWithExit is the single audit point that sits between a runner function
// (runInstall, runVerify, ...) and os.Exit. It collapses two concerns:
//
//   1. The runner returns an integer exit code on its own (the existing
//      pattern from S1 / S7 / S8). When wired through here, the runner's
//      int return is the os.Exit value verbatim — so usage errors (2),
//      generic errors (1), and ok (0) keep flowing through unchanged.
//
//   2. Some callers prefer `func() error` semantics — useful for callers
//      that want to leverage verify.ExitCode mapping directly. The
//      runWithExitErr variant handles that case: any non-nil error whose
//      sentinel matches a §11 code is mapped via verify.ExitCode; all
//      other errors map to exitGeneric (1).
//
// Why a single helper: SPEC-0188 §11 mandates that `skillctl install` and
// `skillctl verify` MUST surface the numbered code. Threading that through
// every subcommand by hand is brittle; one helper, one audit point, no
// chance of an exit code getting silently re-mapped to 1 mid-flight.

import (
	"fmt"
	"io"
	"os"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

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

// runWithExitErr is the error-shaped variant. It invokes fn and:
//
//	nil error                          → exit 0
//	error matching a §11 sentinel      → exit 10..16 (verify.ExitCode)
//	any other non-nil error            → exit 1 (generic), printed to stderr
//
// stderr is parameterised so tests can capture; production passes os.Stderr.
//
// Not currently wired into main.go — the existing runners return int
// directly — but kept here as the canonical shape for future runners that
// want to defer exit-code translation entirely.
func runWithExitErr(fn func() error, stderr io.Writer) {
	err := fn()
	if err == nil {
		os.Exit(exitOK)
	}
	if code := verify.ExitCode(err); code > exitGeneric {
		// Sentinel match (10..16). Print + exit with the SPEC-0188 §11 code.
		fmt.Fprintln(stderr, err)
		os.Exit(code)
	}
	// Unknown error → generic.
	fmt.Fprintln(stderr, err)
	os.Exit(exitGeneric)
}
