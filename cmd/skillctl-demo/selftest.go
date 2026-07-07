package main

// selftest.go — `skillctl-demo --selftest`.
//
// Runs the three LIVE scenarios non-interactively against the real skillctl and
// asserts the observed exit codes match the scenario expectations. Prints a
// PASS/FAIL table and exits non-zero if any assertion fails — the CI-friendly
// proof that the honest core actually blocks.

import (
	"fmt"
	"os"
)

func runSelftest(sb *Sandbox, skctl string) int {
	renderer := &CLIRenderer{W: os.Stdout, Color: false}
	bus := NewBus(renderer)

	type check struct {
		label    string
		code     int
		expected int
		ok       bool
	}
	var checks []check

	bus.AddTap(func(e Event) {
		if e.Kind == "exit" || e.Kind == "verdict" {
			checks = append(checks, check{
				label:    e.Verdict,
				code:     e.Code,
				expected: e.Expected,
				ok:       e.OK,
			})
		}
	})

	d := &Driver{sb: sb, run: &Runner{Skillctl: skctl, Home: sb.Home}, bus: bus}
	d.wait = func() {} // no pauses in selftest

	for _, s := range Scenarios() {
		if s.Run == nil {
			continue // roadmap panels run nothing
		}
		d.scenario(&s)
		s.Run(d)
	}

	fmt.Println("\n──────── selftest summary ────────")
	failed := 0
	for i, c := range checks {
		status := "PASS"
		if !c.ok {
			status = "FAIL"
			failed++
		}
		fmt.Printf("  %d. %-8s exit=%d expected=%d  [%s]\n", i+1, c.label, c.code, c.expected, status)
	}
	if failed == 0 {
		fmt.Printf("\n  ✔ all %d exit-code assertions passed (real skillctl).\n", len(checks))
		return 0
	}
	fmt.Printf("\n  ✗ %d/%d assertions FAILED.\n", failed, len(checks))
	return 1
}
