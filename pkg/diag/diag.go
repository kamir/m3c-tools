// Package diag provides diagnostic check types and rendering for the
// m3c-tools doctor command (SPEC-0143).
package diag

import "fmt"

// Status represents the outcome of a diagnostic check.
type Status int

const (
	OK      Status = iota // check passed
	Fail                  // check failed — action needed
	Warn                  // works but suboptimal
	Skipped               // not configured / not needed
)

// Symbol returns the terminal indicator for a status.
func (s Status) Symbol() string {
	switch s {
	case OK:
		return "\u2713" // ✓
	case Fail:
		return "\u2717" // ✗
	case Warn:
		return "!"
	case Skipped:
		return "\u00b7" // ·
	default:
		return "?"
	}
}

// Check is the result of a single diagnostic check.
type Check struct {
	Name   string
	Status Status
	Detail string
}

// String returns a formatted single line for terminal output.
func (c Check) String() string {
	return fmt.Sprintf("  %-20s %s %s", c.Name+":", c.Status.Symbol(), c.Detail)
}

// Section groups related checks under a heading.
type Section struct {
	Title  string
	Checks []Check
}

// Print writes the section to stdout.
func (s Section) Print() {
	fmt.Println(s.Title)
	for _, c := range s.Checks {
		fmt.Println(c.String())
	}
	fmt.Println()
}

// HasFailures returns true if any check in the section failed.
func (s Section) HasFailures() bool {
	for _, c := range s.Checks {
		if c.Status == Fail {
			return true
		}
	}
	return false
}

// Report holds all diagnostic sections and computes the overall result.
type Report struct {
	Sections []Section
}

// Print writes the full report to stdout.
func (r Report) Print() {
	fmt.Println("m3c-tools doctor — connectivity & config diagnostics")
	fmt.Println()
	for _, s := range r.Sections {
		s.Print()
	}
	if r.HasFailures() {
		fmt.Println("Result: CHECKS FAILED \u2717")
	} else {
		fmt.Println("Result: ALL CHECKS PASSED \u2713")
	}
}

// HasFailures returns true if any section has a failed check.
func (r Report) HasFailures() bool {
	for _, s := range r.Sections {
		if s.HasFailures() {
			return true
		}
	}
	return false
}
