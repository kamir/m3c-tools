//go:build !darwin || !cgo

// Package menubar provides a macOS menu bar application for monitoring
// the Claude Code skill inventory.
//
// On non-macOS platforms, this package provides stub implementations
// that print an error and exit.
package menubar

import (
	"fmt"
	"os"
	"time"
)

// SkillBar is a stub for non-macOS platforms.
type SkillBar struct{}

// New returns nil on non-macOS platforms.
func New(paths []string, interval time.Duration, includeHome bool) *SkillBar {
	return nil
}

// Run prints an error and exits on non-macOS platforms.
func (sb *SkillBar) Run() {
	fmt.Fprintln(os.Stderr, "Error: menu bar mode requires macOS")
	os.Exit(1)
}
