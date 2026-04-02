//go:build !darwin

package main

import (
	"fmt"
	"os"
)

// cmdMenubar prints an error and exits on non-macOS platforms.
func cmdMenubar(args []string) {
	fmt.Fprintln(os.Stderr, "Error: menu bar mode requires macOS")
	os.Exit(1)
}
