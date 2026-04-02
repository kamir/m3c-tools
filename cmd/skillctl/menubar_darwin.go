//go:build darwin && cgo

package main

import (
	"fmt"
	"os"
	"time"

	skillmenubar "github.com/kamir/m3c-tools/pkg/skillctl/menubar"
)

// cmdMenubar launches the macOS menu bar skill monitor.
func cmdMenubar(args []string) {
	var paths []string
	interval := 30 * time.Minute
	includeHome := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 < len(args) {
				i++
				paths = append(paths, args[i])
			}
		case "--interval":
			if i+1 < len(args) {
				i++
				d, err := time.ParseDuration(args[i])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Invalid interval %q: %v\n", args[i], err)
					os.Exit(1)
				}
				interval = d
			}
		case "--include-home":
			includeHome = true
		default:
			if args[i] != "" && args[i][0] != '-' {
				paths = append(paths, args[i])
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	// Default to current directory if no paths given.
	if len(paths) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
			os.Exit(1)
		}
		paths = []string{cwd}
	}

	sb := skillmenubar.New(paths, interval, includeHome)
	sb.Run() // blocks forever
}
