// POC 1: macOS Menu Bar App with menuet
//
// Validates:
//   - Menu bar icon + title
//   - Dropdown menu with items, separators, submenus
//   - Alert dialog with text input (video ID entry)
//   - Dynamic menu updates (history list)
//   - Notifications
//
// This is a thin wrapper around pkg/menubar. All menu logic lives in the
// library package; this binary just configures and launches it.
//
// Run: go run ./cmd/poc-menubar
package main

import (
	"fmt"

	"github.com/kamir/m3c-tools/pkg/menubar"
)

func main() {
	app := menubar.NewApp()

	// POC uses the default config but overrides the label for the POC bundle ID
	// and the log path to the POC-specific location.
	app.Config.AppLabel = "com.kamir.m3c-tools-poc"
	app.Config.LogPath = "/tmp/m3c-tools-poc.log"

	// Wire up a simple action logger so we can observe events during POC testing.
	app.Handlers.OnAction = func(action menubar.ActionType, data string) {
		fmt.Printf("[poc-menubar] action=%s data=%q\n", action, data)
	}

	app.Run()
}
