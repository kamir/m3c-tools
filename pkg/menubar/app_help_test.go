//go:build darwin

package menubar

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenLogFileReportsFailureBeforeAction(t *testing.T) {
	for _, test := range []struct {
		name        string
		exit        string
		wantActions int
	}{
		{"failure", "1", 0},
		{"success", "0", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("PATH", home)
			if err := os.WriteFile(filepath.Join(home, "open"), []byte("#!/bin/sh\nexit "+test.exit+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&output)
			t.Cleanup(func() { log.SetOutput(previous) })
			actions := 0
			app := &App{Config: MenuConfig{LogPath: filepath.Join(home, "demo.log")}}
			app.Handlers.OnAction = func(action ActionType, data string) {
				actions++
				if action != ActionOpenLog || data != app.Config.LogPath {
					t.Errorf("unexpected action %v, %q", action, data)
				}
			}
			app.buildHelpMenu().Children()[0].Clicked()
			if actions != test.wantActions {
				t.Errorf("action count = %d, want %d", actions, test.wantActions)
			}
			if test.exit != "0" && !strings.Contains(output.String(), "open log file:") {
				t.Errorf("missing failure diagnostic: %q", output.String())
			}
		})
	}
}
