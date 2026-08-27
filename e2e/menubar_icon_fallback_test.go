//go:build darwin

package e2e

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/menubar"
)

// TestResolveMenuBarTitle locks in the "never invisible" contract for the menu
// bar label: an empty title is only allowed when an icon was actually applied,
// otherwise a visible fallback (or the M3C_MENUBAR_TITLE override) must appear.
// This guards against the regression where a non-rendering icon + empty title
// produced a completely invisible menu bar item.
func TestResolveMenuBarTitle(t *testing.T) {
	fb := menubar.MenuBarFallbackTitle

	cases := []struct {
		name        string
		configured  string
		iconApplied bool
		envOverride string
		want        string
	}{
		{"icon-only when icon applies", "", true, "", ""},
		{"configured title kept with icon", "M3C", true, "", "M3C"},
		{"fallback when icon fails and no title", "", false, "", fb},
		{"configured title kept without icon", "M3C", false, "", "M3C"},
		{"env override wins over icon-only", "", true, "●", "●"},
		{"env override wins when icon fails", "", false, "MyLabel", "MyLabel"},
		{"whitespace env override is ignored", "", false, "   ", fb},
		{"whitespace env override ignored, keeps title", "X", true, "  ", "X"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := menubar.ResolveMenuBarTitle(tc.configured, tc.iconApplied, tc.envOverride)
			if got != tc.want {
				t.Fatalf("ResolveMenuBarTitle(%q, %v, %q) = %q, want %q",
					tc.configured, tc.iconApplied, tc.envOverride, got, tc.want)
			}
		})
	}

	if fb == "" {
		t.Fatal("MenuBarFallbackTitle must be non-empty so the menu bar item is never invisible")
	}
}
