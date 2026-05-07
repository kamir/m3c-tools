//go:build darwin

// timetracking_test.go — BUG-0124 Layer 3 tests for the empty-state error
// surfacing in the Projects submenu.
package menubar

import (
	"testing"
)

func TestSetTimeTrackingError_StoresAndClears(t *testing.T) {
	// Reset state.
	SetTimeTrackingError("")
	if got := GetTimeTrackingError(); got != "" {
		t.Fatalf("baseline: GetTimeTrackingError() = %q, want empty", got)
	}

	// Set a diagnostic.
	want := "ER1 key invalid (401) — open Settings to update"
	SetTimeTrackingError(want)
	if got := GetTimeTrackingError(); got != want {
		t.Errorf("after SetTimeTrackingError(%q): got %q", want, got)
	}

	// Clear with empty string.
	SetTimeTrackingError("")
	if got := GetTimeTrackingError(); got != "" {
		t.Errorf("after clear: got %q, want empty", got)
	}
}

func TestSetTimeTrackingProjects_ClearsErrorOnSuccess(t *testing.T) {
	// Pre-condition: error set, no projects.
	SetTimeTrackingError("ER1 key invalid (401)")
	SetTimeTrackingProjects(nil)
	if got := GetTimeTrackingError(); got == "" {
		t.Fatalf("baseline: error should be retained when no projects loaded yet")
	}

	// Loading a non-empty project list must clear the error — recovery path.
	SetTimeTrackingProjects([]TimeTrackingProject{
		{ID: "p1", Name: "Project One"},
	})
	if got := GetTimeTrackingError(); got != "" {
		t.Errorf("after successful load: error = %q, want empty (auto-clear)", got)
	}

	// Cleanup.
	SetTimeTrackingProjects(nil)
	SetTimeTrackingError("")
}

func TestSetTimeTrackingProjects_PreservesErrorOnEmptyLoad(t *testing.T) {
	// Subtle case: an empty project list arriving while an error is set
	// (e.g. healthcheck failed but a degraded fallback returned no items)
	// should NOT clear the error — the diagnostic is more useful than
	// "0 items". Layer 3 explicit decision.
	SetTimeTrackingError("Server unreachable — check network")
	SetTimeTrackingProjects(nil)
	if got := GetTimeTrackingError(); got == "" {
		t.Errorf("after empty load with error set: error was wiped (regression of explicit Layer-3 decision)")
	}

	// Cleanup.
	SetTimeTrackingError("")
}
