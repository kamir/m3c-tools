package timetracking

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testEngine(t *testing.T) (*Engine, *Store) {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	// Seed a project.
	s.UpsertProjects([]CachedProject{
		{ProjectID: "p1", Name: "Alpha", Status: "active", UpdatedAt: time.Now()},
		{ProjectID: "p2", Name: "Beta", Status: "active", UpdatedAt: time.Now()},
	})

	var mu sync.Mutex
	var notifications []string
	notify := func(title, msg string) {
		mu.Lock()
		defer mu.Unlock()
		notifications = append(notifications, title+": "+msg)
	}

	e := NewEngine(s, notify)
	return e, s
}

func TestEngineActivateDeactivate(t *testing.T) {
	e, s := testEngine(t)

	// Activate.
	if err := e.Activate("p1", "Alpha"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if !e.IsActive("p1") {
		t.Error("p1 should be active")
	}

	// Activate again should be a no-op.
	if err := e.Activate("p1", "Alpha"); err != nil {
		t.Fatalf("Activate (again): %v", err)
	}

	// Deactivate.
	if err := e.Deactivate("p1", "user"); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if e.IsActive("p1") {
		t.Error("p1 should not be active")
	}

	// Check events were recorded.
	now := time.Now().UTC()
	events, _ := s.ListAllEvents(now.Add(-time.Minute), now.Add(time.Minute))
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].EventType != "activate" {
		t.Errorf("first event should be activate, got %s", events[0].EventType)
	}
	if events[1].EventType != "deactivate" {
		t.Errorf("second event should be deactivate, got %s", events[1].EventType)
	}
	if events[1].DurationSec == nil || *events[1].DurationSec < 0 {
		t.Errorf("deactivation should have non-negative duration, got %v", events[1].DurationSec)
	}

	// Active contexts should be empty.
	ctxs, _ := s.ListActiveContexts()
	if len(ctxs) != 0 {
		t.Errorf("expected 0 active contexts, got %d", len(ctxs))
	}
}

func TestEngineMultipleProjectsOverlap(t *testing.T) {
	e, _ := testEngine(t)

	e.Activate("p1", "Alpha")
	e.Activate("p2", "Beta")

	if !e.IsActive("p1") || !e.IsActive("p2") {
		t.Error("both p1 and p2 should be active")
	}

	active := e.ActiveProjects()
	if len(active) != 2 {
		t.Errorf("expected 2 active, got %d", len(active))
	}

	// Deactivate one doesn't affect the other.
	e.Deactivate("p1", "user")
	if e.IsActive("p1") {
		t.Error("p1 should not be active")
	}
	if !e.IsActive("p2") {
		t.Error("p2 should still be active")
	}
}

func TestEngineToggle(t *testing.T) {
	e, _ := testEngine(t)

	e.Toggle("p1", "Alpha")
	if !e.IsActive("p1") {
		t.Error("p1 should be active after first toggle")
	}

	e.Toggle("p1", "Alpha")
	if e.IsActive("p1") {
		t.Error("p1 should be inactive after second toggle")
	}
}

func TestEngineShutdownAll(t *testing.T) {
	e, s := testEngine(t)

	e.Activate("p1", "Alpha")
	e.Activate("p2", "Beta")

	e.ShutdownAll()

	if e.IsActive("p1") || e.IsActive("p2") {
		t.Error("all should be deactivated after shutdown")
	}

	// Check events have app_quit trigger.
	now := time.Now().UTC()
	events, _ := s.ListAllEvents(now.Add(-time.Minute), now.Add(time.Minute))
	quitCount := 0
	for _, ev := range events {
		if ev.Trigger == "app_quit" {
			quitCount++
		}
	}
	if quitCount != 2 {
		t.Errorf("expected 2 app_quit events, got %d", quitCount)
	}
}

func TestEngineRecoverOrphanedContextsRestore(t *testing.T) {
	e, s := testEngine(t)

	// Simulate a restart within timeout: activated 30 min ago, expires in 90 min.
	s.SetActiveContext(ActiveContext{
		ProjectID: "p1", ProjectName: "Alpha",
		ActivatedAt: time.Now().Add(-30 * time.Minute),
		ExpiresAt:   time.Now().Add(90 * time.Minute),
	})

	if err := e.RecoverOrphanedContexts(); err != nil {
		t.Fatalf("RecoverOrphanedContexts: %v", err)
	}

	// Should NOT generate a deactivation event — project is restored.
	now := time.Now().UTC()
	events, _ := s.ListAllEvents(now.Add(-time.Hour), now.Add(time.Minute))
	if len(events) != 0 {
		t.Fatalf("expected 0 events (restored, not deactivated), got %d", len(events))
	}

	// Project should be active in the engine.
	active := e.ActiveProjects()
	if len(active) != 1 || active[0] != "p1" {
		t.Errorf("expected p1 active after restore, got %v", active)
	}

	// Active context should still be in the DB.
	ctxs, _ := s.ListActiveContexts()
	if len(ctxs) != 1 {
		t.Errorf("expected 1 active context after restore, got %d", len(ctxs))
	}
}

func TestEngineRecoverOrphanedContextsExpired(t *testing.T) {
	e, s := testEngine(t)

	// Simulate a long offline period: activated 5h ago, expired 3h ago.
	activated := time.Now().Add(-5 * time.Hour)
	expired := time.Now().Add(-3 * time.Hour)
	s.SetActiveContext(ActiveContext{
		ProjectID: "p1", ProjectName: "Alpha",
		ActivatedAt: activated,
		ExpiresAt:   expired,
	})

	if err := e.RecoverOrphanedContexts(); err != nil {
		t.Fatalf("RecoverOrphanedContexts: %v", err)
	}

	// Should have recorded a crash_recovery deactivation capped at ExpiresAt.
	events, _ := s.ListAllEvents(activated.Add(-time.Minute), time.Now().Add(time.Minute))
	if len(events) != 1 {
		t.Fatalf("expected 1 recovery event, got %d", len(events))
	}
	if events[0].Trigger != "crash_recovery" {
		t.Errorf("trigger should be crash_recovery, got %s", events[0].Trigger)
	}
	// Duration should be ~7200s (2h), NOT ~18000s (5h).
	if events[0].DurationSec == nil {
		t.Fatal("duration should not be nil")
	}
	dur := *events[0].DurationSec
	if dur < 7100 || dur > 7300 {
		t.Errorf("duration should be ~7200s (2h cap), got %ds", dur)
	}
	// Deactivation timestamp should be at ExpiresAt, not now.
	deactTime := events[0].Timestamp
	gap := deactTime.Sub(expired)
	if gap < 0 {
		gap = -gap
	}
	if gap > 5*time.Second {
		t.Errorf("deactivation should be at ExpiresAt (%s), got %s (gap=%s)", expired.Format(time.RFC3339), deactTime.Format(time.RFC3339), gap)
	}

	ctxs, _ := s.ListActiveContexts()
	if len(ctxs) != 0 {
		t.Errorf("expected 0 active contexts after recovery, got %d", len(ctxs))
	}
}

func TestContextTimeout(t *testing.T) {
	// Default.
	d := ContextTimeout()
	if d != 2*time.Hour {
		t.Errorf("default timeout should be 2h, got %v", d)
	}

	// Custom.
	t.Setenv("M3C_CONTEXT_TIMEOUT", "30")
	d = ContextTimeout()
	if d != 30*time.Minute {
		t.Errorf("custom timeout should be 30m, got %v", d)
	}
}
