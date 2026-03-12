package timetracking

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempDB(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenStoreAndMigrate(t *testing.T) {
	s := tempDB(t)
	// Should be able to list empty tables.
	projects, err := s.ListProjects()
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 0 {
		t.Errorf("expected 0 projects, got %d", len(projects))
	}
}

func TestUpsertAndListProjects(t *testing.T) {
	s := tempDB(t)

	now := time.Now().UTC()
	projects := []CachedProject{
		{ProjectID: "p1", Name: "Alpha", Client: "Acme", Status: "active", UpdatedAt: now},
		{ProjectID: "p2", Name: "Beta", Client: "Corp", Status: "active", UpdatedAt: now.Add(-time.Hour)},
	}
	if err := s.UpsertProjects(projects); err != nil {
		t.Fatalf("UpsertProjects: %v", err)
	}

	got, err := s.ListProjects()
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 projects, got %d", len(got))
	}
	// Should be sorted by updated_at desc (p1 first).
	if got[0].ProjectID != "p1" {
		t.Errorf("first project should be p1, got %s", got[0].ProjectID)
	}
	if got[1].ProjectID != "p2" {
		t.Errorf("second project should be p2, got %s", got[1].ProjectID)
	}

	// Upsert again replaces.
	if err := s.UpsertProjects([]CachedProject{
		{ProjectID: "p3", Name: "Gamma", Status: "active", UpdatedAt: now},
	}); err != nil {
		t.Fatalf("UpsertProjects (replace): %v", err)
	}
	got, _ = s.ListProjects()
	if len(got) != 1 || got[0].ProjectID != "p3" {
		t.Errorf("expected only p3 after replace, got %+v", got)
	}
}

func TestProjectsCacheAge(t *testing.T) {
	s := tempDB(t)

	// Empty store returns -1.
	if age := s.ProjectsCacheAge(); age != -1 {
		t.Errorf("expected -1 for empty cache, got %v", age)
	}

	s.UpsertProjects([]CachedProject{
		{ProjectID: "p1", Name: "Test", Status: "active", UpdatedAt: time.Now()},
	})

	age := s.ProjectsCacheAge()
	if age < 0 || age > 2*time.Second {
		t.Errorf("cache age should be ~0, got %v", age)
	}
}

func TestInsertAndListEvents(t *testing.T) {
	s := tempDB(t)

	now := time.Now().UTC()
	s.UpsertProjects([]CachedProject{
		{ProjectID: "p1", Name: "Alpha", Status: "active", UpdatedAt: now},
	})

	e1 := Event{
		EventID: "e1", ProjectID: "p1", ProjectName: "Alpha",
		EventType: "activate", Timestamp: now, Trigger: "user",
	}
	if err := s.InsertEvent(e1); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}

	dur := 3600
	e2 := Event{
		EventID: "e2", ProjectID: "p1", ProjectName: "Alpha",
		EventType: "deactivate", Timestamp: now.Add(time.Hour), Trigger: "user",
		DurationSec: &dur,
	}
	if err := s.InsertEvent(e2); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}

	events, err := s.ListEvents("p1", now.Add(-time.Minute), now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].EventType != "activate" {
		t.Errorf("first event should be activate, got %s", events[0].EventType)
	}
	if events[1].EventType != "deactivate" {
		t.Errorf("second event should be deactivate, got %s", events[1].EventType)
	}
	if events[1].DurationSec == nil || *events[1].DurationSec != 3600 {
		t.Errorf("duration should be 3600, got %v", events[1].DurationSec)
	}
}

func TestUnsyncedAndMarkSynced(t *testing.T) {
	s := tempDB(t)

	now := time.Now().UTC()
	s.UpsertProjects([]CachedProject{
		{ProjectID: "p1", Name: "Alpha", Status: "active", UpdatedAt: now},
	})

	s.InsertEvent(Event{
		EventID: "e1", ProjectID: "p1", ProjectName: "Alpha",
		EventType: "activate", Timestamp: now, Trigger: "user",
	})

	unsynced, _ := s.UnsyncedEvents()
	if len(unsynced) != 1 {
		t.Fatalf("expected 1 unsynced, got %d", len(unsynced))
	}

	s.MarkSynced("e1")
	unsynced, _ = s.UnsyncedEvents()
	if len(unsynced) != 0 {
		t.Errorf("expected 0 unsynced after mark, got %d", len(unsynced))
	}
}

func TestActiveContexts(t *testing.T) {
	s := tempDB(t)

	now := time.Now().UTC()
	s.SetActiveContext(ActiveContext{
		ProjectID: "p1", ProjectName: "Alpha",
		ActivatedAt: now, ExpiresAt: now.Add(2 * time.Hour),
	})
	s.SetActiveContext(ActiveContext{
		ProjectID: "p2", ProjectName: "Beta",
		ActivatedAt: now, ExpiresAt: now.Add(2 * time.Hour),
	})

	ctxs, err := s.ListActiveContexts()
	if err != nil {
		t.Fatalf("ListActiveContexts: %v", err)
	}
	if len(ctxs) != 2 {
		t.Fatalf("expected 2 active contexts, got %d", len(ctxs))
	}

	s.RemoveActiveContext("p1")
	ctxs, _ = s.ListActiveContexts()
	if len(ctxs) != 1 {
		t.Errorf("expected 1 after remove, got %d", len(ctxs))
	}
	if ctxs[0].ProjectID != "p2" {
		t.Errorf("remaining should be p2, got %s", ctxs[0].ProjectID)
	}
}

func TestSummarize(t *testing.T) {
	s := tempDB(t)

	now := time.Now().UTC()
	s.UpsertProjects([]CachedProject{
		{ProjectID: "p1", Name: "Alpha", Status: "active", UpdatedAt: now},
	})

	s.InsertEvent(Event{
		EventID: "e1", ProjectID: "p1", ProjectName: "Alpha",
		EventType: "activate", Timestamp: now.Add(-2 * time.Hour), Trigger: "user",
	})
	dur := 3600
	s.InsertEvent(Event{
		EventID: "e2", ProjectID: "p1", ProjectName: "Alpha",
		EventType: "deactivate", Timestamp: now.Add(-time.Hour), Trigger: "user",
		DurationSec: &dur,
	})

	summaries, err := s.Summarize(now.Add(-3*time.Hour), now)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].TotalSeconds != 3600 {
		t.Errorf("total should be 3600, got %d", summaries[0].TotalSeconds)
	}
	if summaries[0].SessionCount != 1 {
		t.Errorf("sessions should be 1, got %d", summaries[0].SessionCount)
	}
}

func TestPruneOldEvents(t *testing.T) {
	s := tempDB(t)

	now := time.Now().UTC()
	s.UpsertProjects([]CachedProject{
		{ProjectID: "p1", Name: "Alpha", Status: "active", UpdatedAt: now},
	})

	// Insert an old synced event.
	s.InsertEvent(Event{
		EventID: "old", ProjectID: "p1", ProjectName: "Alpha",
		EventType: "activate", Timestamp: now.Add(-100 * 24 * time.Hour), Trigger: "user",
		Synced: true,
	})
	// Manually set synced since InsertEvent uses the Synced field.
	s.MarkSynced("old")

	// Insert a recent event.
	s.InsertEvent(Event{
		EventID: "new", ProjectID: "p1", ProjectName: "Alpha",
		EventType: "activate", Timestamp: now, Trigger: "user",
	})

	pruned, err := s.PruneOldEvents(90 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("PruneOldEvents: %v", err)
	}
	if pruned != 1 {
		t.Errorf("expected 1 pruned, got %d", pruned)
	}

	// The recent event should remain.
	all, _ := s.ListAllEvents(now.Add(-200*24*time.Hour), now.Add(time.Hour))
	if len(all) != 1 {
		t.Errorf("expected 1 remaining, got %d", len(all))
	}
}

func TestDefaultDBPath(t *testing.T) {
	// With env var set.
	os.Setenv("M3C_TIMETRACKING_DB", "/custom/path.db")
	defer os.Unsetenv("M3C_TIMETRACKING_DB")
	if got := DefaultDBPath(); got != "/custom/path.db" {
		t.Errorf("expected /custom/path.db, got %s", got)
	}

	// Without env var.
	os.Unsetenv("M3C_TIMETRACKING_DB")
	path := DefaultDBPath()
	if !filepath.IsAbs(path) {
		t.Errorf("expected absolute path, got %s", path)
	}
}
