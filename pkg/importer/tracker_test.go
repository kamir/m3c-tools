package importer

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestNewTracker(t *testing.T) {
	t.Run("empty path returns error", func(t *testing.T) {
		_, err := NewTracker("")
		if err == nil {
			t.Fatal("expected error for empty path")
		}
	})

	t.Run("valid path succeeds", func(t *testing.T) {
		tmp := filepath.Join(t.TempDir(), "tracker.md")
		tr, err := NewTracker(tmp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tr.Path() != tmp {
			t.Errorf("path = %q, want %q", tr.Path(), tmp)
		}
	})
}

func TestTrackerLoadEmpty(t *testing.T) {
	// Load from a non-existent file should succeed with 0 entries.
	tmp := filepath.Join(t.TempDir(), "nonexistent.md")
	tr, err := NewTracker(tmp)
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}

	if err := tr.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	count, err := tr.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Errorf("Count = %d, want 0", count)
	}
}

func TestTrackerLoadExisting(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "tracker.md")
	content := `# M3C Import Tracker
# Some comment

file1.mp3
file2.wav

# Another comment
file3.m4a
`
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	tr, err := NewTracker(tmp)
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}

	if err := tr.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	count, err := tr.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 3 {
		t.Errorf("Count = %d, want 3", count)
	}

	// Check individual entries.
	for _, name := range []string{"file1.mp3", "file2.wav", "file3.m4a"} {
		tracked, err := tr.IsTracked(name)
		if err != nil {
			t.Errorf("IsTracked(%q): %v", name, err)
		}
		if !tracked {
			t.Errorf("IsTracked(%q) = false, want true", name)
		}
	}

	// Check untracked file.
	tracked, err := tr.IsTracked("unknown.mp3")
	if err != nil {
		t.Fatalf("IsTracked: %v", err)
	}
	if tracked {
		t.Error("IsTracked(unknown.mp3) = true, want false")
	}
}

func TestTrackerAdd(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "sub", "tracker.md")

	tr, err := NewTracker(tmp)
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}

	// Add entries — should create the file with header.
	if err := tr.Add("alpha.mp3", "beta.wav"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Verify file exists and has correct content.
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "# M3C Import Tracker") {
		t.Error("file missing header")
	}
	if !strings.Contains(content, "alpha.mp3") {
		t.Error("file missing alpha.mp3")
	}
	if !strings.Contains(content, "beta.wav") {
		t.Error("file missing beta.wav")
	}

	// Verify in-memory state.
	count, _ := tr.Count()
	if count != 2 {
		t.Errorf("Count = %d, want 2", count)
	}

	// Add duplicate — should not write again.
	if err := tr.Add("alpha.mp3"); err != nil {
		t.Fatalf("Add duplicate: %v", err)
	}
	count, _ = tr.Count()
	if count != 2 {
		t.Errorf("Count after duplicate = %d, want 2", count)
	}

	// Add new entry — should append.
	if err := tr.Add("gamma.flac"); err != nil {
		t.Fatalf("Add gamma: %v", err)
	}
	count, _ = tr.Count()
	if count != 3 {
		t.Errorf("Count after gamma = %d, want 3", count)
	}

	// Re-read from disk to verify persistence.
	tr2, err := NewTracker(tmp)
	if err != nil {
		t.Fatalf("NewTracker2: %v", err)
	}
	if err := tr2.Load(); err != nil {
		t.Fatalf("Load2: %v", err)
	}
	count2, _ := tr2.Count()
	if count2 != 3 {
		t.Errorf("Count from disk = %d, want 3", count2)
	}
}

func TestTrackerAddEmpty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "tracker.md")
	tr, _ := NewTracker(tmp)

	// Add empty and whitespace-only entries — should be no-ops.
	if err := tr.Add("", "  ", "\t"); err != nil {
		t.Fatalf("Add empty: %v", err)
	}

	count, _ := tr.Count()
	if count != 0 {
		t.Errorf("Count = %d, want 0", count)
	}

	// File should not exist since nothing was written.
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("tracker file should not exist for empty adds")
	}
}

func TestTrackerIsTrackedAutoLoads(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "tracker.md")
	content := "recording.mp3\n"
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	tr, _ := NewTracker(tmp)

	// IsTracked should auto-load the file.
	tracked, err := tr.IsTracked("recording.mp3")
	if err != nil {
		t.Fatalf("IsTracked: %v", err)
	}
	if !tracked {
		t.Error("IsTracked(recording.mp3) = false, want true")
	}
}

func TestTrackerIsTrackedEmpty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "tracker.md")
	tr, _ := NewTracker(tmp)

	// Empty filename always returns false.
	tracked, err := tr.IsTracked("")
	if err != nil {
		t.Fatalf("IsTracked: %v", err)
	}
	if tracked {
		t.Error("IsTracked('') = true, want false")
	}
}

func TestTrackerEntries(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "tracker.md")
	tr, _ := NewTracker(tmp)
	_ = tr.Add("charlie.wav", "alpha.mp3", "bravo.m4a")

	entries, err := tr.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	sort.Strings(entries)

	want := []string{"alpha.mp3", "bravo.m4a", "charlie.wav"}
	if len(entries) != len(want) {
		t.Fatalf("Entries len = %d, want %d", len(entries), len(want))
	}
	for i, e := range entries {
		if e != want[i] {
			t.Errorf("entries[%d] = %q, want %q", i, e, want[i])
		}
	}
}

func TestStatusCheckerFromTracker(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "tracker.md")
	tr, _ := NewTracker(tmp)
	_ = tr.Add("tracked-file.mp3")

	checker := StatusCheckerFromTracker(tr)

	t.Run("tracked file returns imported", func(t *testing.T) {
		status, err := checker("/some/path/tracked-file.mp3")
		if err != nil {
			t.Fatalf("checker: %v", err)
		}
		if status != StatusImported {
			t.Errorf("status = %q, want %q", status, StatusImported)
		}
	})

	t.Run("untracked file returns new", func(t *testing.T) {
		status, err := checker("/other/path/new-file.wav")
		if err != nil {
			t.Fatalf("checker: %v", err)
		}
		if status != StatusNew {
			t.Errorf("status = %q, want %q", status, StatusNew)
		}
	})

	t.Run("nil tracker returns new", func(t *testing.T) {
		nilChecker := StatusCheckerFromTracker(nil)
		status, err := nilChecker("/any/path.mp3")
		if err != nil {
			t.Fatalf("nilChecker: %v", err)
		}
		if status != StatusNew {
			t.Errorf("status = %q, want %q", status, StatusNew)
		}
	})
}

func TestTrackerReload(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "tracker.md")

	// Create initial tracker with one entry.
	tr1, _ := NewTracker(tmp)
	_ = tr1.Add("initial.mp3")

	// Externally append another entry (simulating another process).
	f, _ := os.OpenFile(tmp, os.O_APPEND|os.O_WRONLY, 0644)
	_, _ = f.WriteString("external.wav\n")
	f.Close()

	// Reload should pick up the external entry.
	if err := tr1.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	count, _ := tr1.Count()
	if count != 2 {
		t.Errorf("Count = %d, want 2", count)
	}
	tracked, _ := tr1.IsTracked("external.wav")
	if !tracked {
		t.Error("external.wav should be tracked after reload")
	}
}
