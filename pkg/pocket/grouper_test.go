package pocket

import (
	"testing"
	"time"
)

func TestSuggestGroups_CloseRecordings(t *testing.T) {
	base := time.Date(2026, 4, 3, 10, 34, 0, 0, time.UTC)
	recordings := []Recording{
		{FilePath: "a.mp3", Timestamp: base, DurationSec: 7, SizeBytes: 28000},
		{FilePath: "b.mp3", Timestamp: base.Add(46 * time.Second), DurationSec: 12, SizeBytes: 48000},
		{FilePath: "c.mp3", Timestamp: base.Add(2 * time.Minute), DurationSec: 5, SizeBytes: 20000},
	}

	groups := SuggestGroups(recordings, 5)

	if len(groups) != 1 {
		t.Fatalf("SuggestGroups() returned %d groups, want 1", len(groups))
	}
	if len(groups[0].Recordings) != 3 {
		t.Errorf("Group has %d recordings, want 3", len(groups[0].Recordings))
	}
	if groups[0].TotalDuration != 24.0 {
		t.Errorf("TotalDuration = %f, want 24.0", groups[0].TotalDuration)
	}
}

func TestSuggestGroups_FarApart(t *testing.T) {
	base := time.Date(2026, 4, 3, 10, 0, 0, 0, time.UTC)
	recordings := []Recording{
		{FilePath: "a.mp3", Timestamp: base, DurationSec: 10, SizeBytes: 40000},
		{FilePath: "b.mp3", Timestamp: base.Add(30 * time.Minute), DurationSec: 10, SizeBytes: 40000},
	}

	groups := SuggestGroups(recordings, 5)

	if len(groups) != 0 {
		t.Errorf("SuggestGroups() returned %d groups for far-apart recordings, want 0", len(groups))
	}
}

func TestSuggestGroups_SingleRecording(t *testing.T) {
	recordings := []Recording{
		{FilePath: "a.mp3", Timestamp: time.Now(), DurationSec: 10, SizeBytes: 40000},
	}

	groups := SuggestGroups(recordings, 5)

	if len(groups) != 0 {
		t.Errorf("SuggestGroups() returned %d groups for single recording, want 0", len(groups))
	}
}

func TestSuggestGroups_MixedSessions(t *testing.T) {
	base := time.Date(2026, 4, 3, 10, 0, 0, 0, time.UTC)
	recordings := []Recording{
		{FilePath: "a.mp3", Timestamp: base, DurationSec: 5, SizeBytes: 20000},
		{FilePath: "b.mp3", Timestamp: base.Add(1 * time.Minute), DurationSec: 5, SizeBytes: 20000},
		// Gap of 20 minutes
		{FilePath: "c.mp3", Timestamp: base.Add(21 * time.Minute), DurationSec: 5, SizeBytes: 20000},
		{FilePath: "d.mp3", Timestamp: base.Add(22 * time.Minute), DurationSec: 5, SizeBytes: 20000},
		{FilePath: "e.mp3", Timestamp: base.Add(23 * time.Minute), DurationSec: 5, SizeBytes: 20000},
	}

	groups := SuggestGroups(recordings, 5)

	if len(groups) != 2 {
		t.Fatalf("SuggestGroups() returned %d groups, want 2", len(groups))
	}
	if len(groups[0].Recordings) != 2 {
		t.Errorf("Group 0 has %d recordings, want 2", len(groups[0].Recordings))
	}
	if len(groups[1].Recordings) != 3 {
		t.Errorf("Group 1 has %d recordings, want 3", len(groups[1].Recordings))
	}
}

func TestCreateGroup(t *testing.T) {
	recordings := []Recording{
		{FilePath: "a.mp3", DurationSec: 7, SizeBytes: 28000},
		{FilePath: "b.mp3", DurationSec: 12, SizeBytes: 48000},
	}

	g := CreateGroup("My Session", recordings, []string{"custom", "tags"})

	if g.Title != "My Session" {
		t.Errorf("Title = %q, want %q", g.Title, "My Session")
	}
	if len(g.Tags) != 2 || g.Tags[0] != "custom" {
		t.Errorf("Tags = %v, want [custom tags]", g.Tags)
	}
	if g.TotalSize != 76000 {
		t.Errorf("TotalSize = %d, want 76000", g.TotalSize)
	}
}

func TestBuildFileList(t *testing.T) {
	recordings := []Recording{
		{FilePath: "/tmp/a.mp3"},
		{FilePath: "/tmp/b.mp3"},
	}

	got := BuildFileList(recordings)
	want := "file '/tmp/a.mp3'\nfile '/tmp/b.mp3'\n"
	if got != want {
		t.Errorf("BuildFileList() = %q, want %q", got, want)
	}
}
