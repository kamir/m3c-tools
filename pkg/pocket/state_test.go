package pocket

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindGroupByFilePath(t *testing.T) {
	tmpDir := t.TempDir()
	stagingDir := filepath.Join(tmpDir, "staging")
	os.MkdirAll(stagingDir, 0755)

	cfg := &Config{
		StagingDir: stagingDir,
		RawDir:     filepath.Join(tmpDir, "raw"),
	}

	// Write a groups.json with one group
	state := GroupState{
		Groups: []GroupMapping{
			{
				GroupID: "test-group-1",
				DocID:   "abc123",
				Title:   "Test Session",
				FilePaths: []string{
					"/Users/kamir/m3c-data/pocket/raw/2026-04-02/20260402163416.mp3",
					"/Users/kamir/m3c-data/pocket/raw/2026-04-02/20260402171200.mp3",
				},
				Segments: 2,
			},
		},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(filepath.Join(stagingDir, "groups.json"), data, 0644)

	// Should find the group by exact file path match
	result := FindGroupByFilePath("/Users/kamir/m3c-data/pocket/raw/2026-04-02/20260402163416.mp3", cfg)
	if result == nil {
		t.Fatal("FindGroupByFilePath should find group for matching path")
	}
	if result.GroupID != "test-group-1" {
		t.Errorf("GroupID = %q, want test-group-1", result.GroupID)
	}

	// Should not find for unknown path
	result = FindGroupByFilePath("/some/other/path.mp3", cfg)
	if result != nil {
		t.Error("FindGroupByFilePath should return nil for unknown path")
	}
}

func TestFindGroupByStagedPath(t *testing.T) {
	tmpDir := t.TempDir()
	stagingDir := filepath.Join(tmpDir, "staging")
	rawDir := filepath.Join(tmpDir, "raw")
	os.MkdirAll(stagingDir, 0755)
	os.MkdirAll(rawDir, 0755)

	cfg := &Config{
		StagingDir: stagingDir,
		RawDir:     rawDir,
	}

	// Groups.json stores STAGED paths (as happens after grouping)
	state := &GroupState{
		Groups: []GroupMapping{
			{
				GroupID: "group-staged",
				DocID:   "doc456",
				Title:   "Staged Session",
				FilePaths: []string{
					filepath.Join(rawDir, "2026-04-02", "20260402163416.mp3"),
					filepath.Join(rawDir, "2026-04-02", "20260402171200.mp3"),
				},
				Segments: 2,
			},
		},
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(filepath.Join(stagingDir, "groups.json"), data, 0644)

	// Recording from device scan (device path, not staged)
	rec := Recording{
		FilePath:  "/Volumes/Pocket/RECORD/2026-04-02/20260402163416.mp3",
		Date:      "2026-04-02",
		Time:      "16:34:16",
		Timestamp: time.Date(2026, 4, 2, 16, 34, 16, 0, time.UTC),
	}

	// FindGroupByFilePath won't find it (device path != staged path)
	result := FindGroupByFilePath(rec.FilePath, cfg)
	if result != nil {
		t.Error("FindGroupByFilePath should NOT find group for device path when stored as staged path")
	}

	// FindGroupByStagedPath SHOULD find it by matching the staged path
	result = FindGroupByStagedPath(rec, cfg, state)
	if result == nil {
		t.Fatal("FindGroupByStagedPath should find group by matching staged path")
	}
	if result.GroupID != "group-staged" {
		t.Errorf("GroupID = %q, want group-staged", result.GroupID)
	}

	// Unknown recording should not match
	unknown := Recording{
		FilePath: "/Volumes/Pocket/RECORD/2099-01-01/20990101000000.mp3",
		Date:     "2099-01-01",
	}
	result = FindGroupByStagedPath(unknown, cfg, state)
	if result != nil {
		t.Error("FindGroupByStagedPath should return nil for unknown recording")
	}
}

func TestFindGroupByStagedPathNilState(t *testing.T) {
	tmpDir := t.TempDir()
	stagingDir := filepath.Join(tmpDir, "staging")
	os.MkdirAll(stagingDir, 0755)

	cfg := &Config{
		StagingDir: stagingDir,
		RawDir:     filepath.Join(tmpDir, "raw"),
	}

	// No groups.json exists — should not panic
	rec := Recording{
		FilePath: "/Volumes/Pocket/RECORD/2026-04-02/20260402163416.mp3",
		Date:     "2026-04-02",
	}
	result := FindGroupByStagedPath(rec, cfg, nil)
	if result != nil {
		t.Error("FindGroupByStagedPath with nil state and no file should return nil")
	}
}

func TestLoadGroupState_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{StagingDir: tmpDir}
	state := LoadGroupState(cfg)
	if len(state.Groups) != 0 {
		t.Errorf("LoadGroupState on empty dir should return 0 groups, got %d", len(state.Groups))
	}
}
