package delta

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// makeInventory is a helper to build an Inventory from skill descriptors.
func makeInventory(skills ...model.SkillDescriptor) *model.Inventory {
	inv := &model.Inventory{
		ScannedAt: "2026-04-02T10:00:00Z",
		ScanPaths: []string{"/tmp/test"},
		Skills:    skills,
		ByType:    make(map[string]int),
		ByProject: make(map[string]int),
	}
	inv.TotalCount = len(skills)
	return inv
}

func skill(id, name, hash, path string) model.SkillDescriptor {
	return model.SkillDescriptor{
		ID:            id,
		Name:          name,
		ContentHash:   hash,
		SourcePath:    path,
		SourceProject: "test-project",
		Type:          model.SkillTypeClaudeCodeSkill,
		Dependencies:  []string{},
		ConflictsWith: []string{},
	}
}

func TestAddedSkillsDetected(t *testing.T) {
	baseline := makeInventory(
		skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
	)
	current := makeInventory(
		skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
		skill("proj/beta", "beta", "hash-b", "/skills/beta.md"),
	)

	report := ComputeDelta(baseline, current)

	if report.Summary.Added != 1 {
		t.Errorf("added = %d, want 1", report.Summary.Added)
	}
	if report.Summary.Total != 1 {
		t.Errorf("total = %d, want 1", report.Summary.Total)
	}

	found := false
	for _, e := range report.Entries {
		if e.DeltaType == DeltaAdded && e.SkillID == "proj/beta" {
			found = true
		}
	}
	if !found {
		t.Error("added entry for proj/beta not found")
	}
}

func TestRemovedSkillsDetected(t *testing.T) {
	baseline := makeInventory(
		skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
		skill("proj/beta", "beta", "hash-b", "/skills/beta.md"),
	)
	current := makeInventory(
		skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
	)

	report := ComputeDelta(baseline, current)

	if report.Summary.Removed != 1 {
		t.Errorf("removed = %d, want 1", report.Summary.Removed)
	}

	found := false
	for _, e := range report.Entries {
		if e.DeltaType == DeltaRemoved && e.SkillID == "proj/beta" {
			found = true
		}
	}
	if !found {
		t.Error("removed entry for proj/beta not found")
	}
}

func TestModifiedSkillsDetected(t *testing.T) {
	baseline := makeInventory(
		skill("proj/alpha", "alpha", "hash-a-v1", "/skills/alpha.md"),
	)
	current := makeInventory(
		skill("proj/alpha", "alpha", "hash-a-v2", "/skills/alpha.md"),
	)

	report := ComputeDelta(baseline, current)

	if report.Summary.Modified != 1 {
		t.Errorf("modified = %d, want 1", report.Summary.Modified)
	}

	found := false
	for _, e := range report.Entries {
		if e.DeltaType == DeltaModified && e.SkillID == "proj/alpha" {
			found = true
			if e.BaselineHash != "hash-a-v1" {
				t.Errorf("baseline hash = %q, want %q", e.BaselineHash, "hash-a-v1")
			}
			if e.CurrentHash != "hash-a-v2" {
				t.Errorf("current hash = %q, want %q", e.CurrentHash, "hash-a-v2")
			}
		}
	}
	if !found {
		t.Error("modified entry for proj/alpha not found")
	}
}

func TestMovedSkillsDetected(t *testing.T) {
	// Same content hash but different ID means the skill was moved/renamed.
	baseline := makeInventory(
		skill("proj/old-name", "old-name", "hash-same", "/skills/old.md"),
	)
	current := makeInventory(
		skill("proj/new-name", "new-name", "hash-same", "/skills/new.md"),
	)

	report := ComputeDelta(baseline, current)

	if report.Summary.Moved != 1 {
		t.Errorf("moved = %d, want 1", report.Summary.Moved)
	}
	// Should not have separate added/removed entries.
	if report.Summary.Added != 0 {
		t.Errorf("added = %d, want 0 (should be detected as move)", report.Summary.Added)
	}
	if report.Summary.Removed != 0 {
		t.Errorf("removed = %d, want 0 (should be detected as move)", report.Summary.Removed)
	}

	found := false
	for _, e := range report.Entries {
		if e.DeltaType == DeltaMoved {
			found = true
			if e.BaselinePath != "/skills/old.md" {
				t.Errorf("baseline path = %q, want %q", e.BaselinePath, "/skills/old.md")
			}
			if e.CurrentPath != "/skills/new.md" {
				t.Errorf("current path = %q, want %q", e.CurrentPath, "/skills/new.md")
			}
		}
	}
	if !found {
		t.Error("moved entry not found")
	}
}

func TestNoChangesProducesEmptyDelta(t *testing.T) {
	skills := []model.SkillDescriptor{
		skill("proj/alpha", "alpha", "hash-a", "/skills/alpha.md"),
		skill("proj/beta", "beta", "hash-b", "/skills/beta.md"),
	}
	baseline := makeInventory(skills...)
	current := makeInventory(skills...)

	report := ComputeDelta(baseline, current)

	if report.Summary.Total != 0 {
		t.Errorf("total = %d, want 0 for identical inventories", report.Summary.Total)
	}
	if len(report.Entries) != 0 {
		t.Errorf("entries = %d, want 0", len(report.Entries))
	}
}

func TestMixedChanges(t *testing.T) {
	baseline := makeInventory(
		skill("proj/stable", "stable", "hash-s", "/skills/stable.md"),
		skill("proj/changed", "changed", "hash-c-v1", "/skills/changed.md"),
		skill("proj/deleted", "deleted", "hash-d", "/skills/deleted.md"),
		skill("proj/old-loc", "old-loc", "hash-move", "/old/path.md"),
	)
	current := makeInventory(
		skill("proj/stable", "stable", "hash-s", "/skills/stable.md"),
		skill("proj/changed", "changed", "hash-c-v2", "/skills/changed.md"),
		skill("proj/new-skill", "new-skill", "hash-n", "/skills/new.md"),
		skill("proj/new-loc", "new-loc", "hash-move", "/new/path.md"),
	)

	report := ComputeDelta(baseline, current)

	if report.Summary.Added != 1 {
		t.Errorf("added = %d, want 1", report.Summary.Added)
	}
	if report.Summary.Modified != 1 {
		t.Errorf("modified = %d, want 1", report.Summary.Modified)
	}
	if report.Summary.Removed != 1 {
		t.Errorf("removed = %d, want 1", report.Summary.Removed)
	}
	if report.Summary.Moved != 1 {
		t.Errorf("moved = %d, want 1", report.Summary.Moved)
	}
	if report.Summary.Total != 4 {
		t.Errorf("total = %d, want 4", report.Summary.Total)
	}
}

func TestEmptyInventories(t *testing.T) {
	baseline := makeInventory()
	current := makeInventory()

	report := ComputeDelta(baseline, current)

	if report.Summary.Total != 0 {
		t.Errorf("total = %d, want 0", report.Summary.Total)
	}
}

func TestGenerateUnifiedDiff(t *testing.T) {
	old := "line1\nline2\nline3\n"
	new := "line1\nline2-modified\nline3\nline4\n"

	diff := GenerateUnifiedDiff(old, new, "a/file", "b/file")

	if diff == "" {
		t.Error("diff should not be empty")
	}
	// Should contain diff markers.
	if !containsStr(diff, "---") {
		t.Error("diff missing --- marker")
	}
	if !containsStr(diff, "+++") {
		t.Error("diff missing +++ marker")
	}
	if !containsStr(diff, "-line2") {
		t.Error("diff missing removed line")
	}
	if !containsStr(diff, "+line2-modified") {
		t.Error("diff missing added line")
	}
}

func TestGenerateUnifiedDiffIdentical(t *testing.T) {
	content := "line1\nline2\n"
	diff := GenerateUnifiedDiff(content, content, "a", "b")

	// Should only contain header and context lines — no actual +/- diff lines.
	// The headers (--- and +++) are expected; we check for non-header +/- lines.
	lines := splitLines(diff)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if line[0] == '-' && !containsStr(line, "--- ") {
			t.Errorf("unexpected removed line in identical diff: %q", line)
		}
		if line[0] == '+' && !containsStr(line, "+++ ") {
			t.Errorf("unexpected added line in identical diff: %q", line)
		}
	}
}

func TestFormatSummary(t *testing.T) {
	report := &DeltaReport{
		ComputedAt:   "2026-04-02T10:00:00Z",
		BaselinePath: "baseline.json",
		CurrentPath:  "current.json",
		Summary: DeltaSummary{
			Added: 2, Modified: 1, Removed: 1, Moved: 0, Total: 4,
		},
	}

	s := FormatSummary(report)
	if !containsStr(s, "Added:    2") {
		t.Error("summary missing added count")
	}
	if !containsStr(s, "Modified: 1") {
		t.Error("summary missing modified count")
	}
}

func TestFormatMarkdown(t *testing.T) {
	report := &DeltaReport{
		ComputedAt: "2026-04-02T10:00:00Z",
		Entries: []DeltaEntry{
			{SkillID: "p/a", SkillName: "a", DeltaType: DeltaAdded, CurrentPath: "/new.md"},
		},
		Summary: DeltaSummary{Added: 1, Total: 1},
	}

	md := FormatMarkdown(report)
	if !containsStr(md, "# Skill Delta Report") {
		t.Error("markdown missing title")
	}
	if !containsStr(md, "| Added | 1 |") {
		t.Error("markdown missing added count")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findSubstring(s, sub))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
