package main

import (
	"strings"
	"testing"
)

func TestParseManifest_HappyPath(t *testing.T) {
	src := `# 6-skill P5 starter set
fetch-contract   green   read-only ER1 contract fetch
er1-push@1.0.0   green   text-only ER1 memory push
wlog             yellow  writes local WLOG/

# comment
session-state
`
	entries, err := ParseManifest(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := len(entries); got != 4 {
		t.Fatalf("entries = %d, want 4", got)
	}
	want := []ManifestEntry{
		{Name: "fetch-contract", Level: "green", Rationale: "read-only ER1 contract fetch", Line: 2},
		{Name: "er1-push", Version: "1.0.0", Level: "green", Rationale: "text-only ER1 memory push", Line: 3},
		{Name: "wlog", Level: "yellow", Rationale: "writes local WLOG/", Line: 4},
		{Name: "session-state", Line: 7},
	}
	for i, w := range want {
		g := entries[i]
		if g.Name != w.Name || g.Version != w.Version || g.Level != w.Level || g.Rationale != w.Rationale {
			t.Errorf("entry %d = %+v, want %+v", i, g, w)
		}
	}
}

func TestParseManifest_RejectsBadLevel(t *testing.T) {
	_, err := ParseManifest(strings.NewReader("skill purple some rationale"))
	if err == nil || !strings.Contains(err.Error(), "must be green|yellow|red") {
		t.Errorf("err = %v, want a bad-level error", err)
	}
}

func TestParseManifest_RejectsEmptyName(t *testing.T) {
	_, err := ParseManifest(strings.NewReader("@1.0.0"))
	if err == nil || !strings.Contains(err.Error(), "empty skill name") {
		t.Errorf("err = %v, want empty-name error", err)
	}
}

func TestParseManifest_SkipsCommentsAndBlanks(t *testing.T) {
	entries, err := ParseManifest(strings.NewReader("\n  # only-comment\n   \n# another\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("len = %d, want 0", len(entries))
	}
}
