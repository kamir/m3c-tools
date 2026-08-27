package skillbundle

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIgnoreMatcher exercises the default-artifact rules on immediate entries
// (the walk prunes ignored dirs via SkipDir, so the matcher only ever judges the
// entry it is handed, not deep descendants).
func TestIgnoreMatcher(t *testing.T) {
	rules := parseIgnore(defaultIgnorePatterns)
	cases := []struct {
		rel   string
		isDir bool
		want  bool
	}{
		{"node_modules", true, true},
		{"node_modules", false, false}, // dir-only rule: a *file* named node_modules stays
		{"dist", true, true},
		{"build", true, true},
		{"target", true, true},
		{"__pycache__", true, true},
		{".venv", true, true},
		{"foo.pyc", false, true},
		{"foo.pyo", false, true},
		{".DS_Store", false, true}, // nested .DS_Store (basename rule, not dir-only)
		{"run.py", false, false},
		{"references/note.md", false, false},
		{"SKILL.md", false, false}, // not matched by rules; the hard guard is separate
	}
	for _, c := range cases {
		if got := ignored(rules, c.rel, c.isDir); got != c.want {
			t.Errorf("ignored(%q, dir=%v) = %v, want %v", c.rel, c.isDir, got, c.want)
		}
	}
}

// TestIgnoreSkbignore covers user patterns, negation of a default, and anchoring.
func TestIgnoreSkbignore(t *testing.T) {
	rules := append(parseIgnore(defaultIgnorePatterns),
		parseIgnore([]string{
			"# a comment",
			"*.tmp",     // add
			"!dist/",    // re-include a default-ignored dir
			"docs/build", // anchored (interior slash): only this exact path
		})...)

	check := func(rel string, isDir, want bool) {
		t.Helper()
		if got := ignored(rules, rel, isDir); got != want {
			t.Errorf("ignored(%q, dir=%v) = %v, want %v", rel, isDir, got, want)
		}
	}
	check("scratch.tmp", false, true) // user *.tmp
	check("dist", true, false)        // default "dist/" then "!dist/" → last wins → kept
	check("docs/build", false, true)  // anchored path match
	check("other/build", true, true)  // NOT the anchored docs/build, but default "build/" (dir) fires
	check("other/thing.md", false, false)
}

// mustWriteSkill builds a skill dir from a rel→body map (+ dirs auto-created).
func mustWriteSkill(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func packNames(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := filepath.Join(t.TempDir(), "x.skb")
	if _, err := Pack(dir, out, PackOptions{Manifest: fixtureManifest(), BuiltAt: fixedTime}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	set := map[string]bool{}
	for _, n := range readTarNames(t, out) {
		set[n] = true
	}
	return set
}

// TestPackExcludesArtifacts: build output / caches never enter the bundle, while
// real skill source does.
func TestPackExcludesArtifacts(t *testing.T) {
	dir := mustWriteSkill(t, map[string]string{
		"SKILL.md":                          "---\nname: x\n---\n",
		"src/main.py":                       "print(1)\n",
		"references/data.json":              "{}\n",
		"node_modules/left-pad/index.js":    "module.exports=1\n",
		"dist/app":                          "BINARY",
		"__pycache__/mod.cpython-313.pyc":   "PYC",
		"scratch.pyc":                       "PYC",
		"nested/.DS_Store":                  "junk",
	})
	names := packNames(t, dir)

	mustHave := []string{"SKILL.md", "src/main.py", "references/data.json"}
	for _, n := range mustHave {
		if !names[n] {
			t.Errorf("expected %q in bundle, missing", n)
		}
	}
	for n := range names {
		switch {
		case n == "dist/app",
			n == "scratch.pyc",
			n == "nested/.DS_Store":
			t.Errorf("artifact %q leaked into bundle", n)
		}
		if len(n) >= 13 && n[:13] == "node_modules/" {
			t.Errorf("node_modules leaked: %q", n)
		}
		if len(n) >= 12 && n[:12] == "__pycache__/" {
			t.Errorf("__pycache__ leaked: %q", n)
		}
	}
}

// TestPackSkbignore: a skill's .skbignore adds a pattern and re-includes a
// default-ignored file; the .skbignore file itself does not ship.
func TestPackSkbignore(t *testing.T) {
	dir := mustWriteSkill(t, map[string]string{
		"SKILL.md":     "---\nname: x\n---\n",
		"keep.txt":     "keep\n",
		"drop.tmp":     "drop\n",
		"vendor.pyc":   "PYC", // default-ignored…
		".skbignore":   "*.tmp\n!vendor.pyc\n",
	})
	names := packNames(t, dir)
	if !names["keep.txt"] {
		t.Error("keep.txt should be packed")
	}
	if names["drop.tmp"] {
		t.Error("drop.tmp matched *.tmp and must be excluded")
	}
	if !names["vendor.pyc"] {
		t.Error("vendor.pyc was re-included by !vendor.pyc and must be packed")
	}
	if names[".skbignore"] {
		t.Error(".skbignore is a pack directive and must not ship")
	}
}

// TestPackSkillMdGuard: SKILL.md is packed even if a rule tries to exclude it.
func TestPackSkillMdGuard(t *testing.T) {
	dir := mustWriteSkill(t, map[string]string{
		"SKILL.md":   "---\nname: x\n---\n",
		".skbignore": "*.md\nSKILL.md\n",
	})
	names := packNames(t, dir)
	if !names["SKILL.md"] {
		t.Fatal("SKILL.md must always be packed regardless of ignore rules")
	}
}
