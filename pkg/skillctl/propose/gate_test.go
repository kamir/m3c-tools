package propose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSkill builds a minimal skill directory with the given SKILL.md
// body. Returns the absolute skillDir path.
func writeSkill(t *testing.T, body string, extras map[string]string) string {
	t.Helper()
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "didactic-session")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	for relPath, content := range extras {
		full := filepath.Join(dir, relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir extra: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write extra: %v", err)
		}
	}
	return dir
}

const validSkillMD = `---
name: didactic-session
version: 1.0.0
description: Scaffolds a live training session for a specific role-track
governance_level: yellow
---

# didactic-session

Body content here.
`

func TestRun_AllChecksPassWithSmokeFile(t *testing.T) {
	dir := writeSkill(t, validSkillMD, map[string]string{
		"tests/smoke.sh": "#!/bin/sh\nexit 0\n",
	})
	r := Run(CheckOptions{
		SkillDir:     dir,
		SkillName:    "didactic-session",
		AuthorIntent: "yellow",
		Rationale:    "weekly iteration",
	})
	if !r.AllPassed {
		for _, c := range r.Checks {
			if !c.Pass && !c.Skipped {
				t.Errorf("check #%d %s: %s", c.Number, c.Name, c.Reason)
			}
		}
	}
}

func TestRun_MissingSkillMDFailsAndStillReportsAllRows(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "ghost-skill")
	_ = os.MkdirAll(dir, 0o755)

	r := Run(CheckOptions{
		SkillDir:     dir,
		SkillName:    "ghost-skill",
		AuthorIntent: "yellow",
		Rationale:    "x",
	})
	if r.AllPassed {
		t.Errorf("AllPassed should be false")
	}
	// Per S3.1 Q1=A: every row should be reported, not just the first failure.
	if len(r.Checks) < 8 {
		t.Errorf("got %d check rows, want at least 8 (full report)", len(r.Checks))
	}
}

func TestRun_BadSemverVersionFails(t *testing.T) {
	body := strings.Replace(validSkillMD, "version: 1.0.0", "version: not-a-semver", 1)
	dir := writeSkill(t, body, map[string]string{"tests/smoke.sh": "#!/bin/sh\nexit 0\n"})
	r := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		AuthorIntent: "yellow", Rationale: "x",
	})
	if r.AllPassed {
		t.Errorf("expected fail on bad semver")
	}
	for _, c := range r.Checks {
		if c.Number == 4 {
			if c.Pass {
				t.Errorf("check #4 should fail; got pass")
			}
			if !strings.Contains(c.Reason, "semver") {
				t.Errorf("reason should mention semver; got %q", c.Reason)
			}
		}
	}
}

func TestRun_DescTooShortFails(t *testing.T) {
	body := strings.Replace(validSkillMD,
		"description: Scaffolds a live training session for a specific role-track",
		"description: short",
		1,
	)
	dir := writeSkill(t, body, map[string]string{"tests/smoke.sh": "#!/bin/sh\nexit 0\n"})
	r := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		AuthorIntent: "yellow", Rationale: "x",
	})
	for _, c := range r.Checks {
		if c.Number == 5 && c.Pass {
			t.Errorf("check #5 should fail; got pass")
		}
	}
}

func TestRun_GovernanceMissingFails(t *testing.T) {
	body := strings.Replace(validSkillMD, "governance_level: yellow\n", "", 1)
	dir := writeSkill(t, body, map[string]string{"tests/smoke.sh": "#!/bin/sh\nexit 0\n"})
	r := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		// No AuthorIntent override either.
	})
	for _, c := range r.Checks {
		if c.Number == 6 && c.Pass {
			t.Errorf("check #6 should fail; got pass")
		}
	}
}

func TestRun_YellowRequiresRationale(t *testing.T) {
	dir := writeSkill(t, validSkillMD, map[string]string{"tests/smoke.sh": "#!/bin/sh\nexit 0\n"})
	r := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		AuthorIntent: "yellow",
		// No Rationale.
	})
	if r.AllPassed {
		t.Errorf("yellow without rationale should fail check #7")
	}
}

func TestRun_GreenSkipsRationaleCheck(t *testing.T) {
	body := strings.Replace(validSkillMD, "governance_level: yellow", "governance_level: green", 1)
	dir := writeSkill(t, body, map[string]string{"tests/smoke.sh": "#!/bin/sh\nexit 0\n"})
	r := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		AuthorIntent: "green",
	})
	for _, c := range r.Checks {
		if c.Number == 7 {
			if !c.Skipped {
				t.Errorf("check #7 should be SKIPPED for green; got pass=%v skipped=%v", c.Pass, c.Skipped)
			}
		}
	}
}

func TestRun_NoSmokeMarkerFails(t *testing.T) {
	dir := writeSkill(t, validSkillMD, nil) // no tests/smoke.sh
	r := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		AuthorIntent: "yellow", Rationale: "x",
	})
	for _, c := range r.Checks {
		if c.Number == 9 && c.Pass {
			t.Errorf("check #9 should fail without smoke marker")
		}
	}
}

func TestRun_SkipSmokeFlagBypassesCheck9(t *testing.T) {
	dir := writeSkill(t, validSkillMD, nil)
	r := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		AuthorIntent: "yellow", Rationale: "x",
		SkipSmoke: true,
	})
	for _, c := range r.Checks {
		if c.Number == 9 {
			if !c.Skipped {
				t.Errorf("check #9 should be SKIPPED when --skip-smoke set")
			}
		}
	}
	if !r.AllPassed {
		t.Errorf("all other checks should pass when --skip-smoke is set")
	}
}

func TestRun_VersionMonotonicityCheck10(t *testing.T) {
	dir := writeSkill(t, validSkillMD, map[string]string{"tests/smoke.sh": "#!/bin/sh\nexit 0\n"})

	// Same version → fail.
	r := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		AuthorIntent: "yellow", Rationale: "x",
		LastAdmittedVersion: "1.0.0",
	})
	for _, c := range r.Checks {
		if c.Number == 10 && c.Pass {
			t.Errorf("check #10 should fail when proposed == last admitted")
		}
	}

	// Higher version → pass.
	r2 := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		ProposedVersion: "1.0.1",
		AuthorIntent:    "yellow", Rationale: "x",
		LastAdmittedVersion: "1.0.0",
	})
	for _, c := range r2.Checks {
		if c.Number == 10 && !c.Pass && !c.Skipped {
			t.Errorf("check #10 should pass when proposed > last admitted; reason=%q", c.Reason)
		}
	}
}

func TestRun_BugReportsCheck8(t *testing.T) {
	dir := writeSkill(t, validSkillMD, map[string]string{"tests/smoke.sh": "#!/bin/sh\nexit 0\n"})
	bugDir := t.TempDir()

	// One unrelated bug report — should not match.
	if err := os.WriteFile(filepath.Join(bugDir, "BUG-0001-something-else.md"),
		[]byte("# BUG\nunrelated to the skill"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	r := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		AuthorIntent: "yellow", Rationale: "x",
		BugReportsDir: bugDir,
	})
	for _, c := range r.Checks {
		if c.Number == 8 && !c.Pass {
			t.Errorf("check #8 should pass when no relevant bug; got %q", c.Reason)
		}
	}

	// Add a matching bug report.
	if err := os.WriteFile(filepath.Join(bugDir, "BUG-0042-didactic-session-broken.md"),
		[]byte("# BUG\nThe didactic-session skill returns an error when..."), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r2 := Run(CheckOptions{
		SkillDir: dir, SkillName: "didactic-session",
		AuthorIntent: "yellow", Rationale: "x",
		BugReportsDir: bugDir,
	})
	for _, c := range r2.Checks {
		if c.Number == 8 && c.Pass {
			t.Errorf("check #8 should fail when matching bug present")
		}
	}
}

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"2.0.0", "1.99.99", 1},
		{"1.0.0-rc1", "1.0.0", 0}, // pre-release stripped; equal cores
	}
	for _, tc := range cases {
		if got := compareSemver(tc.a, tc.b); got != tc.want {
			t.Errorf("compareSemver(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
