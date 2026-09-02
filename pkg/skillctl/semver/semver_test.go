package semver

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Basic ordering.
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.1.9", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0", "1.0.0", 0},
		// THE BUG FIX: a leading "v" is stripped, so these are EQUAL. The prior
		// registry/install_trust_mode copy did NOT strip "v" and returned
		// "v1.2.0" < "1.2.0" (v1.2.0 parsed as major 0) — this case bites it.
		{"v1.2.0", "1.2.0", 0},
		{"v2.0.0", "1.9.9", 1}, // old registry impl: "v2..."→0 → wrongly -1
		{"1.2.0", "v1.2.1", -1},
		// Pre-release / build metadata dropped → EQUAL to the release core
		// (preserves all four prior call sites' behavior; NOT SemVer precedence).
		{"1.0.0-rc.1", "1.0.0", 0},
		{"1.0.0+build7", "1.0.0", 0},
		{"1.0.1-rc", "1.0.0", 1},
		{"v1.0.0-rc", "1.0.0", 0},
		// Zero-extend shorter forms.
		{"1.2", "1.2.0", 0},
		{"1", "1.0.0", 0},
		{"1.2.0.0", "1.2", 0},
		// Non-numeric fields fall back to 0.
		{"1.x.0", "1.0.9", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// Antisymmetry.
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

// TestMax_MixedVPrefix is the "pick highest non-revoked version" bite: a list
// mixing v-prefixed and bare tags must pick the true maximum. The old registry
// impl would sort "v1.3.0" as major 0 and pick "1.2.0" instead.
func TestMax_MixedVPrefix(t *testing.T) {
	got := Max([]string{"1.1.0", "v1.3.0", "1.2.0", "1.0.9"})
	if got != "v1.3.0" {
		t.Fatalf("Max mixed v-prefix = %q, want v1.3.0 (old registry impl mis-picks 1.2.0)", got)
	}
	if Max(nil) != "" {
		t.Errorf("Max(nil) = %q, want empty", Max(nil))
	}
	if got := Max([]string{"3.0.0"}); got != "3.0.0" {
		t.Errorf("Max single = %q, want 3.0.0", got)
	}
}

// TestMonotonicity mirrors the propose-gate use (proposed must be > lastAdmitted):
// a pre-release of the SAME core is not a valid increment, but a higher core is.
func TestMonotonicity(t *testing.T) {
	if Compare("1.0.0-rc", "1.0.0") > 0 {
		t.Error("1.0.0-rc must NOT count as > 1.0.0 (pre-release is not an increment)")
	}
	if Compare("1.0.1", "1.0.0") <= 0 {
		t.Error("1.0.1 must count as > 1.0.0")
	}
}

func TestLess(t *testing.T) {
	if !Less("1.0.0", "1.0.1") || Less("1.0.1", "1.0.0") || Less("1.0.0", "1.0.0") {
		t.Error("Less is inconsistent with Compare")
	}
}
