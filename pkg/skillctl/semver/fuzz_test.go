package semver

// Native Go fuzz target for the loose-semver comparator. Version strings come
// from manifests and git tags (untrusted), and Compare gates version
// monotonicity + "highest non-revoked version" selection in a trust path, so a
// panic or an ordering inconsistency here is a correctness bug. The oracles are
// the order axioms the callers rely on.

import "testing"

// FuzzCompare checks the comparator's total-preorder axioms under fuzzed input.
// Oracles: never panics; antisymmetry Compare(a,b) == -Compare(b,a);
// reflexivity Compare(a,a) == 0.
func FuzzCompare(f *testing.F) {
	seeds := [][2]string{
		{"1.2.0", "1.2.0"},
		{"1.2.0", "1.2.3"},
		{"v1.2.0", "1.2.0"},
		{"1.0.0-rc", "1.0.0"},
		{"1.0.0+meta", "1.0.0"},
		{"2.0", "1.9.9"},
		{"", "0"},
		{"1.2.0-rc.1", "1.2.0"},
		{"v0", "v0.0.0"},
		{"abc", "1.0.0"},
		{"1.2.3.4.5", "1.2.3"},
		{"  1.2.0  ", "1.2.0"},
		{"99999999999999999999", "1"}, // Atoi overflow path, both sides
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, a, b string) {
		ab := Compare(a, b) // must never panic
		ba := Compare(b, a)
		if ab != -ba {
			t.Fatalf("antisymmetry violated: Compare(%q,%q)=%d but -Compare(%q,%q)=%d", a, b, ab, b, a, -ba)
		}
		if aa := Compare(a, a); aa != 0 {
			t.Fatalf("reflexivity violated: Compare(%q,%q)=%d, want 0", a, a, aa)
		}
		if ab < -1 || ab > 1 {
			t.Fatalf("Compare(%q,%q)=%d out of the {-1,0,1} range", a, b, ab)
		}
	})
}
