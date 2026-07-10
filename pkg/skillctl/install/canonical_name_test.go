package install

import (
	"errors"
	"testing"
)

// TestCanonicalSkillName_FixedPoint locks SEC F12: the gate and the verifier
// must resolve the SAME directory for any given invoked name. The root cause
// was that the verifier resolved a LOSSY sanitizeFilename(name) (dropping unsafe
// chars) while the gate classified/loaded the raw name — so two distinct names
// could collapse to one dir, letting a clean sibling be verified while a
// malicious dir loaded.
//
// CanonicalSkillName must therefore NEVER silently rewrite: a valid name comes
// back verbatim (idempotent fixed point); an unsafe one is rejected. In
// particular it must never map two distinct valid names onto the same output.
func TestCanonicalSkillName_FixedPoint(t *testing.T) {
	valid := []string{"er1-push", "er1_push", "browse", "a.b.c", "Foo123", "er1@push", "plugin:foo", "skill name"}
	for _, n := range valid {
		got, err := CanonicalSkillName(n)
		if err != nil {
			t.Errorf("CanonicalSkillName(%q) unexpectedly rejected: %v", n, err)
			continue
		}
		if got != n {
			t.Errorf("CanonicalSkillName(%q) = %q — must be verbatim (no lossy rewrite)", n, got)
		}
		// Idempotent fixed point.
		if again, err := CanonicalSkillName(got); err != nil || again != got {
			t.Errorf("not idempotent: CanonicalSkillName(%q) = %q, err=%v", got, again, err)
		}
	}

	unsafe := []string{"", ".", "..", "../etc", "a/b", "a\\b", "a\x00b", "/abs", "..hidden-climb", "x\x1fy"}
	for _, n := range unsafe {
		if got, err := CanonicalSkillName(n); err == nil {
			t.Errorf("CanonicalSkillName(%q) = %q, want rejection", n, got)
		} else if !errors.Is(err, ErrUnsafeSkillName) {
			t.Errorf("CanonicalSkillName(%q) error %v, want ErrUnsafeSkillName", n, err)
		}
	}

	// The divergence proof: names that the OLD lossy sanitizeFilename collapsed
	// onto the SAME dir must NOT collapse under CanonicalSkillName — either they
	// survive distinct (verbatim) or are rejected, but two distinct accepted
	// names never share an output.
	pairs := [][2]string{{"er1@push", "er1push"}, {"a b", "ab"}, {"x!y", "xy"}}
	for _, p := range pairs {
		a, aErr := CanonicalSkillName(p[0])
		b, bErr := CanonicalSkillName(p[1])
		if aErr == nil && bErr == nil && a == b && p[0] != p[1] {
			t.Errorf("collision: CanonicalSkillName(%q) == CanonicalSkillName(%q) == %q (lossy)", p[0], p[1], a)
		}
		// Sanity that the old transform really would have collided (documents the bug).
		if sanitizeFilename(p[0]) != sanitizeFilename(p[1]) {
			t.Logf("note: sanitizeFilename(%q)=%q vs (%q)=%q", p[0], sanitizeFilename(p[0]), p[1], sanitizeFilename(p[1]))
		}
	}
}
