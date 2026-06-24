package testutil

import "testing"

// TestEnvEnabled covers the truthy/falsey parsing used by every Require* gate.
func TestEnvEnabled(t *testing.T) {
	const key = "M3C_TEST_REQUIREDEPS_PROBE"
	cases := []struct {
		val  string
		set  bool
		want bool
	}{
		{set: false, want: false}, // unset
		{val: "", set: true, want: false},
		{val: "0", set: true, want: false},
		{val: "false", set: true, want: false},
		{val: "1", set: true, want: true},
		{val: "true", set: true, want: true},
		{val: "yes", set: true, want: true},
	}
	for _, c := range cases {
		if c.set {
			t.Setenv(key, c.val)
		} else {
			// t.Setenv has no unset; emulate absence with an env that is never set.
			if v := envEnabled(key + "_NEVER_SET"); v {
				t.Fatalf("unset probe should be false")
			}
			continue
		}
		if got := envEnabled(key); got != c.want {
			t.Errorf("envEnabled(%q=%q) = %v, want %v", key, c.val, got, c.want)
		}
	}
}

// TestRequireGatesSkipWhenAbsent verifies that, with no env set, each helper
// skips. We run them in subtests and assert the subtest was skipped. This is
// what the Windows CI job relies on: env-clean → these tests self-skip.
func TestRequireGatesSkipWhenAbsent(t *testing.T) {
	gates := map[string]func(*testing.T){
		"ER1":     RequireER1,
		"Network": RequireNetwork,
		"Mic":     RequireMic,
		"Plaud":   RequirePlaud,
	}
	for name, gate := range gates {
		t.Run(name, func(t *testing.T) {
			// Force the env clean for this subtest.
			t.Setenv("M3C_TEST_"+upper(name), "0")
			gate(t)
			// If we reach here, the gate did NOT skip — that is a failure for
			// the absent-dependency contract.
			t.Fatalf("Require%s did not skip when dependency absent", name)
		})
	}
}

// upper maps the gate name to its env suffix (ER1→ER1, Network→NETWORK, …).
func upper(name string) string {
	switch name {
	case "ER1":
		return "ER1"
	case "Network":
		return "NETWORK"
	case "Mic":
		return "MIC"
	case "Plaud":
		return "PLAUD"
	}
	return name
}
