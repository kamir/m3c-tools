// flag_order_test.go: BUG-0450 for skillctl.
//
// install, verify and export-bundle stopped parsing at the name, so
// `skillctl install <name> --registry <url>` ended with a usage line (exit 2)
// while `skillctl publish <name> --kind agent` accepted the same order. The
// handbook lines that new users type first ended that way. Each case below runs
// once with flags first and once with the name first; both orders must reach
// the same exit code, and the name-first order must not be a usage error.
package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestBUG0450_SkillctlAcceptsFlagsAfterName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TRUST_ROOTS", filepath.Join(home, "absent-trust-roots.yaml"))
	out := filepath.Join(home, "out")
	for _, tc := range []struct {
		name  string
		run   func(args []string, stdout, stderr *bytes.Buffer) int
		flags []string
		pos   []string
	}{
		{"install", func(a []string, o, e *bytes.Buffer) int { return runInstall(a, o, e) },
			[]string{"--home", home}, []string{"demo@1.0.0"}},
		{"verify", func(a []string, o, e *bytes.Buffer) int { return runVerify(a, o, e) },
			[]string{"--home", home}, []string{"demo"}},
		{"export-bundle", func(a []string, o, e *bytes.Buffer) int { return runExportBundle(a, o, e) },
			[]string{"--out", out}, []string{"demo@1.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var o1, e1, o2, e2 bytes.Buffer
			first := tc.run(append(append([]string{}, tc.flags...), tc.pos...), &o1, &e1)
			after := tc.run(append(append([]string{}, tc.pos...), tc.flags...), &o2, &e2)
			if first == exitUsage {
				t.Fatalf("flags-first order is itself a usage error, the case proves nothing: %s", &e1)
			}
			if after != first {
				t.Fatalf("name-first exit=%d, flags-first exit=%d\nname-first stderr:\n%s", after, first, &e2)
			}
		})
	}
}
