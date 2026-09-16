package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// SPEC-0432 §8. The three outcomes, and the one that must NOT happen.

func TestParseDeclaredDeps(t *testing.T) {
	good, err := parseDeclaredDeps([]string{"skill:didactic-session", " agent:release-agent "})
	if err != nil {
		t.Fatalf("parseDeclaredDeps: %v", err)
	}
	if len(good) != 2 || good[0].Kind != "skill" || good[0].Name != "didactic-session" {
		t.Fatalf("parsed = %+v", good)
	}
	for _, bad := range []string{"didactic-session", "skill:", ":name", "zauber:x"} {
		if _, err := parseDeclaredDeps([]string{bad}); err == nil {
			t.Errorf("parseDeclaredDeps(%q) accepted a malformed entry", bad)
		}
	}
}

// TestScanOnlyMatchesPathForm is AC-15, the counter-probe against over-blocking.
// Matching every mention hits 8 of 20 agents; the path form hits 2, and those
// two are the real dependencies.
func TestScanOnlyMatchesPathForm(t *testing.T) {
	reverse := []byte("Parses a transcript.\nInvoked by /session-review.\n" +
		"It complements the /security-scan skill and /review-plan.\n")
	if got := scanSkillPathMentions(reverse); len(got) != 0 {
		t.Fatalf("the reverse direction warned: %+v", got)
	}

	forward := []byte("# didactic-reviewer\n\nSome prose.\n" +
		"Read `~/.claude/skills/didactic-session/profiles/<role>.md` for the criteria.\n")
	got := scanSkillPathMentions(forward)
	if len(got) != 1 || got[0].name != "didactic-session" || got[0].line != 4 {
		t.Fatalf("path form scan = %+v, want didactic-session at line 4", got)
	}
}

// TestCheckAgentDepsCatalogSaysNo is AC-7: a definite no stops the build.
func TestCheckAgentDepsCatalogSaysNo(t *testing.T) {
	var errBuf bytes.Buffer
	deps, _ := parseDeclaredDeps([]string{"skill:gibt-es-nicht"})
	err := checkAgentDeps("a.md", []byte("x\n"), deps,
		func(kind, name string) (bool, error) { return false, nil }, &errBuf)
	if err == nil {
		t.Fatal("a missing declared dependency did not stop the build")
	}
	for _, want := range []string{"skill:gibt-es-nicht", "no bundle written"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// TestCheckAgentDepsCatalogUnreachable is AC-16 / E-5: no answer is not a no.
func TestCheckAgentDepsCatalogUnreachable(t *testing.T) {
	var errBuf bytes.Buffer
	deps, _ := parseDeclaredDeps([]string{"skill:didactic-session"})
	err := checkAgentDeps("a.md", []byte("x\n"), deps,
		func(kind, name string) (bool, error) { return false, errors.New("dial tcp: timeout") },
		&errBuf)
	if err != nil {
		t.Fatalf("an unreachable catalog stopped the build: %v", err)
	}
	msg := errBuf.String()
	for _, want := range []string{"warn:", "did not run", "skill:didactic-session"} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning %q does not carry %q", msg, want)
		}
	}
}

// TestCheckAgentDepsUndeclaredMention is AC-8: warn with the line, never abort.
func TestCheckAgentDepsUndeclaredMention(t *testing.T) {
	var errBuf bytes.Buffer
	body := []byte("line one\nline two\nRead ~/.claude/skills/didactic-session/SKILL.md\n")
	err := checkAgentDeps("didactic-reviewer.md", body, nil, nil, &errBuf)
	if err != nil {
		t.Fatalf("an undeclared mention stopped the build: %v", err)
	}
	msg := errBuf.String()
	for _, want := range []string{"didactic-reviewer.md:3", "skills/didactic-session"} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning %q does not carry %q", msg, want)
		}
	}
}

// TestCheckAgentDepsDeclaredAndFound: the quiet path. Declared, in the catalog,
// mentioned in prose: no warning at all, because there is nothing to report.
func TestCheckAgentDepsDeclaredAndFound(t *testing.T) {
	var errBuf bytes.Buffer
	deps, _ := parseDeclaredDeps([]string{"skill:didactic-session"})
	body := []byte("Read ~/.claude/skills/didactic-session/SKILL.md\n")
	if err := checkAgentDeps("a.md", body, deps,
		func(kind, name string) (bool, error) { return true, nil }, &errBuf); err != nil {
		t.Fatalf("checkAgentDeps: %v", err)
	}
	if errBuf.Len() != 0 {
		t.Fatalf("a fully declared dependency produced output: %q", errBuf.String())
	}
}

// TestEnsureBundleAgentDepsReachBundle: end to end through the packer. The
// declaration lands in bundle.json, and a denied one leaves no file behind.
func TestEnsureBundleAgentDepsReachBundle(t *testing.T) {
	src := t.TempDir()
	def := filepath.Join(src, "helper-agent.md")
	body := "---\nname: helper-agent\ndepends_on:\n  - skill:didactic-session\n---\n\nRead the profiles.\n"
	if err := os.WriteFile(def, []byte(body), 0644); err != nil {
		t.Fatalf("write def: %v", err)
	}

	t.Run("found", func(t *testing.T) {
		t.Chdir(t.TempDir())
		out, _, err := ensureBundle(publishAdmitArgs{
			name: "helper-agent", version: "1.0.0",
			kind: skillbundle.KindAgent, agentFile: def,
			catalogLookup: func(kind, name string) (bool, error) { return true, nil },
		}, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("ensureBundle: %v", err)
		}
		m := bundleManifestOf(t, out)
		deps, _ := m["depends_on"].([]any)
		if len(deps) != 1 {
			t.Fatalf("depends_on = %v, want one entry", m["depends_on"])
		}
		d, _ := deps[0].(map[string]any)
		if d["kind"] != "skill" || d["name"] != "didactic-session" {
			t.Fatalf("dependency = %v", d)
		}
	})

	t.Run("denied", func(t *testing.T) {
		work := t.TempDir()
		t.Chdir(work)
		_, _, err := ensureBundle(publishAdmitArgs{
			name: "helper-agent", version: "1.0.0",
			kind: skillbundle.KindAgent, agentFile: def,
			catalogLookup: func(kind, name string) (bool, error) { return false, nil },
		}, &bytes.Buffer{})
		if err == nil {
			t.Fatal("a denied dependency still produced a bundle")
		}
		if entries, _ := os.ReadDir(work); len(entries) != 0 {
			t.Fatalf("something was written despite the error: %v", entries)
		}
	})
}
