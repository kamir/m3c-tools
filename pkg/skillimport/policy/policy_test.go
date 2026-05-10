package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillimport/parser"
)

const validHex = "a3f5b9c4e8d2f1a0b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4"

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "skill-import-policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func mustParseRef(t *testing.T, s string) *parser.Reference {
	t.Helper()
	r, err := parser.Parse(s)
	if err != nil {
		t.Fatalf("parser.Parse(%q): %v", s, err)
	}
	return r
}

func TestLoad_HappyPath(t *testing.T) {
	body := `version: 1
default_deny: true
allowed_hosts:
  - github.com
  - skillhub.club
blocked_hosts:
  - badhost.example
source_caps:
  github.com:
    max_intent_level: yellow
    blocked_owners:
      - unknown-vendor
      - sketchy-org
`
	p, err := Load(writePolicy(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Version != 1 {
		t.Errorf("Version = %d", p.Version)
	}
	if !p.DefaultDeny {
		t.Errorf("DefaultDeny = false, want true")
	}
	if len(p.AllowedHosts) != 2 || p.AllowedHosts[0] != "github.com" {
		t.Errorf("AllowedHosts = %v", p.AllowedHosts)
	}
	if len(p.BlockedHosts) != 1 || p.BlockedHosts[0] != "badhost.example" {
		t.Errorf("BlockedHosts = %v", p.BlockedHosts)
	}
	cap, ok := p.SourceCaps["github.com"]
	if !ok {
		t.Fatalf("SourceCaps missing github.com: %#v", p.SourceCaps)
	}
	if cap.MaxIntentLevel != "yellow" {
		t.Errorf("MaxIntentLevel = %q", cap.MaxIntentLevel)
	}
	if len(cap.BlockedOwners) != 2 {
		t.Errorf("BlockedOwners = %v", cap.BlockedOwners)
	}
}

func TestLoad_Missing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if !errors.Is(err, ErrNoSourcePolicy) {
		t.Errorf("err = %v, want ErrNoSourcePolicy", err)
	}
}

func TestLoad_VersionMismatch(t *testing.T) {
	body := `version: 2
default_deny: true
`
	_, err := Load(writePolicy(t, body))
	if err == nil || !strings.Contains(err.Error(), "unsupported source policy version") {
		t.Errorf("err = %v, want version mismatch", err)
	}
}

func TestLoad_Malformed(t *testing.T) {
	cases := []string{
		"version: notanumber\n",
		"version: 1\nweird_key: 1\n",
		"version: 1\nallowed_hosts: oops\n  - x\n", // value on the line + list below
	}
	for _, body := range cases {
		_, err := Load(writePolicy(t, body))
		if err == nil {
			t.Errorf("expected error for %q", body)
		}
	}
}

func TestLoad_Comments(t *testing.T) {
	body := `# top comment
version: 1   # trailing
default_deny: true
allowed_hosts:
  - github.com   # ok
`
	p, err := Load(writePolicy(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(p.AllowedHosts) != 1 || p.AllowedHosts[0] != "github.com" {
		t.Errorf("AllowedHosts = %v", p.AllowedHosts)
	}
}

func TestEvaluate_Allow(t *testing.T) {
	p := &SourcePolicy{
		Version:      1,
		DefaultDeny:  true,
		AllowedHosts: []string{"github.com"},
	}
	ref := mustParseRef(t, "github.com:anthropics/code-reviewer@sha256:"+validHex)
	d, reason := p.Evaluate(ref)
	if d != Allow || reason != ReasonOK {
		t.Errorf("got (%s,%s), want (allow, ok)", d, reason)
	}
}

func TestEvaluate_BlockedHost(t *testing.T) {
	p := &SourcePolicy{
		Version:      1,
		DefaultDeny:  false,
		AllowedHosts: []string{"github.com"},
		BlockedHosts: []string{"github.com"},
	}
	ref := mustParseRef(t, "github.com:o/n@sha256:"+validHex)
	d, reason := p.Evaluate(ref)
	if d != Block || reason != ReasonHostBlocked {
		t.Errorf("got (%s,%s), want (block, host_blocked)", d, reason)
	}
}

func TestEvaluate_BlockedOwner(t *testing.T) {
	p := &SourcePolicy{
		Version:      1,
		DefaultDeny:  true,
		AllowedHosts: []string{"github.com"},
		SourceCaps: map[string]SourceCap{
			"github.com": {BlockedOwners: []string{"unknown-vendor"}},
		},
	}
	ref := mustParseRef(t, "github.com:unknown-vendor/n@sha256:"+validHex)
	d, reason := p.Evaluate(ref)
	if d != Block || reason != ReasonOwnerBlocked {
		t.Errorf("got (%s,%s), want (block, owner_blocked)", d, reason)
	}
}

func TestEvaluate_DefaultDenyHostNotAllowed(t *testing.T) {
	p := &SourcePolicy{
		Version:      1,
		DefaultDeny:  true,
		AllowedHosts: []string{"github.com"},
	}
	ref := mustParseRef(t, "skillhub.club:o/n@sha256:"+validHex)
	d, reason := p.Evaluate(ref)
	if d != Block || reason != ReasonHostNotAllowed {
		t.Errorf("got (%s,%s), want (block, host_not_allowed)", d, reason)
	}
}

func TestEvaluate_DefaultAllowRequireReview(t *testing.T) {
	p := &SourcePolicy{
		Version:      1,
		DefaultDeny:  false,
		AllowedHosts: []string{"github.com"},
	}
	ref := mustParseRef(t, "skillhub.club:o/n@sha256:"+validHex)
	d, reason := p.Evaluate(ref)
	if d != RequireReview || reason != ReasonNoPolicyForHost {
		t.Errorf("got (%s,%s), want (require_review, no_policy_for_host)", d, reason)
	}
}

func TestEvaluate_NilSafe(t *testing.T) {
	var p *SourcePolicy
	d, reason := p.Evaluate(nil)
	if d != Block || reason != ReasonNoPolicyForHost {
		t.Errorf("nil-safe Evaluate returned (%s,%s)", d, reason)
	}
}

func TestDefaultPath(t *testing.T) {
	got := DefaultPath()
	if got == "" {
		t.Fatal("DefaultPath() empty")
	}
	if !strings.HasSuffix(got, filepath.Join(".claude", "skill-import-policy.yaml")) {
		t.Errorf("DefaultPath() = %q", got)
	}
}

func TestDecisionString(t *testing.T) {
	cases := map[Decision]string{
		Allow:         "allow",
		Block:         "block",
		RequireReview: "require_review",
		Decision(99):  "unknown",
	}
	for d, want := range cases {
		if got := d.String(); got != want {
			t.Errorf("Decision(%d).String() = %q, want %q", d, got, want)
		}
	}
}
