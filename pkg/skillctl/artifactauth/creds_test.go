package artifactauth

import (
	"context"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

func TestResolverEnvOverride(t *testing.T) {
	t.Setenv("M3C_GITLAB_TOKEN", "env-pat-123")
	c, err := New().Credential(context.Background(), "gitlab", "192.168.0.135:8929", artifact.ModeWrite)
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "env-pat-123" || c.User != "oauth2" || c.Scheme != "gitlab" {
		t.Errorf("got %+v", c)
	}
}

func TestResolverUnknownSchemeAnonymous(t *testing.T) {
	c, err := New().Credential(context.Background(), "oci", "ghcr.io", artifact.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "" {
		t.Errorf("expected anonymous for unmanaged scheme, got %+v", c)
	}
}

func TestResolverAnonymousWhenNothingSet(t *testing.T) {
	t.Setenv("M3C_GITLAB_TOKEN", "")
	// A host with (almost certainly) no Keychain entry → anonymous, no error.
	c, err := New().Credential(context.Background(), "gitlab", "no-such-host.invalid:9999", artifact.ModeWrite)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Token != "" {
		t.Skip("a Keychain entry exists for the probe host on this machine; skipping")
	}
}

// TestResolverReadWriteSplit, CD-13: with BOTH a write PAT and a distinct
// read-only token provisioned, ModeRead resolves the read-only token and ModeWrite
// resolves the write PAT, so a verifying pull never transmits the write token.
func TestResolverReadWriteSplit(t *testing.T) {
	t.Setenv("M3C_GITLAB_TOKEN", "write-pat")
	t.Setenv("M3C_GITLAB_RO_TOKEN", "readonly-deploy-token")
	r := New()
	w, err := r.Credential(context.Background(), "gitlab", "gitlab.example.com", artifact.ModeWrite)
	if err != nil || w.Token != "write-pat" {
		t.Fatalf("ModeWrite = %+v, %v; want write-pat", w, err)
	}
	ro, err := r.Credential(context.Background(), "gitlab", "gitlab.example.com", artifact.ModeRead)
	if err != nil || ro.Token != "readonly-deploy-token" {
		t.Fatalf("ModeRead = %+v, %v; want readonly-deploy-token", ro, err)
	}
}

// TestResolverReadFallsBackToWrite, CD-13 backward compatibility: an operator who
// provisioned ONLY a write token still gets it on the read path (no RO token set),
// so a single-token setup is unchanged.
func TestResolverReadFallsBackToWrite(t *testing.T) {
	t.Setenv("M3C_GITLAB_TOKEN", "only-write-pat")
	t.Setenv("M3C_GITLAB_RO_TOKEN", "")
	ro, err := New().Credential(context.Background(), "gitlab", "gitlab.example.com", artifact.ModeRead)
	if err != nil || ro.Token != "only-write-pat" {
		t.Fatalf("ModeRead fallback = %+v, %v; want only-write-pat", ro, err)
	}
}
