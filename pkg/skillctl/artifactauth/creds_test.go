package artifactauth

import (
	"context"
	"testing"
)

func TestResolverEnvOverride(t *testing.T) {
	t.Setenv("M3C_GITLAB_TOKEN", "env-pat-123")
	c, err := New().Credential(context.Background(), "gitlab", "192.168.0.135:8929")
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "env-pat-123" || c.User != "oauth2" || c.Scheme != "gitlab" {
		t.Errorf("got %+v", c)
	}
}

func TestResolverUnknownSchemeAnonymous(t *testing.T) {
	c, err := New().Credential(context.Background(), "oci", "ghcr.io")
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
	c, err := New().Credential(context.Background(), "gitlab", "no-such-host.invalid:9999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Token != "" {
		t.Skip("a Keychain entry exists for the probe host on this machine; skipping")
	}
}
