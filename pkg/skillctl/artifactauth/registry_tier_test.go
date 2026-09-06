package artifactauth

import (
	"context"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// The read tier is preferred on a read, and the write tier is the fallback. An
// operator who provisioned both must never transmit the write token on a pull;
// one who provisioned only the write token must keep working.
func TestRegistryTierPrecedence(t *testing.T) {
	t.Setenv("M3C_REGISTRY_TOKEN", "write-token")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "read-token")

	got, err := New().Credential(context.Background(), "registry", "reg.example", artifact.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "read-token" {
		t.Errorf("read mode took %q, want the read tier", got.Token)
	}

	got, err = New().Credential(context.Background(), "registry", "reg.example", artifact.ModeWrite)
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "write-token" {
		t.Errorf("write mode took %q, want the write tier", got.Token)
	}
}

func TestRegistryReadFallsBackToTheWriteTier(t *testing.T) {
	t.Setenv("M3C_REGISTRY_TOKEN", "write-token")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "")

	got, err := New().Credential(context.Background(), "registry", "reg.example", artifact.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "write-token" {
		t.Errorf("a single-token setup must keep working; got %q", got.Token)
	}
}

// Nothing provisioned is anonymous with a nil error, not a failure: a public
// instance has to keep working for someone who set nothing up.
func TestRegistryWithoutCredentialIsAnonymous(t *testing.T) {
	t.Setenv("M3C_REGISTRY_TOKEN", "")
	t.Setenv("M3C_REGISTRY_RO_TOKEN", "")

	got, err := New().Credential(context.Background(), "registry", "", artifact.ModeRead)
	if err != nil {
		t.Fatalf("a missing credential must not be an error: %v", err)
	}
	if got.Token != "" {
		t.Errorf("expected anonymous, got a token")
	}
}
