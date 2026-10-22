package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAgentRevocationListRegistryBinding(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const registry = "https://reg.example/api/skills"
	for _, tc := range []struct {
		name, rootURL, listURL string
		allowed                bool
	}{
		{"same", registry, registry, true},
		{"canonical-trimming", " " + registry + "/ ", registry + "/", true},
		{"foreign-path", registry, registry + "/foreign", false},
		{"foreign-host", registry, "https://foreign.invalid/api/skills", false},
		{"foreign-scheme", registry, "http://reg.example/api/skills", false},
		{"empty-root", "", registry, false},
		{"empty-list", registry, "", false},
		{"both-empty", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := revocationRoot(t, public)
			root.RegistryURL = tc.rootURL
			root.MinRevocationEpoch = 5
			list, err := NewSignedAgentRevocationList(tc.listURL, "2026-10-23T12:00:00Z", 7, []string{"agent:synthetic"}, private)
			if err != nil {
				t.Fatal(err)
			}
			set, err := VerifyAgentRevocationList(list, root, 5)
			if tc.allowed {
				if err != nil || len(set) != 1 {
					t.Fatalf("same-registry agent set refused: %v", err)
				}
			} else {
				if set != nil || !errors.Is(err, ErrRegistryNotTrusted) {
					t.Fatalf("foreign or empty registry agent set accepted: %v", err)
				}
				want := "agent revocation list: registry does not match pinned root: " + ErrRegistryNotTrusted.Error()
				if err.Error() != want {
					t.Fatal("registry mismatch diagnostic must not reflect input URLs")
				}
			}
			data, err := json.Marshal(list)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "agent-revocations.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, loadErr := LoadVerifiedAgentRevocations(path, root)
			if tc.allowed {
				if loadErr != nil || len(loaded) != 1 {
					t.Fatalf("same-registry loader failed: %v", loadErr)
				}
			} else if loaded != nil || !errors.Is(loadErr, ErrRegistryNotTrusted) {
				t.Fatalf("loader bypassed registry binding: %v", loadErr)
			}
		})
	}
}
