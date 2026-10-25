//go:build !windows

package mutationstate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func TestStateUnixRefusesUnsafeAuthorityPaths(t *testing.T) {
	for _, kind := range []string{"record_symlink", "record_hardlink", "record_mode", "registry_dir_mode", "lock_symlink", "lock_mode"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			enrollFixture(t, f, 7)
			record := stateJSONPath(t, f.store.dir)
			switch kind {
			case "record_symlink":
				raw, err := os.ReadFile(record)
				if err != nil {
					t.Fatal(err)
				}
				external := filepath.Join(t.TempDir(), "record.json")
				if err := os.WriteFile(external, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(record); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, record); err != nil {
					t.Fatal(err)
				}
			case "record_hardlink":
				if err := os.Link(record, filepath.Join(t.TempDir(), "record-link.json")); err != nil {
					t.Fatal(err)
				}
			case "record_mode":
				if err := os.Chmod(record, 0644); err != nil {
					t.Fatal(err)
				}
			case "registry_dir_mode":
				if err := os.Chmod(f.store.dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "lock_symlink":
				if err := os.Remove(f.store.lockPath); err != nil {
					t.Fatal(err)
				}
				external := filepath.Join(t.TempDir(), "lock")
				if err := os.WriteFile(external, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(external, f.store.lockPath); err != nil {
					t.Fatal(err)
				}
			case "lock_mode":
				if err := os.Chmod(f.store.lockPath, 0644); err != nil {
					t.Fatal(err)
				}
			}
			s := f.reopen(t)
			if _, err := s.Status(context.Background()); err == nil {
				t.Fatal("unsafe state path accepted")
			}
			if session, err := s.Begin(context.Background(), verify.MutationInstall, f.digest); err == nil || session != nil {
				t.Fatal("unsafe state path authorized mutation")
			}
		})
	}
}

func TestStateUnixSelectedBaseSymlinkRefused(t *testing.T) {
	f := newStateFixture(t)
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link, f.root); err == nil {
		t.Fatal("selected symlink base accepted")
	}
}
