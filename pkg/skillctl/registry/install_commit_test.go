package registry

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallCommitRecovery(t *testing.T) {
	for _, scenario := range []string{"success", "backup fails", "commit fails", "restore fails"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			target, staged := filepath.Join(root, "skill"), filepath.Join(root, "staged")
			for path, content := range map[string]string{target: "previous", staged: "replacement"} {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var backup string
			injected := errors.New("injected rename failure")
			rename := func(from, to string) error {
				if from == target {
					backup = to
					if scenario == "backup fails" {
						return injected
					}
				}
				if from == staged && (scenario == "commit fails" || scenario == "restore fails") {
					return injected
				}
				if from == backup && scenario == "restore fails" {
					return injected
				}
				return os.Rename(from, to)
			}
			overwrite, _, err := commitInstallDirectory(staged, target, rename, os.RemoveAll)
			if scenario == "success" {
				if err != nil || !overwrite {
					t.Fatalf("commit = %v, %v", overwrite, err)
				}
				assertInstallContent(t, target, "replacement")
				if _, err := os.Stat(filepath.Dir(backup)); !os.IsNotExist(err) {
					t.Fatalf("successful commit retained backup: %v", err)
				}
				return
			}
			if !errors.Is(err, injected) {
				t.Fatalf("injected failure not returned: %v", err)
			}
			if scenario == "restore fails" {
				assertInstallContent(t, backup, "previous")
				if !strings.Contains(err.Error(), backup) {
					t.Fatalf("recovery location missing from error: %v", err)
				}
			} else {
				assertInstallContent(t, target, "previous")
			}
		})
	}
}

func assertInstallContent(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(path, "SKILL.md"))
	if err != nil || string(data) != want {
		t.Fatalf("content at %s = %q, %v; want %q", path, data, err, want)
	}
}

func TestInstallCommitCleanupWarning(t *testing.T) {
	root := t.TempDir()
	target, staged := filepath.Join(root, "skill"), filepath.Join(root, "staged")
	for _, path := range []string{target, staged} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	overwrite, backup, err := commitInstallDirectory(staged, target, os.Rename, func(string) error {
		return errors.New("injected cleanup failure")
	})
	if err != nil || !overwrite || backup == "" {
		t.Fatalf("successful commit must return its cleanup warning separately: %v, %q, %v", overwrite, backup, err)
	}
	for _, path := range []string{target, filepath.Join(backup, "previous")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected installed/backup directory %s: %v", path, err)
		}
	}
}

func TestInstallCommitFreshAndNonDirectory(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing-file-%v", existing), func(t *testing.T) {
			root := t.TempDir()
			target, staged := filepath.Join(root, "skill"), filepath.Join(root, "staged")
			if err := os.Mkdir(staged, 0o700); err != nil {
				t.Fatal(err)
			}
			if existing {
				if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			overwrite, _, err := commitInstallDirectory(staged, target, os.Rename, os.RemoveAll)
			if (err != nil) != existing || overwrite {
				t.Fatalf("commit = %v, %v", overwrite, err)
			}
			if existing {
				data, err := os.ReadFile(target)
				if err != nil || string(data) != "preserve" {
					t.Fatalf("non-directory target was modified: %q, %v", data, err)
				}
			}
		})
	}
}
