package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCreateProfileReplacesPermissiveFile(t *testing.T) {
	manager := &ProfileManager{BaseDir: t.TempDir()}
	if err := os.MkdirAll(manager.profilesDir(), 0700); err != nil {
		t.Fatal(err)
	}
	path, err := manager.profilePath("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := manager.CreateProfile("test", "synthetic", map[string]string{"ER1_API_KEY": "synthetic-key"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("profile permissions=%o", info.Mode().Perm())
	}
	privateFileNoTemps(t, manager.profilesDir())
}

func TestWritePrivateFileRefusesSymlinkWithoutChangingTarget(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "unrelated")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config")
	if err := os.Symlink(target, path); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := WritePrivateFile(path, []byte("synthetic secret")); err == nil {
		t.Fatal("symlink accepted")
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "original" {
		t.Fatalf("target modified: %q %v", content, err)
	}
	privateFileNoTemps(t, directory)
}

func TestWritePrivateFileCreationFailurePreservesOldFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions are not enforced on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory permission failure fixture")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "config")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0500); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(directory, 0700); err != nil {
			t.Error(err)
		}
	}()
	err := WritePrivateFile(path, []byte("synthetic secret"))
	if err == nil {
		t.Fatal("write unexpectedly succeeded in non-writable directory")
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "original" {
		t.Fatalf("old file modified: %q %v", content, err)
	}
	privateFileNoTemps(t, directory)
}

func privateFileNoTemps(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".private-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files=%v error=%v", matches, err)
	}
}

func TestWritePrivateFileRenameFailurePreservesOldFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	commitErr := errors.New("injected rename failure")
	called := false
	err := writePrivateFile(path, []byte("synthetic secret"), func(source, target string) error {
		called = true
		if target != path || filepath.Dir(source) != directory {
			t.Fatalf("unexpected rename paths: %s -> %s", source, target)
		}
		content, err := os.ReadFile(source)
		if err != nil || string(content) != "synthetic secret" {
			t.Fatalf("commit did not reach a complete temporary file: %q %v", content, err)
		}
		return commitErr
	})
	if !called || !errors.Is(err, commitErr) {
		t.Fatalf("rename called=%v, error=%v", called, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "original" {
		t.Fatalf("failed commit changed old file: %q %v", content, err)
	}
	privateFileNoTemps(t, directory)
}
