package er1

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteConfigReplacesPermissiveFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(home, ".m3c-tools.env")
	if err := os.WriteFile(path, []byte("old\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteConfig("https://example.test/upload_2", "synthetic-key", "context", true, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions=%o", info.Mode().Perm())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "ER1_API_KEY=synthetic-key\n") {
		t.Fatal("new configuration missing")
	}
	leftovers, err := filepath.Glob(filepath.Join(home, ".private-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("leftover temp files=%v error=%v", leftovers, err)
	}
}

func TestWriteConfigRefusesSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	target := filepath.Join(t.TempDir(), "unrelated.txt")
	if err := os.WriteFile(target, []byte("keep this content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".m3c-tools.env")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := WriteConfig("https://example.test", "synthetic-key", "context", true, ""); err == nil {
		t.Fatal("symlink config accepted")
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "keep this content" {
		t.Fatalf("symlink target modified: %q %v", content, err)
	}
}
