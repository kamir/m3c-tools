package registry

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallRejectsNonportableNames(t *testing.T) {
	for _, name := range []string{"a:stream", "CON", "nul.txt", "COM1", "COM¹.ext", "CON .txt", "lpt9.ext", "trailing.", "trailing "} {
		if err := sanitizeBundleName(name); !errors.Is(err, ErrUnsafeBundleName) {
			t.Errorf("%q: want unsafe name error, got %v", name, err)
		}
	}
}

func TestStashInstalledBundleRefusesCollisionAndEscape(t *testing.T) {
	dir := t.TempDir()
	if err := stashInstalledBundle(dir, "demo.skb", []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := stashInstalledBundle(dir, "demo.skb", []byte("replacement")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("want collision error, got %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "demo.skb"))
	if err != nil || string(got) != "original" {
		t.Fatalf("original changed: %q %v", got, err)
	}
	if err := stashInstalledBundle(dir, "../escape.skb", []byte("escape")); err == nil {
		t.Fatal("escape accepted")
	}
	outside := filepath.Join(t.TempDir(), "outside.skb")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.skb")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := stashInstalledBundle(dir, "link.skb", []byte("replacement")); err == nil {
		t.Fatal("symlink accepted")
	}
	got, err = os.ReadFile(outside)
	if err != nil || string(got) != "outside" {
		t.Fatalf("symlink target changed: %q %v", got, err)
	}
}
