package delta

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSealFilesAreOwnerOnly pins the challenge-gate MED fix: the scanner's
// SealStore.Seal writes trust artifacts (the seal record AND the full installed
// inventory) owner-only (0600), in an owner-only store dir (0700) — never
// world-readable, matching the review-server seal path.
func TestSealFilesAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "seals") // fresh → NewSealStoreAt MkdirAll's it
	store, err := NewSealStoreAt(dir)
	if err != nil {
		t.Fatalf("NewSealStoreAt: %v", err)
	}
	record, err := store.Seal(testInventory(), "test-user")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if runtime.GOOS == "windows" { // POSIX mode bits are not enforced on Windows
		t.Skip("POSIX mode bits are not enforced on Windows")
	}

	if info, err := os.Stat(dir); err != nil {
		t.Fatalf("stat store dir: %v", err)
	} else if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("store dir mode = %o, want 0700", perm)
	}

	for _, p := range []string{filepath.Join(dir, record.SealID+".json"), record.InventoryPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 0600 (trust seal, not world-readable)", filepath.Base(p), perm)
		}
	}
}
