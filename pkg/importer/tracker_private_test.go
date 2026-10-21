package importer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestTrackerAppendRestrictsExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	path := filepath.Join(t.TempDir(), "tracker.md")
	if err := os.WriteFile(path, []byte("previous.wav\n"), 0644); err != nil {
		t.Fatal(err)
	}
	tracker, err := NewTracker(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Add("new.wav"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private tracker permissions: info=%v err=%v", info, err)
	}
	for _, name := range []string{"previous.wav", "new.wav"} {
		if tracked, err := tracker.IsTracked(name); err != nil || !tracked {
			t.Fatalf("lost tracked filename %q: %v", name, err)
		}
	}
}
