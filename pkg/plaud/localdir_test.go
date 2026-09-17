package plaud

import (
	"path/filepath"
	"testing"
)

func TestLocalSyncDir_RejectsTraversal(t *testing.T) {
	if _, err := LocalSyncDir("/tmp", "../etcpasswd"); err == nil {
		t.Fatal("expected error for a path-like id")
	}
	if _, err := LocalSyncDir("/tmp", "ab/cd/efgh"); err == nil {
		t.Fatal("expected error for an id containing slashes")
	}
	got, err := LocalSyncDir("/tmp", "abcdefgh")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join("/tmp", "plaud-sync", "abcdefgh")
	if got != want {
		t.Errorf("LocalSyncDir = %q, want %q", got, want)
	}
}
