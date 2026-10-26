//go:build !windows

package projectpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func nativeProfileSpecialFiles(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	fifo := filepath.Join(dir, "selected-fifo")
	if e := unix.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "selected-link")
	if e := os.Symlink(fifo, link); e != nil {
		t.Fatal(e)
	}
	return []string{dir, fifo, link}
}
