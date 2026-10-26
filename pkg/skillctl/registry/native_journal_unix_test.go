//go:build !windows

package registry

import (
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func nativeJournalSpecialKinds() []string {
	return []string{"directory", "fifo", "symlink-fifo", "hardlink"}
}
func nativeJournalMakeSpecial(t *testing.T, path, kind string) {
	t.Helper()
	switch kind {
	case "directory":
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	case "fifo":
		if err := unix.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
	case "symlink-fifo":
		if err := unix.Mkfifo(path+".fifo", 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path+".fifo", path); err != nil {
			t.Fatal(err)
		}
	case "hardlink":
		if err := os.WriteFile(path+".outside", []byte("not-a-record"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path+".outside", path); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown fixture kind")
	}
}
