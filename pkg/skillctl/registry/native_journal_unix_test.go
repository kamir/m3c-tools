//go:build !windows

package registry

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func nativeJournalCheckPlatformPermissions(t *testing.T) {
	t.Helper()
	t.Run("platform-private-permissions", func(t *testing.T) {
		for _, directory := range []bool{false, true} {
			path := filepath.Join(t.TempDir(), "private-object")
			mode := os.FileMode(0600)
			if directory {
				mode = 0700
				if err := os.Mkdir(path, mode); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("fixture"), mode); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = nativeJournalPermissions(path, info, directory); err != nil {
				t.Fatal("private ordinary object rejected", err)
			}
			if err = os.Chmod(path, mode|0044); err != nil {
				t.Fatal(err)
			}
			info, err = os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = nativeJournalPermissions(path, info, directory); !errors.Is(err, ErrNativeHistoryInvalid) {
				t.Fatal("group/other access accepted", err)
			}
		}
	})
}

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
