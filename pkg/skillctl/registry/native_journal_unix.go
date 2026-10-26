//go:build !windows

package registry

import (
	"errors"
	"os"
	"syscall"
)

func nativeJournalSecure(string) error { return nil }
func nativeJournalPermissions(_ string, info os.FileInfo, dir bool) error {
	want := os.FileMode(0600)
	if dir {
		want = 0700
	}
	if info.Mode().Perm() != want || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrNativeHistoryInvalid
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) != int64(os.Geteuid()) || (!dir && st.Nlink != 1) {
		return ErrNativeHistoryInvalid
	}
	return nil
}
func nativeJournalCheckOpened(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	return nativeJournalPermissions("", info, false)
}
func nativeJournalSyncDir(path string) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	f, err := root.Open(".")
	if err != nil {
		return errors.Join(err, root.Close())
	}
	return errors.Join(f.Sync(), f.Close(), root.Close())
}
