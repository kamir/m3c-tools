//go:build !windows

package mutationstate

import (
	"errors"
	"os"
	"syscall"
)

func secureCreated(string) error { return nil }
func checkPermissions(_ string, info os.FileInfo, dir bool) error {
	want := os.FileMode(0600)
	if dir {
		want = 0700
	}
	if info.Mode().Perm() != want || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrInvalidState
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(st.Uid) != int64(os.Geteuid()) || (!dir && st.Nlink != 1) {
		return ErrInvalidState
	}
	return nil
}
func tryLock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func lockBusy(err error) bool {
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}
func replaceFile(old, next string) error { return os.Rename(old, next) }
func syncDirectory(path string) error {
	// #nosec G304 -- local state directory selected by this package, never a remote path.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func checkOpened(*os.File) error { return nil }
