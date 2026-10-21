//go:build !windows

package outbox

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func trySpoolLock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func spoolLockBusy(err error) bool {
	return err == syscall.EWOULDBLOCK || err == syscall.EAGAIN
}

func renameSpool(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func syncSpoolDir(dir string) error {
	// #nosec G304 -- dir is the local audit directory or its ancestor, derived by the directory-creation helper; no event supplies it.
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("outbox: spool directory open: %w", err)
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("outbox: spool directory sync/close: %w", err)
	}
	return nil
}
