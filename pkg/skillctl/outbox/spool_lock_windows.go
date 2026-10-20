//go:build windows

package outbox

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func trySpoolLock(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}

func spoolLockBusy(err error) bool {
	return errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

func renameSpool(oldPath, newPath string) error {
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldName, newName, windows.MOVEFILE_WRITE_THROUGH)
}

func syncSpoolDir(string) error {
	// Windows does not support directory fsync. File.Sync flushes the append;
	// rotation uses MoveFileEx with WRITE_THROUGH to persist the rename.
	return nil
}
