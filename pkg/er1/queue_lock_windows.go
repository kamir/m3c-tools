//go:build windows

package er1

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockQueueFile(path string, nonblocking bool) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if nonblocking {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &windows.Overlapped{}); err != nil {
		closeErr := file.Close()
		if nonblocking && errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.Join(errQueueBusy, closeErr)
		}
		return nil, errors.Join(err, closeErr)
	}
	return file, nil
}

func syncQueueDirectory(string) error {
	// Windows does not support fsync on a directory opened by os.Open.
	return nil
}

func renameQueueFile(oldPath, newPath string) error {
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(oldName, newName, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
