//go:build !windows

package er1

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockQueueFile(path string, nonblocking bool) (*os.File, error) {
	// #nosec G304 -- path is a lock sibling of the operator-selected local queue, not a path supplied by uploaded content.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	flags := unix.LOCK_EX
	if nonblocking {
		flags |= unix.LOCK_NB
	}
	if err := unix.Flock(int(file.Fd()), flags); err != nil {
		closeErr := file.Close()
		if nonblocking && errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.Join(errQueueBusy, closeErr)
		}
		return nil, errors.Join(err, closeErr)
	}
	return file, nil
}

func syncQueueDirectory(path string) error {
	// #nosec G304 -- path is the operator-selected queue directory or its ancestor, used only to persist local namespace updates.
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func renameQueueFile(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }
