//go:build !windows

package probe

import (
	"fmt"
	"os"
	"syscall"
)

// defaultWorkingDir is the working directory of a command whose request
// names none: the filesystem root, never the current directory of skillctl.
// Several tools read configuration from their working directory (git reads
// .git/config, whose core.fsmonitor names a command to run), and a deleted or
// hung working directory makes tools fail or block before they start.
func defaultWorkingDir() string { return "/" }

// systemDirectory is the Windows system directory; empty elsewhere.
func systemDirectory() string { return "" }

// openRegularFile opens path for reading without blocking and without
// following a final symlink, and refuses anything but a regular file. A
// FIFO would otherwise block the open until a writer appears, and the
// reader has no context to give up with; O_NOFOLLOW closes the window in
// which a symlink swapped in after EvalSymlinks could lead out of the roots
// (directory components are not covered). O_NONBLOCK has no effect on a
// regular file and is cleared before the read.
func openRegularFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		_ = syscall.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("%w: %q", ErrNotRegularFile, path)
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		_ = syscall.Close(fd)
		return nil, &os.PathError{Op: "fcntl", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
