//go:build windows

package probe

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// defaultWorkingDir is the working directory of a command whose request
// names none: the Windows directory as the OS reports it, never the current
// directory of skillctl (see the Unix variant for why).
func defaultWorkingDir() string {
	if d, err := windows.GetSystemWindowsDirectory(); err == nil && d != "" {
		return d
	}
	return `C:\Windows`
}

// systemDirectory is the system directory as the OS reports it, not as the
// caller's %SystemRoot% claims it.
func systemDirectory() string {
	d, err := windows.GetSystemDirectory()
	if err != nil {
		return ""
	}
	return d
}

// openRegularFile opens path and refuses anything but a regular file.
// Windows has no FIFO in the file namespace, so a plain open cannot block.
func openRegularFile(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.Join(fmt.Errorf("%w: %q", ErrNotRegularFile, path), f.Close())
	}
	return f, nil
}
