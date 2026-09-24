//go:build windows

package probe

import (
	"testing"

	"golang.org/x/sys/windows"
)

// processAlive reports whether pid can still be opened.
func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

// skipGrandchild: the grandchild part of TF02-AC1 runs on windows too; the
// timeout kills the started process and every descendant traceable by
// parent pid (procgroup_windows.go).
func skipGrandchild(*testing.T) bool { return false }
