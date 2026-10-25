//go:build windows

package registry

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func tryAgentLock(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}
func agentLockBusy(err error) bool { return errors.Is(err, windows.ERROR_LOCK_VIOLATION) }
func replaceAgentFile(old, next string) error {
	a, e := windows.UTF16PtrFromString(old)
	if e != nil {
		return e
	}
	b, e := windows.UTF16PtrFromString(next)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func syncAgentParent(string) error {
	// Windows publication uses checked file FlushFileBuffers (File.Sync) followed
	// by MoveFileEx WRITE_THROUGH, not directory fsync. Creation/deletion namespace
	// durability and powerloss survival are not promised by this mode.
	return nil
}
func checkAgentOpened(f *os.File) error {
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); e != nil {
		return e
	}
	if info.NumberOfLinks != 1 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrAgentEvidenceInvalid
	}
	return nil
}
