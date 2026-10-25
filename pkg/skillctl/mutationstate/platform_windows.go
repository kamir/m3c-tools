//go:build windows

package mutationstate

import (
	"errors"
	"os"
	"unsafe"

	"github.com/kamir/m3c-tools/pkg/skillctl/secfile"
	"golang.org/x/sys/windows"
)

func secureCreated(path string) error { return secfile.SecureFileDACL(path) }
func checkPermissions(path string, _ os.FileInfo, _ bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !owner.Equals(user.User.Sid) {
		return ErrInvalidState
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return ErrInvalidState
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil || acl.AceCount != 2 {
		return ErrInvalidState
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	seenUser, seenSystem := false, false
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return ErrInvalidState
		}
		// #nosec G103 -- GetAce returns a validated OS ACL entry; SidStart is the documented inline SID field.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(user.User.Sid) {
			seenUser = true
		} else if sid.Equals(system) {
			seenSystem = true
		} else {
			return ErrInvalidState
		}
		if ace.Mask == 0 {
			return ErrInvalidState
		}
	}
	if !seenUser || !seenSystem {
		return ErrInvalidState
	}
	return nil
}
func tryLock(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}
func lockBusy(err error) bool { return errors.Is(err, windows.ERROR_LOCK_VIOLATION) }
func replaceFile(old, next string) error {
	a, err := windows.UTF16PtrFromString(old)
	if err != nil {
		return err
	}
	b, err := windows.UTF16PtrFromString(next)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func syncDirectory(string) error {
	// Windows has no directory fsync. Replacement uses MoveFileEx WRITE_THROUGH;
	// the record file is flushed before that call. Native durability needs OS tests.
	return nil
}

func checkOpened(f *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrInvalidState
	}
	return nil
}
