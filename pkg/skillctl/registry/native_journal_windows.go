//go:build windows

package registry

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/kamir/m3c-tools/pkg/skillctl/secfile"
	"golang.org/x/sys/windows"
)

func nativeJournalSecure(path string) error { return secfile.SecureFileDACL(path) }
func nativeJournalPermissions(path string, info os.FileInfo, _ bool) error {
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || attributes.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal reparse or file attributes"))
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return validateNativeJournalDescriptor(sd, user.User.Sid)
}

// validateNativeJournalDescriptor requires binary owner and ACE identities.
// No display string or owner alias is used to determine ACE authority.
func validateNativeJournalDescriptor(sd *windows.SECURITY_DESCRIPTOR, current *windows.SID) error {
	if sd == nil || current == nil || !sd.IsValid() || !current.IsValid() {
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal descriptor missing"))
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(current) {
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal owner mismatch"))
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal DACL not protected"))
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil || acl.AceCount != 2 {
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal DACL absent or ACE count"))
	}
	err = validateNativeJournalACEs(acl, current)
	runtime.KeepAlive(sd)
	if err != nil {
		return err
	}
	return nil
}

func validateNativeJournalACEs(acl *windows.ACL, current *windows.SID) error {
	if acl == nil || acl.AceCount != 2 || current == nil || !current.IsValid() {
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal binary ACL input"))
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	if current.Equals(system) {
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal binary principals are not distinct"))
	}
	seenUser, seenSystem := false, false
	for i := uint32(0); i < 2; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		sid, err := nativeJournalAllowedSID(ace)
		if err != nil {
			return err
		}
		switch {
		case sid.Equals(current) && !seenUser:
			seenUser = true
		case sid.Equals(system) && !seenSystem:
			seenSystem = true
		default:
			return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal binary trustee mismatch or duplicate"))
		}
	}
	if !seenUser || !seenSystem {
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal binary trustees incomplete"))
	}
	return nil
}

// nativeJournalAllowedSID accepts only an ACE returned by GetAce from the
// validated OS descriptor. SidStart begins the variable-length SID. Check its
// complete byte extent before passing that pointer to Windows SID routines.
func nativeJournalAllowedSID(ace *windows.ACCESS_ALLOWED_ACE) (*windows.SID, error) {
	deny := func() (*windows.SID, error) {
		return nil, nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal binary ACE bounds or rights"))
	}
	if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
		return deny()
	}
	const sidHeaderBytes = 8
	const maxSubAuthorities = 15
	const sidOffset = int(unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart))
	const maxSIDBytes = sidHeaderBytes + 4*maxSubAuthorities
	size := int(ace.Header.AceSize)
	if size < sidOffset+sidHeaderBytes || size > sidOffset+maxSIDBytes {
		return deny()
	}
	// FILE_ALL_ACCESS is STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x1ff.
	const fileAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff
	if ace.Mask != windows.GENERIC_ALL && ace.Mask != fileAllAccess {
		return deny()
	}
	// Supported Windows Go targets are little-endian. SidStart already exposes
	// the first DWORD, so revision/count need no pointer conversion or slice.
	revision := ace.SidStart & 0xff
	count := (ace.SidStart >> 8) & 0xff
	if revision != 1 || count > maxSubAuthorities {
		return deny()
	}
	required := sidHeaderBytes + 4*int(count)
	if size != sidOffset+required {
		return deny()
	}
	// #nosec G103 -- OS-validated GetAce; exact ACE/SID bounds checked above, binary SID validation below.
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.IsValid() || sid.Len() != required {
		return deny()
	}
	return sid, nil
}

func nativeJournalCheckOpened(f *os.File) error { return checkAgentOpened(f) }
func nativeJournalSyncDir(string) error {
	// File.Sync and MoveFileEx WRITE_THROUGH are checked. Windows directory
	// namespace/power-loss durability is explicitly not promised by this mode.
	return nil
}
