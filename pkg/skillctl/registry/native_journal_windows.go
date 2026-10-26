//go:build windows

package registry

import (
	"os"
	"strings"
	"syscall"

	"github.com/kamir/m3c-tools/pkg/skillctl/secfile"
	"golang.org/x/sys/windows"
)

func nativeJournalSecure(path string) error { return secfile.SecureFileDACL(path) }
func nativeJournalPermissions(path string, info os.FileInfo, _ bool) error {
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || attributes.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrNativeHistoryInvalid
	}
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
		return ErrNativeHistoryInvalid
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return ErrNativeHistoryInvalid
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil || acl.AceCount != 2 {
		return ErrNativeHistoryInvalid
	}
	// OS-produced SDDL exposes the ACEs without unsafe SID pointer arithmetic.
	// Only two unqualified full-control allow ACEs, for this user and SYSTEM,
	// match the SecureFileDACL contract; inherited or other rights fail closed.
	text := sd.String()
	i := strings.Index(text, "D:")
	if i < 0 {
		return ErrNativeHistoryInvalid
	}
	dacl := text[i+2:]
	if !strings.HasPrefix(dacl, "P(") || !strings.HasSuffix(dacl, ")") {
		return ErrNativeHistoryInvalid
	}
	aces := strings.Split(strings.TrimSuffix(strings.TrimPrefix(dacl, "P("), ")"), ")(")
	if len(aces) != 2 {
		return ErrNativeHistoryInvalid
	}
	seenUser, seenSystem := false, false
	for _, ace := range aces {
		parts := strings.Split(ace, ";")
		if len(parts) != 6 || parts[0] != "A" || parts[1] != "" || (parts[2] != "FA" && parts[2] != "GA") || parts[3] != "" || parts[4] != "" {
			return ErrNativeHistoryInvalid
		}
		switch parts[5] {
		case user.User.Sid.String():
			seenUser = true
		case "SY", "S-1-5-18":
			seenSystem = true
		default:
			return ErrNativeHistoryInvalid
		}
	}
	if !seenUser || !seenSystem {
		return ErrNativeHistoryInvalid
	}
	return nil
}
func nativeJournalCheckOpened(f *os.File) error { return checkAgentOpened(f) }
func nativeJournalSyncDir(string) error {
	// File.Sync and MoveFileEx WRITE_THROUGH are checked. Windows directory
	// namespace/power-loss durability is explicitly not promised by this mode.
	return nil
}
