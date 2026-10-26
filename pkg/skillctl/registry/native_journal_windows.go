//go:build windows

package registry

import (
	"errors"
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
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New("native journal reparse or file attributes"))
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
	// OS-produced SDDL exposes the ACEs without unsafe SID pointer arithmetic.
	// Only two unqualified full-control allow ACEs, for this user and SYSTEM,
	// match the SecureFileDACL contract; inherited or other rights fail closed.
	return validateNativeJournalDACL(sd.String(), user.User.Sid.String())
}

// validateNativeJournalDACL reads only the bounded, OS-produced DACL string.
// P protects the DACL; AI and AR describe its inheritance control state, not
// permission granted by an ACE. ACE inheritance flags remain forbidden.
func validateNativeJournalDACL(text, currentSID string) error {
	deny := func(branch string) error {
		return nativeJournalFail(ErrNativeHistoryInvalid, errors.New(branch))
	}
	if len(text) == 0 || len(text) > 4096 || len(currentSID) < 5 || len(currentSID) > 256 || !strings.HasPrefix(currentSID, "S-1-") || strings.ContainsAny(currentSID, ";(): \t\r\n") {
		return deny("native journal DACL input bounds")
	}
	if strings.Count(text, "D:") != 1 {
		return deny("native journal DACL component")
	}
	i := strings.Index(text, "D:")
	dacl := text[i+2:]
	start := strings.IndexByte(dacl, '(')
	if start < 1 {
		return deny("native journal DACL flags missing")
	}
	flags := dacl[:start]
	protected, inherited, requested := false, false, false
	for flags != "" {
		switch {
		case strings.HasPrefix(flags, "P") && !protected:
			protected = true
			flags = flags[1:]
		case strings.HasPrefix(flags, "AI") && !inherited:
			inherited = true
			flags = flags[2:]
		case strings.HasPrefix(flags, "AR") && !requested:
			requested = true
			flags = flags[2:]
		default:
			return deny("native journal DACL flags invalid")
		}
	}
	if !protected {
		return deny("native journal DACL not protected")
	}
	remaining := dacl[start:]
	seenUser, seenSystem := false, false
	for n := 0; n < 2; n++ {
		if !strings.HasPrefix(remaining, "(") {
			return deny("native journal DACL ACE count")
		}
		end := strings.IndexByte(remaining, ')')
		if end < 1 {
			return deny("native journal DACL ACE framing")
		}
		ace := remaining[1:end]
		remaining = remaining[end+1:]
		parts := strings.Split(ace, ";")
		if len(parts) != 6 || parts[0] != "A" || parts[1] != "" || (parts[2] != "FA" && parts[2] != "GA") || parts[3] != "" || parts[4] != "" {
			return deny("native journal DACL ACE rights or flags")
		}
		switch parts[5] {
		case currentSID:
			if seenUser {
				return deny("native journal DACL duplicate user")
			}
			seenUser = true
		case "SY", "S-1-5-18":
			if seenSystem {
				return deny("native journal DACL duplicate SYSTEM")
			}
			seenSystem = true
		default:
			return deny("native journal DACL trustee")
		}
	}
	if remaining != "" || !seenUser || !seenSystem {
		return deny("native journal DACL incomplete or extra ACE")
	}
	return nil
}
func nativeJournalCheckOpened(f *os.File) error { return checkAgentOpened(f) }
func nativeJournalSyncDir(string) error {
	// File.Sync and MoveFileEx WRITE_THROUGH are checked. Windows directory
	// namespace/power-loss durability is explicitly not promised by this mode.
	return nil
}
