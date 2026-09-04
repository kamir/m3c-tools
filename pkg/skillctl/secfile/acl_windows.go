//go:build windows

// Package secfile hardens the on-disk permissions of security-sensitive files
// (trust-roots, HMAC/token caches) to owner-only.
//
// On Unix the callers already create these files with mode 0600, which the
// kernel enforces. On Windows the Go os package largely IGNORES the Unix perm
// bits (only the read-only attribute is honoured): an NTFS file created with
// 0600 still inherits the parent directory's DACL, so a trust-root/token/cache
// file can end up readable (or writable) by other principals via inheritance.
// SecureFileDACL is the Windows enforcement of the 0600 intent (WIN-T7); on
// every other OS it is a no-op (see acl_other.go) because 0600 already holds.
//
// It lives in its own leaf package, not in pkg/skillctl/verify, because verify
// already imports pkg/skillctl/registry, and the registry install path is one of
// the callers; a setter in verify called from registry would be an import cycle.
package secfile

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// SecureFileDACL replaces the DACL on path with a PROTECTED (inheritance-disabled)
// DACL that grants FULL control to exactly two trustees, the current user (whom
// it also sets as the OWNER) and the local SYSTEM account, and to no one else.
// PROTECTED_DACL strips any ACEs inherited from the parent directory, so the file
// no longer leaks read/write access through inheritance. Fail-closed: any Win32
// error is returned so the caller can treat a failed hardening as a failed write.
func SecureFileDACL(path string) error {
	if path == "" {
		return fmt.Errorf("secfile: empty path")
	}

	// Owner = the current process user (a real, closeable token).
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("secfile: open process token: %w", err)
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("secfile: query token user: %w", err)
	}
	ownerSID := tu.User.Sid

	// SYSTEM keeps full access (backup/AV/indexing, and so an elevated repair can
	// still touch the file); the protected DACL excludes everyone else.
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("secfile: build SYSTEM sid: %w", err)
	}

	entries := []windows.EXPLICIT_ACCESS{
		fullControlFor(ownerSID, windows.TRUSTEE_IS_USER),
		fullControlFor(systemSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("secfile: assemble DACL: %w", err)
	}

	// DACL_SECURITY_INFORMATION (replace the DACL,
	// PROTECTED_DACL_SECURITY_INFORMATION) and DROP inherited ACEs (no inheritance),
	// OWNER_SECURITY_INFORMATION: pin ownership to the current user.
	secInfo := windows.SECURITY_INFORMATION(
		windows.DACL_SECURITY_INFORMATION |
			windows.PROTECTED_DACL_SECURITY_INFORMATION |
			windows.OWNER_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, secInfo,
		ownerSID, nil, dacl, nil); err != nil {
		return fmt.Errorf("secfile: SetNamedSecurityInfo %q: %w", path, err)
	}
	return nil
}

// fullControlFor returns a non-inheritable "grant full control" ACE for sid.
func fullControlFor(sid *windows.SID, ttype windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  ttype,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
