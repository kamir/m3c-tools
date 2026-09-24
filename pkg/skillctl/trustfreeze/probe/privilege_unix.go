//go:build !windows

package probe

import "os"

// DetectPrivilege reports elevated when the effective user is root. Trust
// Freeze never raises privilege; this only records what the process has.
//
// It means euid 0 in the current user namespace. In a rootless container
// euid 0 maps to an unprivileged host uid and is still reported as elevated,
// while a binary with file capabilities (for example CAP_DAC_READ_SEARCH) can
// read more than "user" suggests.
func DetectPrivilege() Privilege {
	if os.Geteuid() == 0 {
		return PrivilegeElevated
	}
	return PrivilegeUser
}
