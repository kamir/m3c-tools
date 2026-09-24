//go:build windows

package probe

import "golang.org/x/sys/windows"

// DetectPrivilege reports elevated when the process token is elevated (an
// administrator process past UAC). Trust Freeze never requests elevation;
// this only records what the process has.
func DetectPrivilege() Privilege {
	if windows.GetCurrentProcessToken().IsElevated() {
		return PrivilegeElevated
	}
	return PrivilegeUser
}
