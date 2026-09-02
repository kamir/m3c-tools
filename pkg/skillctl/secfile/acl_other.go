//go:build !windows

package secfile

// SecureFileDACL is a no-op on non-Windows platforms: the callers already create
// these files with mode 0600, which the Unix kernel enforces directly. The DACL
// hardening in acl_windows.go exists only because Windows/NTFS does not honour the
// Unix perm bits (see the package doc there).
func SecureFileDACL(path string) error { return nil }
