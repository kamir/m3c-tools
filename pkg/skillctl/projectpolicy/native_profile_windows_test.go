//go:build windows

package projectpolicy

import "testing"

// Windows exercises the ordinary-directory refusal. FIFO cases are Unix-only.
func nativeProfileSpecialFiles(t *testing.T) []string { t.Helper(); return []string{t.TempDir()} }
