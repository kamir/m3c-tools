//go:build windows

package trustfreeze

import "os"

// checkVolumeTarget: drive roots are refused by checkTargetLocation. A
// volume mounted into a folder is not detected here: that needs
// GetVolumePathName, outside the standard library this package is limited
// to. Known gap.
func checkVolumeTarget(string, os.FileInfo) error { return nil }
