//go:build !windows

package trustfreeze

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// extraVolumeRoots are refused as targets by file identity. On macOS the data
// volume is mounted at /System/Volumes/Data, and "/", "/Volumes" and that
// mount report the same device number, so the device check alone misses it.
func extraVolumeRoots() []string {
	if runtime.GOOS == "darwin" {
		return []string{"/System/Volumes/Data"}
	}
	return nil
}

// checkVolumeTarget refuses an existing target that is a mount point (its
// device differs from its parent's, for example /Volumes/<name> or
// /mnt/<x>) or one of the extra volume roots. ti is os.Stat of abs.
func checkVolumeTarget(abs string, ti os.FileInfo) error {
	for _, root := range extraVolumeRoots() {
		if ri, err := os.Stat(root); err == nil && os.SameFile(ti, ri) {
			return fmt.Errorf("%w: %q is a volume root", ErrUnsafeTarget, abs)
		}
	}
	pi, err := os.Stat(filepath.Dir(abs))
	if err != nil {
		return nil
	}
	ts, ok1 := ti.Sys().(*syscall.Stat_t)
	ps, ok2 := pi.Sys().(*syscall.Stat_t)
	if ok1 && ok2 && ts.Dev != ps.Dev {
		return fmt.Errorf("%w: %q is a mount point", ErrUnsafeTarget, abs)
	}
	return nil
}
