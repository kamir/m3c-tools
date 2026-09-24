//go:build !windows

package trustfreeze

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// TestMountPointTargetRefused: a mount point is a volume root and never a
// target. /dev is its own filesystem on linux and darwin.
func TestMountPointTargetRefused(t *testing.T) {
	di, err1 := os.Stat("/dev")
	ri, err2 := os.Stat("/")
	if err1 != nil || err2 != nil {
		t.Skip("no /dev here")
	}
	ds, ok1 := di.Sys().(*syscall.Stat_t)
	rs, ok2 := ri.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 || ds.Dev == rs.Dev {
		t.Skip("/dev is not a separate filesystem here")
	}
	if err := checkTargetLocation("/dev", ""); !errors.Is(err, ErrUnsafeTarget) {
		t.Fatalf("checkTargetLocation(/dev) = %v, want ErrUnsafeTarget", err)
	}
	if err := checkTargetLocation(t.TempDir(), ""); err != nil {
		t.Fatalf("an ordinary directory is refused: %v", err)
	}
}
