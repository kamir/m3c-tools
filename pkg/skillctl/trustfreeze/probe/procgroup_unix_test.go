//go:build !windows

package probe

import (
	"errors"
	"syscall"
	"testing"
)

// processAlive reports whether pid exists (a zombie counts as alive).
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func skipGrandchild(*testing.T) bool { return false }

// TestKillGroupRefusesUnsafePIDs: kill(0) and kill(-1) semantics must never
// be reachable.
func TestKillGroupRefusesUnsafePIDs(t *testing.T) {
	for _, pid := range []int{-1, 0, 1} {
		if err := killGroup(pid); err != nil {
			t.Fatalf("killGroup(%d) = %v, want a refused no-op", pid, err)
		}
	}
}
