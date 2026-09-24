//go:build !windows

package probe

import (
	"errors"
	"os/exec"
	"syscall"
)

// configureProcessGroup starts the command in a session of its own (setsid,
// so pid == pgid == sid) and makes cancellation (timeout) kill the whole
// process group, so a timed-out tool leaves neither a child nor a grandchild
// behind (SPEC-0467 TF02-AC1). The new session has no controlling terminal:
// a tool that opens /dev/tty to prompt (sudo, ssh, a curses pinentry) fails
// at once instead of stopping on SIGTTIN until the deadline (TF02-AC5).
// Setsid and Setpgid must not both be set: setpgid on a session leader is
// EPERM and the start fails.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return killGroup(cmd.Process.Pid)
	}
}

// cleanupProcessGroup kills whatever is left in the group after the leader
// exited: nothing a probe starts may outlive the probe. Processes that left
// the group on purpose (a daemon calling setsid) are not touched.
//
// Remaining risk: Wait has reaped the leader, so when the group is already
// empty its id could in theory be reused by a new group leader before this
// kill. The window is microseconds; pids wrap soonest on macOS (99999).
func cleanupProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = killGroup(cmd.Process.Pid)
}

// killGroup sends SIGKILL to the process group pgid. pgid must be a real
// child pid: kill(0) would hit our own group and kill(-1) every process we
// may signal, so both are refused.
func killGroup(pgid int) error {
	if pgid <= 1 {
		return nil
	}
	err := syscall.Kill(-pgid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
