//go:build windows

package probe

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no process group that one signal reaches. Instead, a timeout
// kills the started process and then every descendant that can be traced to
// it, and after a normal exit the descendants left behind are killed, so
// nothing a probe starts outlives the probe (SPEC-0467 TF02-AC1), as on Unix.
//
// Descendants are found in a process snapshot (Toolhelp32): a process whose
// parent pid is the started process or a descendant found before. Windows
// records only the creator's pid and reuses pids, so every candidate is
// checked on a handle to it: its parent pid (NtQueryInformationProcess) must
// still be the expected one, and it must have been created after that parent
// (and, when the parent has already been reaped, before the parent exited).
// Every process found stays open until the walk ends, so none of their pids
// can be reused meanwhile, which makes a parent-pid match exact.
//
// Known gaps:
//   - An orphan below an intermediate process that exited before the walk
//     is not found: nothing links it to the tree any more.
//   - A process that keeps starting children can outrun the walk, which
//     takes at most treeWalkRounds snapshots.
//   - A descendant that runs elevated or protected cannot be opened and
//     survives; the walk reports it in its error, which the runner does not
//     record yet.
//   - Processes started on the tool's behalf by a service or a broker (Task
//     Scheduler, WMI, COM servers, the WSL service) are not descendants and
//     are not killed.
//
// A job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE closes the first two
// gaps (not the last two). It must be assigned while the child is still
// suspended (CREATE_SUSPENDED, assign, resume), which needs a hook between
// Start and Wait; the runner calls cmd.Run and has none yet.

const (
	// treeKillExitCode is the exit code of every killed process, the code
	// os.Process.Kill uses.
	treeKillExitCode = 1
	// treeWalkRounds bounds the snapshots one walk takes.
	treeWalkRounds = 8
	// treeProcessAccess covers the parent pid and creation time (query) and
	// the kill.
	treeProcessAccess = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_TERMINATE
	// stillActive is the exit code GetExitCodeProcess reports for a running
	// process (STILL_ACTIVE).
	stillActive = 259
)

// configureProcessGroup makes cancellation (timeout) kill the process tree.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return killTree(cmd.Process)
	}
}

// cleanupProcessGroup kills the descendants left after the started process
// exited. Its pid may already belong to another process, so only processes
// created while it ran count as its children.
func cleanupProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil || cmd.ProcessState == nil {
		return
	}
	ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return
	}
	_ = killDescendants(uint32(cmd.Process.Pid), ru.CreationTime.Nanoseconds(), ru.ExitTime.Nanoseconds())
}

// killTree kills p and then its descendants.
func killTree(p *os.Process) error {
	// Open a handle of our own before Kill. When Kill then finds p not yet
	// reaped, p's handle has been open since Start, so this handle names the
	// same process and keeps its pid from being reused during the walk.
	root, openErr := windows.OpenProcess(treeProcessAccess, false, uint32(p.Pid))
	killErr := p.Kill()
	if errors.Is(killErr, os.ErrProcessDone) || errors.Is(killErr, syscall.EINVAL) {
		// Wait has reaped p (os reports EINVAL for a released process): its
		// pid may name another process by now, so no walk from here.
		// cleanupProcessGroup walks with p's exit time instead.
		if openErr == nil {
			_ = windows.CloseHandle(root)
		}
		return os.ErrProcessDone
	}
	if openErr != nil {
		return errors.Join(killErr, fmt.Errorf("open process %d: %w", p.Pid, openErr))
	}
	defer windows.CloseHandle(root)
	created, err := processCreationTime(root)
	if err != nil {
		return errors.Join(killErr, err)
	}
	return errors.Join(killErr, killDescendants(uint32(p.Pid), created, math.MaxInt64))
}

// killDescendants kills every process that descends from the process rootPID
// created at rootCreated. A direct child must have been created within
// [rootCreated, rootExited]; math.MaxInt64 is right only while the caller
// holds the root open. Times are nanoseconds since the Unix epoch.
func killDescendants(rootPID uint32, rootCreated, rootExited int64) error {
	if rootPID == 0 {
		return nil
	}
	type span struct{ from, to int64 }
	parents := map[uint32]span{rootPID: {rootCreated, rootExited}}
	var open []windows.Handle
	defer func() {
		for _, h := range open {
			_ = windows.CloseHandle(h)
		}
	}()
	var errs []error
	for round := 0; round < treeWalkRounds; round++ {
		procs, err := processSnapshot()
		if err != nil {
			return errors.Join(append(errs, err)...)
		}
		found := false
		for _, e := range procs {
			par, ok := parents[e.parent]
			if !ok || e.pid == 0 || e.pid == e.parent {
				continue
			}
			if _, seen := parents[e.pid]; seen {
				continue
			}
			h, err := windows.OpenProcess(treeProcessAccess, false, e.pid)
			if err != nil {
				if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
					errs = append(errs, fmt.Errorf("process %d, listed as a child of %d: %w", e.pid, e.parent, err))
				}
				continue // any other error: it exited since the snapshot
			}
			created, parent, err := processOrigin(h)
			if err != nil || parent != e.parent || created < par.from || created > par.to {
				// Not the process the snapshot listed (pid reused since), or
				// not created while its parent held that pid.
				_ = windows.CloseHandle(h)
				continue
			}
			open = append(open, h)
			parents[e.pid] = span{created, math.MaxInt64}
			found = true
			if err := windows.TerminateProcess(h, treeKillExitCode); err != nil && !processExited(h) {
				errs = append(errs, fmt.Errorf("terminate process %d: %w", e.pid, err))
			}
		}
		if !found {
			return errors.Join(errs...)
		}
	}
	return errors.Join(append(errs, fmt.Errorf("descendants of process %d still appeared after %d snapshots", rootPID, treeWalkRounds))...)
}

type procEntry struct{ pid, parent uint32 }

// processSnapshot lists every process with its parent pid.
func processSnapshot() ([]procEntry, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	var out []procEntry
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		out = append(out, procEntry{pid: pe.ProcessID, parent: pe.ParentProcessID})
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	return out, nil
}

// processOrigin returns the creation time and the parent pid of the open
// process h.
func processOrigin(h windows.Handle) (int64, uint32, error) {
	created, err := processCreationTime(h)
	if err != nil {
		return 0, 0, err
	}
	var info windows.PROCESS_BASIC_INFORMATION
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return 0, 0, fmt.Errorf("query process: %w", err)
	}
	return created, uint32(info.InheritedFromUniqueProcessId), nil
}

func processCreationTime(h windows.Handle) (int64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, fmt.Errorf("process times: %w", err)
	}
	return created.Nanoseconds(), nil
}

func processExited(h windows.Handle) bool {
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code != stillActive
}
