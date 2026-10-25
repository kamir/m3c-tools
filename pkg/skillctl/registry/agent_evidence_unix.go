//go:build !windows

package registry

import (
	"errors"
	"os"
	"syscall"
)

func tryAgentLock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
func agentLockBusy(err error) bool {
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}
func replaceAgentFile(old, next string) error { return os.Rename(old, next) }
func syncAgentParent(path string) error {
	// #nosec G304 -- directory of the explicitly selected local agent destination, not a remote route.
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}
func checkAgentOpened(f *os.File) error {
	info, e := f.Stat()
	if e != nil {
		return e
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || s.Nlink != 1 {
		return ErrAgentEvidenceInvalid
	}
	return nil
}
