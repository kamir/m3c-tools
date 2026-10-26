package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type nativeJournalFileOps struct {
	write       func(*os.File, []byte) (int, error)
	sync, close func(*os.File) error
	closeDir    func(*os.Root) error
	replace     func(string, string) error
	syncDir     func(string) error
}

func defaultNativeJournalFileOps() nativeJournalFileOps {
	return nativeJournalFileOps{write: func(f *os.File, b []byte) (int, error) { return f.Write(b) }, sync: func(f *os.File) error { return f.Sync() }, close: func(f *os.File) error { return f.Close() }, closeDir: func(r *os.Root) error { return r.Close() }, replace: replaceAgentFile, syncDir: nativeJournalSyncDir}
}

type nativeJournalDir struct {
	root       *os.Root
	parent     *nativeJournalDir
	path, name string
	info       os.FileInfo
	private    bool
}

func nativeJournalOrdinary(info os.FileInfo, dir bool) bool {
	return info != nil && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 && ((dir && info.IsDir()) || (!dir && info.Mode().IsRegular()))
}
func (d *nativeJournalDir) validate() error {
	if d == nil || d.root == nil {
		return ErrNativeHistoryInvalid
	}
	var current os.FileInfo
	var err error
	if d.parent == nil {
		current, err = os.Lstat(d.path)
	} else {
		if err = d.parent.validate(); err != nil {
			return err
		}
		current, err = d.parent.root.Lstat(d.name)
	}
	if err != nil || !nativeJournalOrdinary(current, true) || !os.SameFile(current, d.info) {
		return ErrNativeHistoryInvalid
	}
	held, err := d.root.Stat(".")
	if err != nil || !os.SameFile(held, current) {
		return ErrNativeHistoryInvalid
	}
	if d.private {
		return nativeJournalPermissions(d.path, current, true)
	}
	return nil
}
func openNativeJournalDir(parent *nativeJournalDir, name string, private bool) (*nativeJournalDir, error) {
	if err := parent.validate(); err != nil {
		return nil, err
	}
	before, err := parent.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !nativeJournalOrdinary(before, true) {
		return nil, ErrNativeHistoryInvalid
	}
	path := filepath.Join(parent.path, name)
	if private {
		if err = nativeJournalPermissions(path, before, true); err != nil {
			return nil, err
		}
	}
	root, err := parent.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	d := &nativeJournalDir{root, parent, path, name, before, private}
	if err = d.validate(); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return d, nil
}
func closeNativeJournalDirs(dirs []*nativeJournalDir, ops nativeJournalFileOps) error {
	var err error
	for i := len(dirs) - 1; i >= 0; i-- {
		err = errors.Join(err, ops.closeDir(dirs[i].root))
	}
	return err
}
func (j *NativeJournal) openDirs(create bool) (dirs []*nativeJournalDir, err error) {
	if err = j.valid(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = nativeJournalFail(ErrNativeHistoryRequired, errors.Join(err, closeNativeJournalDirs(dirs, j.ops)))
			dirs = nil
		}
	}()
	root, err := os.OpenRoot(j.selection.home)
	if err != nil {
		return nil, err
	}
	home := &nativeJournalDir{root: root, path: j.selection.home, info: j.selection.homeInfo}
	dirs = append(dirs, home)
	if err = home.validate(); err != nil {
		return dirs, err
	}
	for i, name := range []string{".claude", "native-mutation-state"} {
		parent := dirs[len(dirs)-1]
		if create {
			e := parent.root.Mkdir(name, 0700)
			if e != nil && !errors.Is(e, os.ErrExist) {
				return dirs, e
			}
			if e == nil {
				if err = nativeJournalSecure(filepath.Join(parent.path, name)); err != nil {
					return dirs, err
				}
				if err = j.ops.syncDir(parent.path); err != nil {
					return dirs, err
				}
			}
		}
		var child *nativeJournalDir
		child, err = openNativeJournalDir(parent, name, i == 1)
		if err != nil {
			return dirs, err
		}
		dirs = append(dirs, child)
	}
	if !create {
		child, e := openNativeJournalDir(dirs[len(dirs)-1], j.selection.authority.historyID, true)
		if e != nil {
			return dirs, e
		}
		dirs = append(dirs, child)
	}
	return dirs, nil
}
func openNativeJournalFile(dir *nativeJournalDir, name string, limit int64, flags int) (*os.File, error) {
	if err := dir.validate(); err != nil {
		return nil, err
	}
	before, err := dir.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !nativeJournalOrdinary(before, false) || before.Size() > limit {
		return nil, ErrNativeHistoryInvalid
	}
	path := filepath.Join(dir.path, name)
	if err = nativeJournalPermissions(path, before, false); err != nil {
		return nil, err
	}
	f, err := dir.root.OpenFile(name, flags, 0)
	if err != nil {
		return nil, err
	}
	held, err := f.Stat()
	if err == nil {
		err = nativeJournalCheckOpened(f)
	}
	current, ce := dir.root.Lstat(name)
	if err == nil && (ce != nil || !nativeJournalOrdinary(held, false) || !nativeJournalOrdinary(current, false) || !os.SameFile(before, held) || !os.SameFile(held, current) || held.Size() > limit) {
		err = ErrNativeHistoryInvalid
	}
	if err == nil {
		err = dir.validate()
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}
func validateNativeJournalOptional(dir *nativeJournalDir, name string, limit int64) error {
	info, err := dir.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return dir.validate()
	}
	if err != nil {
		return err
	}
	if !nativeJournalOrdinary(info, false) || info.Size() > limit {
		return ErrNativeHistoryInvalid
	}
	f, err := openNativeJournalFile(dir, name, limit, os.O_RDONLY)
	if err != nil {
		return err
	}
	return f.Close()
}
func nativeJournalTempName() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return ".record-" + hex.EncodeToString(b[:]), nil
}
func (j *NativeJournal) acquire(ctx context.Context) (*nativeJournalLease, error) {
	if err := nativeJournalContext(ctx); err != nil {
		return nil, err
	}
	dirs, err := j.openDirs(false)
	if err != nil {
		return nil, err
	}
	f, err := openNativeJournalFile(dirs[len(dirs)-1], nativeJournalLock, 0, os.O_RDWR)
	if err != nil {
		return nil, nativeJournalFail(ErrNativeHistoryInvalid, errors.Join(err, closeNativeJournalDirs(dirs, j.ops)))
	}
	lease := &nativeJournalLease{journal: j, dirs: dirs, file: f}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if err = wait.Err(); err != nil {
			return nil, errors.Join(err, lease.Close())
		}
		err = tryAgentLock(f)
		if err == nil {
			if err = wait.Err(); err == nil {
				err = lease.validate()
			}
			if err != nil {
				return nil, errors.Join(err, lease.Close())
			}
			info, e := dirs[len(dirs)-1].root.Lstat(nativeJournalState)
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return nil, nativeJournalFail(ErrNativeHistoryInvalid, errors.Join(e, lease.Close()))
			}
			if e == nil {
				lease.stateInfo = info
			}
			return lease, nil
		}
		if !agentLockBusy(err) {
			return nil, nativeJournalFail(ErrNativeHistoryInvalid, errors.Join(err, lease.Close()))
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-wait.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}
func (l *nativeJournalLease) validate() error {
	if l == nil || l.journal == nil || l.file == nil || l.closed || l.poisoned {
		return ErrNativeSessionUnavailable
	}
	if err := l.journal.valid(); err != nil {
		return err
	}
	for _, d := range l.dirs {
		if err := d.validate(); err != nil {
			return err
		}
	}
	d := l.dirs[len(l.dirs)-1]
	current, err := d.root.Lstat(nativeJournalLock)
	held, he := l.file.Stat()
	if err != nil || he != nil || !nativeJournalOrdinary(current, false) || current.Size() != 0 || !os.SameFile(current, held) {
		return ErrNativeHistoryInvalid
	}
	if err = nativeJournalPermissions(filepath.Join(d.path, nativeJournalLock), held, false); err != nil {
		return err
	}
	return nativeJournalCheckOpened(l.file)
}

func (l *nativeJournalLease) checkRecordIdentity() error {
	d := l.dirs[len(l.dirs)-1]
	current, err := d.root.Lstat(nativeJournalState)
	if errors.Is(err, os.ErrNotExist) && l.stateInfo == nil {
		return nil
	}
	if err != nil || l.stateInfo == nil || !nativeJournalOrdinary(current, false) || !os.SameFile(current, l.stateInfo) {
		return ErrNativeHistoryInvalid
	}
	return nil
}
