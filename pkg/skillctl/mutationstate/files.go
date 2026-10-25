package mutationstate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type fileOps struct {
	write   func(*os.File, []byte) (int, error)
	sync    func(*os.File) error
	close   func(*os.File) error
	replace func(string, string) error
	syncDir func(string) error
}

func defaultFileOps() fileOps {
	return fileOps{write: func(f *os.File, b []byte) (int, error) { return f.Write(b) }, sync: func(f *os.File) error { return f.Sync() }, close: func(f *os.File) error { return f.Close() }, replace: replaceFile, syncDir: syncDirectory}
}

// Resolve existing OS ancestor aliases, such as macOS /var, without accepting a
// symlink as the selected state directory. Registry entries are checked on use.
func canonicalBase(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", ErrInvalidState
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if info, e := os.Lstat(abs); e == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidState
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	ancestor := filepath.Dir(abs)
	parts := []string{filepath.Base(abs)}
	for {
		_, err = os.Stat(ancestor)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", ErrInvalidState
		}
		parts = append(parts, filepath.Base(ancestor))
		ancestor = parent
	}
	resolved, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return "", err
	}
	for i := len(parts) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, parts[i])
	}
	return resolved, nil
}

func (s *Store) prepareBase() error {
	var missing []string
	path := s.base
	for {
		info, err := os.Lstat(path)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return ErrInvalidState
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, path)
		parent := filepath.Dir(path)
		if parent == path {
			return ErrInvalidState
		}
		path = parent
	}
	for i := len(missing) - 1; i >= 0; i-- {
		path = missing[i]
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := secureCreated(path); err != nil {
			return errors.Join(ErrPersistence, err)
		}
		if err := checkPath(path, true); err != nil {
			return err
		}
		if err := s.ops.syncDir(filepath.Dir(path)); err != nil {
			return errors.Join(ErrPersistence, err)
		}
	}
	return checkPath(s.base, true)
}

func checkPath(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != dir || (!dir && !info.Mode().IsRegular()) {
		return ErrInvalidState
	}
	return checkPermissions(path, info, dir)
}

func openExisting(path string, dir bool) (*os.File, error) {
	if err := checkPath(path, dir); err != nil {
		return nil, err
	}
	// #nosec G304 -- fixed local state/lock path; validated type, permissions and inode identity, not a remote path.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err == nil {
		err = checkOpened(f)
	}
	var current os.FileInfo
	if err == nil {
		current, err = os.Lstat(path)
	}
	if err == nil && (!os.SameFile(opened, current) || current.Mode()&os.ModeSymlink != 0) {
		err = ErrInvalidState
	}
	if err == nil {
		err = checkPermissions(path, opened, dir)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func (s *Store) acquire(ctx context.Context) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkPath(s.base, true); err != nil {
		return nil, errors.Join(ErrNotEnrolled, err)
	}
	if err := checkPath(s.dir, true); err != nil {
		return nil, errors.Join(ErrNotEnrolled, err)
	}
	f, err := openExisting(s.lockPath, false)
	if err != nil {
		return nil, errors.Join(ErrNotEnrolled, err)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if err = wait.Err(); err != nil {
			return nil, errors.Join(err, f.Close())
		}
		err = tryLock(f)
		if err == nil {
			if err = wait.Err(); err != nil {
				return nil, errors.Join(err, f.Close())
			}
			return f, nil
		}
		if !lockBusy(err) {
			return nil, errors.Join(err, f.Close())
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-wait.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (s *Store) publish(ctx context.Context, r record) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return errors.Join(ErrPersistence, err)
	}
	if len(raw) > maxRecordBytes {
		return errors.Join(ErrPersistence, ErrInvalidState)
	}
	if _, statErr := os.Lstat(s.statePath); statErr == nil {
		if err = checkPath(s.statePath, false); err != nil {
			return errors.Join(ErrPersistence, err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.Join(ErrPersistence, statErr)
	}
	f, err := os.CreateTemp(s.dir, ".record-*")
	if err != nil {
		return errors.Join(ErrPersistence, err)
	}
	name := f.Name()
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		if e := os.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
			err = errors.Join(err, ErrPersistence, e)
		}
	}()
	if err = secureCreated(name); err != nil {
		return errors.Join(ErrPersistence, err)
	}
	n, err := s.ops.write(f, raw)
	if err != nil {
		return errors.Join(ErrPersistence, err)
	}
	if n != len(raw) {
		return errors.Join(ErrPersistence, io.ErrShortWrite)
	}
	if err = s.ops.sync(f); err != nil {
		return errors.Join(ErrPersistence, err)
	}
	if err = s.ops.close(f); err != nil {
		return errors.Join(ErrPersistence, err)
	}
	closed = true
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = s.ops.replace(name, s.statePath); err != nil {
		return errors.Join(ErrPersistence, err)
	}
	if err = s.ops.syncDir(s.dir); err != nil {
		return errors.Join(ErrPersistence, err)
	}
	return ctx.Err()
}
