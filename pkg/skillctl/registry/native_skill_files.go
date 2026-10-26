package registry

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// These per-instance operations substitute I/O failures, never authorization.
type nativeSkillFileOps struct {
	rename     func(*os.Root, string, string) error
	remove     func(*os.Root, string) error
	syncFile   func(*os.File) error
	closeFile  func(*os.File) error
	closeRoot  func(*os.Root) error
	syncParent func(string) error
}

func defaultNativeSkillFileOps() nativeSkillFileOps {
	return nativeSkillFileOps{
		rename:   func(r *os.Root, a, b string) error { return r.Rename(a, b) },
		remove:   func(r *os.Root, name string) error { return r.Remove(name) },
		syncFile: (*os.File).Sync, closeFile: (*os.File).Close,
		closeRoot: (*os.Root).Close, syncParent: syncAgentParent,
	}
}

type nativeSkillFS struct {
	home, claude, skills             *os.Root
	homeInfo, claudeInfo, skillsInfo os.FileInfo
	selection                        *NativeInstallSelection
	work                             *int64
	ops                              nativeSkillFileOps
	handles                          int
	oldArchives                      map[string][]byte
	ownedDirs                        map[string]os.FileInfo
	cleanupLeft                      int64
	cleaning                         bool
	ioErr                            error
	uncertainFiles                   map[*os.File]bool
	uncertainRoots                   map[*os.Root]bool
}

func (f *nativeSkillFS) reserve(n int64) error {
	if f.ioErr != nil {
		return f.ioErr
	}
	if f.cleaning {
		if n < 0 || n > f.cleanupLeft {
			return ErrNativeEvidenceInvalid
		}
		f.cleanupLeft -= n
		return nil
	}
	if !nativeLiveReserve(f.work, n) {
		return ErrNativeEvidenceInvalid
	}
	return nil
}
func (f *nativeSkillFS) take() error {
	if err := f.reserve(512); err != nil {
		return err
	}
	if f.handles >= 64 {
		return ErrNativeEvidenceInvalid
	}
	f.handles++
	return nil
}
func (f *nativeSkillFS) closeRoot(r *os.Root) error {
	if r == nil {
		return nil
	}
	err := f.ops.closeRoot(r)
	if err != nil {
		f.ioErr = errors.Join(f.ioErr, ErrNativePersistence, err)
		f.uncertainRoots[r] = true
	} else {
		f.handles--
	}
	return err
}
func (f *nativeSkillFS) closeFile(r *os.File) error {
	if r == nil {
		return nil
	}
	err := f.ops.closeFile(r)
	if err != nil {
		f.ioErr = errors.Join(f.ioErr, ErrNativePersistence, err)
		f.uncertainFiles[r] = true
	} else {
		f.handles--
	}
	return err
}

func openNativeSkillFS(s *NativeInstallSelection, work *int64, ops nativeSkillFileOps) (out *nativeSkillFS, resultErr error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	f := &nativeSkillFS{selection: s, work: work, ops: ops, oldArchives: make(map[string][]byte), ownedDirs: make(map[string]os.FileInfo), uncertainFiles: make(map[*os.File]bool), uncertainRoots: make(map[*os.Root]bool)}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, f.Close())
			out = nil
		}
	}()
	if err := f.take(); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(s.home)
	if err != nil {
		f.handles--
		return nil, err
	}
	f.home = r
	f.homeInfo, err = r.Stat(".")
	if err != nil {
		return nil, err
	}
	f.claude, f.claudeInfo, err = f.child(r, ".claude", true)
	if err != nil {
		return nil, err
	}
	f.skills, f.skillsInfo, err = f.child(f.claude, "skills", true)
	if err != nil {
		return nil, err
	}
	if err = f.live(); err != nil {
		return nil, err
	}
	// Persist creation of the fixed home/.claude/skills parent chain before
	// relying on a pending reservation below it. Windows' helper explicitly
	// documents its namespace-durability limitation.
	for _, path := range []string{s.home, filepath.Join(s.home, ".claude"), filepath.Join(s.home, ".claude", "skills")} {
		if err = ops.syncParent(path); err != nil {
			f.ioErr = errors.Join(ErrNativePersistence, err)
			return nil, f.ioErr
		}
	}
	return f, nil
}

func (f *nativeSkillFS) child(parent *os.Root, name string, create bool) (*os.Root, os.FileInfo, error) {
	if !nativeSkillComponent(name) {
		return nil, nil, ErrNativeHistoryInvalid
	}
	if err := f.reserve(int64(2*len(parent.Name()) + 2*len(name) + 512)); err != nil {
		return nil, nil, err
	}
	before, err := parent.Lstat(name)
	created := false
	if errors.Is(err, os.ErrNotExist) && create {
		err = parent.Mkdir(name, 0700)
		created = err == nil
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, nil, err
		}
		before, err = parent.Lstat(name)
	}
	if err != nil {
		return nil, nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, nil, ErrNativeHistoryInvalid
	}
	key := filepath.Join(parent.Name(), name)
	if created {
		f.ownedDirs[key] = before
	}
	if known := f.ownedDirs[key]; known == nil || !os.SameFile(known, before) {
		if err = f.exactName(parent, name); err != nil {
			return nil, nil, err
		}
	}
	if err = f.take(); err != nil {
		return nil, nil, err
	}
	r, err := parent.OpenRoot(name)
	if err != nil {
		f.handles--
		return nil, nil, err
	}
	held, e := r.Stat(".")
	after, aerr := parent.Lstat(name)
	if e != nil || aerr != nil || !held.IsDir() || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, held) || !os.SameFile(held, after) {
		return nil, nil, errors.Join(ErrNativeHistoryInvalid, e, aerr, f.closeRoot(r))
	}
	return r, held, nil
}

func nativeSkillComponent(s string) bool {
	return s != "" && s != "." && s != ".." && len(s) <= 4096 && !strings.ContainsAny(s, "/\\:\x00")
}

// Verify the actual directory spelling, including case/Unicode aliases on the
// selected filesystem. Enumeration is partial and cumulatively charged.
func (f *nativeSkillFS) exactName(parent *os.Root, name string) (resultErr error) {
	if err := f.take(); err != nil {
		return err
	}
	d, err := parent.Open(".")
	if err != nil {
		f.handles--
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, f.closeFile(d)) }()
	n := 0
	for {
		if err = f.reserve(4096 + 256); err != nil {
			return err
		}
		entries, e := d.ReadDir(1)
		n += len(entries)
		if n > 100000 {
			return ErrNativeHistoryInvalid
		}
		for _, entry := range entries {
			if entry.Name() == name {
				return nil
			}
		}
		if errors.Is(e, io.EOF) {
			return ErrNativeHistoryInvalid
		}
		if e != nil {
			return e
		}
	}
}

func (f *nativeSkillFS) live() error {
	if f.ioErr != nil {
		return f.ioErr
	}
	if err := f.selection.validate(); err != nil {
		return err
	}
	for _, pair := range []struct {
		parent *os.Root
		name   string
		info   os.FileInfo
	}{{f.home, ".claude", f.claudeInfo}, {f.claude, "skills", f.skillsInfo}} {
		info, err := pair.parent.Lstat(pair.name)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pair.info) {
			return ErrPlanDrift
		}
	}
	i, err := f.home.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(i, f.homeInfo) {
		return ErrPlanDrift
	}
	return nil
}

// All intermediate directories are opened as direct children of held ordinary
// directory handles. The live chain is checked again before returning/closing.
func (f *nativeSkillFS) dir(rel string, create bool) (*os.Root, func() error, error) {
	if err := f.live(); err != nil {
		return nil, nil, err
	}
	if rel == "." || rel == "" {
		return f.skills, func() error { return f.live() }, nil
	}
	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
	parent := f.skills
	var roots []*os.Root
	var infos []os.FileInfo
	closeAll := func() error {
		var e error
		for i := len(roots) - 1; i >= 0; i-- {
			e = errors.Join(e, f.closeRoot(roots[i]))
		}
		return e
	}
	for _, name := range parts {
		r, info, err := f.child(parent, name, create)
		if err != nil {
			return nil, nil, errors.Join(err, closeAll())
		}
		roots = append(roots, r)
		infos = append(infos, info)
		parent = r
	}
	check := func() error {
		var e error
		for i := range parts {
			info, err := f.skills.Lstat(filepath.Join(parts[:i+1]...))
			if err != nil {
				e = errors.Join(e, err)
				break
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, infos[i]) {
				e = errors.Join(e, ErrPlanDrift)
				break
			}
		}
		return errors.Join(e, f.live(), closeAll())
	}
	return parent, check, nil
}

func (f *nativeSkillFS) read(ctx context.Context, parent *os.Root, name string, limit int64) (raw []byte, info os.FileInfo, resultErr error) {
	if err := nativeSkillContext(ctx); err != nil {
		return nil, nil, err
	}
	if !nativeSkillComponent(name) || limit < 0 {
		return nil, nil, ErrNativeHistoryInvalid
	}
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return nil, nil, ErrNativeHistoryInvalid
	}
	if err = f.reserve(3 * (before.Size() + 1)); err != nil {
		return nil, nil, err
	}
	if err = f.take(); err != nil {
		return nil, nil, err
	}
	file, err := parent.Open(name)
	if err != nil {
		f.handles--
		return nil, nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, f.closeFile(file))
		if resultErr != nil {
			raw = nil
			info = nil
		}
	}()
	held, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !nativeSkillSameFile(before, held) || !held.Mode().IsRegular() || checkAgentOpened(file) != nil {
		return nil, nil, ErrNativeHistoryInvalid
	}
	raw, err = io.ReadAll(io.LimitReader(&nativeSkillContextReader{reader: file, ctx: ctx}, held.Size()+1))
	if err != nil {
		return nil, nil, err
	}
	after, err := parent.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	post, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if int64(len(raw)) != held.Size() || !nativeSkillSameFile(held, after) || !nativeSkillSameFile(held, post) {
		return nil, nil, ErrPlanDrift
	}
	return raw, held, nil
}
func nativeSkillSameFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func (f *nativeSkillFS) write(rel string, raw []byte) (info os.FileInfo, resultErr error) {
	return f.writeMode(rel, raw, 0600)
}

func (f *nativeSkillFS) writeMode(rel string, raw []byte, mode os.FileMode) (info os.FileInfo, resultErr error) {
	if err := f.reserve(int64(len(raw))); err != nil {
		return nil, err
	}
	d, closeDir, err := f.dir(filepath.Dir(rel), false)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeDir()) }()
	name := filepath.Base(rel)
	if !nativeSkillComponent(name) {
		return nil, ErrNativeEvidenceInvalid
	}
	if err = f.take(); err != nil {
		return nil, err
	}
	file, err := d.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		f.handles--
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, f.closeFile(file)) }()
	if n, e := file.Write(raw); e != nil {
		return nil, e
	} else if n != len(raw) {
		return nil, io.ErrShortWrite
	}
	if err = file.Chmod(mode.Perm()); err != nil {
		return nil, err
	}
	if err = f.ops.syncFile(file); err != nil {
		f.ioErr = errors.Join(ErrNativePersistence, err)
		return nil, err
	}
	return file.Stat()
}

func (f *nativeSkillFS) payloadDirectory(rel string) (resultErr error) {
	d, done, err := f.dir(rel, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, done()) }()
	if err = f.take(); err != nil {
		return err
	}
	file, err := d.Open(".")
	if err != nil {
		f.handles--
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, f.closeFile(file)) }()
	if err = file.Chmod(0755); err != nil {
		return err
	}
	return f.sync(rel)
}

func (f *nativeSkillFS) sync(rel string) error {
	root, done, err := f.dir(rel, false)
	if err != nil {
		return err
	}
	_ = root
	err = f.ops.syncParent(filepath.Join(f.selection.home, ".claude", "skills", rel))
	err = errors.Join(err, done())
	if err != nil {
		f.ioErr = errors.Join(f.ioErr, ErrNativePersistence, err)
	}
	return err
}
func (f *nativeSkillFS) Close() error {
	var e error
	for _, r := range []*os.Root{f.skills, f.claude, f.home} {
		e = errors.Join(e, f.closeRoot(r))
	}
	f.skills = nil
	f.claude = nil
	f.home = nil
	// Retry only retained known descriptors; uncertainty remains observable even
	// if a second Close establishes that an earlier syscall already closed it.
	for file := range f.uncertainFiles {
		err := f.ops.closeFile(file)
		if err == nil || errors.Is(err, os.ErrClosed) {
			f.handles--
			delete(f.uncertainFiles, file)
		}
		e = errors.Join(e, err)
	}
	for root := range f.uncertainRoots {
		err := f.ops.closeRoot(root)
		if err == nil || errors.Is(err, os.ErrClosed) {
			f.handles--
			delete(f.uncertainRoots, root)
		}
		e = errors.Join(e, err)
	}
	return errors.Join(e, f.ioErr)
}

func nativeSkillContext(ctx context.Context) error {
	if ctx == nil {
		return ErrNativeSessionUnavailable
	}
	return ctx.Err()
}

type nativeSkillContextReader struct {
	reader io.Reader
	ctx    context.Context
}

func (r *nativeSkillContextReader) Read(p []byte) (int, error) {
	if err := nativeSkillContext(r.ctx); err != nil {
		return 0, err
	}
	if len(p) > 64<<10 {
		p = p[:64<<10]
	}
	return r.reader.Read(p)
}
