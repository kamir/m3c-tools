package install

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
	"unicode/utf8"
)

type installedProofLimits struct {
	WorkBytes                                      int64
	Entries, PathBytes, PathLength, Depth, Handles int
}

var defaultInstalledProofLimits = installedProofLimits{512 << 20, 100000, 4 << 20, 4096, 128, 64}

type installedProofBudget struct {
	limits                         *installedProofLimits
	work                           int64
	entries, paths, handles        int
	reservedWork                   int64
	reservedEntries, reservedPaths int
}

func (b *installedProofBudget) charge(n int64) error {
	if n < 0 || n > b.limits.WorkBytes-b.work-b.reservedWork {
		return errors.New("installed proof work budget exhausted")
	}
	b.work += n
	return nil
}
func (b *installedProofBudget) handle() error {
	if b.handles >= b.limits.Handles {
		return errors.New("installed proof handle budget exhausted")
	}
	b.handles++
	return nil
}
func (b *installedProofBudget) entry(p string, depth int) error {
	if !utf8.ValidString(p) || b.entries+b.reservedEntries >= b.limits.Entries || depth > b.limits.Depth || len(p) > b.limits.PathLength || len(p) > b.limits.PathBytes-b.paths-b.reservedPaths {
		return errors.New("installed proof tree budget exhausted")
	}
	if err := b.charge(int64(len(p)) + 256); err != nil {
		return err
	}
	b.entries++
	b.paths += len(p)
	return nil
}

type installedProofRoot struct {
	root           *os.Root
	parent         *installedProofRoot
	name, absolute string
	identity       os.FileInfo
	budget         *installedProofBudget
	observed       map[string]os.FileInfo
	baseline       []installedProofEntry
}

func openProofRoot(b *installedProofBudget, parent *installedProofRoot, name string) (*installedProofRoot, error) {
	if len(name) > b.limits.PathLength {
		return nil, errors.New("installed proof path too long")
	}
	var before os.FileInfo
	var err error
	if parent == nil {
		before, err = os.Lstat(name)
	} else {
		before, err = parent.root.Lstat(name)
	}
	if err != nil || !plainProofDir(before) {
		return nil, errors.New("installed proof directory unavailable")
	}
	if err = b.handle(); err != nil {
		return nil, err
	}
	var r *os.Root
	if parent == nil {
		r, err = os.OpenRoot(name)
	} else {
		r, err = parent.root.OpenRoot(name)
	}
	if err != nil {
		b.handles--
		return nil, errors.New("installed proof directory open failed")
	}
	p := &installedProofRoot{root: r, parent: parent, name: name, identity: before, budget: b}
	if parent == nil {
		p.absolute = name
	}
	if err = p.validate(); err != nil {
		return nil, errors.Join(err, p.close())
	}
	return p, nil
}
func plainProofDir(i os.FileInfo) bool { return i != nil && i.Mode()&os.ModeType == os.ModeDir }
func (p *installedProofRoot) validate() error {
	held, err := p.root.Stat(".")
	if err != nil || !plainProofDir(held) || !os.SameFile(p.identity, held) {
		return errors.New("installed proof directory identity changed")
	}
	var live os.FileInfo
	if p.parent == nil {
		live, err = os.Lstat(p.absolute)
	} else {
		live, err = p.parent.root.Lstat(p.name)
	}
	if err != nil || !plainProofDir(live) || !os.SameFile(held, live) {
		return errors.New("installed proof live directory changed")
	}
	return nil
}
func (p *installedProofRoot) close() error {
	if p.root == nil {
		return nil
	}
	// An externally invalidated descriptor is not a successful cleanup proof,
	// even on platforms where Root.Close itself is idempotent.
	_, statErr := p.root.Stat(".")
	err := errors.Join(statErr, p.root.Close())
	p.root = nil
	p.budget.handles--
	if err != nil {
		return errors.New("installed proof directory close failed")
	}
	return nil
}

type installedProofEntry struct {
	rel  string
	info os.FileInfo
}

func (p *installedProofRoot) inventory(ctx context.Context) ([]installedProofEntry, error) {
	type node struct {
		rel   string
		depth int
		info  os.FileInfo
	}
	if p.observed == nil {
		p.observed = map[string]os.FileInfo{".": p.identity}
	}
	queue := []node{{".", 0, p.identity}}
	var out []installedProofEntry
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := queue[0]
		queue = queue[1:]
		f, err := p.openRegular(ctx, n.rel, n.info, true)
		if err != nil {
			return nil, err
		}
		scanErr := func() error {
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				// A bounded partial read detects the first excess entry without an unbounded ReadDir allocation.
				count := 128
				if remaining := p.budget.limits.Entries - p.budget.entries + 1; remaining < count {
					count = remaining
				}
				if count < 1 {
					return errors.New("installed proof entry budget exhausted")
				}
				entries, readErr := f.ReadDir(count)
				for _, e := range entries {
					rel := e.Name()
					if n.rel != "." {
						rel = n.rel + "/" + rel
					}
					if err := p.budget.entry(rel, n.depth+1); err != nil {
						return err
					}
					info, err := f.parent.root.Lstat(e.Name())
					if err != nil {
						return errors.New("installed proof entry unavailable")
					}
					// Type checks precede every metadata and platform-file exemption.
					if !info.Mode().IsRegular() && !plainProofDir(info) {
						return errors.New("installed proof links and special files unsupported")
					}
					if old, ok := p.observed[rel]; ok && (!os.SameFile(old, info) || old.Mode().Type() != info.Mode().Type()) {
						return errors.New("installed proof inventory identity changed")
					}
					p.observed[rel] = info
					out = append(out, installedProofEntry{rel, info})
					if info.IsDir() {
						queue = append(queue, node{rel, n.depth + 1, info})
					}
				}
				if readErr == io.EOF {
					return nil
				}
				if readErr != nil {
					return errors.New("installed proof directory read failed")
				}
			}
		}()
		checkErr := p.checkOpened(n.rel, n.info, f, true)
		closeErr := p.closeFile(f)
		if err := errors.Join(scanErr, checkErr, closeErr); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// A file keeps its ordinary intermediate directory descriptors until its final
// identity check. Root confinement alone permits symlink traversal inside a root.
type installedProofFile struct {
	*os.File
	parent  *installedProofRoot
	name    string
	parents []*installedProofRoot
}

func (p *installedProofRoot) openRegular(ctx context.Context, rel string, before os.FileInfo, directory bool) (*installedProofFile, error) {
	parent := p
	var held []*installedProofRoot
	fail := func(err error) (*installedProofFile, error) {
		for i := len(held) - 1; i >= 0; i-- {
			err = errors.Join(err, held[i].close())
		}
		return nil, err
	}
	parts := strings.Split(rel, "/")
	count := len(parts) - 1
	if directory && rel != "." {
		count = len(parts)
	}
	prefix := ""
	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if prefix != "" {
			prefix += "/"
		}
		prefix += parts[i]
		expected := p.observed[prefix]
		if !plainProofDir(expected) {
			return fail(errors.New("installed proof intermediate directory missing"))
		}
		next, err := openProofRoot(p.budget, parent, parts[i])
		if err != nil {
			return fail(err)
		}
		held = append(held, next)
		if !os.SameFile(expected, next.identity) {
			return fail(errors.New("installed proof intermediate directory changed"))
		}
		parent = next
	}
	name := parts[len(parts)-1]
	if directory {
		name = "."
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	live, err := parent.root.Lstat(name)
	if err != nil || !os.SameFile(before, live) || (directory && !plainProofDir(live)) || (!directory && !live.Mode().IsRegular()) {
		return fail(errors.New("installed proof entry changed before open"))
	}
	if err = p.budget.handle(); err != nil {
		return fail(err)
	}
	raw, err := parent.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		p.budget.handles--
		return fail(errors.New("installed proof file open failed"))
	}
	f := &installedProofFile{File: raw, parent: parent, name: name, parents: held}
	if err = p.checkOpened(rel, before, f, directory); err != nil {
		return nil, errors.Join(err, p.closeFile(f))
	}
	return f, nil
}
func (p *installedProofRoot) checkOpened(_ string, before os.FileInfo, f *installedProofFile, directory bool) error {
	for _, parent := range f.parents {
		if err := parent.validate(); err != nil {
			return err
		}
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) || (directory && !plainProofDir(opened)) || (!directory && (!opened.Mode().IsRegular() || opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()))) {
		return errors.New("installed proof opened entry changed")
	}
	live, err := f.parent.root.Lstat(f.name)
	if err != nil || !os.SameFile(opened, live) || (!directory && !live.Mode().IsRegular()) || (directory && !plainProofDir(live)) {
		return errors.New("installed proof live entry changed")
	}
	return nil
}
func (p *installedProofRoot) closeFile(f *installedProofFile) error {
	err := f.Close()
	p.budget.handles--
	for i := len(f.parents) - 1; i >= 0; i-- {
		err = errors.Join(err, f.parents[i].close())
	}
	if err != nil {
		return errors.New("installed proof file close failed")
	}
	return nil
}

// Re-enumeration is charged to the same phase and compares identity as well as
// type/size/timestamp. It detects ordinary persistent changes, not arbitrary ABA.
func (p *installedProofRoot) sameInventory(ctx context.Context, before []installedProofEntry) error {
	current, err := p.inventory(ctx)
	if err != nil {
		return err
	}
	if len(current) != len(before) {
		return errors.New("installed proof inventory changed")
	}
	if err := p.budget.charge(int64(len(before)) * 128); err != nil {
		return err
	}
	expected := make(map[string]os.FileInfo, len(before))
	for _, e := range before {
		expected[e.rel] = e.info
	}
	for _, e := range current {
		old := expected[e.rel]
		if old == nil || !os.SameFile(old, e.info) || old.Mode().Type() != e.info.Mode().Type() || old.Size() != e.info.Size() || !old.ModTime().Equal(e.info.ModTime()) {
			return errors.New("installed proof inventory changed")
		}
	}
	return nil
}
func (p *installedProofRoot) read(ctx context.Context, e installedProofEntry, capBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.info.Size() < 0 || e.info.Size() > capBytes {
		return nil, errors.New("installed proof file exceeds limit")
	}
	// Reserve read storage and copying before allocating the bounded buffer.
	n := e.info.Size()
	if n > int64(int(^uint(0)>>1))-1 {
		return nil, errors.New("installed proof file exceeds address space")
	}
	if err := p.budget.charge(n + 1); err != nil {
		return nil, err
	}
	f, err := p.openRegular(ctx, e.rel, e.info, false)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, int(n)+1)
	read := 0
	for read < len(raw) {
		if err = ctx.Err(); err != nil {
			break
		}
		var k int
		k, err = f.Read(raw[read:])
		read += k
		if err != nil {
			break
		}
		if k == 0 {
			err = io.ErrNoProgress
			break
		}
	}
	checkErr := p.checkOpened(e.rel, e.info, f, false)
	closeErr := p.closeFile(f)
	if err == io.EOF && int64(read) == n {
		err = nil
	}
	if err != nil || int64(read) != n || checkErr != nil || closeErr != nil {
		return nil, errors.New("installed proof bounded file read failed")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return raw[:read], nil
}
func proofExempt(rel string) bool {
	if path.Base(rel) == ".DS_Store" {
		return true
	}
	if strings.Contains(rel, "/") {
		return false
	}
	return rel == offlineMetaFile || rel == ".m3c-provenance.json" || rel == ".skillctl-attest.json" || strings.HasSuffix(rel, ".skb")
}
