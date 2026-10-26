package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type nativeSkillPending struct {
	Schema, Name, Home, Target, Selection, Archive, Context, Source, Transaction, Stage, Backup string
}
type nativeSkillWorkspace struct {
	marker, transaction, stage, backup string
	markerRaw                          []byte
	markerInfo, transactionInfo        os.FileInfo
	stageTree                          *nativeSkillTree
	lock                               *os.File
	lockInfo                           os.FileInfo
	complete                           bool
}

func (s *NativeLiveSkillSession) reserveWorkspace(ctx context.Context) (out *nativeSkillWorkspace, resultErr error) {
	f := s.fs
	d, done, err := f.dir(".native-skill", true)
	if err != nil {
		return nil, errors.Join(ErrNativePersistence, err)
	}
	defer func() { resultErr = errors.Join(resultErr, done()) }()
	w := &nativeSkillWorkspace{}
	out = w
	before, err := d.Lstat("publish.lock")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return w, err
	}
	if err == nil && !before.Mode().IsRegular() {
		return w, ErrNativeHistoryInvalid
	}
	if err = f.take(); err != nil {
		return w, err
	}
	flag := os.O_RDWR
	if before == nil {
		flag |= os.O_CREATE | os.O_EXCL
	}
	lock, err := d.OpenFile("publish.lock", flag, 0600)
	if err != nil {
		f.handles--
		return w, err
	}
	w.lock = lock
	held, err := lock.Stat()
	if err != nil {
		return w, err
	}
	if !held.Mode().IsRegular() || checkAgentOpened(lock) != nil || (before != nil && !nativeSkillSameFile(before, held)) {
		return w, ErrNativeHistoryInvalid
	}
	w.lockInfo = held
	if before == nil {
		if err = f.ops.syncFile(lock); err != nil {
			f.ioErr = errors.Join(ErrNativePersistence, err)
			return w, f.ioErr
		}
	}
	lockctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if err = lockctx.Err(); err != nil {
			return w, err
		}
		err = tryAgentLock(lock)
		if err == nil {
			break
		}
		if !agentLockBusy(err) {
			return w, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-lockctx.Done():
			timer.Stop()
			return w, lockctx.Err()
		case <-timer.C:
		}
	}
	for _, name := range []string{"pending", "transactions"} {
		r, _, e := f.child(d, name, true)
		if e != nil {
			return w, e
		}
		if e = f.closeRoot(r); e != nil {
			return w, e
		}
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return w, err
	}
	tx := hex.EncodeToString(random[:])
	w.transaction = filepath.Join(".native-skill", "transactions", tx)
	w.stage = filepath.Join(w.transaction, "stage")
	w.backup = filepath.Join(w.transaction, "backup")
	h := sha256.Sum256([]byte(s.prepared.bundle.Name))
	w.marker = filepath.Join(".native-skill", "pending", hex.EncodeToString(h[:])+".json")
	if _, err = f.skills.Lstat(w.marker); err == nil {
		return w, ErrNativeHistoryExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return w, err
	}
	if _, err = f.skills.Lstat(w.transaction); err == nil {
		return w, ErrNativeHistoryExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return w, err
	}
	p := nativeSkillPending{Schema: "m3c.native-skill-pending/v1", Name: s.prepared.bundle.Name, Home: s.journal.selection.home, Target: filepath.Join(s.journal.selection.home, ".claude", "skills", s.prepared.bundle.Name), Selection: s.journal.selection.selectionID, Archive: s.rootDigest, Context: agentDigest(s.prepared.contextRaw), Source: s.sourceBinding, Transaction: tx, Stage: w.stage, Backup: w.backup}
	w.markerRaw, err = json.Marshal(p)
	if err != nil || len(w.markerRaw) > 64<<10 {
		return w, ErrNativeEvidenceInvalid
	}
	w.markerInfo, err = f.write(w.marker, w.markerRaw)
	if err != nil {
		return w, errors.Join(ErrNativePersistence, err)
	}
	if err = f.sync(filepath.Join(".native-skill", "pending")); err != nil {
		return w, errors.Join(ErrNativePersistence, err)
	}
	for _, path := range []string{".native-skill", "."} {
		if err = f.sync(path); err != nil {
			return w, errors.Join(ErrNativePersistence, err)
		}
	}
	parent, closeParent, err := f.dir(filepath.Dir(w.transaction), false)
	if err != nil {
		return w, err
	}
	err = parent.Mkdir(tx, 0700)
	if err == nil {
		w.transactionInfo, err = parent.Lstat(tx)
		if err == nil {
			f.ownedDirs[filepath.Join(parent.Name(), tx)] = w.transactionInfo
		}
	}
	err = errors.Join(err, closeParent())
	if err != nil {
		return w, err
	}
	if err = f.sync(filepath.Join(".native-skill", "transactions")); err != nil {
		return w, errors.Join(ErrNativePersistence, err)
	}
	return w, nil
}

func (s *NativeLiveSkillSession) stage(ctx context.Context) error {
	f, w, p := s.fs, s.workspace, s.prepared
	if w == nil || p == nil {
		return ErrNativeSessionUnavailable
	}
	tx, done, err := f.dir(w.transaction, false)
	if err != nil {
		return err
	}
	err = tx.Mkdir("stage", 0700)
	if err == nil {
		info, e := tx.Lstat("stage")
		err = e
		if e == nil {
			f.ownedDirs[filepath.Join(tx.Name(), "stage")] = info
		}
	}
	err = errors.Join(err, done())
	if err != nil {
		return err
	}
	// Parents implicit in Pack archives are created with exact actual spelling;
	// an existing alias is refused by child/exactName rather than normalized.
	dirs := map[string]bool{w.stage: true}
	for _, entry := range p.entries {
		if err = nativeSkillContext(ctx); err != nil {
			return err
		}
		rel := filepath.Join(w.stage, filepath.FromSlash(entry.Rel))
		parent := filepath.Dir(rel)
		if entry.IsDir {
			parent = rel
		}
		d, closeDir, e := f.dir(parent, true)
		if e != nil {
			return e
		}
		_ = d
		if e = closeDir(); e != nil {
			return e
		}
		for path := parent; strings.HasPrefix(path, w.stage); path = filepath.Dir(path) {
			dirs[path] = true
			if path == w.stage {
				break
			}
		}
		if !entry.IsDir {
			if _, e = f.writeMode(rel, entry.Content, entry.Mode); e != nil {
				return e
			}
		}
	}
	selector := nativeSkillSelector{Schema: nativeSkillSelectorSchema, Kind: "skill", Name: p.bundle.Name, Version: p.bundle.Version, BundleDigest: s.rootDigest, ContextSHA256: strings.TrimPrefix(agentDigest(p.contextRaw), "sha256:")}
	raw, err := json.Marshal(selector)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		name string
		data []byte
	}{{p.bundle.Name + ".skb", p.archive}, {AttestationStashName, p.contextRaw}, {ProvenanceSidecarName, raw}} {
		if _, err = f.write(filepath.Join(w.stage, entry.name), entry.data); err != nil {
			return err
		}
	}
	paths := make([]string, 0, len(dirs))
	for path := range dirs {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, path := range paths {
		if err = f.payloadDirectory(path); err != nil {
			return err
		}
	}
	if err = f.sync(w.transaction); err != nil {
		return err
	}
	w.stageTree, err = f.tree(ctx, w.stage, false, p.bundle.Name)
	return err
}

func (s *NativeLiveSkillSession) checkMarker() (resultErr error) {
	f, w := s.fs, s.workspace
	if f == nil || w == nil || w.markerInfo == nil || w.lock == nil {
		return ErrNativeSessionUnavailable
	}
	if err := f.live(); err != nil {
		return err
	}
	parent, done, err := f.dir(filepath.Dir(w.marker), false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, done()) }()
	raw, held, err := f.read(context.Background(), parent, filepath.Base(w.marker), 64<<10)
	if err != nil {
		return err
	}
	if !nativeSkillSameFile(held, w.markerInfo) || !bytes.Equal(raw, w.markerRaw) {
		return ErrNativeHistoryInvalid
	}
	state, closeState, err := f.dir(".native-skill", false)
	if err != nil {
		return err
	}
	info, err := state.Lstat("publish.lock")
	err = errors.Join(err, closeState())
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, w.lockInfo) {
		return ErrNativeHistoryInvalid
	}
	held, e := w.lock.Stat()
	if e != nil {
		return errors.Join(ErrNativePersistence, e)
	}
	if !held.Mode().IsRegular() || !os.SameFile(held, w.lockInfo) || checkAgentOpened(w.lock) != nil {
		return ErrNativeHistoryInvalid
	}
	return nil
}

func (s *NativeLiveSkillSession) checkWorkspace() error {
	if err := s.checkMarker(); err != nil {
		return err
	}
	w := s.workspace
	info, err := s.fs.skills.Lstat(w.transaction)
	if err != nil {
		return err
	}
	if w.transactionInfo == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, w.transactionInfo) {
		return ErrNativeHistoryInvalid
	}
	d, done, err := s.fs.dir(w.transaction, false)
	if err != nil {
		return err
	}
	_ = d
	return done()
}

func (s *NativeLiveSkillSession) publish(ctx context.Context, p *nativeSkillPlan) (out *InstallResult, resultErr error) {
	f, w := s.fs, s.workspace
	if err := s.checkWorkspace(); err != nil {
		return nil, err
	}
	stage, err := f.tree(ctx, w.stage, false, s.prepared.bundle.Name)
	if err != nil {
		return nil, err
	}
	if !nativeSkillTreesEqual(w.stageTree, stage) {
		return nil, ErrPlanDrift
	}
	s.observe("before-first-rename")
	if err = s.recheckLocked(ctx); err != nil {
		return nil, err
	}
	actual, err := f.tree(ctx, s.prepared.bundle.Name, true, s.prepared.bundle.Name)
	if err != nil {
		return nil, err
	}
	if !nativeSkillTreesEqual(p.target, actual) {
		return nil, ErrPlanDrift
	}
	if err = s.checkWorkspace(); err != nil {
		return nil, err
	}
	stage, err = f.tree(ctx, w.stage, false, s.prepared.bundle.Name)
	if err != nil {
		return nil, err
	}
	if !nativeSkillTreesEqual(w.stageTree, stage) {
		return nil, ErrPlanDrift
	}
	if err = s.recheckLocked(ctx); err != nil {
		return nil, err
	}
	name := s.prepared.bundle.Name
	// A held publication lock serializes participating writers; identity/tree
	// observations do not claim an atomic snapshot against hostile same-UID code.
	if p.target.exists {
		if _, err = f.skills.Lstat(w.backup); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = ErrNativeHistoryExists
			}
			return nil, err
		}
		s.published = true
		if err = f.ops.rename(f.skills, name, w.backup); err != nil {
			return nil, err
		}
		s.observe("after-backup-rename")
		if err = s.checkWorkspace(); err != nil {
			return nil, s.restore(err)
		}
		stage, err = f.tree(ctx, w.stage, false, name)
		if err != nil {
			return nil, s.restore(err)
		}
		if !nativeSkillTreesEqual(w.stageTree, stage) {
			return nil, s.restore(ErrPlanDrift)
		}
		if err = s.recheckLocked(ctx); err != nil {
			return nil, s.restore(err)
		}
		if err = f.live(); err != nil {
			return nil, s.restore(err)
		}
		if _, err = f.skills.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = ErrPlanDrift
			}
			return nil, s.restore(err)
		}
	} else {
		if _, err = f.skills.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				err = ErrPlanDrift
			}
			return nil, err
		}
		s.published = true
	}
	if err = s.recheckLocked(ctx); err != nil {
		if p.target.exists {
			return nil, s.restore(err)
		}
		return nil, err
	}
	if err = s.checkWorkspace(); err != nil {
		if p.target.exists {
			return nil, s.restore(err)
		}
		return nil, err
	}
	if err = f.ops.rename(f.skills, w.stage, name); err != nil {
		if p.target.exists {
			return nil, s.restore(err)
		}
		return nil, err
	}
	s.observe("after-publish")
	out = &InstallResult{SkillPath: p.row.Target, ProvenancePath: filepath.Join(p.row.Target, ProvenanceSidecarName), BackupPath: p.row.BackupPath, CreatedFresh: !p.target.exists, OverwroteOld: p.target.exists, OldDigest: p.row.OldDigest}
	if err = f.sync("."); err != nil {
		return out, err
	}
	if err = f.sync(w.transaction); err != nil {
		return out, err
	}
	if err = s.removeMarker(); err != nil {
		return out, err
	}
	w.complete = true
	return out, nil
}

func (s *NativeLiveSkillSession) restore(cause error) error {
	f, w := s.fs, s.workspace
	// Restore only this transaction's backup to observed absence. Never overwrite
	// a newly appeared target or remove an unknown namespace entry.
	name := s.prepared.bundle.Name
	if _, err := f.skills.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, ErrPlanDrift, err)
	}
	if err := f.live(); err != nil {
		return errors.Join(cause, err)
	}
	if err := s.checkWorkspace(); err != nil {
		return errors.Join(cause, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.recheckLocked(ctx); err != nil {
		return errors.Join(cause, err)
	}
	backup, err := f.tree(ctx, w.backup, true, name)
	if err != nil {
		return errors.Join(cause, err)
	}
	if s.active == nil || !nativeSkillTreesEqual(s.active.target, backup) {
		return errors.Join(cause, ErrPlanDrift)
	}
	if err := f.ops.rename(f.skills, w.backup, name); err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, f.sync("."), f.sync(w.transaction))
}

func (s *NativeLiveSkillSession) removeMarker() (resultErr error) {
	if err := s.checkMarker(); err != nil {
		return err
	}
	f, w := s.fs, s.workspace
	d, done, err := f.dir(filepath.Dir(w.marker), false)
	if err != nil {
		return err
	}
	err = f.ops.remove(d, filepath.Base(w.marker))
	err = errors.Join(err, done())
	if err == nil {
		err = f.sync(filepath.Dir(w.marker))
	}
	if err != nil {
		s.poisoned = true
		// Unlink may have succeeded before sync failed. Preserve/recreate only
		// our exact reservation at an absent path; its survival is not promised.
		if _, e := f.skills.Lstat(w.marker); errors.Is(e, os.ErrNotExist) {
			info, e := f.write(w.marker, w.markerRaw)
			if e == nil {
				w.markerInfo = info
			}
			err = errors.Join(err, e)
		}
		return errors.Join(ErrNativePersistence, err)
	}
	w.markerInfo = nil
	return nil
}

func (s *NativeLiveSkillSession) cancelWorkspace() error {
	f, w := s.fs, s.workspace
	if w == nil {
		return nil
	}
	f.cleaning = true
	defer func() { f.cleaning = false }()
	var err error
	if w.markerInfo == nil {
		return nil
	} // an unknown/partially written marker is retained
	if w.stageTree == nil {
		return ErrNativePersistence
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	actual, e := f.tree(ctx, w.stage, false, s.prepared.bundle.Name)
	if e != nil {
		return e
	}
	if !nativeSkillTreesEqual(actual, w.stageTree) {
		return ErrPlanDrift
	}
	entries := append([]nativeSkillTreeEntry(nil), actual.entries...)
	sort.Slice(entries, func(i, j int) bool { return len(entries[i].path) > len(entries[j].path) })
	for _, entry := range entries {
		rel := w.stage
		if entry.path != "." {
			rel = filepath.Join(rel, entry.path)
		}
		parent, done, e := f.dir(filepath.Dir(rel), false)
		if e != nil {
			return e
		}
		info, e := parent.Lstat(filepath.Base(rel))
		if e == nil && (!os.SameFile(info, entry.info) || info.Mode() != entry.info.Mode()) {
			e = ErrPlanDrift
		}
		if e == nil {
			e = f.ops.remove(parent, filepath.Base(rel))
		}
		e = errors.Join(e, done())
		if e != nil {
			return e
		}
	}
	tx, done, e := f.dir(w.transaction, false)
	if e != nil {
		return e
	}
	if e = f.take(); e != nil {
		return errors.Join(e, done())
	}
	s.observe("cleanup-empty-check")
	dir, e := tx.Open(".")
	if e != nil {
		f.handles--
		return errors.Join(e, done())
	}
	rows, re := dir.ReadDir(1)
	if errors.Is(re, io.EOF) {
		re = nil
	}
	e = errors.Join(e, re, f.closeFile(dir), done())
	if len(rows) > 0 {
		return errors.Join(ErrNativeHistoryInvalid, e)
	}
	if e != nil {
		return e
	}
	parent, closeParent, e := f.dir(filepath.Dir(w.transaction), false)
	if e != nil {
		return e
	}
	err = f.ops.remove(parent, filepath.Base(w.transaction))
	err = errors.Join(err, closeParent())
	if err != nil {
		return err
	}
	return s.removeMarker()
}
