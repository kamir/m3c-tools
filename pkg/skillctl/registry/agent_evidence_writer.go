package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/secfile"
)

type agentFileOps struct {
	write         func(*os.File, []byte) (int, error)
	sync          func(*os.File) error
	close         func(*os.File) error
	closeDir      func(*os.Root) error
	replace       func(string, string) error
	syncParent    func(string) error
	removeAll     func(string) error
	snapshotClose func(*os.File) error
}

func defaultAgentFileOps() agentFileOps {
	return agentFileOps{
		closeDir: func(r *os.Root) error { return r.Close() },
		write:    func(f *os.File, b []byte) (int, error) { return f.Write(b) }, sync: func(f *os.File) error { return f.Sync() }, close: func(f *os.File) error { return f.Close() }, replace: replaceAgentFile, syncParent: syncAgentParent, removeAll: os.RemoveAll, snapshotClose: func(f *os.File) error { return f.Close() },
	}
}
func agentOpsOf(opts InstallOpts) agentFileOps {
	if opts.agentOps != nil {
		return *opts.agentOps
	}
	return defaultAgentFileOps()
}
func agentContextOf(opts InstallOpts) context.Context {
	if opts.Ctx != nil {
		return opts.Ctx
	}
	return context.Background()
}
func agentClockOf(opts InstallOpts) time.Time {
	if opts.agentNow != nil {
		return opts.agentNow()
	}
	return time.Now()
}

type agentDir struct {
	root       *os.Root
	parent     *agentDir
	name, path string
	info       os.FileInfo
}

func openAgentDir(parent *agentDir, path string, create bool) (*agentDir, error) {
	name := path
	if parent != nil {
		name = filepath.Base(path)
	}
	var info os.FileInfo
	var err error
	if parent == nil {
		info, err = os.Lstat(path)
	} else {
		info, err = parent.root.Lstat(name)
	}
	if errors.Is(err, os.ErrNotExist) && create && parent != nil {
		if err = parent.root.Mkdir(name, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		info, err = parent.root.Lstat(name)
	}
	if err != nil || info == nil || info.Mode()&os.ModeType != os.ModeDir {
		return nil, ErrAgentEvidenceInvalid
	}
	var r *os.Root
	if parent == nil {
		r, err = os.OpenRoot(path)
	} else {
		r, err = parent.root.OpenRoot(name)
	}
	if err != nil {
		return nil, err
	}
	d := &agentDir{root: r, parent: parent, name: name, path: path, info: info}
	if err = d.validate(); err != nil {
		return nil, errors.Join(err, r.Close())
	}
	return d, nil
}
func (d *agentDir) validate() error {
	if d == nil || d.root == nil {
		return ErrAgentEvidenceInvalid
	}
	held, e := d.root.Stat(".")
	if e != nil || held.Mode()&os.ModeType != os.ModeDir || !os.SameFile(held, d.info) {
		return ErrAgentEvidenceInvalid
	}
	var live os.FileInfo
	if d.parent == nil {
		live, e = os.Lstat(d.path)
	} else {
		if e = d.parent.validate(); e != nil {
			return e
		}
		live, e = d.parent.root.Lstat(d.name)
	}
	if e != nil || live.Mode()&os.ModeType != os.ModeDir || !os.SameFile(live, held) {
		return ErrAgentEvidenceInvalid
	}
	return nil
}

type agentPublicationLease struct {
	file             *os.File
	dirs             []*agentDir
	agents, evidence *agentDir
	ops              agentFileOps
	published        bool
	closed           bool
}

func (l *agentPublicationLease) validate() error {
	if l == nil || l.closed || l.file == nil {
		return ErrAgentEvidenceInvalid
	}
	if e := l.evidence.validate(); e != nil {
		return e
	}
	held, e := l.file.Stat()
	if e != nil || !held.Mode().IsRegular() {
		return ErrAgentEvidenceInvalid
	}
	live, e := l.evidence.root.Lstat(".publish.lock")
	if e != nil || !live.Mode().IsRegular() || !os.SameFile(held, live) {
		return ErrAgentEvidenceInvalid
	}
	return checkAgentOpened(l.file)
}
func (l *agentPublicationLease) Close() error {
	if l == nil || l.closed {
		return nil
	}
	l.closed = true
	var err error
	if l.file != nil {
		err = l.ops.close(l.file)
	}
	for i := len(l.dirs) - 1; i >= 0; i-- {
		err = errors.Join(err, l.ops.closeDir(l.dirs[i].root))
	}
	if err != nil && l.published {
		return agentPublicationFailure(err)
	}
	return err
}
func acquireAgentPublication(ctx context.Context, agents string, ops agentFileOps) (lease *agentPublicationLease, resultErr error) {
	if ctx == nil {
		return nil, ErrAgentEvidenceInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	abs, e := filepath.Abs(agents)
	if e != nil {
		return nil, e
	}
	parent := filepath.Dir(abs)
	anchor := filepath.Dir(parent)
	// The caller selects the installation parent. Canonicalize only the anchor,
	// leaving the actual parent/agents/evidence components ordinary and bound.
	if e = os.MkdirAll(anchor, 0700); e != nil {
		return nil, e
	}
	anchor, e = filepath.EvalSymlinks(anchor)
	if e != nil {
		return nil, e
	}
	parent = filepath.Join(anchor, filepath.Base(parent))
	abs = filepath.Join(parent, filepath.Base(abs))
	l := &agentPublicationLease{ops: ops}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, l.Close())
		}
	}()
	a, e := openAgentDir(nil, anchor, false)
	if e != nil {
		return nil, e
	}
	l.dirs = append(l.dirs, a)
	p, e := openAgentDir(a, parent, true)
	if e != nil {
		return nil, e
	}
	l.dirs = append(l.dirs, p)
	ag, e := openAgentDir(p, abs, true)
	if e != nil {
		return nil, e
	}
	l.dirs = append(l.dirs, ag)
	l.agents = ag
	ev, e := openAgentDir(ag, filepath.Join(abs, agentEvidenceDir), true)
	if e != nil {
		return nil, e
	}
	l.dirs = append(l.dirs, ev)
	l.evidence = ev
	// O_EXCL creates the stable inode; another cooperating creator may win.
	f, e := ev.root.OpenFile(".publish.lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e == nil {
		if e = secfile.SecureFileDACL(filepath.Join(ev.path, ".publish.lock")); e == nil {
			e = f.Sync()
		}
		if e == nil {
			e = ops.syncParent(ev.path)
		}
		if e != nil {
			return nil, errors.Join(e, f.Close())
		}
	}
	if errors.Is(e, os.ErrExist) {
		info, err := ev.root.Lstat(".publish.lock")
		if err != nil || !info.Mode().IsRegular() {
			return nil, ErrAgentEvidenceInvalid
		}
		f, e = ev.root.OpenFile(".publish.lock", os.O_RDWR, 0)
	}
	if e != nil {
		return nil, e
	}
	l.file = f
	if e = l.validate(); e != nil {
		return nil, e
	}
	wait, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for {
		if e = wait.Err(); e != nil {
			return nil, e
		}
		e = tryAgentLock(f)
		if e == nil {
			break
		}
		if !agentLockBusy(e) {
			return nil, e
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-wait.Done():
			timer.Stop()
			return nil, wait.Err()
		case <-timer.C:
		}
	}
	if e = l.validate(); e != nil {
		return nil, e
	}
	return l, nil
}

func readBoundAgentSnapshot(path, expected string, ops agentFileOps) (blob []byte, err error) {
	// The explicitly selected local cache file is read once, not a confinement API.
	// #nosec G304 -- intentionally reading the caller-selected local staged archive; not a remote file-inclusion route.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, ops.snapshotClose(f))
		if err != nil {
			blob = nil
		}
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrAgentEvidenceInvalid
	}
	return readInstallSnapshot(f, expected, MaxBlobSize)
}

func strictAgentManifest(entries []skillbundle.Entry, b *StagedBundle) (skillbundle.BundleManifest, []byte, error) {
	var man skillbundle.BundleManifest
	var raw, body []byte
	seen := map[string]bool{}
	for _, entry := range entries {
		if seen[entry.Rel] {
			return man, nil, ErrAgentEvidenceInvalid
		}
		seen[entry.Rel] = true
		if entry.IsDir {
			if entry.Rel != "." {
				return man, nil, ErrAgentEvidenceInvalid
			}
			continue
		}
		switch entry.Rel {
		case "bundle.json":
			if raw != nil {
				return man, nil, ErrAgentEvidenceInvalid
			}
			raw = entry.Content
		case "CHECKSUMS":
		case b.Name + ".md":
			if body != nil {
				return man, nil, ErrAgentEvidenceInvalid
			}
			body = entry.Content
		default:
			return man, nil, errors.Join(ErrAgentEvidenceInvalid, errors.New("unexpected agent content; nothing was installed"))
		}
	}
	m, err := readAgentJSON(raw, 1<<20)
	if err != nil {
		return man, nil, err
	}
	for key := range m {
		for _, canonical := range []string{"name", "version", "kind", "schema", "depends_on", "package_dependencies", "data_dependencies"} {
			if key != canonical && strings.EqualFold(key, canonical) {
				return man, nil, ErrAgentEvidenceInvalid
			}
		}
	}
	if json.Unmarshal(raw, &man) != nil {
		return man, nil, ErrAgentEvidenceInvalid
	}
	if !skillbundle.KnownSchema(man.Schema) {
		return man, nil, fmt.Errorf("install: %s carries schema %q, which this build does not know; upgrade skillctl (nothing was installed)", b.Name, man.Schema)
	}
	if man.EffectiveKind() != b.Kind {
		return man, nil, fmt.Errorf("install: registry tag says kind %q but the bundle manifest says %q; nothing was installed", b.Kind, man.EffectiveKind())
	}
	if man.Schema != skillbundle.SchemaAgent || man.Kind != skillbundle.KindAgent || man.Name != b.Name || man.Version != b.Version || b.Kind != skillbundle.KindAgent || body == nil {
		return man, nil, ErrAgentEvidenceInvalid
	}
	return man, body, nil
}

func validateAgentTarget(d *agentDir, name string) error {
	if err := d.validate(); err != nil {
		return err
	}
	before, err := d.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !before.Mode().IsRegular() {
		return ErrAgentEvidenceInvalid
	}
	f, err := d.root.Open(name)
	if err != nil {
		return err
	}
	held, err := f.Stat()
	if err == nil && (!held.Mode().IsRegular() || !os.SameFile(before, held)) {
		err = ErrAgentEvidenceInvalid
	}
	if err == nil {
		err = checkAgentOpened(f)
	}
	if err == nil {
		after, e := d.root.Lstat(name)
		if e != nil || !after.Mode().IsRegular() || !os.SameFile(after, held) {
			err = ErrAgentEvidenceInvalid
		}
	}
	return errors.Join(err, f.Close())
}

type agentOpsWriter struct {
	ctx  context.Context
	file *os.File
	ops  agentFileOps
}

func (w agentOpsWriter) Write(b []byte) (int, error) {
	if e := w.ctx.Err(); e != nil {
		return 0, e
	}
	return w.ops.write(w.file, b)
}
func writeAgentStaged(ctx context.Context, d *agentDir, name string, mode os.FileMode, ops agentFileOps, write func(io.Writer) error) (info os.FileInfo, err error) {
	f, err := d.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return nil, err
	}
	err = write(agentOpsWriter{ctx, f, ops})
	if err == nil {
		err = ops.sync(f)
	}
	if err == nil {
		info, err = f.Stat()
		if err == nil && (!info.Mode().IsRegular() || checkAgentOpened(f) != nil) {
			err = ErrAgentEvidenceInvalid
		}
		if err == nil {
			live, e := d.root.Lstat(name)
			if e != nil || !os.SameFile(live, info) {
				err = ErrAgentEvidenceInvalid
			}
		}
	}
	err = errors.Join(err, ops.close(f))
	return info, err
}
func writeAgentBytes(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return e
}

type preparedAgent struct {
	bundle                    *StagedBundle
	archive, contextRaw, body []byte
	roots                     *SelfTrustRoots
	manifest                  skillbundle.BundleManifest
	entries                   []skillbundle.Entry
}

func prepareAgentEvidence(b *StagedBundle, skb []byte, opts InstallOpts) (*preparedAgent, error) {
	return prepareAgentEvidenceMode(b, skb, opts, false)
}

func prepareNativeAgentEvidence(b *StagedBundle, skb []byte, opts InstallOpts) (*preparedAgent, error) {
	return prepareAgentEvidenceMode(b, skb, opts, true)
}

// nativeManifest selects stricter parsing only; it never grants publication.
func prepareAgentEvidenceMode(b *StagedBundle, skb []byte, opts InstallOpts, nativeManifest bool) (*preparedAgent, error) {
	if b == nil {
		return nil, ErrAgentEvidenceInvalid
	}
	if !validAgentName(b.Name) {
		return nil, ErrAgentEvidenceInvalid
	}
	roots, err := snapshotAgentRoots(opts.NativeTrustRoots)
	if err != nil {
		return nil, agentEvidenceDiagnostic(err)
	}
	ctxSnapshot, contextRaw, err := snapshotAgentContext(b.Attestation)
	if err != nil {
		return nil, agentEvidenceDiagnostic(err)
	}
	copyBundle := *b
	copyBundle.Attestation = ctxSnapshot
	b = &copyBundle
	for _, s := range []string{b.Name, b.Version, b.Digest, b.Governance, b.SourceDocID, b.AuthorIdentity, opts.RegistrySpec, opts.ContextID, opts.TrustRootsFingerprint} {
		if len(s) > 8192 {
			return nil, ErrAgentEvidenceInvalid
		}
	}
	if !agentText(b.Version, 256) {
		return nil, ErrAgentEvidenceInvalid
	}
	ctx := agentContextOf(opts)
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if nativeManifest {
		if err = verifyAgentContext(roots, ctxSnapshot, b.Digest, b.Name, b.Version, agentClockOf(opts)); err != nil {
			return nil, err
		}
	}
	// The native byte cap is explicit and finite, including hidden tar metadata.
	inflated := skillbundle.DefaultMaxExtractedBytes + int64(skillbundle.DefaultMaxExtractedFiles)*1024 + (1 << 20)
	entries, _, err := skillbundle.UnpackBounded(ctx, skb, skillbundle.UnpackOptions{}, inflated)
	if err != nil {
		return nil, err
	}
	if nativeManifest {
		if err = nativeEmptyAgentDependencies(entries); err != nil {
			return nil, err
		}
	}
	manifest, body, err := strictAgentManifest(entries, b)
	if err != nil {
		return nil, err
	}
	if err = verifyAgentContext(roots, ctxSnapshot, b.Digest, b.Name, b.Version, agentClockOf(opts)); err != nil {
		return nil, err
	}

	return &preparedAgent{bundle: b, archive: skb, contextRaw: contextRaw, body: body, roots: roots, manifest: manifest, entries: entries}, nil
}

func publishAgentEvidence(b *StagedBundle, skb []byte, opts InstallOpts) (*InstallResult, error) {
	prepared, err := prepareAgentEvidence(b, skb, opts)
	if err != nil {
		return nil, agentEvidenceDiagnostic(err)
	}
	return publishPreparedAgent(prepared, opts, nil)
}

// Both legacy and native session installation use this checked C2 publisher.
// A native capability is concrete and private, never a caller approval callback.
func publishPreparedAgent(prepared *preparedAgent, opts InstallOpts, native *NativeInstallSession) (result *InstallResult, resultErr error) {
	published := false
	defer func() {
		if resultErr != nil {
			result = nil
			resultErr = agentEvidenceDiagnostic(resultErr)
			if published {
				resultErr = agentPublicationFailure(resultErr)
			}
		}
	}()
	if prepared == nil || prepared.bundle == nil {
		return nil, ErrAgentEvidenceInvalid
	}
	b, skb, contextRaw, body, roots := prepared.bundle, prepared.archive, prepared.contextRaw, prepared.body, prepared.roots
	ctxSnapshot := b.Attestation
	ctx := agentContextOf(opts)
	var err error
	if native != nil {
		native.observe("before-artifact-write")
		if err = native.recheckLocked(ctx, prepared); err != nil {
			return nil, err
		}
	}
	ops := agentOpsOf(opts)
	l := opts.agentLease
	if l == nil {
		l, err = acquireAgentPublication(ctx, agentsDirFor(opts.SkillsDir), ops)
		if err != nil {
			return nil, err
		}
		defer func() { resultErr = errors.Join(resultErr, l.Close()) }()
	}
	if err = l.validate(); err != nil {
		return nil, err
	}
	target := filepath.Join(l.agents.path, b.Name+".md")
	record := filepath.Join(l.evidence.path, agentRecordName(b.Name))
	provPath := filepath.Join(l.agents.path, ".provenance", b.Name+".json")
	previous, statErr := l.agents.root.Lstat(b.Name + ".md")
	if statErr == nil && !previous.Mode().IsRegular() {
		return nil, ErrAgentEvidenceInvalid
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	provenance, err := openAgentDir(l.agents, filepath.Join(l.agents.path, ".provenance"), true)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, ops.closeDir(provenance.root)) }()
	for _, target := range []struct {
		dir  *agentDir
		name string
	}{{l.agents, b.Name + ".md"}, {l.evidence, agentRecordName(b.Name)}, {provenance, b.Name + ".json"}} {
		if err = validateAgentTarget(target.dir, target.name); err != nil {
			return nil, err
		}
	}
	if !opts.AllowDowngrade {
		pre, e := readAgentProvenance(provenance, b.Name+".json")
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		if e == nil && agentVersionOlder(b.Version, pre.Version) {
			return nil, errAgentDowngrade(b.Name, pre.Version, b.Version)
		}
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	stageName := ".stage-" + hex.EncodeToString(random[:])
	stage, err := openAgentDir(l.evidence, filepath.Join(l.evidence.path, stageName), true)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := ops.closeDir(stage.root)
		cleanupErr := ops.removeAll(stage.path)
		e := errors.Join(closeErr, cleanupErr)
		if e != nil && published {
			e = agentPublicationFailure(e)
		}
		resultErr = errors.Join(resultErr, e)
	}()
	h := agentRecordHeader{agentRecordSchema, "agent", b.Name, b.Version, b.Digest, int64(len(skb)), int64(len(contextRaw)), strings.TrimPrefix(agentDigest(contextRaw), "sha256:")}
	if native != nil {
		if err = native.recheckLocked(ctx, prepared); err != nil {
			return nil, err
		}
	}
	recordInfo, err := writeAgentStaged(ctx, stage, "record", 0600, ops, func(w io.Writer) error { return writeAgentRecord(w, h, skb, contextRaw) })
	if err != nil {
		return nil, err
	}
	bodyInfo, err := writeAgentStaged(ctx, stage, "body", 0644, ops, func(w io.Writer) error { return writeAgentBytes(w, body) })
	if err != nil {
		return nil, err
	}
	rawProvenance, err := json.Marshal(provenanceFor(b, opts))
	if err != nil || len(rawProvenance) > 65536 {
		return nil, ErrAgentEvidenceInvalid
	}
	provenanceInfo, err := writeAgentStaged(ctx, stage, "provenance", 0644, ops, func(w io.Writer) error { return writeAgentBytes(w, rawProvenance) })
	if err != nil {
		return nil, err
	}
	if err = ops.syncParent(stage.path); err != nil {
		return nil, err
	}
	if err = verifyAgentContext(roots, ctxSnapshot, b.Digest, b.Name, b.Version, agentClockOf(opts)); err != nil {
		return nil, err
	}
	for _, row := range []struct {
		src, target string
		parent      *agentDir
		name        string
		info        os.FileInfo
	}{{"record", record, l.evidence, agentRecordName(b.Name), recordInfo}, {"body", target, l.agents, b.Name + ".md", bodyInfo}, {"provenance", provPath, provenance, b.Name + ".json", provenanceInfo}} {
		if err = ctx.Err(); err == nil {
			err = l.validate()
		}
		if err == nil {
			err = stage.validate()
		}
		if err == nil {
			err = row.parent.validate()
		}
		if err != nil {
			if published {
				return nil, agentPublicationFailure(err)
			}
			return nil, err
		}
		if err = validateAgentTarget(row.parent, row.name); err != nil {
			if published {
				return nil, agentPublicationFailure(err)
			}
			return nil, err
		}
		info, e := stage.root.Lstat(row.src)
		if e != nil || !info.Mode().IsRegular() || !os.SameFile(info, row.info) {
			return nil, agentPublicationFailure(ErrAgentEvidenceInvalid)
		}
		if err = verifyAgentContext(roots, ctxSnapshot, b.Digest, b.Name, b.Version, agentClockOf(opts)); err != nil {
			if published {
				return nil, agentPublicationFailure(err)
			}
			return nil, err
		}
		if native != nil {
			native.observe("before-replace")
			if err = native.recheckLocked(ctx, prepared); err != nil {
				return nil, err
			}
			native.terminal = true
		}
		published = true
		l.published = true
		if err = ops.replace(filepath.Join(stage.path, row.src), row.target); err != nil {
			return nil, agentPublicationFailure(err)
		}
		if err = errors.Join(ops.syncParent(stage.path), ops.syncParent(row.parent.path)); err != nil {
			return nil, agentPublicationFailure(err)
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, agentPublicationFailure(err)
	}
	return &InstallResult{SkillPath: filepath.Join(agentsDirFor(opts.SkillsDir), b.Name+".md"), ProvenancePath: filepath.Join(agentsDirFor(opts.SkillsDir), ".provenance", b.Name+".json"), CreatedFresh: errors.Is(statErr, os.ErrNotExist), OverwroteOld: statErr == nil}, nil
}

// readAgentProvenance is a bounded, confined selector read after target validation.
func readAgentProvenance(d *agentDir, name string) (pre *ProvenanceSidecar, err error) {
	if err = validateAgentTarget(d, name); err != nil {
		return nil, err
	}
	before, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	f, err := d.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	held, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !held.Mode().IsRegular() || !os.SameFile(before, held) || held.Size() > 65536 || checkAgentOpened(f) != nil {
		return nil, ErrAgentEvidenceInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return nil, err
	}
	if len(raw) > 65536 {
		return nil, ErrAgentEvidenceInvalid
	}
	after, err := d.root.Lstat(name)
	if err != nil || !os.SameFile(held, after) || d.validate() != nil {
		return nil, ErrAgentEvidenceInvalid
	}
	pre = &ProvenanceSidecar{}
	if json.Unmarshal(raw, pre) != nil {
		return nil, ErrAgentEvidenceInvalid
	}
	return pre, nil
}
