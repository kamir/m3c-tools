package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

const nativeSkillSelectorSchema = "m3c.native-skill-selector/v1"

// A selector only binds retained bytes to a namespace. It is never an authority.
type nativeSkillSelector struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	BundleDigest  string `json:"bundle_digest"`
	ContextSHA256 string `json:"context_sha256"`
}
type nativeSkillTreeEntry struct {
	path, digest string
	info         os.FileInfo
}
type nativeSkillTree struct {
	exists                     bool
	digest, version, oldDigest string
	entries                    []nativeSkillTreeEntry
	proof                      map[string][]byte
}
type nativeSkillTreeBudget struct {
	entries, pathBytes int
	seen               map[string]bool
}

func (f *nativeSkillFS) tree(ctx context.Context, rel string, managed bool, name string) (out *nativeSkillTree, resultErr error) {
	if err := nativeSkillContext(ctx); err != nil {
		return nil, err
	}
	parent, done, err := f.dir(filepath.Dir(rel), false)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, done())
		if resultErr != nil {
			out = nil
		}
	}()
	info, err := parent.Lstat(filepath.Base(rel))
	if errors.Is(err, os.ErrNotExist) {
		return &nativeSkillTree{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrNativeHistoryInvalid
	}
	target, held, err := f.child(parent, filepath.Base(rel), false)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, f.closeRoot(target))
		if resultErr != nil {
			out = nil
		}
	}()
	t := &nativeSkillTree{exists: true, proof: make(map[string][]byte)}
	t.entries = append(t.entries, nativeSkillTreeEntry{path: ".", info: held})
	budget := nativeSkillTreeBudget{seen: make(map[string]bool)}
	if err = f.walk(ctx, target, "", 0, &budget, t, name); err != nil {
		return nil, err
	}
	post, err := parent.Lstat(filepath.Base(rel))
	if err != nil {
		return nil, err
	}
	if !nativeSkillSameFile(held, post) {
		return nil, ErrPlanDrift
	}
	sort.Slice(t.entries, func(i, j int) bool { return t.entries[i].path < t.entries[j].path })
	h := sha256.New()
	if _, err = fmt.Fprintf(h, "m3c.native-skill-tree/v1\x00entries=%d\x00mode=go-filemode-exact\x00", len(t.entries)); err != nil {
		return nil, err
	}
	for _, e := range t.entries {
		modified := e.info.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
		if _, err = fmt.Fprintf(h, "%d:%s\x00%d\x00%d\x00%d:%s\x00%d:%s\n", len(e.path), e.path, uint32(e.info.Mode()), e.info.Size(), len(modified), modified, len(e.digest), e.digest); err != nil {
			return nil, err
		}
	}
	t.digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	if managed {
		if err = f.oldProof(ctx, t, name); err != nil {
			return nil, err
		}
	}
	if err = nativeSkillContext(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

func (f *nativeSkillFS) walk(ctx context.Context, root *os.Root, rel string, depth int, b *nativeSkillTreeBudget, t *nativeSkillTree, name string) (resultErr error) {
	if depth > 128 {
		return ErrNativeEvidenceInvalid
	}
	if err := nativeSkillContext(ctx); err != nil {
		return err
	}
	if err := f.take(); err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		f.handles--
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, f.closeFile(d)) }()
	var names []string
	for {
		if err = f.reserve(4096 + 256); err != nil {
			return err
		}
		entries, e := d.ReadDir(1)
		for _, entry := range entries {
			n := entry.Name()
			path := filepath.Join(rel, n)
			b.entries++
			b.pathBytes += len(path)
			key := nativeSkillPathKey(filepath.ToSlash(path))
			if b.entries > 100000 || b.pathBytes > 4<<20 || len(path) > 4096 || !nativeSkillEntryPath(filepath.ToSlash(path)) || b.seen[key] {
				return ErrNativeEvidenceInvalid
			}
			b.seen[key] = true
			names = append(names, n)
		}
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
	}
	sort.Strings(names)
	for _, n := range names {
		if err = nativeSkillContext(ctx); err != nil {
			return err
		}
		path := filepath.Join(rel, n)
		info, e := root.Lstat(n)
		if e != nil {
			return e
		}
		entry := nativeSkillTreeEntry{path: path, info: info}
		switch {
		case info.IsDir() && info.Mode()&os.ModeSymlink == 0:
			child, held, e := f.child(root, n, false)
			if e != nil {
				return e
			}
			entry.info = held
			e = f.walk(ctx, child, path, depth+1, b, t, name)
			post, pe := root.Lstat(n)
			e = errors.Join(e, pe)
			if pe == nil && !nativeSkillSameFile(held, post) {
				e = errors.Join(e, ErrPlanDrift)
			}
			e = errors.Join(e, f.closeRoot(child))
			if e != nil {
				return e
			}
		case info.Mode().IsRegular():
			limit := int64(100 << 20)
			keep := rel == "" && (n == "bundle.json" || n == name+".skb" || n == ".skillctl-attest.json" || n == ".m3c-provenance.json")
			if n == name+".skb" && rel == "" {
				limit = 16 << 20
			}
			if n == ".skillctl-attest.json" && rel == "" {
				limit = 1 << 20
			}
			if n == ".m3c-provenance.json" && rel == "" {
				limit = 64 << 10
			}
			if n == "bundle.json" && rel == "" {
				limit = 1 << 20
			}
			raw, held, e := f.read(ctx, root, n, limit)
			if e != nil {
				return e
			}
			entry.info = held
			entry.digest = agentDigest(raw)
			if keep {
				t.proof[n] = raw
			}
		default:
			return ErrNativeHistoryInvalid
		}
		t.entries = append(t.entries, entry)
	}
	return nil
}

func nativeSkillTreesEqual(a, b *nativeSkillTree) bool {
	if a == nil || b == nil || a.exists != b.exists || a.digest != b.digest || a.version != b.version || a.oldDigest != b.oldDigest || len(a.entries) != len(b.entries) {
		return false
	}
	for i := range a.entries {
		x, y := a.entries[i], b.entries[i]
		if x.path != y.path || x.digest != y.digest || !nativeSkillSameFile(x.info, y.info) {
			return false
		}
	}
	return true
}

func (f *nativeSkillFS) oldProof(ctx context.Context, t *nativeSkillTree, name string) error {
	raw := t.proof[".m3c-provenance.json"]
	m, err := readAgentJSON(raw, 64<<10)
	if err != nil || len(m) != 6 {
		return ErrNativeHistoryInvalid
	}
	for _, k := range []string{"schema", "kind", "name", "version", "bundle_digest", "context_sha256"} {
		if _, ok := m[k]; !ok {
			return ErrNativeHistoryInvalid
		}
	}
	var p nativeSkillSelector
	if json.Unmarshal(raw, &p) != nil || p.Schema != nativeSkillSelectorSchema || p.Kind != "skill" || p.Name != name || !validAgentName(p.Name) || !nativeSkillVersionValid(p.Version) || !nativeSubject(p.BundleDigest) || !nativeSHA(p.ContextSHA256) {
		return ErrNativeHistoryInvalid
	}
	archive := t.proof[name+".skb"]
	contextRaw := t.proof[".skillctl-attest.json"]
	if len(archive) == 0 || len(contextRaw) == 0 || agentDigest(archive) != p.BundleDigest || strings.TrimPrefix(agentDigest(contextRaw), "sha256:") != p.ContextSHA256 {
		return ErrNativeHistoryInvalid
	}
	if err = f.reserve(int64(4 * len(contextRaw))); err != nil {
		return err
	}
	_, err = readAgentJSON(contextRaw, 1<<20)
	if err != nil {
		return ErrNativeHistoryInvalid
	}
	// The complete signed context is retained, not a claim that an old artifact
	// is freshly approved. Bind the declared archive identity without counting it
	// toward the new installation's independently verified quorum/history.
	var c AttestationContext
	if json.Unmarshal(contextRaw, &c) != nil || c.AdmitEvent == nil || len(c.GovernanceAttestations) == 0 {
		return ErrNativeHistoryInvalid
	}
	for _, event := range append([]map[string]any{c.AdmitEvent, c.GovernanceAttestation}, c.GovernanceAttestations...) {
		if event == nil || event["bundle_digest"] != p.BundleDigest {
			return ErrNativeHistoryInvalid
		}
	}
	if c.AdmitEvent["name"] != p.Name || c.AdmitEvent["version"] != p.Version {
		return ErrNativeHistoryInvalid
	}
	roots := f.selection.artifactRoots
	if err = f.reserve(int64(4*len(contextRaw)) * int64(len(roots.Signers)+1)); err != nil {
		return err
	}
	if VerifyEnvelopeSignature(roots.pub, c.AdmitEvent) != nil || verifyBundleSignatures(c.AdmitEvent, roots.pub, p.BundleDigest) != nil || nativeSkillContextTenant(f.selection, &c) != nil {
		return ErrNativeHistoryInvalid
	}
	for _, event := range append([]map[string]any{c.GovernanceAttestation}, c.GovernanceAttestations...) {
		if verifyGovernanceSigner(roots.pub, roots.Signers, event) != nil {
			return ErrNativeHistoryInvalid
		}
	}
	if f.oldArchives[p.BundleDigest] == nil {
		// Stream the old archive once: retain only its bounded manifest. Its
		// signed kind/name/version must agree; payload changes are still covered
		// by the complete target-tree consent, not old freshness or quorum.
		if err = f.reserve(2*(4<<20) + 10000*256 + 4*(1<<20)); err != nil {
			return err
		}
		manifest, e := nativeSkillOldManifest(ctx, archive, p, f)
		if e != nil {
			return e
		}
		f.oldArchives[p.BundleDigest] = manifest
	}
	if !bytes.Equal(t.proof["bundle.json"], f.oldArchives[p.BundleDigest]) {
		return ErrNativeHistoryInvalid
	}
	t.version = p.Version
	t.oldDigest = p.BundleDigest
	return nil
}

func nativeSkillOldManifest(ctx context.Context, archive []byte, selected nativeSkillSelector, f *nativeSkillFS) (rawManifest []byte, resultErr error) {
	g, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, ErrNativeHistoryInvalid
	}
	defer func() {
		resultErr = errors.Join(resultErr, g.Close())
		if resultErr != nil {
			rawManifest = nil
		}
	}()
	capBytes := nativeLiveInflatedReservation()
	l := &io.LimitedReader{R: &nativeSkillChargedReader{reader: g, fs: f, ctx: ctx}, N: capBytes + 1}
	t := tar.NewReader(l)
	var manifest []byte
	seen := map[string]bool{}
	entries, paths := 0, 0
	var size int64
	for {
		h, e := t.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil || l.N <= 0 {
			return nil, errors.Join(ErrNativeHistoryInvalid, e)
		}
		entries++
		paths += len(h.Name)
		name := h.Name
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		if entries > 10000 || paths > 4<<20 || !nativeSkillEntryPath(name) || seen[name] || h.Size < 0 || h.Size > 100<<20-size {
			return nil, ErrNativeHistoryInvalid
		}
		seen[name] = true
		size += h.Size
		if h.Typeflag != tar.TypeReg && h.Typeflag != byte(0) && h.Typeflag != tar.TypeDir {
			return nil, ErrNativeHistoryInvalid
		}
		if h.Name == "bundle.json" {
			if h.Size > 1<<20 || h.Typeflag == tar.TypeDir {
				return nil, ErrNativeHistoryInvalid
			}
			manifest, e = io.ReadAll(io.LimitReader(t, h.Size+1))
			if e != nil || int64(len(manifest)) != h.Size {
				return nil, ErrNativeHistoryInvalid
			}
		}
	}
	if _, err = io.Copy(io.Discard, l); err != nil || l.N <= 0 {
		return nil, errors.Join(ErrNativeHistoryInvalid, err)
	}
	m, err := readAgentJSON(manifest, 1<<20)
	if err != nil {
		return nil, ErrNativeHistoryInvalid
	}
	for k := range m {
		for _, key := range []string{"schema", "kind", "name", "version"} {
			if strings.EqualFold(k, key) && k != key {
				return nil, ErrNativeHistoryInvalid
			}
		}
	}
	if m["schema"] != skillbundle.Schema || m["name"] != selected.Name || m["version"] != selected.Version {
		return nil, ErrNativeHistoryInvalid
	}
	if kind, ok := m["kind"]; ok && kind != "" && kind != "skill" {
		return nil, ErrNativeHistoryInvalid
	}
	return manifest, nil
}

// Charge each bounded inflated read before it is issued; old archive payloads
// are discarded, not allocated as a second publication candidate.
type nativeSkillChargedReader struct {
	reader io.Reader
	fs     *nativeSkillFS
	ctx    context.Context
}

func (r *nativeSkillChargedReader) Read(p []byte) (int, error) {
	if err := nativeSkillContext(r.ctx); err != nil {
		return 0, err
	}
	if len(p) > 64<<10 {
		p = p[:64<<10]
	}
	if err := r.fs.reserve(int64(2 * len(p))); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
