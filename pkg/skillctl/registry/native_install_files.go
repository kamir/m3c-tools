package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The cache is an explicitly selected local source. Validate ordinary type
// before Open so a FIFO cannot block before any bounded read can run.
func readNativeAgentSnapshot(path, digest string, ops agentFileOps) (raw []byte, resultErr error) {
	if !agentText(path, 8192) || !nativeSubject(digest) {
		return nil, ErrAgentEvidenceInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > MaxBlobSize {
		return nil, ErrAgentEvidenceInvalid
	}
	// #nosec G304 -- explicit local staged archive, prechecked as ordinary and digest-bound below.
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, ops.snapshotClose(f))
		if resultErr != nil {
			raw = nil
		}
	}()
	held, err := f.Stat()
	if err != nil || !held.Mode().IsRegular() || !os.SameFile(before, held) || checkAgentOpened(f) != nil {
		return nil, ErrAgentEvidenceInvalid
	}
	raw, err = readInstallSnapshot(f, digest, MaxBlobSize)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(abs)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(held, after) {
		return nil, ErrAgentEvidenceInvalid
	}
	return raw, nil
}

type nativeTargetObservation struct {
	Path     string
	Exists   bool
	Digest   string
	Bytes    int64
	Modified string
	Version  string
	info     os.FileInfo
}

// Observe every object that C2 will replace, without creating directories.
// Missing parents are permitted, but existing selected components must be
// ordinary. A case/Unicode alias on this actual filesystem is refused.
func nativeObserveTargets(selected *NativeInstallSelection, name string) (out []nativeTargetObservation, resultErr error) {
	if err := selected.validate(); err != nil {
		return nil, err
	}
	if !validAgentName(name) {
		return nil, ErrAgentEvidenceInvalid
	}
	r, err := os.OpenRoot(selected.home)
	if err != nil {
		return nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, r.Close())
		if resultErr != nil {
			out = nil
		}
	}()
	for _, rel := range []string{filepath.Join(".claude", "agents", name+".md"), filepath.Join(".claude", "agents", agentEvidenceDir, agentRecordName(name)), filepath.Join(".claude", "agents", ".provenance", name+".json")} {
		observation, err := nativeObserveTarget(r, rel)
		if err != nil {
			return nil, err
		}
		out = append(out, observation)
	}
	return out, nil
}

func nativeObserveTarget(root *os.Root, rel string) (out nativeTargetObservation, resultErr error) {
	out.Path = rel
	parts := strings.Split(rel, string(filepath.Separator))
	for i := 1; i < len(parts); i++ {
		info, err := root.Lstat(filepath.Join(parts[:i]...))
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return out, ErrAgentEvidenceInvalid
		}
	}
	before, err := root.Lstat(rel)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	const maxTargetBytes = MaxBlobSize + maxAgentContext + maxAgentHeader + 12
	limit := maxTargetBytes
	if filepath.Base(filepath.Dir(rel)) == ".provenance" {
		limit = 65536
	}
	if !before.Mode().IsRegular() || before.Size() > limit {
		return out, ErrAgentEvidenceInvalid
	}
	f, err := root.Open(rel)
	if err != nil {
		return out, err
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	held, err := f.Stat()
	if err != nil || !held.Mode().IsRegular() || held.Size() > limit || !os.SameFile(before, held) || checkAgentOpened(f) != nil {
		return out, ErrAgentEvidenceInvalid
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, limit+1))
	if err != nil {
		return out, err
	}
	if n != held.Size() || n > limit {
		return out, ErrAgentEvidenceInvalid
	}
	after, err := root.Lstat(rel)
	if err != nil || !os.SameFile(held, after) || after.Size() != held.Size() || !after.ModTime().Equal(held.ModTime()) {
		return out, ErrAgentEvidenceInvalid
	}
	if err = nativeRejectTargetAlias(root, rel, held); err != nil {
		return out, err
	}
	if filepath.Base(filepath.Dir(rel)) == ".provenance" {
		if held.Size() > 65536 {
			return out, ErrAgentEvidenceInvalid
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			return out, err
		}
		raw, err := io.ReadAll(io.LimitReader(f, 65537))
		if err != nil {
			return out, err
		}
		var provenance ProvenanceSidecar
		if len(raw) > 65536 || json.Unmarshal(raw, &provenance) != nil || !agentText(provenance.Version, 256) {
			return out, ErrAgentEvidenceInvalid
		}
		out.Version = provenance.Version
	}
	out.Exists = true
	out.Digest = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	out.Bytes = n
	out.Modified = held.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	out.info = held
	return out, nil
}

func nativeRejectTargetAlias(root *os.Root, rel string, expected os.FileInfo) (resultErr error) {
	dir, err := root.Open(filepath.Dir(rel))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, dir.Close()) }()
	entries, err := dir.ReadDir(8193)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) > 8192 {
		return ErrAgentEvidenceInvalid
	}
	for _, entry := range entries {
		if entry.Name() == filepath.Base(rel) {
			continue
		}
		info, err := root.Lstat(filepath.Join(filepath.Dir(rel), entry.Name()))
		if err != nil {
			return err
		}
		if os.SameFile(info, expected) {
			return ErrAgentEvidenceInvalid
		}
	}
	return nil
}

func nativeTargetsEqual(a, b []nativeTargetObservation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Path != y.Path || x.Exists != y.Exists || x.Digest != y.Digest || x.Bytes != y.Bytes || x.Modified != y.Modified || x.Version != y.Version {
			return false
		}
		if x.Exists && (x.info == nil || y.info == nil || !os.SameFile(x.info, y.info)) {
			return false
		}
	}
	return true
}
