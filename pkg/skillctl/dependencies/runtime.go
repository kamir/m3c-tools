package dependencies

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

const maxExecutableBytes = 256 << 20
const maxProbeBytes = 4 << 20
const probeTimeout = 15 * time.Second

//go:embed python_probe.py
var pythonProbe string

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > maxProbeBytes-b.Len() {
		return 0, ErrUnresolved
	}
	return b.Buffer.Write(p)
}
func executable(path string) (string, string, error) {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return "", "", ErrUnresolved
	}
	f, e := os.Open(resolved)
	if e != nil {
		return "", "", ErrUnresolved
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > maxExecutableBytes {
		return "", "", ErrUnresolved
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, maxExecutableBytes+1))
	if e != nil || n > maxExecutableBytes {
		return "", "", ErrUnresolved
	}
	return resolved, hex.EncodeToString(h.Sum(nil)), nil
}
func probe(ctx context.Context, p Profile, path string, args []string, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	// The executable path is explicitly operator-selected. No shell or PATH
	// search is used; the environment contains no inherited credential variables.
	// #nosec G204 -- absolute executable selected by the validated runtime profile.
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = p.ProjectRoot
	cmd.Env = []string{}
	if runtime.GOOS == "windows" {
		for _, k := range []string{"SYSTEMROOT", "WINDIR"} {
			if v := os.Getenv(k); v != "" {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
		}
	}
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr cappedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = time.Second
	if e := cmd.Run(); e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnresolved
	}
	return stdout.Bytes(), nil
}
func (r *Resolver) checkTools(ctx context.Context, deps []skillbundle.Dependency) ([]Observation, error) {
	if len(deps) > 0 && r.profile.Schema != ProfileSchema {
		return nil, ErrUnresolved
	}
	byName := map[string]Tool{}
	for _, t := range r.profile.Tools {
		byName[t.Name] = t
	}
	checked := map[string]Observation{}
	for _, d := range deps {
		t, ok := byName[d.Name]
		if !ok {
			return nil, ErrUnresolved
		}
		o, done := checked[d.Name]
		if !done {
			path, hash, e := executable(t.Path)
			if e != nil {
				return nil, e
			}
			output, e := probe(ctx, r.profile, t.Path, t.Args, nil)
			if e != nil {
				return nil, e
			}
			pattern := regexp.MustCompile(t.VersionPattern)
			match := pattern.FindStringSubmatch(strings.TrimSpace(string(output)))
			if len(match) != 2 || match[0] != strings.TrimSpace(string(output)) {
				return nil, ErrUnresolved
			}
			resolvedAfter, after, e := executable(t.Path)
			if e != nil || after != hash || resolvedAfter != path {
				return nil, ErrDrift
			}
			o = Observation{Kind: "system", Name: d.Name, Version: match[1], Path: path, ExecutableDigest: hash, EvidenceDigest: digest(output)}
			checked[d.Name] = o
		}
		ok, e := matchRelease(o.Version, d.Constraint)
		if e != nil {
			return nil, e
		}
		if !ok {
			return nil, ErrUnresolved
		}
	}
	out := []Observation{}
	for _, o := range checked {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type pythonResult struct {
	Environment     map[string]string `json:"environment"`
	SitePackages    string            `json:"site_packages"`
	InterpreterRoot string            `json:"interpreter_root"`
	Schema          string            `json:"schema"`
	Version         string            `json:"version"`
	Prefix          string            `json:"prefix"`
	Packages        []pythonPackage   `json:"packages"`
}
type pythonPackage struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	EvidenceDigest string `json:"evidence_digest"`
}

func (r *Resolver) checkPython(ctx context.Context, deps []skillbundle.Dependency) ([]Observation, error) {
	if len(deps) == 0 {
		return []Observation{}, nil
	}
	if r.profile.Python == nil {
		return nil, ErrUnresolved
	}
	site, tree, e := siteFingerprint(ctx, r.profile.Python.SitePackages)
	if e != nil {
		return nil, e
	}
	if tree != r.profile.Python.TreeDigest {
		return nil, ErrDrift
	}
	var interpreterRoot, rootHash string
	if runtime.GOOS == "windows" {
		selectedRoot, e := windowsVenvRoot(r.profile.Python)
		if e != nil {
			return nil, e
		}
		interpreterRoot, rootHash, e = siteFingerprint(ctx, selectedRoot)
		if e != nil {
			return nil, e
		}
		if rootHash != r.profile.Python.InterpreterRootDigest {
			return nil, ErrDrift
		}
	}
	path, hash, e := executable(r.profile.Python.Path)
	if e != nil {
		return nil, e
	}
	sort.Slice(deps, func(i, j int) bool {
		a, b := deps[i], deps[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Constraint < b.Constraint
	})
	input, e := json.Marshal(struct {
		Declarations    []skillbundle.Dependency `json:"declarations"`
		SitePackages    string                   `json:"site_packages"`
		InterpreterRoot string                   `json:"interpreter_root"`
	}{deps, site, interpreterRoot})
	if e != nil {
		return nil, ErrInvalid
	}
	output, e := probe(ctx, r.profile, r.profile.Python.Path, []string{"-I", "-B", "-c", pythonProbe}, input)
	if e != nil {
		return nil, e
	}
	var result pythonResult
	if strictJSON(output, &result) != nil || !sameRuntimePath(result.InterpreterRoot, interpreterRoot) || !sameRuntimePath(result.SitePackages, site) || (interpreterRoot != "" && !sameRuntimePath(result.Prefix, interpreterRoot)) || result.Schema != "m3c.python-runtime/v1" || result.Version == "" || !filepath.IsAbs(result.Prefix) || len(result.Packages) == 0 || len(result.Packages) > 1024 {
		return nil, ErrUnresolved
	}
	resolvedAfter, after, e := executable(r.profile.Python.Path)
	if e != nil || after != hash || resolvedAfter != path {
		return nil, ErrDrift
	}
	_, afterTree, e := siteFingerprint(ctx, r.profile.Python.SitePackages)
	if e != nil {
		return nil, e
	}
	if afterTree != tree {
		return nil, ErrDrift
	}
	if interpreterRoot != "" {
		_, afterRoot, e := siteFingerprint(ctx, interpreterRoot)
		if e != nil {
			return nil, e
		}
		if afterRoot != rootHash {
			return nil, ErrDrift
		}
	}
	evidence := append(append([]byte{}, output...), []byte(tree+rootHash)...)
	out := []Observation{{Kind: "python_runtime", Name: "interpreter", Version: result.Version, Path: path, ExecutableDigest: hash, EvidenceDigest: digest(evidence)}}
	seen := map[string]bool{}
	for _, p := range result.Packages {
		if !validName(p.Name) || p.Version == "" || seen[p.Name] {
			return nil, ErrUnresolved
		}
		seen[p.Name] = true
		h, e := canonicalDigest(p.EvidenceDigest)
		if e != nil {
			return nil, ErrUnresolved
		}
		out = append(out, Observation{Kind: "python", Name: p.Name, Version: p.Version, Path: result.Prefix, ExecutableDigest: hash, EvidenceDigest: h})
	}
	return out, nil
}

// siteFingerprint uses the version prefix followed by newline-delimited JSON
// entries in WalkDir lexical order. Paths are UTF-8 relative slash paths; every
// directory and regular file is recorded. Files bind actual SHA256 and byte size.
// In-tree symlinks and special Go file types, over 100000 entries, 4MiB total relative path bytes,
// 4096-byte paths and over 256MiB file data are rejected. No timestamp or RECORD
// inventory is used. Go classifies transparent Windows DEDUP files as regular;
// these bind their actual bytes too. Directory depth is capped at 128. The operator must provide the expected digest separately.
type treeLimits = TreeObservationLimits

func defaultTreeLimits() treeLimits {
	return treeLimits{100000, 4 << 20, 4096, 128, maxExecutableBytes}
}

func siteFingerprint(ctx context.Context, path string) (string, string, error) {
	return siteFingerprintBounded(ctx, path, defaultTreeLimits())
}
func siteFingerprintBounded(ctx context.Context, path string, limits treeLimits) (string, string, error) {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil {
		return "", "", ErrUnresolved
	}
	st, e := os.Stat(resolved)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeType != os.ModeDir {
		return "", "", ErrUnresolved
	}
	h := sha256.New()
	_, _ = h.Write([]byte(treeFingerprintAlgorithm + "\n"))
	enc := json.NewEncoder(h)
	count, pathBytes := 0, 0
	var total int64
	e = walkSite(ctx, resolved, limits, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrUnresolved
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		rel, e := filepath.Rel(resolved, path)
		if e != nil {
			return ErrUnresolved
		}
		rel = filepath.ToSlash(rel)
		count++
		pathBytes += len(rel)
		if count > limits.Entries || len(rel) > limits.PathLength || pathBytes > limits.PathBytes || !utf8.ValidString(rel) {
			return ErrUnresolved
		}
		record := struct {
			Path   string `json:"path"`
			Kind   string `json:"kind"`
			Digest string `json:"digest"`
			Size   int64  `json:"size"`
		}{Path: rel, Kind: "dir"}
		if kind := entry.Type() & os.ModeType; kind != 0 && kind != os.ModeDir {
			return ErrUnresolved
		}
		if !entry.IsDir() {
			info, e := entry.Info()
			if e != nil || !info.Mode().IsRegular() {
				return ErrUnresolved
			}
			// #nosec G304 -- read-only hashing of the operator-selected package baseline tree; not a remote file-inclusion route.
			file, e := os.Open(path)
			if e != nil {
				return ErrUnresolved
			}
			actual, e := file.Stat()
			if e != nil || !actual.Mode().IsRegular() {
				_ = file.Close()
				return ErrUnresolved
			}
			fh := sha256.New()
			var size int64
			block := make([]byte, 65536)
			for {
				if ctx.Err() != nil {
					_ = file.Close()
					return ctx.Err()
				}
				window := block
				if left := limits.Bytes - total + 1; left < int64(len(window)) {
					if left <= 0 {
						_ = file.Close()
						return ErrUnresolved
					}
					window = window[:left]
				}
				n, re := file.Read(window)
				size += int64(n)
				total += int64(n)
				if total > limits.Bytes {
					_ = file.Close()
					return ErrUnresolved
				}
				if n > 0 {
					_, _ = fh.Write(block[:n])
				}
				if re == io.EOF {
					break
				}
				if re != nil {
					_ = file.Close()
					return ErrUnresolved
				}
			}
			if file.Close() != nil {
				return ErrUnresolved
			}
			record.Kind = "file"
			record.Digest = hex.EncodeToString(fh.Sum(nil))
			record.Size = size
		}
		if enc.Encode(record) != nil {
			return ErrUnresolved
		}
		return nil
	})
	if e != nil {
		return "", "", e
	}
	return resolved, hex.EncodeToString(h.Sum(nil)), nil
}

// ReadDir batches and reserves entry/path budgets before sorting a directory.
// filepath.WalkDir would materialize an unlimited directory before its callback.
func walkSite(ctx context.Context, root string, limits treeLimits, visit func(string, os.DirEntry, error) error) error {
	info, e := os.Stat(root)
	if e != nil {
		return ErrUnresolved
	}
	entries, pathBytes := 1, 1
	var walk func(string, os.DirEntry, int) error
	walk = func(path string, entry os.DirEntry, depth int) error {
		if depth > limits.Depth {
			return ErrUnresolved
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if e := visit(path, entry, nil); e != nil {
			return e
		}
		if !entry.IsDir() {
			return nil
		}
		// #nosec G304 -- read-only enumeration of the operator-selected package baseline tree; not a remote file-inclusion route.
		dir, e := os.Open(path)
		if e != nil {
			return ErrUnresolved
		}
		children := []os.DirEntry{}
		for {
			batch, re := dir.ReadDir(256)
			for _, child := range batch {
				rel, e := filepath.Rel(root, filepath.Join(path, child.Name()))
				if e != nil {
					_ = dir.Close()
					return ErrUnresolved
				}
				rel = filepath.ToSlash(rel)
				entries++
				pathBytes += len(rel)
				if entries > limits.Entries || len(rel) > limits.PathLength || pathBytes > limits.PathBytes || !utf8.ValidString(rel) {
					_ = dir.Close()
					return ErrUnresolved
				}
				children = append(children, child)
			}
			if re == io.EOF {
				break
			}
			if re != nil {
				_ = dir.Close()
				return ErrUnresolved
			}
			if e := ctx.Err(); e != nil {
				_ = dir.Close()
				return e
			}
		}
		if dir.Close() != nil {
			return ErrUnresolved
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, child := range children {
			if e := walk(filepath.Join(path, child.Name()), child, depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	return walk(root, fs.FileInfoToDirEntry(info), 0)
}

func sameRuntimePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
