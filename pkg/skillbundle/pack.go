package skillbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PackOptions controls deterministic packing.
type PackOptions struct {
	// Manifest is the seed manifest. Pack() fills in BundleDigest and (if zero)
	// BuiltAt and BuiltBy.
	Manifest BundleManifest

	// BuiltAt overrides Manifest.BuiltAt. If both are zero, Pack uses Unix
	// epoch (NOT time.Now()) so identical inputs hash identically.
	BuiltAt time.Time

	// BuiltBy overrides Manifest.BuiltBy. Defaults to "skillctl/dev".
	BuiltBy string
}

const defaultBuiltBy = "skillctl/dev"

type fileEntry struct {
	relPath string // bundle-relative path, forward slashes
	mode    int64  // 0644 or 0755
	data    []byte
}

// Pack produces a deterministic `.skb` (gzipped tar) at outFile from skillDir
// per SPEC-0188 §3 (canonicalization rules + digest computation). Returns the
// bundle digest "sha256:<hex>". Two-pass: hash an archive whose manifest has
// an empty bundle_digest, then re-emit with the digest filled in for humans.
// Verifiers always recompute and ignore the embedded value.
func Pack(skillDir, outFile string, opts PackOptions) (digest string, err error) {
	skillDir = filepath.Clean(skillDir)

	if _, err := os.Stat(filepath.Join(skillDir, "SKILL.md")); err != nil {
		return "", fmt.Errorf("skill dir %q must contain SKILL.md: %w", skillDir, err)
	}

	// LIBRARY-BOUNDARY SCOPE GATE (P2b challenge-gate fix). The author signature
	// covers manifest.Intent + manifest.DataDependencies, so NO unvalidated scope
	// may ever be author-signed — the gate must live HERE, at the pack/sign
	// boundary, not only in the CLI. A programmatic producer (e.g.
	// publish_cmds.go ensureBundle) that calls Pack directly is now bound by the
	// SAME datascope.Validate rule the CLI runs. Fail-closed: an invalid or §3.3-
	// contradictory scope returns an error and writes NO bundle. The CLI still
	// pre-validates to map exact exit codes (18/2) before calling Pack; this is a
	// belt-and-braces enforcement, not a different verdict (same validator, same
	// failed_rule).
	if err := ValidateManifestDataScope(opts.Manifest); err != nil {
		return "", err
	}

	contentFiles, err := collectFiles(skillDir)
	if err != nil {
		return "", fmt.Errorf("collecting files: %w", err)
	}

	manifest := opts.Manifest
	if manifest.Schema == "" {
		manifest.Schema = Schema
	}
	switch {
	case !opts.BuiltAt.IsZero():
		manifest.BuiltAt = opts.BuiltAt.UTC()
	case !manifest.BuiltAt.IsZero():
		manifest.BuiltAt = manifest.BuiltAt.UTC()
	default:
		manifest.BuiltAt = time.Unix(0, 0).UTC()
	}
	if opts.BuiltBy != "" {
		manifest.BuiltBy = opts.BuiltBy
	} else if manifest.BuiltBy == "" {
		manifest.BuiltBy = defaultBuiltBy
	}
	if manifest.DependsOn == nil {
		manifest.DependsOn = []Dependency{}
	}

	checksumsBytes := buildChecksums(contentFiles)

	// Pass 1: archive with empty bundle_digest → its SHA-256 IS the digest.
	manifestBytesEmpty, err := marshalManifest(manifest.withEmptyDigest())
	if err != nil {
		return "", fmt.Errorf("marshaling canonical manifest: %w", err)
	}
	canonicalArchive, err := buildArchive(contentFiles, manifestBytesEmpty, checksumsBytes)
	if err != nil {
		return "", fmt.Errorf("building canonical archive: %w", err)
	}
	sum := sha256.Sum256(canonicalArchive)
	digest = "sha256:" + hex.EncodeToString(sum[:])

	// Pass 2: archive with bundle_digest filled in (for humans).
	manifest.BundleDigest = digest
	manifestBytesFinal, err := marshalManifest(manifest)
	if err != nil {
		return "", fmt.Errorf("marshaling final manifest: %w", err)
	}
	finalArchive, err := buildArchive(contentFiles, manifestBytesFinal, checksumsBytes)
	if err != nil {
		return "", fmt.Errorf("building final archive: %w", err)
	}

	if err := os.WriteFile(outFile, finalArchive, 0644); err != nil {
		return "", fmt.Errorf("writing %s: %w", outFile, err)
	}
	return digest, nil
}

// collectFiles walks skillDir and returns sorted file entries. Skips
// top-level dotfiles (e.g. .DS_Store) and synthesized files (bundle.json,
// CHECKSUMS) if they happen to exist on disk. Nested dotfiles are kept.
func collectFiles(skillDir string) ([]fileEntry, error) {
	var entries []fileEntry
	err := filepath.WalkDir(skillDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == skillDir {
			return nil
		}
		rel, relErr := filepath.Rel(skillDir, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		if !strings.Contains(rel, "/") && strings.HasPrefix(rel, ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == "bundle.json" || rel == "CHECKSUMS" {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks/devices/sockets out of scope for v1
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", rel, readErr)
		}
		entries = append(entries, fileEntry{relPath: rel, mode: canonicalMode(rel), data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].relPath < entries[j].relPath })
	return entries, nil
}

func canonicalMode(relPath string) int64 {
	if strings.HasPrefix(relPath, "scripts/") {
		return 0755
	}
	return 0644
}

// buildChecksums emits CHECKSUMS lines: `<sha256-hex>  <relpath>\n`, in the
// already-sorted order of entries.
func buildChecksums(entries []fileEntry) []byte {
	var b bytes.Buffer
	for _, e := range entries {
		sum := sha256.Sum256(e.data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), e.relPath)
	}
	return b.Bytes()
}

// marshalManifest emits indented JSON with HTML escaping off so `>=` survives.
// json.Encoder appends a trailing newline that's part of the canonical input.
func marshalManifest(m BundleManifest) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildArchive emits the gzipped tar. Synthesized CHECKSUMS and bundle.json
// are merged into the entry list and re-sorted with the content files so the
// final tar is always lex-sorted regardless of source.
func buildArchive(contentFiles []fileEntry, manifestBytes, checksumsBytes []byte) ([]byte, error) {
	all := make([]fileEntry, 0, len(contentFiles)+2)
	all = append(all, fileEntry{relPath: "CHECKSUMS", mode: 0644, data: checksumsBytes})
	all = append(all, fileEntry{relPath: "bundle.json", mode: 0644, data: manifestBytes})
	all = append(all, contentFiles...)
	sort.Slice(all, func(i, j int) bool { return all[i].relPath < all[j].relPath })

	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("gzip writer: %w", err)
	}
	// Strip host metadata from gzip header (= `gzip --no-name`).
	gz.Header = gzip.Header{}

	tw := tar.NewWriter(gz)
	zeroTime := time.Unix(0, 0).UTC()

	for _, e := range all {
		hdr := &tar.Header{
			Name:       e.relPath,
			Mode:       e.mode,
			Size:       int64(len(e.data)),
			ModTime:    zeroTime,
			AccessTime: zeroTime,
			ChangeTime: zeroTime,
			Uid:        0,
			Gid:        0,
			Uname:      "",
			Gname:      "",
			Typeflag:   tar.TypeReg,
			Format:     tar.FormatPAX,
			PAXRecords: nil,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("tar header %s: %w", e.relPath, err)
		}
		if _, err := io.Copy(tw, bytes.NewReader(e.data)); err != nil {
			return nil, fmt.Errorf("tar body %s: %w", e.relPath, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("closing tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("closing gzip: %w", err)
	}
	return buf.Bytes(), nil
}
