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
// per SPEC-0188 §3 (canonicalization rules), and returns the bundle digest
// "sha256:<hex>".
//
// ONE pass since v0.7.0 (ADR-0047): the digest is formed over the canonical
// TAR, before the compression, so it names the content and not the gzip
// implementation that happened to be linked in. `bundle.json` carries no
// `bundle_digest` any more, because a digest inside the bytes it covers forces
// every verifier to rebuild the archive first; see digest.go. A verifier
// recomputes the same value from the finished file with DigestBundleFile.
func Pack(skillDir, outFile string, opts PackOptions) (digest string, err error) {
	skillDir = filepath.Clean(skillDir)

	// If the skill dir is itself a symlink (e.g. ~/.claude/skills/<name> →
	// gstack/<name>), resolve it to the real target BEFORE walking. filepath.WalkDir
	// Lstats its root: a symlink root is reported as a non-dir, so WalkDir never
	// descends and collectFiles returns nothing: the historical "symlink skills
	// pack EMPTY" bug (SPEC-0188 §3). EvalSymlinks canonicalizes the root so the walk
	// packs the target's real contents. Best-effort: a broken/absent link falls
	// through to the original path and the anchor check below reports it.
	if resolved, rerr := filepath.EvalSymlinks(skillDir); rerr == nil {
		skillDir = resolved
	}

	// The anchor file the source dir must contain. A skill anchors on SKILL.md,
	// an agent on its own definition file (SPEC-0432 §3.1: an agent bundle
	// carries exactly one content file, <name>.md). One check, parameterized by
	// kind, so both kinds go through the same canonicalization and digest path.
	anchor := "SKILL.md"
	if opts.Manifest.EffectiveKind() == KindAgent {
		if opts.Manifest.Name == "" {
			return "", fmt.Errorf("agent bundle needs a manifest name; "+
				"without it the anchor would be %q and no bundle is written", ".md")
		}
		anchor = opts.Manifest.Name + ".md"
	}
	if _, err := os.Stat(filepath.Join(skillDir, anchor)); err != nil {
		return "", fmt.Errorf("source dir %q must contain %s: %w", skillDir, anchor, err)
	}

	// LIBRARY-BOUNDARY SCOPE GATE (P2b challenge-gate fix). The author signature
	// covers manifest.Intent + manifest.DataDependencies, so NO unvalidated scope
	// may ever be author-signed. The gate must live HERE, at the pack/sign
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

	// Fail closed on an unknown kind: write nothing (SPEC-0432 AC-12). Same
	// line as the ValidateManifestDataScope gate above, and deliberately
	// BEFORE any file is produced.
	if !ValidKind(manifest.Kind) {
		return "", fmt.Errorf("bad kind %q (want %q or %q); no bundle written",
			manifest.Kind, KindSkill, KindAgent)
	}
	if manifest.Schema == "" {
		// One format marker for both arts. The art is Kind, and the branch that
		// used to put it in the schema is gone with the owner's decision of
		// 2026-10-08 (see Schema in manifest.go).
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

	// The manifest never carries its own digest (ADR-0047), so there is one
	// canonical tar and one hash over it.
	manifest.BundleDigest = ""
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		return "", fmt.Errorf("marshaling canonical manifest: %w", err)
	}
	canonicalTar, err := buildTar(contentFiles, manifestBytes, checksumsBytes)
	if err != nil {
		return "", fmt.Errorf("building canonical tar: %w", err)
	}
	digest = FormatDigest(CanonicalDigest(canonicalTar))

	finalArchive, err := gzipTar(canonicalTar)
	if err != nil {
		return "", fmt.Errorf("compressing canonical tar: %w", err)
	}

	// #nosec G306 -- Klassenentscheidung: nicht geheimes lokales Artefakt. Die enge Form ist im Baum fuer Geheimnisse besetzt (0600/0700). Herleitung: docs/security/gosec-backlog.md, "Klassenentscheidung G301/G306".
	if err := os.WriteFile(outFile, finalArchive, 0644); err != nil {
		return "", fmt.Errorf("writing %s: %w", outFile, err)
	}
	return digest, nil
}

// collectFiles walks skillDir and returns sorted file entries. Skips
// top-level dotfiles (e.g. .DS_Store) and synthesized files (bundle.json,
// CHECKSUMS) if they happen to exist on disk. Nested dotfiles are kept.
//
// SPEC-0188 §3.4: build artifacts (a `dist/` binary, `node_modules/`,
// `__pycache__/`, …) and any `.skbignore` patterns are pruned so bundles stay
// source-sized. The required top-level SKILL.md is never ignored. See ignore.go
// for the pattern language; the trim is deterministic so the digest is stable.
func collectFiles(skillDir string) ([]fileEntry, error) {
	ignoreRules := loadIgnoreRules(skillDir)
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
		// SPEC-0188 §3.4 artifact / .skbignore prune. Guard: the required
		// top-level SKILL.md is always kept, whatever the rules say.
		if rel != "SKILL.md" && ignored(ignoreRules, rel, d.IsDir()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks/devices/sockets out of scope for v1
		}

		// #nosec G122,G304 -- die Wettlauf-Luecke ist hier ohne Gewinn. Drei Zeilen
		// darueber weist d.Type().IsRegular() Symlinks ab; wer sie zwischen
		// Pruefung und Lesen austauschen will, braucht Schreibrecht im
		// Quellverzeichnis des AUTORS, und mit dem koennte er den Inhalt direkt
		// aendern. Das Verzeichnis kommt aus --skill (cmd/skillctl/pack.go:102).
		// Faellt das Recht auseinander, etwa wenn je ein fremdes Verzeichnis
		// gepackt wird, ist os.Root die Antwort, nicht diese Anmerkung. G304
		// ("Dateizugriff ueber Variable") sitzt auf derselben Zeile und traegt
		// dieselbe Begruendung: der Pfad stammt aus dem Verzeichnis des Autors.
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

// buildTar emits the canonical tar, uncompressed. Synthesized CHECKSUMS and
// bundle.json are merged into the entry list and re-sorted with the content
// files so the tar is always lex-sorted regardless of source.
//
// These bytes, and not the compressed ones, are what the bundle digest covers
// (ADR-0047). The split from gzipTar is the whole point: the identity has to be
// formable without a compressor in the loop.
func buildTar(contentFiles []fileEntry, manifestBytes, checksumsBytes []byte) ([]byte, error) {
	all := make([]fileEntry, 0, len(contentFiles)+2)
	all = append(all, fileEntry{relPath: "CHECKSUMS", mode: 0644, data: checksumsBytes})
	all = append(all, fileEntry{relPath: "bundle.json", mode: 0644, data: manifestBytes})
	all = append(all, contentFiles...)
	sort.Slice(all, func(i, j int) bool { return all[i].relPath < all[j].relPath })

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
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
	return buf.Bytes(), nil
}

// gzipTar compresses the canonical tar into the shipped `.skb` body. The gzip
// header is stripped of host metadata (= `gzip --no-name`) so the file stays
// byte-identical per toolchain; the file bytes carry no identity any more, so a
// gzip change across Go versions no longer moves the digest.
func gzipTar(canonicalTar []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("gzip writer: %w", err)
	}
	gz.Header = gzip.Header{}
	if _, err := gz.Write(canonicalTar); err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("closing gzip: %w", err)
	}
	return buf.Bytes(), nil
}
