package skillbundle

// checksums.go verifies a bundle's own CHECKSUMS manifest against the files it
// describes, after extraction and before anything is trusted or moved.
//
// This lives here, in the format package, rather than next to either installer,
// because BOTH installers need it and neither may import the other. It used to
// live unexported in pkg/skillctl/install, which is why the trust-mode path in
// pkg/skillctl/registry never called it: the code was on the wrong side of an
// import edge, and the omission was invisible from either side (BUG-0217).
//
// SPEC-0188 §7 step 8: extract the bundle to a temp dir and verify the CHECKSUMS
// file inside it. Any failure in steps 3 to 8 means no write.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrChecksumMismatch marks every failure this file can produce, so a caller can
// map the whole class onto its own refusal without matching on message text.
var ErrChecksumMismatch = errors.New("bundle CHECKSUMS does not describe the extracted files")

// ValidateChecksums checks every entry in the extracted bundle's CHECKSUMS file.
//
// A bundle with no CHECKSUMS passes: the manifest is optional in SPEC §3.1, and
// refusing its absence here would reject bundles from before it existed. What is
// NOT optional is that a present manifest describes the bytes on disk.
//
// Two layouts are accepted because two producers exist: the flat archive that
// skillbundle.Pack emits, and the one wrapped in a single <name>-<version>/
// directory. The single-entry directory heuristic is what tells them apart.
func ValidateChecksums(extractDir string) error {
	root := extractDir
	if entries, err := os.ReadDir(extractDir); err == nil && len(entries) == 1 && entries[0].IsDir() {
		root = filepath.Join(extractDir, entries[0].Name())
	}
	checksumPath := filepath.Join(root, "CHECKSUMS")
	// #nosec G304 -- a path built from the caller's own extraction directory.
	f, err := os.Open(checksumPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open CHECKSUMS: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Accept "<hex>  <path>" or "<hex> <path>" (one or two spaces).
		var wantHex, rel string
		if i := strings.Index(line, "  "); i >= 0 {
			wantHex = line[:i]
			rel = strings.TrimSpace(line[i+2:])
		} else if i := strings.Index(line, " "); i >= 0 {
			wantHex = line[:i]
			rel = strings.TrimSpace(line[i+1:])
		} else {
			return fmt.Errorf("CHECKSUMS malformed line %q: %w", line, ErrChecksumMismatch)
		}
		if rel == "" {
			return fmt.Errorf("CHECKSUMS missing path on line %q: %w", line, ErrChecksumMismatch)
		}
		// A manifest is attacker-influenced input like any other: an entry that
		// escapes the root would send the hash check at a file outside the bundle
		// and could be used to probe the consumer's disk.
		cleanRel := filepath.Clean(rel)
		if strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
			return fmt.Errorf("CHECKSUMS entry %q escapes root: %w", rel, ErrChecksumMismatch)
		}
		if cleanRel == "CHECKSUMS" {
			continue
		}
		fp := filepath.Join(root, cleanRel)
		got, err := fileSHA256Hex(fp)
		if err != nil {
			return fmt.Errorf("hash %s: %w", fp, errors.Join(ErrChecksumMismatch, err))
		}
		if !strings.EqualFold(got, wantHex) {
			return fmt.Errorf("CHECKSUMS mismatch for %s (got %s, want %s): %w",
				rel, got, wantHex, ErrChecksumMismatch)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read CHECKSUMS: %w", err)
	}
	return nil
}

func fileSHA256Hex(path string) (string, error) {
	// #nosec G304 -- a path inside the caller's extraction directory, cleaned and
	// checked for escape above.
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
