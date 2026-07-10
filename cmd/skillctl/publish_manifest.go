package main

// Manifest parser for `skillctl publish --all`. The format mirrors
// INFRA/skill-registry/self/publish-manifest.example.txt: one entry per line,
// `#` starts a comment, blank lines ignored. Each entry has one of these
// forms:
//
//	<name>                       # version inferred from SKILL.md frontmatter or "0.0.0"
//	<name>@<version>
//	<name>  <level>  <rationale words…>
//	<name>@<version>  <level>  <rationale words…>
//
// `level` is one of green/yellow/red — used by the --attest pass that follows
// each admit so a manifest run produces both admitted and attested events.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ManifestEntry describes one row of the manifest. Version may be empty (the
// admit path falls back to "0.0.0" or to SKILL.md frontmatter once that
// integration lands).
type ManifestEntry struct {
	Name      string
	Version   string
	Level     string // "green" | "yellow" | "red" — empty if no attestation column
	Rationale string
	Line      int // 1-indexed source line, for error reporting
}

// ParseManifest reads a publish manifest from r. Returns the list of entries
// in source order. Lenient about whitespace; strict about the level enum.
func ParseManifest(r io.Reader) ([]ManifestEntry, error) {
	var out []ManifestEntry
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 1024), 1<<20)
	line := 0
	for s.Scan() {
		line++
		raw := s.Text()
		// Strip comment.
		if i := strings.IndexByte(raw, '#'); i >= 0 {
			raw = raw[:i]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		fields := strings.Fields(raw)
		e := ManifestEntry{Line: line}
		name := fields[0]
		if strings.HasPrefix(name, "@") {
			return nil, fmt.Errorf("manifest line %d: empty skill name (leading @)", line)
		}
		if at := strings.Index(name, "@"); at > 0 {
			e.Name = name[:at]
			e.Version = name[at+1:]
		} else {
			e.Name = name
		}
		if e.Name == "" {
			return nil, fmt.Errorf("manifest line %d: empty skill name", line)
		}
		if len(fields) >= 2 {
			lvl := fields[1]
			if lvl != "green" && lvl != "yellow" && lvl != "red" {
				return nil, fmt.Errorf("manifest line %d: level %q must be green|yellow|red", line, lvl)
			}
			e.Level = lvl
		}
		if len(fields) >= 3 {
			e.Rationale = strings.Join(fields[2:], " ")
		}
		out = append(out, e)
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("manifest scan: %w", err)
	}
	return out, nil
}

// LoadManifestFile is a convenience wrapper around ParseManifest.
func LoadManifestFile(path string) ([]ManifestEntry, error) {
	if path == "" {
		return nil, errors.New("manifest path required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open manifest: %w", err)
	}
	defer f.Close()
	return ParseManifest(f)
}
