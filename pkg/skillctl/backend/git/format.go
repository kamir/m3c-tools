package git

// SPEC-0356 §6a — Git Wire Format v1 (FROZEN).
//
// The on-disk layout of a git skill registry is a permanent, externally-pinned
// contract the moment real skills land in it (tags, events/<digesthex>/ paths,
// consumer digest-pins). This file freezes that contract with a machine-readable
// version anchor and the byte-safety attribute that keeps the .skb digest intact
// across platforms.
//
// The anchor is a DEDICATED, WRITE-ONCE marker — `.skillctl/registry.json` —
// created at first publish and never rewritten afterwards. It is deliberately
// NOT the generated digest→ref index (a churned, write-contended, derived file):
// a format-stability contract must live on the most stable object in the repo,
// checked FIRST, before anything else is read. The marker is unsigned by design;
// it carries no trust claim (trust is the Ed25519 chain over the .skb + events).
// A version a client cannot understand makes every op FAIL CLOSED (refuse), which
// is the safe degradation.
import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// WireFormatVersion is the git carrier layout version this build writes and can
// read. A repo marked with a HIGHER version is refused (fail closed); an ABSENT
// marker is treated as compatible (a fresh or pre-marker repo — first publish
// stamps it), so the freeze is backward-compatible.
const WireFormatVersion = 1

const (
	markerPath    = ".skillctl/registry.json" // write-once version anchor
	gitAttributes = ".gitattributes"          // *.skb byte-safety
	// skbAttrLine pins *.skb as binary with EOL normalization OFF. Without this a
	// Windows checkout (autocrlf) rewrites LF→CRLF inside the gzip-tar and the
	// recomputed sha256 no longer matches the pinned digest — silent corruption.
	skbAttrLine = "*.skb binary -text\n"
)

// formatMarker is the content of `.skillctl/registry.json`. SchemaVersion is the
// only load-bearing field; the rest is provenance for humans/audit.
type formatMarker struct {
	SchemaVersion int    `json:"schema_version"`
	CreatedBy     string `json:"created_by,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
}

// maxFormatFileBytes caps reads of the marker + .gitattributes. Both are tiny;
// bounding the read stops a hostile repo from OOM-ing us with a giant file or a
// marker pointed at an unbounded source (e.g. /dev/zero).
const maxFormatFileBytes = 1 << 20 // 1 MiB

// lstatRegular reports whether p exists as a regular (non-symlink) file, and
// FAILS CLOSED on a symlink. The git host is untrusted (SPEC-0356 §6): a repo
// must never redirect our read or write through a link that escapes the clone.
// Lstat sees the link itself, so a DANGLING symlink is refused here rather than
// mis-reported as "absent" (which would let the write path proceed and follow
// it). not-exist is the normal (false, nil).
func lstatRegular(p string) (bool, error) {
	fi, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, &formatError{reason: "refusing symlinked " + filepath.Base(p) +
			" in an untrusted repo (possible path-escape attack)"}
	}
	return true, nil
}

// readBounded reads at most maxFormatFileBytes (anti-DoS).
func readBounded(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxFormatFileBytes))
}

// readMarker reads `.skillctl/registry.json` from a clone. exists is false when
// the file is absent (a fresh/pre-marker repo); err is set on a present but
// unreadable/unparseable marker, OR on a symlinked marker (fail closed).
func readMarker(dir string) (m formatMarker, exists bool, err error) {
	p := filepath.Join(dir, markerPath)
	present, serr := lstatRegular(p) // fail closed on symlink; (false,nil) on not-exist
	if serr != nil {
		return formatMarker{}, false, serr
	}
	if !present {
		return formatMarker{}, false, nil
	}
	data, rerr := readBounded(p)
	if rerr != nil {
		return formatMarker{}, false, rerr
	}
	if uerr := json.Unmarshal(data, &m); uerr != nil {
		return formatMarker{}, true, &formatError{reason: "malformed " + markerPath + ": " + uerr.Error()}
	}
	return m, true, nil
}

// checkMarkerCompatible is the FAIL-CLOSED gate run right after every clone
// (reads AND writes). Absent marker → ok. Present marker whose schema_version is
// 0/negative → refuse (malformed). Present marker newer than this build → refuse
// with an actionable message. Present marker == this build → ok.
func checkMarkerCompatible(dir string) error {
	m, exists, err := readMarker(dir)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if m.SchemaVersion <= 0 {
		return &formatError{reason: "invalid schema_version in " + markerPath + " (want >= 1)"}
	}
	if m.SchemaVersion > WireFormatVersion {
		return &formatError{reason: "git registry wire-format v" +
			strconv.Itoa(m.SchemaVersion) + " is newer than this build (supports v" +
			strconv.Itoa(WireFormatVersion) + "); upgrade skillctl to publish/pull from it"}
	}
	return nil
}

// ensureFormatFiles stamps the write-once marker + the .gitattributes byte-safety
// line if they are absent. Idempotent: it never rewrites an existing marker (that
// is what "write-once" means — the version rides the most stable object in the
// repo). Returns whether it changed anything, so the caller can note it; the git
// `add -A` in Publish commits the new files either way. now is injected so tests
// stay deterministic.
func ensureFormatFiles(dir, createdBy string, now time.Time) (changed bool, err error) {
	_, exists, rerr := readMarker(dir)
	if rerr != nil {
		return false, rerr
	}
	if !exists {
		m := formatMarker{SchemaVersion: WireFormatVersion, CreatedBy: createdBy, CreatedAt: now.UTC().Format(time.RFC3339)}
		data, merr := json.MarshalIndent(m, "", "  ")
		if merr != nil {
			return false, merr
		}
		if werr := writeRepoFile(dir, markerPath, append(data, '\n')); werr != nil {
			return false, werr
		}
		changed = true
	}
	// .gitattributes: ensure the *.skb byte-safety line is present exactly once.
	if aChanged, aerr := ensureGitAttributes(dir); aerr != nil {
		return changed, aerr
	} else if aChanged {
		changed = true
	}
	return changed, nil
}

// ensureGitAttributes appends the *.skb binary line if the repo has no
// .gitattributes or the line is missing. Never removes existing rules.
func ensureGitAttributes(dir string) (bool, error) {
	p := filepath.Join(dir, gitAttributes)
	present, serr := lstatRegular(p) // fail closed if .gitattributes is a symlink
	if serr != nil {
		return false, serr
	}
	var existing []byte
	if present {
		data, rerr := readBounded(p)
		if rerr != nil {
			return false, rerr
		}
		existing = data
	}
	for _, ln := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(ln) == "*.skb binary -text" {
			return false, nil
		}
	}
	next := string(existing)
	if next != "" && !strings.HasSuffix(next, "\n") {
		next += "\n"
	}
	next += skbAttrLine
	if werr := writeRepoFile(dir, gitAttributes, []byte(next)); werr != nil {
		return false, werr
	}
	return true, nil
}

// formatError is the fail-closed sentinel for wire-format incompatibility.
type formatError struct{ reason string }

func (e *formatError) Error() string { return "git wire-format: " + e.reason }
