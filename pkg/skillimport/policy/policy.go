// Package policy implements SPEC-0201 §4 source-policy file loading and
// evaluation for the import airlock.
//
// The policy file is a small flat YAML schema. The MVP P1-P4 surface uses a
// stdlib-only mini-parser; the schema is intentionally narrow so a fuller
// dependency-free reader is sufficient. The shape:
//
//	version: 1
//	default_deny: true
//	allowed_hosts:
//	  - github.com
//	  - skillhub.club
//	blocked_hosts:
//	  - badhost.example
//	source_caps:
//	  github.com:
//	    max_intent_level: yellow
//	    blocked_owners:
//	      - unknown-vendor
//
// Decision semantics (Evaluate):
//
//   - host in BlockedHosts                   → Block        (host_blocked)
//   - host has SourceCap with blocked_owners → Block        (owner_blocked) when matched
//   - host in AllowedHosts                   → Allow        (ok)
//   - host not in AllowedHosts AND default_deny: true       → Block (host_not_allowed)
//   - host not in AllowedHosts AND default_deny: false      → RequireReview (no_policy_for_host)
//
// max_intent_level on a SourceCap caps the importer-author's self-declared
// intent (D3 of SPEC-0201). It is exposed via Evaluate's caller-side check;
// the policy struct simply surfaces the cap.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillimport/parser"
)

// ErrNoSourcePolicy is returned by Load when the policy file does not exist.
// CLI maps this to exit code 17.
var ErrNoSourcePolicy = errors.New("no source policy at expected path")

// Decision is the verdict an evaluation returns.
type Decision int

const (
	// Allow means the host is explicitly allowed.
	Allow Decision = iota
	// Block means the host is explicitly blocked or default-deny tripped.
	Block
	// RequireReview means the host is not in the allowlist but default_deny is
	// false; the operator should review before fetch.
	RequireReview
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Block:
		return "block"
	case RequireReview:
		return "require_review"
	default:
		return "unknown"
	}
}

// Reason codes. Stable strings; the CLI surfaces these to operators.
const (
	ReasonOK              = "ok"
	ReasonHostNotAllowed  = "host_not_allowed"
	ReasonHostBlocked     = "host_blocked"
	ReasonOwnerBlocked    = "owner_blocked"
	ReasonNoPolicyForHost = "no_policy_for_host"
)

// SourceCap is a per-host policy override.
type SourceCap struct {
	MaxIntentLevel string   // "green" | "yellow" — caps importer-author intent.
	BlockedOwners  []string // exact-match list of blocked upstream owners.
}

// SourcePolicy is the v1 schema record.
type SourcePolicy struct {
	Version      int
	DefaultDeny  bool
	AllowedHosts []string
	BlockedHosts []string
	SourceCaps   map[string]SourceCap
}

// DefaultPath returns ~/.claude/skill-import-policy.yaml. Falls back to
// ./skill-import-policy.yaml if the home dir is unresolvable.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "skill-import-policy.yaml"
	}
	return filepath.Join(home, ".claude", "skill-import-policy.yaml")
}

// Load reads and parses the policy file at the given path. Returns
// ErrNoSourcePolicy if the file does not exist.
func Load(path string) (*SourcePolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrNoSourcePolicy, path)
		}
		return nil, fmt.Errorf("read source policy %s: %w", path, err)
	}
	p, err := parsePolicyYAML(data)
	if err != nil {
		return nil, fmt.Errorf("parse source policy %s: %w", path, err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported source policy version %d (expected 1) at %s", p.Version, path)
	}
	return p, nil
}

// Evaluate decides whether the reference may proceed under this policy.
// The string return is the stable reason code (one of the Reason* constants).
func (p *SourcePolicy) Evaluate(ref *parser.Reference) (Decision, string) {
	if p == nil || ref == nil {
		return Block, ReasonNoPolicyForHost
	}
	host := ref.Host

	// 1. Block list wins.
	for _, b := range p.BlockedHosts {
		if strings.EqualFold(b, host) {
			return Block, ReasonHostBlocked
		}
	}

	// 2. Per-host owner blocks.
	if cap, ok := p.SourceCaps[host]; ok {
		for _, bo := range cap.BlockedOwners {
			if bo == ref.Owner {
				return Block, ReasonOwnerBlocked
			}
		}
	}

	// 3. Allow list.
	allowed := false
	for _, a := range p.AllowedHosts {
		if strings.EqualFold(a, host) {
			allowed = true
			break
		}
	}
	if allowed {
		return Allow, ReasonOK
	}

	// 4. Not in allowlist — default-deny vs review.
	if p.DefaultDeny {
		return Block, ReasonHostNotAllowed
	}
	return RequireReview, ReasonNoPolicyForHost
}

// ───────────────────────────────────────────────────────────────────────────
// Stdlib-only YAML mini-parser.
//
// The schema is flat enough that we can implement a small line-oriented reader
// without a full YAML implementation. We support:
//
//   - top-level scalars: `key: value`
//   - top-level scalar lists with leading `- item` lines
//   - one level of nested mapping under a top-level key
//   - one level of nested list under a nested mapping key
//   - `# comments` at end of line
//   - bool: true/false; int: bare integers; strings unquoted or "..."/'...'
//
// This deliberately rejects multi-line strings, anchors, flow style, and other
// YAML features; the schema does not need them. Errors are precise so a
// malformed file surfaces at the offending line.
// ───────────────────────────────────────────────────────────────────────────

// yamlTok is a single tokenized policy-file line (top-level package-private
// type so helper functions can share it).
type yamlTok struct {
	lineNo int
	indent int
	text   string // trimmed of trailing comment + space
}

func parsePolicyYAML(data []byte) (*SourcePolicy, error) {
	p := &SourcePolicy{
		SourceCaps: map[string]SourceCap{},
	}

	lines := strings.Split(string(data), "\n")

	// Tokenize into trimmed-but-indent-tracking records.
	var toks []yamlTok
	for i, raw := range lines {
		// Strip trailing comments. A '#' that is not in a string literal terminates
		// the line. Our schema has no '#' inside values, so a simple split works.
		line := stripComment(raw)
		// Compute indent from the original raw line (count leading spaces).
		trimmed := strings.TrimRight(line, " \t\r")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		indent := 0
		for _, c := range trimmed {
			if c == ' ' {
				indent++
			} else if c == '\t' {
				indent += 2
			} else {
				break
			}
		}
		toks = append(toks, yamlTok{lineNo: i + 1, indent: indent, text: strings.TrimLeft(trimmed, " \t")})
	}

	// State machine: walk top-level keys, dispatching on schema.
	i := 0
	for i < len(toks) {
		t := toks[i]
		if t.indent != 0 {
			return nil, fmt.Errorf("line %d: unexpected indent at top level: %q", t.lineNo, t.text)
		}
		key, val, isList, err := splitMappingLine(t.text, t.lineNo)
		if err != nil {
			return nil, err
		}

		switch key {
		case "version":
			n, err := parseInt(val, t.lineNo)
			if err != nil {
				return nil, err
			}
			p.Version = n
			i++

		case "default_deny":
			b, err := parseBool(val, t.lineNo)
			if err != nil {
				return nil, err
			}
			p.DefaultDeny = b
			i++

		case "allowed_hosts":
			if !isList {
				return nil, fmt.Errorf("line %d: %q must be a list", t.lineNo, key)
			}
			items, consumed, err := readScalarList(toks, i+1, t.indent)
			if err != nil {
				return nil, err
			}
			p.AllowedHosts = items
			i = consumed

		case "blocked_hosts":
			if !isList {
				return nil, fmt.Errorf("line %d: %q must be a list", t.lineNo, key)
			}
			items, consumed, err := readScalarList(toks, i+1, t.indent)
			if err != nil {
				return nil, err
			}
			p.BlockedHosts = items
			i = consumed

		case "source_caps":
			if val != "" {
				return nil, fmt.Errorf("line %d: %q must be a mapping (no inline value)", t.lineNo, key)
			}
			caps, consumed, err := readSourceCaps(toks, i+1, t.indent)
			if err != nil {
				return nil, err
			}
			for k, v := range caps {
				p.SourceCaps[k] = v
			}
			i = consumed

		default:
			return nil, fmt.Errorf("line %d: unknown top-level key %q", t.lineNo, key)
		}
	}

	return p, nil
}

func stripComment(line string) string {
	// A '#' anywhere outside quotes terminates. The schema has no '#' in values
	// so a naive split is safe.
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}

// splitMappingLine parses a `key: value` or `key:` or `- item` line.
// Returns (key, value, isList, err). isList is true iff value is empty AND the
// caller should look for indented `- item` lines below.
func splitMappingLine(text string, lineNo int) (string, string, bool, error) {
	if strings.HasPrefix(text, "- ") || text == "-" {
		return "", "", false, fmt.Errorf("line %d: unexpected list item at this position: %q", lineNo, text)
	}
	colon := strings.Index(text, ":")
	if colon < 0 {
		return "", "", false, fmt.Errorf("line %d: malformed line (no ':'): %q", lineNo, text)
	}
	key := strings.TrimSpace(text[:colon])
	val := strings.TrimSpace(text[colon+1:])
	if key == "" {
		return "", "", false, fmt.Errorf("line %d: empty key", lineNo)
	}
	return key, unquote(val), val == "", nil
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func parseInt(val string, lineNo int) (int, error) {
	if val == "" {
		return 0, fmt.Errorf("line %d: expected integer, got empty", lineNo)
	}
	n := 0
	for i, c := range val {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("line %d: invalid integer %q (bad char at %d)", lineNo, val, i)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func parseBool(val string, lineNo int) (bool, error) {
	switch strings.ToLower(val) {
	case "true", "yes":
		return true, nil
	case "false", "no":
		return false, nil
	default:
		return false, fmt.Errorf("line %d: invalid bool %q", lineNo, val)
	}
}

// readScalarList reads `- item` lines indented strictly more than parentIndent.
// Returns the items, the index of the first non-list token, and any error.
func readScalarList(toks []yamlTok, start, parentIndent int) ([]string, int, error) {
	var items []string
	i := start
	for i < len(toks) {
		t := toks[i]
		if t.indent <= parentIndent {
			break
		}
		if !strings.HasPrefix(t.text, "- ") && t.text != "-" {
			return nil, i, fmt.Errorf("line %d: expected '- item', got %q", t.lineNo, t.text)
		}
		item := strings.TrimSpace(strings.TrimPrefix(t.text, "-"))
		items = append(items, unquote(item))
		i++
	}
	return items, i, nil
}

// readSourceCaps reads a mapping-of-mappings under `source_caps:`.
func readSourceCaps(toks []yamlTok, start, parentIndent int) (map[string]SourceCap, int, error) {
	out := map[string]SourceCap{}
	i := start
	for i < len(toks) {
		t := toks[i]
		if t.indent <= parentIndent {
			break
		}
		// First-level child: host key.
		hostKey, hostVal, _, err := splitMappingLine(t.text, t.lineNo)
		if err != nil {
			return nil, i, err
		}
		if hostVal != "" {
			return nil, i, fmt.Errorf("line %d: source_caps entry %q must be a mapping", t.lineNo, hostKey)
		}
		hostIndent := t.indent
		i++

		cap := SourceCap{}
		// Second-level: cap fields.
		for i < len(toks) && toks[i].indent > hostIndent {
			t2 := toks[i]
			fieldKey, fieldVal, isList, err := splitMappingLine(t2.text, t2.lineNo)
			if err != nil {
				return nil, i, err
			}
			switch fieldKey {
			case "max_intent_level":
				cap.MaxIntentLevel = fieldVal
				i++
			case "blocked_owners":
				if !isList {
					return nil, i, fmt.Errorf("line %d: blocked_owners must be a list", t2.lineNo)
				}
				items, consumed, err := readScalarList(toks, i+1, t2.indent)
				if err != nil {
					return nil, consumed, err
				}
				cap.BlockedOwners = items
				i = consumed
			default:
				return nil, i, fmt.Errorf("line %d: unknown source_caps field %q", t2.lineNo, fieldKey)
			}
		}
		out[hostKey] = cap
	}
	return out, i, nil
}
