// Package dependencies resolves runtime declarations against an explicitly
// selected local environment and consumer-authenticated artifact candidates.
// It does not authenticate artifacts or install software.
package dependencies

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

const ProfileSchema = "m3c.skillctl.runtime-profile/v1"
const ReleaseConstraintPolicy = "numeric-release/v1"
const maxProfileBytes = 64 << 10

var ErrUnresolved = errors.New("runtime dependencies unresolved")
var ErrInvalid = errors.New("runtime dependency input invalid")
var ErrDrift = errors.New("runtime dependency lock changed")

// Profile is operator-selected environment provenance, not an issuer attestation.
// Paths identify executable files. Args are literal argv, never shell commands.
type Profile struct {
	Schema      string  `json:"schema"`
	ProjectRoot string  `json:"project_root"`
	Python      *Python `json:"python,omitempty"`
	Tools       []Tool  `json:"tools"`
}

// Python pins an operator-reviewed site tree, never an automatically learned one.
// Only a single active site-packages directory and in-tree distribution files
// are supported. Windows additionally requires the derived active venv prefix
// fingerprint; Unix rejects that Windows-only field. Startup/site hooks stay trusted.
type Python struct {
	Path                  string `json:"path"`
	SitePackages          string `json:"site_packages"`
	TreeDigest            string `json:"tree_digest"`
	InterpreterRootDigest string `json:"interpreter_root_digest,omitempty"`
}
type Tool struct {
	Name           string   `json:"name"`
	Path           string   `json:"path"`
	Args           []string `json:"args"`
	VersionPattern string   `json:"version_pattern"`
}

// ParseProfile rejects ambiguous, unknown and trailing JSON before validation.
func ParseProfile(raw []byte) (Profile, error) {
	var p Profile
	if len(raw) > maxProfileBytes || strictJSON(raw, &p) != nil || !profileKeys(raw) {
		return p, ErrInvalid
	}
	if validateProfile(p) != nil {
		return Profile{}, ErrInvalid
	}
	return p, nil
}
func validateProfile(p Profile) error {
	if !typedProfileBudget(p) {
		return ErrInvalid
	}
	if p.Schema != ProfileSchema || !filepath.IsAbs(p.ProjectRoot) || filepath.Clean(p.ProjectRoot) != p.ProjectRoot || strings.ContainsAny(p.ProjectRoot, "\x00\r\n") {
		return ErrInvalid
	}
	if p.Python != nil && (!validPath(p.Python.Path) || !validPath(p.Python.SitePackages)) {
		return ErrInvalid
	}
	if p.Python != nil {
		if runtime.GOOS == "windows" {
			if _, e := windowsVenvRoot(p.Python); e != nil {
				return ErrInvalid
			}
			h, e := canonicalDigest(p.Python.InterpreterRootDigest)
			if e != nil || h != p.Python.InterpreterRootDigest {
				return ErrInvalid
			}
		} else if p.Python.InterpreterRootDigest != "" {
			return ErrInvalid
		}
		h, e := canonicalDigest(p.Python.TreeDigest)
		if e != nil || h != p.Python.TreeDigest {
			return ErrInvalid
		}
	}
	if len(p.Tools) > 128 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, t := range p.Tools {
		if !validName(t.Name) || seen[t.Name] || !validPath(t.Path) || len(t.Args) > 16 || len(t.VersionPattern) > 512 {
			return ErrInvalid
		}
		seen[t.Name] = true
		for _, a := range t.Args {
			if len(a) > 256 || strings.ContainsAny(a, "\x00\r\n") {
				return ErrInvalid
			}
		}
		r, e := regexp.Compile(t.VersionPattern)
		if e != nil || r.NumSubexp() != 1 || !strings.HasPrefix(t.VersionPattern, "^") || !strings.HasSuffix(t.VersionPattern, "$") {
			return ErrInvalid
		}
	}
	return nil
}
func validPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validName(s string) bool { return nameRE.MatchString(s) }
func digest(b []byte) string  { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func canonicalDigest(s string) (string, error) {
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) != 64 {
		return "", ErrInvalid
	}
	b, e := hex.DecodeString(s)
	if e != nil {
		return "", ErrInvalid
	}
	return hex.EncodeToString(b), nil
}
func strictJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if e := jsonValue(d, 0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return ErrInvalid
	}
	return nil
}
func jsonValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return ErrInvalid
	}
	t, e := d.Token()
	if e != nil {
		return ErrInvalid
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			s, ok := k.(string)
			if e != nil || !ok {
				return ErrInvalid
			}
			fold := strings.ToLower(s)
			if seen[fold] {
				return ErrInvalid
			}
			seen[fold] = true
			if e := jsonValue(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for d.More() {
			if e := jsonValue(d, depth+1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Exact wire keys prevent encoding/json field-folding aliases.
func profileKeys(raw []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || top == nil {
		return false
	}
	for k := range top {
		if k != "schema" && k != "project_root" && k != "python" && k != "tools" {
			return false
		}
	}
	if python, ok := top["python"]; ok {
		var fields map[string]json.RawMessage
		if json.Unmarshal(python, &fields) != nil || fields == nil {
			return false
		}
		for k := range fields {
			if k != "path" && k != "site_packages" && k != "tree_digest" && k != "interpreter_root_digest" {
				return false
			}
		}
	}
	if tools, ok := top["tools"]; ok {
		var list []map[string]json.RawMessage
		if json.Unmarshal(tools, &list) != nil {
			return false
		}
		for _, fields := range list {
			if fields == nil {
				return false
			}
			for k := range fields {
				if k != "name" && k != "path" && k != "args" && k != "version_pattern" {
					return false
				}
			}
		}
	}
	return true
}

// This conservative escaped-JSON upper bound runs before Marshal. Limits apply
// to typed callers too, without copying their potentially huge strings/slices.
func typedProfileBudget(p Profile) bool {
	if len(p.Tools) > 128 || len(p.Schema) > 128 {
		return false
	}
	left := maxProfileBytes - 1024
	add := func(s string, max int) bool {
		if len(s) > max || len(s) > left/6 || !utf8.ValidString(s) {
			return false
		}
		left -= 6 * len(s)
		return true
	}
	if !add(p.Schema, 128) || !add(p.ProjectRoot, 4096) {
		return false
	}
	if p.Python != nil {
		if !add(p.Python.Path, 4096) || !add(p.Python.SitePackages, 4096) || !add(p.Python.TreeDigest, 64) || !add(p.Python.InterpreterRootDigest, 64) {
			return false
		}
	}
	for _, tool := range p.Tools {
		if left < 192 || len(tool.Args) > 16 {
			return false
		}
		left -= 192
		if !add(tool.Name, 128) || !add(tool.Path, 4096) || !add(tool.VersionPattern, 512) {
			return false
		}
		for _, arg := range tool.Args {
			if left < 3 {
				return false
			}
			left -= 3
			if !add(arg, 256) {
				return false
			}
		}
	}
	return true
}

// Windows v1 supports only the normal explicit venv launcher layout. The root
// path is derived from the selected executable, never accepted from probe output.
func windowsVenvRoot(p *Python) (string, error) {
	if !strings.EqualFold(filepath.Base(p.Path), "python.exe") || !strings.EqualFold(filepath.Base(filepath.Dir(p.Path)), "Scripts") {
		return "", ErrInvalid
	}
	root := filepath.Dir(filepath.Dir(p.Path))
	if !strings.EqualFold(filepath.Join(root, "Lib", "site-packages"), p.SitePackages) {
		return "", ErrInvalid
	}
	return root, nil
}
