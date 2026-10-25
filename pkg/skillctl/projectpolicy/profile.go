// Package projectpolicy loads an explicitly selected, pinned project policy.
// Configuration is operator provenance, not an issuer or tenant attestation.
package projectpolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
	"gopkg.in/yaml.v3"
)

const Schema = "m3c.enterprise-project-profile/v1"
const maxProfileBytes = 64 << 10
const maxTrustBytes = 1 << 20

var ErrInvalid = errors.New("enterprise project profile invalid")
var ErrSelection = errors.New("enterprise project profile selection conflicts")
var ErrUnsupported = errors.New("enterprise project profile requires unsupported trust mapping")

type fileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type document struct {
	Schema            string  `json:"schema"`
	ProjectRoot       string  `json:"project_root"`
	ArtifactHome      string  `json:"artifact_home"`
	RegistryURL       string  `json:"registry_url"`
	AllowLoopbackHTTP bool    `json:"allow_loopback_http,omitempty"`
	ArtifactTrust     fileRef `json:"artifact_trust"`
	RevocationTrust   fileRef `json:"revocation_trust"`
	Runtime           fileRef `json:"runtime"`
}

// Policy retains private snapshots. Getters return copies, never mutable authority.
type Policy struct {
	project, home, registry, base, digest string
	allowLoopback                         bool
	roots                                 *verify.TrustRoots
	root, revocation                      *verify.TrustRoot
	runtime                               dependencies.Profile
}

func Load(path, actualProjectRoot, actualArtifactHome string) (*Policy, error) {
	return load(path, "", actualProjectRoot, actualArtifactHome)
}

// LoadPinned binds the one bounded profile read to an independent expected hash.
func LoadPinned(path, expectedProfileSHA, actualProjectRoot, actualArtifactHome string) (*Policy, error) {
	if !validSHA(expectedProfileSHA) {
		return nil, ErrInvalid
	}
	return load(path, expectedProfileSHA, actualProjectRoot, actualArtifactHome)
}

func load(path, expected, actualProject, actualHome string) (*Policy, error) {
	raw, err := readFile(path, maxProfileBytes)
	if err != nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(raw)
	profileDigest := hex.EncodeToString(sum[:])
	if expected != "" && !equalSHA(sum[:], expected) {
		return nil, ErrSelection
	}
	if !utf8.Valid(raw) || strictJSON(raw) != nil {
		return nil, ErrInvalid
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, ErrInvalid
	}
	allowed := map[string]bool{"schema": true, "project_root": true, "artifact_home": true, "registry_url": true, "allow_loopback_http": true, "artifact_trust": true, "revocation_trust": true, "runtime": true}
	for key := range object {
		if !allowed[key] {
			return nil, ErrInvalid
		}
	}
	for _, key := range []string{"artifact_trust", "revocation_trust", "runtime"} {
		var ref map[string]json.RawMessage
		if json.Unmarshal(object[key], &ref) != nil || len(ref) != 2 || ref["path"] == nil || ref["sha256"] == nil {
			return nil, ErrInvalid
		}
	}
	if rawFlag, ok := object["allow_loopback_http"]; ok && !bytes.Equal(rawFlag, []byte("true")) && !bytes.Equal(rawFlag, []byte("false")) {
		return nil, ErrInvalid
	}
	var doc document
	if json.Unmarshal(raw, &doc) != nil || doc.Schema != Schema {
		return nil, ErrInvalid
	}
	project, e1 := canonicalDirectory(doc.ProjectRoot)
	home, e2 := canonicalDirectory(doc.ArtifactHome)
	actualP, e3 := canonicalDirectory(actualProject)
	actualH, e4 := canonicalDirectory(actualHome)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return nil, ErrInvalid
	}
	if project != actualP || home != actualH {
		return nil, ErrSelection
	}
	registry := strings.TrimRight(doc.RegistryURL, "/")
	if !strings.HasPrefix(strings.ToLower(registry), "https://") && !strings.HasPrefix(strings.ToLower(registry), "http://") {
		return nil, ErrUnsupported
	}
	base, err := httpsafe.ParseAPIBase(registry, doc.AllowLoopbackHTTP)
	if err != nil {
		return nil, ErrInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInvalid
	}
	dir := filepath.Dir(abs)
	artifactRaw, err := readRef(dir, doc.ArtifactTrust, maxTrustBytes)
	if err != nil {
		return nil, err
	}
	revocationRaw, err := readRef(dir, doc.RevocationTrust, maxTrustBytes)
	if err != nil {
		return nil, err
	}
	runtimeRaw, err := readRef(dir, doc.Runtime, maxProfileBytes)
	if err != nil {
		return nil, err
	}
	if singleYAML(artifactRaw) != nil || singleYAML(revocationRaw) != nil {
		return nil, ErrInvalid
	}
	roots, err := verify.ParseTrustRoots(artifactRaw)
	if err != nil {
		return nil, ErrInvalid
	}
	revRoots, err := verify.ParseTrustRoots(revocationRaw)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(roots.Roots) != 1 || len(revRoots.Roots) != 1 {
		return nil, ErrUnsupported
	}
	root, revocation := &roots.Roots[0], &revRoots.Roots[0]
	if root.RegistryURL != registry || revocation.RegistryURL != registry || !root.IsManaged() || !revocation.IsManaged() {
		return nil, ErrSelection
	}
	// Existing history and verifier APIs use one complete root. Distinct role
	// roots require a future explicit adapter, never a synthesized merged root.
	if !reflect.DeepEqual(root, revocation) || roots.TenantScope != revRoots.TenantScope {
		return nil, ErrUnsupported
	}
	runtimeProfile, err := dependencies.ParseProfile(runtimeRaw)
	if err != nil {
		return nil, ErrInvalid
	}
	runtimeProject, err := canonicalDirectory(runtimeProfile.ProjectRoot)
	if err != nil || runtimeProject != project {
		return nil, ErrSelection
	}
	runtimeProfile.ProjectRoot = project
	return &Policy{project: project, home: home, registry: registry, base: strings.TrimRight(base.URL, "/"), digest: profileDigest, allowLoopback: doc.AllowLoopbackHTTP, roots: roots, root: root, revocation: revocation, runtime: runtimeProfile}, nil
}

func (p *Policy) ProjectRoot() string {
	if p == nil {
		return ""
	}
	return p.project
}
func (p *Policy) ArtifactHome() string {
	if p == nil {
		return ""
	}
	return p.home
}
func (p *Policy) RegistryURL() string {
	if p == nil {
		return ""
	}
	return p.registry
}
func (p *Policy) ProfileDigest() string {
	if p == nil {
		return ""
	}
	return p.digest
}
func (p *Policy) TrustRoots() *verify.TrustRoots {
	if p == nil {
		return nil
	}
	return clone(p.roots)
}
func (p *Policy) TrustRoot() *verify.TrustRoot {
	if p == nil {
		return nil
	}
	return clone(p.root)
}
func (p *Policy) RevocationTrustRoot() *verify.TrustRoot {
	if p == nil {
		return nil
	}
	return clone(p.revocation)
}
func (p *Policy) Runtime() dependencies.Profile {
	if p == nil {
		return dependencies.Profile{}
	}
	return *clone(&p.runtime)
}

// ValidateSelection checks the actual SDK selection before any remote operation.
// An empty clientURL is allowed for an offline local bundle only.
func (p *Policy) ValidateSelection(root *verify.TrustRoot, home, clientURL string) error {
	if p == nil || p.root == nil || p.digest == "" || root == nil {
		return ErrSelection
	}
	actual, err := canonicalDirectory(home)
	if err != nil || actual != p.home || !reflect.DeepEqual(root, p.root) {
		return ErrSelection
	}
	if clientURL != "" {
		base, err := httpsafe.ParseAPIBase(clientURL, p.allowLoopback)
		if err != nil || strings.TrimRight(base.URL, "/") != p.base {
			return ErrSelection
		}
	}
	return nil
}

func clone[T any](v *T) *T {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out T
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return &out
}
func validSHA(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func equalSHA(actual []byte, expected string) bool {
	if !validSHA(expected) {
		return false
	}
	want, _ := hex.DecodeString(expected)
	return subtle.ConstantTimeCompare(actual, want) == 1
}
func canonicalDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", ErrInvalid
	}
	path, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", ErrInvalid
	}
	st, err := os.Stat(path)
	if err != nil || !st.IsDir() {
		return "", ErrInvalid
	}
	return path, nil
}
func readRef(dir string, ref fileRef, limit int64) ([]byte, error) {
	if ref.Path == "" || !validSHA(ref.SHA256) {
		return nil, ErrInvalid
	}
	path := ref.Path
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	raw, err := readFile(path, limit)
	if err != nil {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(raw)
	if !equalSHA(sum[:], ref.SHA256) {
		return nil, ErrSelection
	}
	return raw, nil
}
func readFile(path string, limit int64) ([]byte, error) {
	if len(path) > 4096 || !utf8.ValidString(path) || strings.ContainsAny(path, "\x00\r\n") {
		return nil, ErrInvalid
	}
	// Explicit operator-selected configuration is read as one bounded snapshot.
	// #nosec G304 -- reading the explicit local project configuration, not a remote file route.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrInvalid
	}
	return raw, nil
}

func strictJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := value(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
func value(d *json.Decoder, depth int) error {
	if depth > 128 {
		return ErrInvalid
	}
	t, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return ErrInvalid
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return ErrInvalid
			}
			seen[s] = true
			if err := value(d, depth+1); err != nil {
				return err
			}
		}
		if t, err = d.Token(); err != nil || t != json.Delim('}') {
			return ErrInvalid
		}
	case json.Delim('['):
		for d.More() {
			if err := value(d, depth+1); err != nil {
				return err
			}
		}
		if t, err = d.Token(); err != nil || t != json.Delim(']') {
			return ErrInvalid
		}
	case json.Delim('}'), json.Delim(']'):
		return ErrInvalid
	}
	return nil
}

func singleYAML(raw []byte) error {
	d := yaml.NewDecoder(bytes.NewReader(raw))
	var node yaml.Node
	if d.Decode(&node) != nil || len(node.Content) != 1 || node.Content[0].Kind != yaml.MappingNode {
		return ErrInvalid
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	return nil
}
