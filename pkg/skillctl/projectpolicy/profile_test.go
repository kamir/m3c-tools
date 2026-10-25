package projectpolicy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
	"gopkg.in/yaml.v3"
)

func profileFixture(t *testing.T) (string, document) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := verify.TrustRoot{RegistryURL: "https://registry.invalid/api/skills", RegistryKeys: []verify.RegistryKey{{ID: "registry", PubkeyB64: base64.StdEncoding.EncodeToString(pub), Issued: "2026-01-01"}}, IdentityKeysAuthorized: "pinned", Authors: []verify.AuthorKey{{ID: "author", PubkeyB64: base64.StdEncoding.EncodeToString(pub)}}, GovernanceMinimum: "green", OfflinePolicy: &verify.OfflinePolicyBlock{Enterprise: true}}
	raw, err := yaml.Marshal(verify.TrustRoots{Roots: []verify.TrustRoot{root}})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := json.Marshal(dependencies.Profile{Schema: dependencies.ProfileSchema, ProjectRoot: home, Tools: []dependencies.Tool{}})
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) fileRef {
		if err := os.WriteFile(filepath.Join(home, name), b, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		return fileRef{Path: name, SHA256: hex.EncodeToString(sum[:])}
	}
	trust := write("roots.yaml", raw)
	runtimeRef := write("runtime.json", runtime)
	return filepath.Join(home, "project.json"), document{Schema: Schema, ProjectRoot: home, ArtifactHome: home, RegistryURL: root.RegistryURL, ArtifactTrust: trust, RevocationTrust: trust, Runtime: runtimeRef}
}
func saveDocument(t *testing.T, path string, doc document) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestProjectProfileSnapshotsAndSelection(t *testing.T) {
	path, doc := profileFixture(t)
	raw := saveDocument(t, path, doc)
	sum := sha256.Sum256(raw)
	p, err := LoadPinned(path, hex.EncodeToString(sum[:]), doc.ProjectRoot, doc.ArtifactHome)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalDirectory(doc.ProjectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProjectRoot() != canonical || p.ArtifactHome() != canonical || p.RegistryURL() != doc.RegistryURL || p.ProfileDigest() != hex.EncodeToString(sum[:]) {
		t.Fatal("selected fields differ")
	}
	original := p.TrustRoot()
	if err := p.ValidateSelection(original, doc.ArtifactHome, doc.RegistryURL); err != nil {
		t.Fatal(err)
	}
	p.TrustRoot().RegistryKeys[0].Pubkey[0] ^= 1
	p.TrustRoots().Roots[0].Authors[0].ID = "changed"
	p.RevocationTrustRoot().RegistryURL = "https://foreign.invalid"
	runtime := p.Runtime()
	runtime.ProjectRoot = "changed"
	if err := p.ValidateSelection(original, doc.ArtifactHome, doc.RegistryURL); err != nil {
		t.Fatal("getter mutated authority", err)
	}
	if err := os.WriteFile(filepath.Join(doc.ProjectRoot, doc.Runtime.Path), []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	if p.Runtime().ProjectRoot != canonical {
		t.Fatal("loaded runtime changed")
	}
	for _, url := range []string{"https://registry.invalid/other", "https://foreign.invalid/api/skills", "http://registry.invalid/api/skills"} {
		if err := p.ValidateSelection(original, doc.ArtifactHome, url); !errors.Is(err, ErrSelection) {
			t.Fatal("foreign target accepted")
		}
	}
	if err := p.ValidateSelection(original, t.TempDir(), doc.RegistryURL); !errors.Is(err, ErrSelection) {
		t.Fatal("foreign home accepted")
	}
	original.GovernanceMinimum = "yellow"
	if err := p.ValidateSelection(original, doc.ArtifactHome, doc.RegistryURL); !errors.Is(err, ErrSelection) {
		t.Fatal("weaker SDK root accepted")
	}
}
func TestProjectProfileStrictInputs(t *testing.T) {
	path, doc := profileFixture(t)
	good := saveDocument(t, path, doc)
	for _, raw := range []string{"null", string(good) + "{}", strings.Replace(string(good), `"schema"`, `"Schema"`, 1), strings.Replace(string(good), `"schema":`, `"schema":"duplicate","schema":`, 1), strings.Replace(string(good), `"path":`, `"Path":`, 1), strings.Replace(string(good), `"runtime":`, `"unknown":{},"runtime":`, 1), strings.Replace(string(good), `"schema":`, `"allow_loopback_http":null,"schema":`, 1)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if p, err := Load(path, doc.ProjectRoot, doc.ArtifactHome); err == nil || p != nil {
			t.Fatal("malformed profile accepted")
		}
	}
	saveDocument(t, path, doc)
	if _, err := LoadPinned(path, strings.Repeat("0", 64), doc.ProjectRoot, doc.ArtifactHome); !errors.Is(err, ErrSelection) {
		t.Fatal("wrong independent digest accepted")
	}
	if _, err := LoadPinned(path, "", doc.ProjectRoot, doc.ArtifactHome); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty digest accepted")
	}
	if _, err := Load(path, t.TempDir(), doc.ArtifactHome); !errors.Is(err, ErrSelection) {
		t.Fatal("foreign project accepted")
	}
	raw := append(append([]byte{}, good...), []byte(strings.Repeat(" ", maxProfileBytes-len(good)))...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, doc.ProjectRoot, doc.ArtifactHome); err != nil {
		t.Fatal("exact profile cap", err)
	}
	if err := os.WriteFile(path, append(raw, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, doc.ProjectRoot, doc.ArtifactHome); err == nil {
		t.Fatal("profile cap+1 accepted")
	}
}
func TestProjectProfilePinnedRolesAndYAML(t *testing.T) {
	path, doc := profileFixture(t)
	saveDocument(t, path, doc)
	if err := os.WriteFile(filepath.Join(doc.ProjectRoot, doc.ArtifactTrust.Path), []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, doc.ProjectRoot, doc.ArtifactHome); !errors.Is(err, ErrSelection) {
		t.Fatal("reference drift accepted")
	}
	path, doc = profileFixture(t)
	raw, err := os.ReadFile(filepath.Join(doc.ProjectRoot, doc.ArtifactTrust.Path))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{[]byte("null\n"), append(append([]byte{}, raw...), []byte("\n---\ntrust_roots: []\n")...)} {
		sum := sha256.Sum256(b)
		doc.ArtifactTrust.SHA256 = hex.EncodeToString(sum[:])
		doc.RevocationTrust = doc.ArtifactTrust
		saveDocument(t, path, doc)
		if err := os.WriteFile(filepath.Join(doc.ProjectRoot, doc.ArtifactTrust.Path), b, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, doc.ProjectRoot, doc.ArtifactHome); !errors.Is(err, ErrInvalid) {
			t.Fatal("ambiguous YAML accepted", err)
		}
	}
	path, doc = profileFixture(t)
	raw, err = os.ReadFile(filepath.Join(doc.ProjectRoot, doc.ArtifactTrust.Path))
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte(strings.Replace(string(raw), "governance_minimum: green", "governance_minimum: yellow", 1))
	if string(changed) == string(raw) {
		t.Fatal("fixture unchanged")
	}
	sum := sha256.Sum256(changed)
	doc.RevocationTrust = fileRef{Path: "revocations.yaml", SHA256: hex.EncodeToString(sum[:])}
	if err := os.WriteFile(filepath.Join(doc.ProjectRoot, doc.RevocationTrust.Path), changed, 0600); err != nil {
		t.Fatal(err)
	}
	saveDocument(t, path, doc)
	if _, err := Load(path, doc.ProjectRoot, doc.ArtifactHome); !errors.Is(err, ErrUnsupported) {
		t.Fatal("distinct policy roles silently merged", err)
	}
}
