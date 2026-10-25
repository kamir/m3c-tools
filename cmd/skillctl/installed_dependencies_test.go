package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

type installedCLIProof struct {
	fixture installableFixture
	author  ed25519.PrivateKey
}

func installedCLIProofFixture(t *testing.T) installedCLIProof {
	t.Helper()
	author, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg, rpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := installableFixture{dir: dir, home: t.TempDir(), trPath: filepath.Join(dir, "roots.yaml"), authorID: "id:bob@m3c", regURL: "https://reg.example/api/skills", regPriv: rpriv, regPubB64: base64.StdEncoding.EncodeToString(reg), authorPubB64: base64.StdEncoding.EncodeToString(author)}
	managedEvidenceRoots(t, f, true, "closed")
	return installedCLIProof{fixture: f, author: priv}
}
func installedCLIBundle(t *testing.T, p installedCLIProof, name, fields string) (installableFixture, *registry.BundleMeta) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, file := range []struct{ name, body string }{{"bundle.json", `{"schema":"m3c-skill-bundle/v1","name":"` + name + `","version":"1.0.0"` + fields + `}`}, {"SKILL.md", "# " + name + "\n"}} {
		if err := tw.WriteHeader(&tar.Header{Name: name + "-1.0.0/" + file.name, Mode: 0600, Size: int64(len(file.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(file.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	f := p.fixture
	f.skbPath = filepath.Join(f.dir, name+".skb")
	f.digest = "sha256:" + hex.EncodeToString(sum[:])
	if err := os.WriteFile(f.skbPath, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	m := &registry.BundleMeta{Bundle: map[string]any{"bundle_digest": f.digest, "name": name, "version": "1.0.0", "status": "admitted"}, CurrentGovernance: "green", Signatures: []registry.SignatureRow{{Role: "author", IdentityID: f.authorID, SignatureB64: signB64(p.author, sum), Status: "active"}, {Role: "registry", IdentityID: "id:registry@aims-core", SignatureB64: signB64(f.regPriv, sum), Status: "active"}}}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaultMetaSidecar(f.skbPath), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return f, m
}
func installedCLICall(t *testing.T, binary string, f installableFixture, want int) {
	t.Helper()
	list := mutationCLIList(t, f, filepath.Base(f.skbPath)+"-fresh", 1, time.Now().UTC().Add(-time.Hour))
	mutationCLI(t, binary, f, want, "install", "--bundle", f.skbPath, "--trust-roots", f.trPath, "--registry", f.regURL, "--home", f.home, "--revocations", list)
}
func installedCLISeedDependency(t *testing.T, binary string, p installedCLIProof) (installableFixture, string) {
	t.Helper()
	leaf, _ := installedCLIBundle(t, p, "required", "")
	installedCLICall(t, binary, leaf, 0)
	return leaf, filepath.Join(leaf.home, ".claude", "skills", "required")
}

func TestInstallInstalledSkillDependenciesActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	p := installedCLIProofFixture(t)
	installedCLISeedDependency(t, binary, p)
	root, _ := installedCLIBundle(t, p, "revo-demo", `,"depends_on":[{"kind":"skill","name":"required","constraint":">=1.0.0"}]`)
	installedCLICall(t, binary, root, 0)
	raw, err := os.ReadFile(filepath.Join(root.home, ".claude", "skills", "revo-demo", "SKILL.md"))
	if err != nil || string(raw) != "# revo-demo\n" {
		t.Fatalf("actual installed body: %q %v", raw, err)
	}
}

func TestInstallInstalledSkillDependenciesTamperActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, mode := range []string{"body", "missing", "extra", "unsigned", "agent", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			p := installedCLIProofFixture(t)
			_, dir := installedCLISeedDependency(t, binary, p)
			kind := "skill"
			switch mode {
			case "body":
				if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Rename(dir, dir+"-inactive"); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("unlisted"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsigned":
				if err := os.Remove(filepath.Join(dir, ".skillctl-offline.json")); err != nil {
					t.Fatal(err)
				}
			case "agent":
				kind = "agent"
			}
			root, _ := installedCLIBundle(t, p, "revo-demo", `,"depends_on":[{"kind":"`+kind+`","name":"required"}]`)
			target := filepath.Join(root.home, ".claude", "skills", "revo-demo")
			if err := os.MkdirAll(target, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("old target"), 0600); err != nil {
				t.Fatal(err)
			}
			if mode == "ignore" {
				args := append([]string{"install", "--home", root.home}, enterpriseInstallFixtureArgs(t, root)...)
				args = append(args, "--bundle", root.skbPath, "--ignore-deps")
				mutationCLI(t, binary, root, 2, args...)
			} else {
				installedCLICall(t, binary, root, 14)
			}
			raw, err := os.ReadFile(filepath.Join(target, "SKILL.md"))
			if err != nil || string(raw) != "old target" {
				t.Fatalf("denial changed prior target: %q %v", raw, err)
			}
		})
	}
}

func TestInstallInstalledSkillDependenciesRevokedActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	p := installedCLIProofFixture(t)
	leaf, _ := installedCLISeedDependency(t, binary, p)
	root, _ := installedCLIBundle(t, p, "revo-demo", `,"depends_on":[{"kind":"skill","name":"required"}]`)
	list, err := verify.NewSignedRevocationList(root.regURL, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), 2, []string{leaf.digest}, root.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root.dir, "dependency-revoked.json")
	writeJSON(t, path, list)
	args := append([]string{"install", "--home", root.home}, enterpriseInstallFixtureArgs(t, root)...)
	args = append(args, "--bundle", root.skbPath, "--registry", root.regURL, "--revocations", path)
	mutationCLI(t, binary, root, 17, args...)
	if _, err := os.Stat(filepath.Join(root.home, ".claude", "skills", "revo-demo")); !os.IsNotExist(err) {
		t.Fatalf("revoked graph installed target: %v", err)
	}
}
