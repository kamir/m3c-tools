package registry

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

func registrySnapshotHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	return home
}

func packedInstallSnapshot(t *testing.T, agent bool, body string) []byte {
	t.Helper()
	name, anchor := "snapshot-skill", "SKILL.md"
	manifest := skillbundle.BundleManifest{Name: name, Version: "1.0.0"}
	if agent {
		name = "snapshot-agent"
		anchor = name + ".md"
		manifest.Name, manifest.Kind, manifest.Schema = name, skillbundle.KindAgent, skillbundle.SchemaAgent
	}
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, anchor), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "snapshot.skb")
	if _, err := skillbundle.Pack(src, out, skillbundle.PackOptions{Manifest: manifest}); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestInstallSnapshotRegistryCacheBinding(t *testing.T) {
	for _, agent := range []bool{false, true} {
		for _, changed := range []bool{false, true} {
			name := "skill/same"
			if agent {
				name = "agent/same"
			}
			if changed {
				name = strings.TrimSuffix(name, "same") + "swapped"
			}
			t.Run(name, func(t *testing.T) {
				home := registrySnapshotHome(t)
				blob := packedInstallSnapshot(t, agent, "original signed body")
				bundleName, kind := "snapshot-skill", skillbundle.KindSkill
				if agent {
					bundleName, kind = "snapshot-agent", skillbundle.KindAgent
				}
				b := stagedFor(t, bundleName, "1.0.0", blob)
				b.Kind = kind
				if agent {
					signAgentStagedFixture(t, b)
				}
				if changed {
					if err := os.WriteFile(b.StagedSkbPath, packedInstallSnapshot(t, agent, "substituted unsigned body"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				skills := filepath.Join(home, "skills")
				target := filepath.Join(skills, bundleName)
				bodyPath := filepath.Join(target, "SKILL.md")
				if agent {
					target = filepath.Join(agentsDirFor(skills), bundleName+".md")
					bodyPath = target
				}
				if changed {
					if err := os.MkdirAll(filepath.Dir(bodyPath), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(bodyPath, []byte("previous installed body"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				plan, err := PlanInstall([]*StagedBundle{b}, skills)
				if err != nil {
					t.Fatal(err)
				}
				res, err := ConfirmInstall([]*StagedBundle{b}, plan.Token, InstallOpts{NativeTrustRoots: agentFixtureRoots(), SkillsDir: skills})
				if !changed {
					if err != nil || len(res) != 1 {
						t.Fatalf("same pulled bytes failed: %v", err)
					}
					body, err := os.ReadFile(bodyPath)
					if err != nil || string(body) != "original signed body" {
						t.Fatalf("same snapshot not installed: %v", err)
					}
					return
				}
				if len(res) != 0 || !errors.Is(err, ErrGateDigest) {
					t.Fatalf("cache swap bypassed pulled digest: %v", err)
				}
				body, err := os.ReadFile(bodyPath)
				if err != nil || string(body) != "previous installed body" {
					t.Fatal("cache refusal changed old skill/agent")
				}
				if !agent {
					if _, err := os.Stat(filepath.Join(target, ProvenanceSidecarName)); !os.IsNotExist(err) {
						t.Fatal("refusal wrote provenance")
					}
				}
			})
		}
	}
}

type snapshotFailureReader struct{ err error }

func (r snapshotFailureReader) Read([]byte) (int, error) { return 0, r.err }

func TestInstallSnapshotRegistryReadBoundary(t *testing.T) {
	registrySnapshotHome(t)
	blob := packedInstallSnapshot(t, false, "synthetic body")
	b := stagedFor(t, "snapshot-skill", "1.0.0", blob)
	for _, expected := range []string{"", "sha256:invalid", "sha256:" + strings.Repeat("0", 64)} {
		if got, err := readInstallSnapshot(bytes.NewReader(blob), expected, MaxBlobSize); got != nil || !errors.Is(err, ErrGateDigest) {
			t.Fatalf("missing/malformed/mismatched digest accepted: %v", err)
		}
	}
	if got, err := readInstallSnapshot(bytes.NewReader(blob), b.Digest, int64(len(blob))); err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("exact cap failed: %v", err)
	}
	if got, err := readInstallSnapshot(bytes.NewReader(blob), b.Digest, int64(len(blob)-1)); err == nil || got != nil || errors.Is(err, ErrGateDigest) {
		t.Fatalf("size failure absent or mislabeled corruption: %v", err)
	}
	sentinel := errors.New("synthetic snapshot IO failure")
	if got, err := readInstallSnapshot(io.MultiReader(bytes.NewReader(blob[:10]), snapshotFailureReader{sentinel}), b.Digest, MaxBlobSize); got != nil || !errors.Is(err, sentinel) || errors.Is(err, ErrGateDigest) {
		t.Fatalf("IO failure lost or mislabeled: %v", err)
	}
	if got, err := readBoundInstallSnapshot(filepath.Join(t.TempDir(), "missing.skb"), b.Digest); got != nil || !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrGateDigest) {
		t.Fatalf("OS read failure lost or mislabeled: %v", err)
	}
}
