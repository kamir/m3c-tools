package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/mutationstate"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func managedEvidenceRoots(t *testing.T, f installableFixture, managed bool, failPolicy string) *verify.TrustRoot {
	t.Helper()
	writePinnedTrustRootsFresh(t, f.trPath, f.regURL, f.regPubB64, f.authorID, f.authorPubB64, "24h", failPolicy)
	if managed {
		body, err := os.ReadFile(f.trPath)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, []byte("    offline_policy:\n      enterprise: true\n")...)
		if err := os.WriteFile(f.trPath, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	roots, err := verify.Load(f.trPath)
	if err != nil || len(roots.Roots) != 1 {
		t.Fatalf("load fixture roots: %v", err)
	}
	root := &roots.Roots[0]
	if root.IsManaged() != managed {
		t.Fatal("fixture managed selection differs")
	}
	policy, err := root.Freshness()
	if err != nil || policy.MaxStaleness != 24*time.Hour || string(policy.FailPolicy) != failPolicy {
		t.Fatalf("fixture freshness policy differs: %+v error=%v", policy, err)
	}
	if managed {
		// Valid managed fixtures now include an explicit prior enrollment event.
		// Candidate list generation remains separate, including invalid cases.
		list, err := verify.NewSignedRevocationList(f.regURL, time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339Nano), 1, nil, f.regPriv)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		store, err := mutationstate.New(filepath.Join(f.home, ".claude", "mutation-state"), root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Enroll(context.Background(), raw); err != nil {
			t.Fatalf("explicit fixture enrollment: %v", err)
		}
	}
	return root
}

func managedEvidenceList(t *testing.T, f installableFixture, root *verify.TrustRoot, age time.Duration, epoch int) string {
	t.Helper()
	list, err := verify.NewSignedRevocationList(f.regURL, time.Now().UTC().Add(-age).Format(time.RFC3339Nano), epoch, nil, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	// Even version-zero and future-dated cases have a genuinely valid signature;
	// their mandatory-mutation policy refusal must not be a forged-input accident.
	if _, err := verify.VerifyRevocationList(list, root, 0); err != nil {
		t.Fatalf("fixture signature not valid: %v", err)
	}
	return writeRevocations(t, f.dir, list)
}

func managedEvidenceCheckpoint(t *testing.T, f installableFixture) string {
	t.Helper()
	checkpoint, err := verify.NewSignedFreshnessCheckpoint(f.regURL, 2, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "fresh-checkpoint.json")
	writeJSON(t, path, checkpoint)
	return path
}

func runManagedEvidenceInstall(t *testing.T, binary string, f installableFixture, want int, extra ...string) {
	t.Helper()
	args := []string{"install", "--json", "--bundle", f.skbPath, "--home", f.home}
	args = append(args, enterpriseInstallFixtureArgs(t, f)...)
	args = append(args, extra...)
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), "HOME="+f.home, "USERPROFILE="+f.home, "M3C_TOKEN_STORE=file", "M3C_TEST_KEYCHAIN=0", "M3C_ER1_KEYCHAIN=off")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	var result bundleVerifyResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("built CLI did not return JSON: %v; stderr=%s", err, stderr.String())
	}
	if result.Schema != trustResultSchema || result.Operation != "install" || result.ExitCode != code || result.OK != (code == 0) {
		t.Fatalf("process/JSON contract differs: exit=%d result=%+v", code, result)
	}
	if code != want {
		t.Fatalf("install exit=%d want=%d; error=%s stderr=%s", code, want, result.Error, stderr.String())
	}
	target := filepath.Join(f.home, ".claude", "skills", "revo-demo")
	if want != 0 {
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("denied install changed target: %v", err)
		}
		if result.InstallPath != "" {
			t.Fatal("denied install claimed an install path")
		}
		if after := installedSkillDirs(t, f.home); len(after) != 0 {
			t.Fatalf("denied install left skill directories: %v", after)
		}
	} else {
		content, err := os.ReadFile(filepath.Join(target, "SKILL.md"))
		if err != nil || len(content) == 0 {
			t.Fatalf("successful process did not install skill: %v", err)
		}
		canonicalTarget, canonicalErr := filepath.EvalSymlinks(target)
		if canonicalErr != nil {
			t.Fatal(canonicalErr)
		}
		canonicalResult, resultErr := filepath.EvalSymlinks(result.InstallPath)
		if resultErr != nil {
			t.Fatal(resultErr)
		}
		if canonicalResult != canonicalTarget || result.Digest != f.digest {
			t.Fatalf("successful install result differs: %+v", result)
		}
	}
}

func TestInstallBundleManagedEvidenceActualCLI(t *testing.T) {
	// Build before fixture HOME changes; child compiler inherits the caller's
	// explicit GOFLAGS, including a native-provider trap when used by the runner.
	binary := skillctlBin(t)
	for _, tc := range []struct {
		name             string
		age              time.Duration
		epoch            int
		missing, managed bool
		want             int
	}{
		{"managed_missing_list", time.Hour, 1, true, true, 22},
		{"managed_fresh_1h", time.Hour, 1, false, true, 0},
		{"managed_unversioned", time.Hour, 0, false, true, 12},
		{"managed_future_list_within_legacy_skew", -time.Minute, 1, false, true, 22},
		{"unmanaged_missing_list_compatible", time.Hour, 1, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := buildInstallableFixture(t)
			root := managedEvidenceRoots(t, f, tc.managed, "closed")
			var extra []string
			if !tc.missing {
				extra = append(extra, "--revocations", managedEvidenceList(t, f, root, tc.age, tc.epoch))
			}
			runManagedEvidenceInstall(t, binary, f, tc.want, extra...)
		})
	}
}

func TestInstallBundleManagedStaleCheckpointCannotReplaceListActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	f := buildInstallableFixture(t)
	root := managedEvidenceRoots(t, f, true, "closed")
	revocations := managedEvidenceList(t, f, root, 48*time.Hour, 1)
	checkpoint := managedEvidenceCheckpoint(t, f)
	bundleBefore, err := os.ReadFile(f.skbPath)
	if err != nil {
		t.Fatal(err)
	}
	listBefore, err := os.ReadFile(revocations)
	if err != nil {
		t.Fatal(err)
	}
	for _, withCheckpoint := range []bool{false, true} {
		t.Run(map[bool]string{false: "without_checkpoint", true: "with_fresh_checkpoint"}[withCheckpoint], func(t *testing.T) {
			extra := []string{"--revocations", revocations}
			if withCheckpoint {
				extra = append(extra, "--checkpoint", checkpoint)
			}
			runManagedEvidenceInstall(t, binary, f, 22, extra...)
			bundleAfter, err := os.ReadFile(f.skbPath)
			if err != nil {
				t.Fatal(err)
			}
			listAfter, err := os.ReadFile(revocations)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bundleBefore, bundleAfter) || !bytes.Equal(listBefore, listAfter) {
				t.Fatal("paired calls did not retain identical bundle/list bytes")
			}
		})
	}
}

// lowRiskInstallEvidenceFixture retains the existing extractable fixture shape
// but gives its read-only scope a genuinely signed archive digest, not merely
// an unsigned registry-row declaration.
func lowRiskInstallEvidenceFixture(t *testing.T) installableFixture {
	t.Helper()
	f := buildInstallableFixture(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# revo-demo\n\nRead the fixture.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := skillbundle.BundleManifest{Schema: "m3c-skill-bundle/v1", Name: "revo-demo", Version: "1.0.0", DataDependencies: []skillbundle.DataDependency{{ID: "ds:fixture/read", Kind: "local_fs", Access: "read", Scope: "fixture/**", Reason: "read the test fixture"}}}
	if _, err := skillbundle.Pack(dir, f.skbPath, skillbundle.PackOptions{Manifest: manifest}); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(f.skbPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(blob)
	f.digest = "sha256:" + hex.EncodeToString(sum[:])
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.authorPubB64 = base64.StdEncoding.EncodeToString(pub)
	body, err := os.ReadFile(defaultMetaSidecar(f.skbPath))
	if err != nil {
		t.Fatal(err)
	}
	var meta registry.BundleMeta
	if err := json.Unmarshal(body, &meta); err != nil {
		t.Fatal(err)
	}
	meta.Bundle["bundle_digest"] = f.digest
	meta.Signatures = []registry.SignatureRow{
		{Role: "author", IdentityID: f.authorID, SignatureB64: signB64(priv, sum), Status: "active"},
		{Role: "registry", IdentityID: "id:registry@aims-core", SignatureB64: signB64(f.regPriv, sum), Status: "active"},
	}
	writeJSON(t, defaultMetaSidecar(f.skbPath), meta)
	decoded, err := verify.ReadDigestVerifiedManifest(f.skbPath, f.digest)
	if err != nil {
		t.Fatal(err)
	}
	scopes := rawScopeListForManagedEvidence(t, decoded)
	if bundleActionRisk(scopes) != verify.RiskLow {
		t.Fatal("fixture not classified read-only")
	}
	return f
}

func rawScopeListForManagedEvidence(t *testing.T, manifest map[string]any) []verify.DeclaredScope {
	t.Helper()
	raw, ok := manifest["data_dependencies"].([]any)
	if !ok || len(raw) != 1 {
		t.Fatal("signed fixture scope missing")
	}
	scope, ok := raw[0].(map[string]any)
	if !ok {
		t.Fatal("signed fixture scope malformed")
	}
	return []verify.DeclaredScope{{Provenance: verify.ScopeProvenanceSignedManifest, Raw: scope}}
}

func TestInstallBundleManagedLowRiskFailOpenStillRequiresFreshListActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, managed := range []bool{true, false} {
		t.Run(map[bool]string{true: "managed_denied", false: "unmanaged_compatibility"}[managed], func(t *testing.T) {
			f := lowRiskInstallEvidenceFixture(t)
			root := managedEvidenceRoots(t, f, managed, "open")
			revocations := managedEvidenceList(t, f, root, 48*time.Hour, 1)
			want := 0
			if managed {
				want = 22
			}
			runManagedEvidenceInstall(t, binary, f, want, "--revocations", revocations)
		})
	}
}

func TestInstallBundleUnmanagedCheckpointCompatibilityActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	f := buildInstallableFixture(t)
	root := managedEvidenceRoots(t, f, false, "closed")
	revocations := managedEvidenceList(t, f, root, 48*time.Hour, 1)
	runManagedEvidenceInstall(t, binary, f, 0, "--revocations", revocations, "--checkpoint", managedEvidenceCheckpoint(t, f))
}
