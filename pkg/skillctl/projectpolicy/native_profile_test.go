package projectpolicy

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
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func nativePolicyFixture(t *testing.T) (string, map[string]any) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	ref := func(name string, raw []byte) map[string]any {
		t.Helper()
		if e := os.WriteFile(filepath.Join(home, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		return map[string]any{"path": name, "sha256": hex.EncodeToString(sum[:])}
	}
	root := func() []byte {
		t.Helper()
		pub, _, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return []byte("registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\ngovernance_minimum: green\ngovernance_quorum: 1\n")
	}
	runtimeRaw, e := json.Marshal(dependencies.Profile{Schema: dependencies.ProfileSchema, ProjectRoot: home, Tools: []dependencies.Tool{}})
	if e != nil {
		t.Fatal(e)
	}
	doc := map[string]any{"schema": NativeSchema, "project_root": home, "artifact_home": home, "runtime": ref("runtime.json", runtimeRaw), "native": map[string]any{"logical_registry": "self", "authority_scope": "key-and-tenant", "tenant_scope": nil, "artifact_trust": ref("artifact.yaml", root()), "revocation_trust": ref("revoke.yaml", root()), "revocation_policy": map[string]any{"minimum_epoch": 1, "max_age_seconds": 86400}, "carrier": map[string]any{"kind": "er1", "base_url": "https://native.invalid", "context_id": "owner___skills", "allow_loopback_http": false}}}
	return filepath.Join(home, "native.json"), doc
}
func writeNativePolicyFixture(t *testing.T, path string, doc map[string]any) {
	t.Helper()
	raw, e := json.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestNativeProfileStrictSelection(t *testing.T) {
	if os.Getenv("M3C_NATIVE_SPECIAL_CHILD") == "1" {
		if _, e := readNativeFile(os.Getenv("M3C_NATIVE_SPECIAL_PATH"), 65536); !errors.Is(e, ErrInvalid) {
			t.Fatal("special file did not fail regular-file boundary", e)
		}
		return
	}
	t.Run("existing-special-files", func(t *testing.T) {
		exe, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		for _, path := range nativeProfileSpecialFiles(t) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestNativeProfileStrictSelection$")
			cmd.WaitDelay = time.Second
			home := t.TempDir()
			cmd.Dir = home
			var env []string
			for _, v := range os.Environ() {
				k, _, _ := strings.Cut(v, "=")
				if k != "HOME" && k != "USERPROFILE" && k != "M3C_NATIVE_SPECIAL_CHILD" && k != "M3C_NATIVE_SPECIAL_PATH" {
					env = append(env, v)
				}
			}
			cmd.Env = append(env, "HOME="+home, "USERPROFILE="+home, "M3C_NATIVE_SPECIAL_CHILD=1", "M3C_NATIVE_SPECIAL_PATH="+path)
			output, e := cmd.CombinedOutput()
			cancel()
			if e != nil {
				t.Fatalf("bounded special-file child failed or blocked: %v %s", e, output)
			}
		}
	})

	t.Run("independent-role-keys-positive", func(t *testing.T) {
		path, doc := nativePolicyFixture(t)
		home := filepath.Dir(path)
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		raw := []byte("registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\ngovernance_minimum: green\ngovernance_quorum: 1\n")
		if e = os.WriteFile(filepath.Join(home, "revoke.yaml"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(raw)
		doc["native"].(map[string]any)["revocation_trust"].(map[string]any)["sha256"] = hex.EncodeToString(sum[:])
		writeNativePolicyFixture(t, path, doc)
		p, e := LoadNative(path, home, home)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Equal(p.ArtifactRoots().Roots().PubKey(), pub) {
			t.Fatal("fixture did not separate roles")
		}
		head, e := registry.BuildRevocationHead(registry.RevocationHeadInput{Epoch: 7, IssuedAt: time.Now().UTC().Add(-time.Minute), Digests: []string{}, Emergency: []string{}})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = registry.SignEnvelopeSignature(key, head); e != nil {
			t.Fatal(e)
		}
		evidence, e := json.Marshal(map[string]any{"schema": "m3c.native-revocation-evidence/v1", "head": head, "revoked_digests": []string{}})
		if e != nil {
			t.Fatal(e)
		}
		observed, e := p.InspectRevocationEvidence(evidence)
		if e != nil || observed.Observation().Epoch != 7 {
			t.Fatal("separate-role native HEAD positive", e)
		}
		if !errors.Is(artifact.RejectNativeEnterpriseMutation(p.Intent()), artifact.ErrNativeMutationUnavailable) {
			t.Fatal("diagnostic granted mutation")
		}
	})

	path, doc := nativePolicyFixture(t)
	writeNativePolicyFixture(t, path, doc)
	home := filepath.Dir(path)
	p, e := LoadNative(path, home, home)
	if e != nil {
		t.Fatal("valid native profile", e)
	}
	if !errors.Is(artifact.RejectNativeEnterpriseMutation(p.Intent()), artifact.ErrNativeMutationUnavailable) {
		t.Fatal("valid profile granted mutation")
	}
	if e = p.ValidateSelection(home, home, "self"); e != nil {
		t.Fatal(e)
	}
	if e = p.ValidateSelection(home, home, "foreign"); !errors.Is(e, ErrSelection) {
		t.Fatal("foreign carrier selection", e)
	}
	carrier := p.CarrierSelection()
	carrier.ContextID = "mutated"
	if p.CarrierSelection().ContextID != "owner___skills" {
		t.Fatal("carrier is not snapshot")
	}
	roots := p.ArtifactRoots().Roots()
	roots.Registry = "changed"
	roots.PubKey()[0] ^= 255
	if p.ArtifactRoots().Roots().Registry != "self" {
		t.Fatal("roots not immutable")
	}
	if _, e = LoadNativePinned(path, p.ProfileDigest(), home, home); e != nil {
		t.Fatal("explicit pin positive", e)
	}
	if _, e = LoadNativePinned(path, strings.Repeat("0", 64), home, home); !errors.Is(e, ErrSelection) {
		t.Fatal("profile pin mismatch", e)
	}
	// Runtime-only ref changes affect configuration pin, not revocation history identity.
	runtime := doc["runtime"].(map[string]any)
	runtimePath := filepath.Join(home, runtime["path"].(string))
	raw, e := os.ReadFile(runtimePath)
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	if e = os.WriteFile(runtimePath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	runtime["sha256"] = hex.EncodeToString(sum[:])
	writeNativePolicyFixture(t, path, doc)
	next, e := LoadNative(path, home, home)
	if e != nil || next.HistoryAuthorityID() != p.HistoryAuthorityID() || next.ProfileDigest() == p.ProfileDigest() {
		t.Fatal("runtime changed stable authority identity", e)
	}
	for _, name := range []string{"top-alias", "mapping-alias", "unknown", "cross-sign", "null-native", "null-loopback", "empty-tenant", "fractional-policy", "too-old-policy", "foreign-root", "path", "runtime-pin"} {
		t.Run(name, func(t *testing.T) {
			path, doc := nativePolicyFixture(t)
			mapping := doc["native"].(map[string]any)
			switch name {
			case "top-alias":
				doc["Native"] = mapping
			case "mapping-alias":
				mapping["Logical_Registry"] = "self"
			case "unknown":
				doc["future"] = true
			case "cross-sign":
				mapping["cross_signing"] = map[string]any{"path": "never-read", "sha256": strings.Repeat("0", 64)}
			case "null-native":
				doc["native"] = nil
			case "null-loopback":
				mapping["carrier"].(map[string]any)["allow_loopback_http"] = nil
			case "empty-tenant":
				mapping["tenant_scope"] = ""
			case "fractional-policy":
				mapping["revocation_policy"].(map[string]any)["minimum_epoch"] = 1.5
			case "too-old-policy":
				mapping["revocation_policy"].(map[string]any)["max_age_seconds"] = 86401
			case "foreign-root":
				mapping["logical_registry"] = "foreign"
			case "path":
				doc["project_root"] = "relative"
			case "runtime-pin":
				doc["runtime"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
			}
			writeNativePolicyFixture(t, path, doc)
			if _, e := LoadNative(path, filepath.Dir(path), filepath.Dir(path)); e == nil {
				t.Fatal("invalid native profile accepted")
			}
		})
	}
	for _, raw := range [][]byte{[]byte(strings.Repeat(" ", 65537)), []byte(`{"schema":"x","schema":"x"}`), {0xff}} {
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = LoadNative(path, home, home); e == nil {
			t.Fatal("raw bounds/duplicates accepted")
		}
	}
	if _, e = LoadNative(path, strings.Repeat("x", 1<<20), home); e == nil {
		t.Fatal("oversize caller path accepted")
	}
	if nativeTokenBudget([]byte("["+strings.Repeat("null,", 4096)+"null]")) == nil {
		t.Fatal("native predecode token cap ignored")
	}
	// The existing HTTP v1 loader and its signed authority contract remain usable.
	hp, hd := profileFixture(t)
	raw, e = json.Marshal(hd)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(hp, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(hp, hd.ProjectRoot, hd.ArtifactHome); e != nil {
		t.Fatal("HTTP v1 compatibility", e)
	}
	if _, e = LoadNative(hp, hd.ProjectRoot, hd.ArtifactHome); e == nil {
		t.Fatal("HTTP roots cast as native profile")
	}
}
