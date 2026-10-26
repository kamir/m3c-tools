package projectpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	t.Run("v4-live-selection-keeps-history-and-denies-unsupported-providers", func(t *testing.T) {
		path, doc := nativePolicyFixture(t)
		home := filepath.Dir(path)
		doc["schema"] = NativeLiveSchema
		mapping := doc["native"].(map[string]any)
		mapping["revocation_source"] = map[string]any{"kind": "https-native-evidence", "url": "https://source.invalid/full.json", "auth": "none", "tls": map[string]any{"mode": "system"}}
		carrier := map[string]any{"kind": "er1", "base_url": "https://native.invalid/prefix", "context_id": "explicit-context", "tls": map[string]any{"mode": "system"}, "auth": map[string]any{"mode": "none"}}
		mapping["carrier"] = carrier
		writeNativePolicyFixture(t, path, doc)
		first, err := LoadNative(path, home, home)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = first.BeginER1AgentInstall(context.Background(), "sha256:"+strings.Repeat("a", 64)); !errors.Is(err, registry.ErrNativeHistoryRequired) {
			t.Fatal("missing journal failed to precede source acquisition", err)
		}
		carrier["auth"] = map[string]any{"mode": "external-env", "family": "api-key", "origin": "https://native.invalid:443"}
		writeNativePolicyFixture(t, path, doc)
		second, err := LoadNative(path, home, home)
		if err != nil {
			t.Fatal(err)
		}
		if first.SelectionID() == second.SelectionID() || first.ProfileDigest() == second.ProfileDigest() || first.HistoryAuthorityID() != second.HistoryAuthorityID() {
			t.Fatal("live credential consent confused stable history authority")
		}
		if err = artifact.RejectNativeEnterpriseMutation(second.Intent()); err == nil {
			t.Fatal("v4 enabled a generic mutation intent")
		}
		carrier["auth"] = map[string]any{"mode": "native-device-token"}
		writeNativePolicyFixture(t, path, doc)
		if _, err = LoadNative(path, home, home); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unsupported native provider accepted", err)
		}
		carrier["auth"] = map[string]any{"mode": "none", "family": "bearer"}
		writeNativePolicyFixture(t, path, doc)
		if _, err = LoadNative(path, home, home); !errors.Is(err, ErrInvalid) {
			t.Fatal("credential-family ambiguity accepted", err)
		}
		carrier["auth"] = map[string]any{"mode": "none"}
		carrier["base_url"] = "http://127.0.0.1/prefix"
		writeNativePolicyFixture(t, path, doc)
		if _, err = LoadNative(path, home, home); !errors.Is(err, ErrInvalid) {
			t.Fatal("live plaintext carrier accepted", err)
		}
	})
	t.Run("explicit-source-selection-and-history-separation", func(t *testing.T) {
		path, doc := nativePolicyFixture(t)
		home := filepath.Dir(path)
		doc["schema"] = NativeEvidenceSchema
		mapping := doc["native"].(map[string]any)
		source := map[string]any{"kind": "https-native-evidence", "url": "https://source.invalid/full.json", "auth": "none", "tls": map[string]any{"mode": "system"}}
		mapping["revocation_source"] = source
		writeNativePolicyFixture(t, path, doc)
		first, err := LoadNative(path, home, home)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = first.AdoptFromSource(context.Background()); !errors.Is(err, registry.ErrNativeHistoryRequired) {
			t.Fatalf("missing history did not deny before source fetch: %v", err)
		}
		source["url"] = "https://other.invalid/full.json"
		writeNativePolicyFixture(t, path, doc)
		second, err := LoadNative(path, home, home)
		if err != nil {
			t.Fatal(err)
		}
		if first.SelectionID() == second.SelectionID() || first.ProfileDigest() == second.ProfileDigest() || first.HistoryAuthorityID() != second.HistoryAuthorityID() {
			t.Fatal("source consent and stable authority history were conflated")
		}
		// A genuine CA validates the pinned role, and byte changes alter consent
		// without inventing a different revocation authority.
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic source CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		caPath := filepath.Join(home, "source-ca.pem")
		if err = os.WriteFile(caPath, ca, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(ca)
		ref := map[string]any{"path": "source-ca.pem", "sha256": hex.EncodeToString(sum[:])}
		source["tls"] = map[string]any{"mode": "pinned-pem", "ca": ref}
		writeNativePolicyFixture(t, path, doc)
		pinned, err := LoadNative(path, home, home)
		if err != nil {
			t.Fatal(err)
		}
		if pinned.SelectionID() == second.SelectionID() || pinned.HistoryAuthorityID() != second.HistoryAuthorityID() {
			t.Fatal("TLS role changed history authority or failed to bind consent")
		}
		if err = os.WriteFile(caPath, []byte("drift"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = LoadNative(path, home, home); !errors.Is(err, ErrSelection) {
			t.Fatal("CA SHA drift accepted", err)
		}
		for _, name := range []string{"source-ca.pem", "native.json", "artifact.yaml", "revoke.yaml", "runtime.json"} {
			if err = os.Remove(filepath.Join(home, name)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err = pinned.AdoptFromSource(context.Background()); !errors.Is(err, registry.ErrNativeHistoryRequired) {
			t.Fatal("immutable policy reloaded deleted pins or fetched before enrollment", err)
		}
		if !errors.Is(artifact.RejectNativeEnterpriseMutation(pinned.Intent()), artifact.ErrNativeMutationUnavailable) {
			t.Fatal("source profile granted live mutation")
		}
	})
	for _, invalid := range []string{"v2-source", "v3-missing", "null", "alias", "auth", "http", "path", "system-ca", "tls-unknown", "pinned-missing"} {
		t.Run("source-schema-"+invalid, func(t *testing.T) {
			path, doc := nativePolicyFixture(t)
			doc["schema"] = NativeEvidenceSchema
			mapping := doc["native"].(map[string]any)
			source := map[string]any{"kind": "https-native-evidence", "url": "https://source.invalid/full.json", "auth": "none", "tls": map[string]any{"mode": "system"}}
			mapping["revocation_source"] = source
			switch invalid {
			case "v2-source":
				doc["schema"] = NativeSchema
			case "v3-missing":
				delete(mapping, "revocation_source")
			case "null":
				mapping["revocation_source"] = nil
			case "alias":
				source["URL"] = source["url"]
			case "auth":
				source["auth"] = "ambient"
			case "http":
				source["url"] = "http://127.0.0.1/full.json"
			case "path":
				source["url"] = "https://source.invalid/a/../full.json"
			case "system-ca":
				source["tls"].(map[string]any)["ca"] = map[string]any{"path": "unused", "sha256": strings.Repeat("0", 64)}
			case "tls-unknown":
				source["tls"] = map[string]any{"mode": "insecure"}
			case "pinned-missing":
				source["tls"] = map[string]any{"mode": "pinned-pem"}
			}
			writeNativePolicyFixture(t, path, doc)
			if p, err := LoadNative(path, filepath.Dir(path), filepath.Dir(path)); p != nil || err == nil {
				t.Fatal("ambiguous or unsupported source profile accepted")
			}
		})
	}
	t.Run("offline-selection-retains-pins-without-live-grant", func(t *testing.T) {
		path, doc := nativePolicyFixture(t)
		home := filepath.Dir(path)
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw := []byte("registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\ngovernance_minimum: green\ngovernance_quorum: 1\n")
		if err = os.WriteFile(filepath.Join(home, "revoke.yaml"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		doc["native"].(map[string]any)["revocation_trust"].(map[string]any)["sha256"] = hex.EncodeToString(sum[:])
		writeNativePolicyFixture(t, path, doc)
		policy, err := LoadNative(path, home, home)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := policy.OfflineInstallSelection()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"native.json", "artifact.yaml", "revoke.yaml", "runtime.json"} {
			if err = os.Remove(filepath.Join(home, name)); err != nil {
				t.Fatal(err)
			}
		}
		journal, err := registry.OpenNativeJournal(selection)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = journal.Status(context.Background()); !errors.Is(err, registry.ErrNativeHistoryRequired) {
			t.Fatalf("factory implicitly enrolled: %v", err)
		}
		head, err := registry.BuildRevocationHead(registry.RevocationHeadInput{Epoch: 1, IssuedAt: time.Now().UTC().Add(-time.Minute), Digests: []string{}, Emergency: []string{}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = registry.SignEnvelopeSignature(key, head); err != nil {
			t.Fatal(err)
		}
		evidence, err := json.Marshal(map[string]any{"schema": "m3c.native-revocation-evidence/v1", "head": head, "revoked_digests": []string{}})
		if err != nil {
			t.Fatal(err)
		}
		status, err := journal.Enroll(context.Background(), evidence)
		if err != nil || status.HistoryAuthorityID != policy.HistoryAuthorityID() {
			t.Fatalf("frozen selected authority lost: %v", err)
		}
		session, err := journal.BeginOfflineInstall(context.Background(), "sha256:"+strings.Repeat("1", 64))
		if err != nil {
			t.Fatal(err)
		}
		if err = session.Close(); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(artifact.RejectNativeEnterpriseMutation(policy.Intent()), artifact.ErrNativeMutationUnavailable) {
			t.Fatal("offline factory enabled live mutation")
		}
		for _, invalid := range []*NativePolicy{nil, {}} {
			if _, err = invalid.OfflineInstallSelection(); err == nil {
				t.Fatal("nil/zero policy produced selection")
			}
		}
	})
	t.Run("git-carrier-selection-without-io", func(t *testing.T) {
		var localWant error
		if !filepath.IsAbs("/explicit-offline-repository") {
			localWant = ErrInvalid
		}
		for _, tc := range []struct {
			locator string
			want    error
		}{
			{"github://example.invalid/owner/repo", nil},
			{"gitlab://example.invalid/group/repo", nil},
			{"local:///explicit-offline-repository", localWant},
			{"github://example.invalid/owner/repo@main", ErrUnsupported},
			{"github://example.invalid/owner/repo?ref=x", ErrUnsupported},
			{"https://example.invalid/owner/repo", ErrUnsupported},
			{"github://", ErrInvalid},
			{"gitlab://host//repo", ErrInvalid},
			{"github://host/../repo", ErrInvalid},
			{"github://host/repo/", ErrInvalid},
			{"gitlab://host:22/repo", ErrInvalid},
			{"gitlab://host\\repo", ErrInvalid},
		} {
			t.Run(tc.locator, func(t *testing.T) {
				path, doc := nativePolicyFixture(t)
				doc["native"].(map[string]any)["carrier"] = map[string]any{"kind": "git", "locator": tc.locator}
				writeNativePolicyFixture(t, path, doc)
				home := filepath.Dir(path)
				p, err := LoadNative(path, home, home)
				if tc.want != nil {
					if p != nil || !errors.Is(err, tc.want) {
						t.Fatalf("carrier refusal got %v want %v", err, tc.want)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if p.CarrierSelection().Locator != tc.locator || p.ValidateSelection(home, home, tc.locator) != nil {
					t.Fatal("selected Git mapping lost")
				}
				if !errors.Is(p.ValidateSelection(home, home, tc.locator+"/foreign"), ErrSelection) {
					t.Fatal("foreign Git selection accepted")
				}
				if !errors.Is(artifact.RejectNativeEnterpriseMutation(p.Intent()), artifact.ErrNativeMutationUnavailable) {
					t.Fatal("Git selection granted mutation")
				}
			})
		}
	})
	t.Run("snapshot-and-history-boundaries", func(t *testing.T) {
		path, doc := nativePolicyFixture(t)
		home := filepath.Dir(path)
		runtimePath := filepath.Join(home, "runtime.json")
		runtime := dependencies.Profile{Schema: dependencies.ProfileSchema, ProjectRoot: home, Tools: []dependencies.Tool{{Name: "fixture", Path: filepath.Join(home, "never-executed"), Args: []string{"--version"}, VersionPattern: `^([0-9]+)$`}}}
		raw, err := json.Marshal(runtime)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(runtimePath, raw, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		doc["runtime"].(map[string]any)["sha256"] = hex.EncodeToString(sum[:])
		writeNativePolicyFixture(t, path, doc)
		p, err := LoadNative(path, home, home)
		if err != nil {
			t.Fatal(err)
		}
		canonicalHome, err := filepath.EvalSymlinks(home)
		if err != nil {
			t.Fatal(err)
		}
		if p.ProjectRoot() != canonicalHome || p.ArtifactHome() != canonicalHome || len(p.SelectionID()) != 64 || len(p.HistoryAuthorityID()) != 64 {
			t.Fatal("selected identity missing")
		}
		view := p.Runtime()
		view.Tools[0].Args[0] = "changed"
		view.Tools[0].Name = "changed"
		view.ProjectRoot = t.TempDir()
		if p.Runtime().Tools[0].Args[0] != "--version" || p.Runtime().Tools[0].Name != "fixture" || p.Runtime().ProjectRoot != canonicalHome {
			t.Fatal("caller mutated runtime snapshot")
		}
		originalKey := append([]byte(nil), p.ArtifactRoots().Roots().PubKey()...)
		roots := p.ArtifactRoots().Roots()
		roots.PubKey()[0] ^= 255
		roots.Registry = "foreign"
		if !bytes.Equal(p.ArtifactRoots().Roots().PubKey(), originalKey) || p.ArtifactRoots().Roots().Registry != "self" {
			t.Fatal("caller mutated authority snapshot")
		}
		// A policy retains its validated role material even if the selected files disappear.
		if err = os.Remove(filepath.Join(home, "artifact.yaml")); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(p.ArtifactRoots().Roots().PubKey(), originalKey) {
			t.Fatal("snapshot reloaded missing authority")
		}
		if loaded, e := LoadNative(path, home, home); loaded != nil || !errors.Is(e, ErrInvalid) {
			t.Fatalf("missing role ref did not deny: %v", e)
		}
		// Policy tightening is distinct from the stable key/tenant history namespace.
		if err = os.WriteFile(filepath.Join(home, "artifact.yaml"), []byte("registry: self\npubkey_b64: "+base64.StdEncoding.EncodeToString(originalKey)+"\ngovernance_minimum: green\ngovernance_quorum: 1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		doc["native"].(map[string]any)["revocation_policy"] = map[string]any{"minimum_epoch": 3, "max_age_seconds": 60}
		writeNativePolicyFixture(t, path, doc)
		tight, e := LoadNative(path, home, home)
		if e != nil || tight.HistoryAuthorityID() != p.HistoryAuthorityID() || tight.ProfileDigest() == p.ProfileDigest() {
			t.Fatalf("policy tightening rewrote history: %v", e)
		}
		doc["native"].(map[string]any)["tenant_scope"] = "tenant-b"
		writeNativePolicyFixture(t, path, doc)
		tenant, e := LoadNative(path, home, home)
		if e != nil || tenant.HistoryAuthorityID() == p.HistoryAuthorityID() || tenant.SelectionID() == p.SelectionID() {
			t.Fatalf("tenant authority collision: %v", e)
		}
		// Key rotation must not silently reuse retained revocation history.
		pub, _, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		raw = []byte("registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\ngovernance_minimum: green\ngovernance_quorum: 1\n")
		if e = os.WriteFile(filepath.Join(home, "revoke.yaml"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		sum = sha256.Sum256(raw)
		doc["native"].(map[string]any)["revocation_trust"].(map[string]any)["sha256"] = hex.EncodeToString(sum[:])
		writeNativePolicyFixture(t, path, doc)
		rotated, e := LoadNative(path, home, home)
		if e != nil || rotated.HistoryAuthorityID() == tenant.HistoryAuthorityID() {
			t.Fatalf("rotated key reused history namespace: %v", e)
		}
	})
	t.Run("selection-and-reference-fail-closed", func(t *testing.T) {
		for _, name := range []string{"project-conflict", "home-conflict", "runtime-root-conflict", "artifact-hash-drift", "revocation-hash-drift", "runtime-invalid", "artifact-unsupported", "revocation-invalid", "bad-ref-pin", "unknown-carrier", "missing-ref", "invalid-profile-pin"} {
			t.Run(name, func(t *testing.T) {
				path, doc := nativePolicyFixture(t)
				home := filepath.Dir(path)
				project, actualHome := home, home
				mapping := doc["native"].(map[string]any)
				want := ErrInvalid
				replaceRef := func(ref map[string]any, raw []byte) {
					t.Helper()
					if e := os.WriteFile(filepath.Join(home, ref["path"].(string)), raw, 0600); e != nil {
						t.Fatal(e)
					}
					sum := sha256.Sum256(raw)
					ref["sha256"] = hex.EncodeToString(sum[:])
				}
				switch name {
				case "project-conflict":
					project = t.TempDir()
					want = ErrSelection
				case "home-conflict":
					actualHome = t.TempDir()
					want = ErrSelection
				case "runtime-root-conflict":
					replaceRef(doc["runtime"].(map[string]any), []byte(`{"schema":"m3c.skillctl.runtime-profile/v1","project_root":`+strconv.Quote(t.TempDir())+`,"tools":[]}`))
					want = ErrSelection
				case "artifact-hash-drift", "revocation-hash-drift":
					key := "artifact_trust"
					if name == "revocation-hash-drift" {
						key = "revocation_trust"
					}
					mapping[key].(map[string]any)["sha256"] = strings.Repeat("0", 64)
					want = ErrSelection
				case "runtime-invalid":
					replaceRef(doc["runtime"].(map[string]any), []byte(`null`))
				case "artifact-unsupported":
					replaceRef(mapping["artifact_trust"].(map[string]any), []byte("registry: self\ncross_sign_path: unsupported\n"))
					want = ErrUnsupported
				case "revocation-invalid":
					replaceRef(mapping["revocation_trust"].(map[string]any), []byte("registry: self\npubkey_b64: invalid\n"))
				case "bad-ref-pin":
					doc["runtime"].(map[string]any)["sha256"] = "invalid"
				case "unknown-carrier":
					mapping["carrier"] = map[string]any{"kind": "oci"}
					want = ErrUnsupported
				case "missing-ref":
					doc["runtime"].(map[string]any)["path"] = "missing"
				}
				writeNativePolicyFixture(t, path, doc)
				var p *NativePolicy
				var e error
				if name == "invalid-profile-pin" {
					p, e = LoadNativePinned(path, "INVALID", project, actualHome)
				} else {
					p, e = LoadNative(path, project, actualHome)
				}
				if p != nil || !errors.Is(e, want) {
					t.Fatalf("%s got %v want %v", name, e, want)
				}
			})
		}
	})
	t.Run("nil-and-zero-never-grant", func(t *testing.T) {
		for _, p := range []*NativePolicy{nil, {}} {
			if !errors.Is(artifact.RejectNativeEnterpriseMutation(p.Intent()), artifact.ErrNativeMutationUnavailable) {
				t.Fatal("empty policy granted mutation")
			}
			if !errors.Is(p.ValidateSelection(t.TempDir(), t.TempDir(), "self"), ErrSelection) {
				t.Fatal("empty policy accepted selection")
			}
			if result, e := p.InspectRevocationEvidence([]byte(`{}`)); result != nil || e == nil {
				t.Fatal("empty policy accepted evidence")
			}
		}
		var p *NativePolicy
		if p.ProjectRoot() != "" || p.ArtifactHome() != "" || p.ProfileDigest() != "" || p.HistoryAuthorityID() != "" || p.SelectionID() != "" || p.ArtifactRoots() != nil || p.Runtime().Schema != "" || p.CarrierSelection().Kind != "" {
			t.Fatal("nil policy exposed a selected authority")
		}
	})
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
