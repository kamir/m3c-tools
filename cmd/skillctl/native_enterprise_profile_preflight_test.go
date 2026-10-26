package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

type nativeCLIQAProfile struct {
	project, home, path, pin   string
	artifactKey, revocationKey ed25519.PrivateKey
	requests                   atomic.Int32
}

func nativeCLIQAWrite(t *testing.T, path string, object any) map[string]string {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return map[string]string{"path": path, "sha256": hex.EncodeToString(sum[:])}
}
func nativeCLIQAProfileFixture(t *testing.T) *nativeCLIQAProfile {
	t.Helper()
	f := &nativeCLIQAProfile{project: t.TempDir(), home: t.TempDir()}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.requests.Add(1)
		http.Error(w, "unexpected native carrier request", 500)
	}))
	t.Cleanup(server.Close)
	roots := func(name string) (map[string]string, ed25519.PrivateKey) {
		pk, sk, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		raw := []byte("registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pk) + "\ngovernance_minimum: green\ngovernance_quorum: 1\nsigners:\n  - reviewer_id: qa-reviewer\n    pubkey_b64: " + base64.StdEncoding.EncodeToString(pk) + "\n")
		path := filepath.Join(f.project, name)
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return map[string]string{"path": path, "sha256": hex.EncodeToString(sum[:])}, sk
	}
	artifactRef, ak := roots("artifact.yaml")
	// Keep the legacy root input valid so a removed selected-profile guard reaches
	// the isolated native credential trap instead of failing on a missing file.
	legacyDir := filepath.Join(f.home, ".claude")
	if err := os.MkdirAll(legacyDir, 0700); err != nil {
		t.Fatal(err)
	}
	legacyRaw, err := os.ReadFile(artifactRef["path"])
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(legacyDir, "trust-roots.yaml"), legacyRaw, 0600); err != nil {
		t.Fatal(err)
	}

	revokeRef, rk := roots("revocation.yaml")
	f.artifactKey = ak
	f.revocationKey = rk
	runtimeRef := nativeCLIQAWrite(t, filepath.Join(f.project, "runtime.json"), map[string]any{"schema": "m3c.skillctl.runtime-profile/v1", "project_root": f.project, "tools": []any{}})
	f.path = filepath.Join(f.project, "native.json")
	ref := nativeCLIQAWrite(t, f.path, map[string]any{"schema": "m3c.enterprise-project-profile/v2", "project_root": f.project, "artifact_home": f.home, "runtime": runtimeRef, "native": map[string]any{
		"logical_registry": "self", "authority_scope": "key-and-tenant", "tenant_scope": nil, "artifact_trust": artifactRef, "revocation_trust": revokeRef, "revocation_policy": map[string]any{"minimum_epoch": 1, "max_age_seconds": 86400}, "carrier": map[string]any{"kind": "er1", "base_url": server.URL, "context_id": "qa___skills", "allow_loopback_http": true},
	}})
	f.pin = ref["sha256"]
	if _, err := projectpolicy.LoadNativePinned(f.path, f.pin, f.project, f.home); err != nil {
		t.Fatalf("native fixture must actually select valid role-separated policy: %v", err)
	}
	return f
}
func nativeCLIQAInventory(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if d.IsDir() {
			out[relative] = "dir"
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		out[relative] = hex.EncodeToString(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func nativeCLIQAEnv(home string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "ER1_") || strings.HasPrefix(key, "M3C_") || strings.HasPrefix(key, "SKILLCTL_") || key == "HOME" || key == "USERPROFILE" || key == "SIGNING_KEY_LOCATION" || strings.HasSuffix(strings.ToUpper(key), "_PROXY") {
			continue
		}
		env = append(env, entry)
	}
	// Explicit native selection makes a removed preflight observable through the
	// inherited provider panic trap, rather than hiding a read with file mode.
	values := map[string]string{
		"HOME":              home,
		"USERPROFILE":       home,
		"M3C_TOKEN_STORE":   "keychain",
		"M3C_ER1_KEYCHAIN":  "off",
		"M3C_TEST_KEYCHAIN": "0",
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}
func nativeCLIQAExecute(t *testing.T, binary string, f *nativeCLIQAProfile, args []string) (int, string) {
	t.Helper()
	beforeHome, beforeProject := nativeCLIQAInventory(t, f.home), nativeCLIQAInventory(t, f.project)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = f.project
	command.Env = nativeCLIQAEnv(f.home)
	command.WaitDelay = time.Second
	var out, diagnostic bytes.Buffer
	command.Stdout = &out
	command.Stderr = &diagnostic
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatal("native preflight child timed out")
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	if f.requests.Load() != 0 {
		t.Fatal("native profile reached carrier before unsupported refusal")
	}
	if !reflect.DeepEqual(beforeHome, nativeCLIQAInventory(t, f.home)) || !reflect.DeepEqual(beforeProject, nativeCLIQAInventory(t, f.project)) {
		t.Fatal("native preflight changed persisted fixture inventory")
	}
	return code, out.String() + diagnostic.String()
}
func TestPullNativeEnterpriseProfilePreflightActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	t.Run("signed-diagnostic-no-grant", func(t *testing.T) {
		f := nativeCLIQAProfileFixture(t)
		policy, err := projectpolicy.LoadNativePinned(f.path, f.pin, f.project, f.home)
		if err != nil {
			t.Fatal(err)
		}
		digest := "sha256:" + strings.Repeat("c", 64)
		head, err := registry.BuildRevocationHead(registry.RevocationHeadInput{Epoch: 2, IssuedAt: time.Now().UTC().Add(-time.Minute), Digests: []string{digest}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = registry.SignEnvelopeSignature(f.revocationKey, head); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(map[string]any{"schema": "m3c.native-revocation-evidence/v1", "head": head, "revoked_digests": []string{digest}})
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := policy.InspectRevocationEvidence(raw)
		if err != nil || snapshot == nil {
			t.Fatalf("genuine signed diagnostic rejected: %v", err)
		}
		observation := snapshot.Observation()
		if observation.Epoch != 2 || observation.RevokedCount != 1 || observation.EvidenceDigest == "" {
			t.Fatal("diagnostic lost actual verified observations")
		}
		if _, err = registry.SignEnvelopeSignature(f.artifactKey, head); err != nil {
			t.Fatal(err)
		}
		forged, err := json.Marshal(map[string]any{"schema": "m3c.native-revocation-evidence/v1", "head": head, "revoked_digests": []string{digest}})
		if err != nil {
			t.Fatal(err)
		}
		if result, e := policy.InspectRevocationEvidence(forged); result != nil || !errors.Is(e, registry.ErrNativeEvidenceInvalid) {
			t.Fatalf("artifact role authorized native HEAD: %v", e)
		}
		if _, err = registry.SignEnvelopeSignature(f.revocationKey, head); err != nil {
			t.Fatal(err)
		}
		incomplete, err := json.Marshal(map[string]any{"schema": "m3c.native-revocation-evidence/v1", "head": head, "revoked_digests": []string{}})
		if err != nil {
			t.Fatal(err)
		}
		if result, e := policy.InspectRevocationEvidence(incomplete); result != nil || !errors.Is(e, registry.ErrNativeEvidenceInvalid) {
			t.Fatalf("incomplete fullset accepted: %v", e)
		}

		substituted, err := json.Marshal(map[string]any{"schema": "m3c.native-revocation-evidence/v1", "head": head, "revoked_digests": []string{"sha256:" + strings.Repeat("d", 64)}})
		if err != nil {
			t.Fatal(err)
		}
		if result, e := policy.InspectRevocationEvidence(substituted); result != nil || !errors.Is(e, registry.ErrNativeEvidenceInvalid) {
			t.Fatalf("same-count substituted fullset accepted: %v", e)
		}
		code, text := nativeCLIQAExecute(t, binary, f, []string{"pull", "--enterprise-profile", f.path, "--enterprise-profile-sha256", f.pin, "--home", f.home, "--install", "--trust-mode"})
		if code != 12 || !strings.Contains(text, artifact.ErrNativeMutationUnavailable.Error()) {
			t.Fatalf("valid diagnostic became mutation or wrong refusal: exit%d %s", code, text)
		}
	})
	for _, mode := range []string{"valid", "git-carrier", "unsupported-local-locator", "foreign-registry", "dryrun", "confirm", "empty-profile", "missing-profile", "bad-pin", "pin-without-profile", "home-without-profile", "help", "unknown-kind"} {
		t.Run(mode, func(t *testing.T) {
			f := nativeCLIQAProfileFixture(t)
			args := []string{"pull", "--enterprise-profile", f.path, "--enterprise-profile-sha256", f.pin, "--home", f.home}
			want := 12
			unavailable := true
			switch mode {
			case "git-carrier", "unsupported-local-locator":
				raw, err := os.ReadFile(f.path)
				if err != nil {
					t.Fatal(err)
				}
				var doc map[string]any
				if err = json.Unmarshal(raw, &doc); err != nil {
					t.Fatal(err)
				}
				// Use a platform-independent supported Git selector. Windows drive
				// paths concatenated with local:// are deliberately unsupported.
				locator := "github://example.invalid/owner/repo"
				if mode == "unsupported-local-locator" {
					locator = "local://C:\\fixture\\repository"
					unavailable = false
				}
				doc["native"].(map[string]any)["carrier"] = map[string]any{"kind": "git", "locator": locator}
				ref := nativeCLIQAWrite(t, f.path, doc)
				args[4] = ref["sha256"]
				args = append(args, "--registry", locator)
				policy, selectedErr := projectpolicy.LoadNativePinned(f.path, ref["sha256"], f.project, f.home)
				if mode == "git-carrier" {
					if selectedErr != nil || policy == nil || policy.CarrierSelection().Locator != locator || policy.ValidateSelection(f.project, f.home, locator) != nil {
						t.Fatalf("Git fixture must select valid native policy before CLI denial: %v", selectedErr)
					}
				} else if policy != nil || !errors.Is(selectedErr, projectpolicy.ErrUnsupported) {
					t.Fatalf("unsupported local locator was accepted: %v", selectedErr)
				}
			case "foreign-registry":
				args = append(args, "--registry", "er1://foreign.invalid")
				unavailable = false
			case "dryrun":
				args = append(args, "--dry-run-install")
			case "confirm":
				args = append(args, "--confirm-install", "--dry-run-install-token", "not-a-token")
			case "empty-profile":
				args = []string{"pull", "--enterprise-profile="}
				unavailable = false
			case "missing-profile":
				args[2] = filepath.Join(f.project, "absent")
				unavailable = false
			case "bad-pin":
				args[4] = strings.Repeat("0", 64)
				unavailable = false
			case "pin-without-profile":
				args = []string{"pull", "--enterprise-profile-sha256", f.pin}
				want = 2
				unavailable = false
			case "home-without-profile":
				args = []string{"pull", "--home", f.home}
				want = 2
				unavailable = false
			case "help":
				args = append(args, "--help")
				want = 2
				unavailable = false
			case "unknown-kind":
				args = append(args, "--kind", "unknown")
				want = 2
				unavailable = false
			}
			code, text := nativeCLIQAExecute(t, binary, f, args)
			if code != want {
				t.Fatalf("preflight exit%d want%d: %s", code, want, text)
			}
			if unavailable != strings.Contains(text, artifact.ErrNativeMutationUnavailable.Error()) {
				t.Fatalf("wrong native preflight classification: %s", text)
			}
		})
	}
}
func TestPublishNativeEnterpriseProfilePreflightActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	for _, mode := range []string{"admit", "all", "attest", "revoke", "dryrun", "empty-profile", "pin-without-profile", "help", "missing-identity"} {
		t.Run(mode, func(t *testing.T) {
			f := nativeCLIQAProfileFixture(t)
			args := []string{"publish", "fixture@1.0.0", "--identity", "id:qa@synthetic", "--enterprise-profile", f.path, "--enterprise-profile-sha256", f.pin, "--home", f.home, "--key", filepath.Join(f.project, "must-not-open.key")}
			want := 12
			unavailable := true
			switch mode {
			case "all":
				args = append(args, "--all", "--manifest", filepath.Join(f.project, "must-not-open.manifest"))
			case "attest":
				args = append(args, "--attest", "--rationale", "synthetic")
			case "revoke":
				args = append(args, "--revoke", "--digest", "sha256:"+strings.Repeat("a", 64), "--reason", "deprecated")
			case "dryrun":
				args = append(args, "--dry-run")
			case "empty-profile":
				args = []string{"publish", "fixture", "--identity", "id:qa@synthetic", "--enterprise-profile="}
				unavailable = false
			case "pin-without-profile":
				args = []string{"publish", "fixture", "--identity", "id:qa@synthetic", "--enterprise-profile-sha256", f.pin}
				want = 2
				unavailable = false
			case "help":
				args = append(args, "--help")
				want = 2
				unavailable = false
			case "missing-identity":
				args = []string{"publish", "fixture", "--enterprise-profile", f.path}
				want = 2
				unavailable = false
			}
			code, text := nativeCLIQAExecute(t, binary, f, args)
			if code != want {
				t.Fatalf("publish preflight exit%d want%d: %s", code, want, text)
			}
			if unavailable != strings.Contains(text, artifact.ErrNativeMutationUnavailable.Error()) {
				t.Fatalf("wrong publish preflight classification: %s", text)
			}
		})
	}
}
