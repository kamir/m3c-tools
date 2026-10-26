package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	_ "github.com/kamir/m3c-tools/pkg/skillctl/backend/git"
	_ "github.com/kamir/m3c-tools/pkg/skillctl/backend/oci"
)

type nativeQACredentials struct{ calls atomic.Int32 }

func (c *nativeQACredentials) Credential(context.Context, string, string, artifact.AccessMode) (artifact.Credential, error) {
	c.calls.Add(1)
	return artifact.Credential{}, nil
}

func nativeQAInventory(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if d.IsDir() {
			out[rel] = "dir"
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		out[rel] = hex.EncodeToString(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNativeEnterpriseProfileEarlyDenial(t *testing.T) {
	f := qaAgentSigned(t, nil)
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ER1_DEVICE_TOKEN", hex.EncodeToString(random))
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	var requests, posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == http.MethodPost {
			posts.Add(1)
			if err := json.NewEncoder(w).Encode(map[string]any{"doc_id": "native-qa-result", "message": "ok"}); err != nil {
				t.Error(err)
			}
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"items": []any{}, "memories": []any{}}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	cfg := &er1.Config{APIURL: server.URL + "/upload_2", VerifySSL: false, ContextID: "skills", UploadTimeout: 5}
	digest := f.staged.Digest
	revoked, err := BuildBundleRevokedEvent(RevokedEventInput{BundleDigest: digest, RevokedBy: "qa-native", ReasonCode: "deprecated", OccurredAt: f.now})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := BuildBundleInstalledEvent(InstalledEventInput{BundleDigest: digest, Name: f.name, Version: "1.0.0", InstalledOnHost: "qa-synthetic", InstalledAt: f.now, Registry: "self", TrustRootsFingerprint: f.roots.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []map[string]any{revoked, installed} {
		if _, err = SignEnvelopeSignature(f.registryKey, ev); err != nil {
			t.Fatal(err)
		}
	}
	skill := SkillMeta{Name: f.name, Version: "1.0.0", BundleDigest: digest, AuthorIdentity: "id:qa@synthetic", GovernanceLevel: "green", PackedOnHost: "qa-synthetic"}
	signedIntent, err := artifact.NewNativeEnterpriseIntent(strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	publish := func(kind string, intent *artifact.NativeEnterpriseIntent) error {
		switch kind {
		case "admit":
			_, e := PublishAdmitted(PublishAdmittedOpts{NativeEnterpriseIntent: intent, ER1Cfg: cfg, ContextID: "skills", Event: f.staged.Attestation.AdmitEvent, Skill: skill, SkbBytes: f.blob, InlineMaxBytes: 1 << 20, Now: f.now})
			return e
		case "attest":
			_, e := PublishAttested(PublishAttestedOpts{NativeEnterpriseIntent: intent, ER1Cfg: cfg, ContextID: "skills", Event: f.attest[0], Skill: skill, Now: f.now})
			return e
		case "revoke":
			_, e := PublishRevoked(PublishRevokedOpts{NativeEnterpriseIntent: intent, ER1Cfg: cfg, ContextID: "skills", Event: revoked, Skill: skill, Now: f.now})
			return e
		case "installed":
			_, e := PublishInstalled(PublishInstalledOpts{NativeEnterpriseIntent: intent, ER1Cfg: cfg, ContextID: "skills", Event: installed, Skill: skill, InstalledOnHost: "qa-synthetic", Now: f.now})
			return e
		default:
			t.Fatal("unknown fixture operation")
			return nil
		}
	}
	for _, tc := range []struct {
		name   string
		intent *artifact.NativeEnterpriseIntent
	}{{"allocated-zero", &artifact.NativeEnterpriseIntent{}}, {"constructed", signedIntent}} {
		t.Run(tc.name, func(t *testing.T) {
			before := nativeQAInventory(t, os.Getenv("HOME"))
			opts := f.opts()
			opts.NativeEnterpriseIntent = tc.intent
			result, e := ConfirmInstall([]*StagedBundle{f.staged}, "invalid-consent-token", opts)
			if !errors.Is(e, artifact.ErrNativeMutationUnavailable) || len(result) != 0 {
				t.Fatalf("selected signed SDK install not refused before consent: %v", e)
			}
			if _, e = ConfirmInstall(nil, "", opts); !errors.Is(e, artifact.ErrNativeMutationUnavailable) {
				t.Fatalf("intent lost before ordinary input validation: %v", e)
			}
			for _, kind := range []string{"admit", "attest", "revoke", "installed"} {
				if e = publish(kind, tc.intent); !errors.Is(e, artifact.ErrNativeMutationUnavailable) {
					t.Fatalf("selected signed SDK %s returned wrong refusal: %v", kind, e)
				}
			}
			credentials := &nativeQACredentials{}
			for _, spec := range []string{"github://invalid.example/qa/repository", "gitlab://invalid.example/qa/repository", "oci://invalid.example/qa/repository", "local:///missing-native-fixture", "self"} {
				backend, e := artifact.Open(spec, artifact.OpenOptions{NativeEnterpriseIntent: tc.intent, Creds: credentials})
				if backend != nil || !errors.Is(e, artifact.ErrNativeMutationUnavailable) {
					t.Fatalf("factory intent not refused: %v", e)
				}
			}
			if credentials.calls.Load() != 0 || requests.Load() != 0 {
				t.Fatal("selected intent reached credential or HTTP source")
			}
			if after := nativeQAInventory(t, os.Getenv("HOME")); !reflect.DeepEqual(before, after) {
				t.Fatal("selected intent changed persisted fixture inventory")
			}
		})
	}
	t.Run("already-open-backends", func(t *testing.T) {
		for _, spec := range []string{"github://invalid.example/qa/repository", "gitlab://invalid.example/qa/repository", "oci://invalid.example/qa/repository"} {
			credentials := &nativeQACredentials{}
			backend, e := artifact.Open(spec, artifact.OpenOptions{Creds: credentials})
			if e != nil {
				t.Fatal(e)
			}
			initial := credentials.calls.Load()
			// Incomplete legacy payload must not hide explicit selected intent.
			result, e := backend.Publish(context.Background(), artifact.PublishRequest{NativeEnterpriseIntent: signedIntent})
			if result != nil || !errors.Is(e, artifact.ErrNativeMutationUnavailable) {
				t.Errorf("already-open backend bypassed intent: %v", e)
			}
			if credentials.calls.Load() != initial {
				t.Error("selected publish reselected credentials")
			}
			if e = backend.Close(); e != nil {
				t.Fatal(e)
			}
		}
		backend := NewER1Backend(cfg, "skills")
		result, e := backend.Publish(context.Background(), artifact.PublishRequest{NativeEnterpriseIntent: signedIntent, Kind: artifact.KindAdmit, Event: f.staged.Attestation.AdmitEvent, Blob: f.blob, Meta: artifact.ArtifactMeta{Name: f.name, Version: "1.0.0", Digest: digest}})
		if result != nil || !errors.Is(e, artifact.ErrNativeMutationUnavailable) || requests.Load() != 0 {
			t.Fatalf("already-open ER1 publish reached source: %v", e)
		}
	})
	t.Run("unselected-signed-controls", func(t *testing.T) {
		for _, kind := range []string{"admit", "attest", "revoke", "installed"} {
			if e := publish(kind, nil); e != nil {
				t.Fatalf("signed legacy %s failed: %v", kind, e)
			}
		}
		if posts.Load() != 4 || requests.Load() < 4 {
			t.Fatal("legacy positive did not actually publish all four signed events")
		}
		results, e := f.confirm(t, f.opts())
		if e != nil || len(results) != 1 {
			t.Fatalf("unselected signed agent retention failed: %v", e)
		}
		qaAgentVerifyRecord(t, f)
	})
}
