package install

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

const registryDependencyID = "id:dependency@m3c"

type registryIdentityFixture struct {
	home          string
	root, leaf    *bundleFixture
	policy        *projectpolicy.Policy
	client        *registry.Client
	server        *httptest.Server
	meta          *registry.BundleMeta
	mu            sync.Mutex
	mode          string
	calls         map[string]int
	rootResponse  bool
	rootOnly      bool
	expectedToken string
	wrongAuth     int
}

func newRegistryIdentityFixture(t *testing.T) *registryIdentityFixture {
	t.Helper()
	home := snapshotTestHome(t)
	keys := mkBundleFixture(t)
	f := &registryIdentityFixture{home: home, root: installedDependencyBundle(t, keys, "fetch-contract", "1.0.0", `,"depends_on":[{"kind":"skill","name":"required","constraint":">=1.0.0"}]`), leaf: installedDependencyBundle(t, keys, "required", "1.0.0", ""), calls: map[string]int{}}
	f.meta = sidecarMeta(t, f.root, "fetch-contract")
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/identities/") {
			id := strings.TrimPrefix(r.URL.Path, "/api/skills/identities/")
			f.mu.Lock()
			f.calls[id]++
			if f.expectedToken != "" && r.Header.Get("Authorization") != "Bearer "+f.expectedToken {
				f.wrongAuth++
			}
			mode := f.mode
			applies := (id == registryDependencyID && !f.rootOnly) || (f.rootResponse && id != registryDependencyID)
			f.mu.Unlock()
			if !applies {
				mode = ""
			}
			key := base64.StdEncoding.EncodeToString(keys.authorPub)
			body := map[string]any{"id": id, "pubkey_b64": key, "auth_source": "manual"}
			switch mode {
			case "foreign-id":
				body["id"] = "id:foreign@m3c"
			case "key-drift":
				body["pubkey_b64"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
			case "revoked":
				body["revoked_at"] = "2026-01-01T00:00:00Z"
			case "blank-auth":
				body["auth_source"] = ""
			case "missing":
				http.NotFound(w, r)
				return
			case "unauthorized":
				w.WriteHeader(401)
				_, _ = io.WriteString(w, "synthetic reflected token")
				return
			case "duplicate":
				_, _ = io.WriteString(w, `{"id":"`+id+`","id":"`+id+`","pubkey_b64":"`+key+`","auth_source":"manual"}`)
				return
			case "alias":
				body["ID"] = id
			case "trailing":
				_, _ = io.WriteString(w, `{"id":"`+id+`","pubkey_b64":"`+key+`","auth_source":"manual"} {}`)
				return
			case "conflicting-keys":
				body["pubkey"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
			case "oversize":
				body["extra"] = strings.Repeat("x", int(registry.IdentityResponseBytes))
			case "redirect":
				w.Header().Set("Location", r.URL.Query().Get("unused"))
				w.WriteHeader(302)
				return
			}
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		if strings.Contains(r.URL.Path, "/by-name/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"versions": []registry.BundleVersion{{Version: "1.0.0", Digest: f.root.digestStr, Status: "admitted"}}})
			return
		}
		if strings.Contains(r.URL.Path, "/bundles/") {
			if r.URL.Query().Get("meta") == "1" {
				_ = json.NewEncoder(w).Encode(f.meta)
			} else {
				_, _ = w.Write(f.root.blob)
			}
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.server.Close)
	root := projectManagedRoot(t, keys)
	root.RegistryURL = f.server.URL + "/api/skills"
	root.IdentityKeysAuthorized = "from-registry"
	root.Authors = nil
	f.policy = installProjectProfile(t, home, root)
	enrollProject(t, home, f.policy.TrustRoot(), keys)
	dir := installedDependencyTree(t, home, f.leaf, "required", "1.0.0")
	p := filepath.Join(dir, offlineMetaFile)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var stash OfflineMeta
	if err = json.Unmarshal(raw, &stash); err != nil {
		t.Fatal(err)
	}
	stash.BundleMeta.Signatures[0].IdentityID = registryDependencyID
	stash.Identities = map[string]*registry.Identity{registryDependencyID: {ID: "id:forged-stash@m3c", PubkeyB64: base64.StdEncoding.EncodeToString(make([]byte, 32)), AuthSource: "forged"}}
	raw, err = json.Marshal(stash)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.client = registry.New(root.RegistryURL, f.server.Client())
	return f
}
func (f *registryIdentityFixture) setMode(mode string) { f.mu.Lock(); f.mode = mode; f.mu.Unlock() }
func (f *registryIdentityFixture) count(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[id]
}
func (f *registryIdentityFixture) install(logger io.Writer) (*Result, error) {
	return Install(Opts{Name: "fetch-contract", Client: f.client, TrustRoot: f.policy.TrustRoot(), ProjectPolicy: f.policy, HomeDir: f.home, Logger: logger})
}
func TestProjectRegistryIdentitySnapshot(t *testing.T) {
	t.Run("stash-cannot-repair-rejected-live-key", func(t *testing.T) {
		f := newRegistryIdentityFixture(t)
		f.setMode("key-drift")
		p := filepath.Join(f.home, installRoot, "required", offlineMetaFile)
		raw, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		var stash OfflineMeta
		if e = json.Unmarshal(raw, &stash); e != nil {
			t.Fatal(e)
		}
		stash.Identities = map[string]*registry.Identity{registryDependencyID: {ID: registryDependencyID, PubkeyB64: base64.StdEncoding.EncodeToString(f.leaf.authorPub), AuthSource: "manual"}}
		raw, e = json.Marshal(stash)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(p, raw, 0600); e != nil {
			t.Fatal(e)
		}
		old := installedDependencyOldTarget(t, f.home)
		r, e := f.install(nil)
		if !errors.Is(e, verify.ErrDepsUnsatisfied) || r != nil {
			t.Fatalf("unsigned stash repaired invalid live identity: %v", e)
		}
		assertInstalledDependencyOldTarget(t, old)
	})

	t.Run("adopt-before-later-identity-denial", func(t *testing.T) {
		f := newRegistryIdentityFixture(t)
		f.setMode("foreign-id")
		old := installedDependencyOldTarget(t, f.home)
		r, e := Install(Opts{Name: "fetch-contract", Client: f.client, TrustRoot: f.policy.TrustRoot(), ProjectPolicy: f.policy, HomeDir: f.home, MutationEvidence: managedLibraryList(t, f.root, f.policy.TrustRoot(), time.Now().Add(-30*time.Minute), 2, false)})
		status, statusErr := managedLibraryStore(t, f.home, f.policy.TrustRoot()).Status(context.Background())
		if !errors.Is(e, verify.ErrDepsUnsatisfied) || r != nil || statusErr != nil || status.Epoch != 2 {
			t.Fatalf("later dependency denial lost adopted floor: %v %+v %v", e, status, statusErr)
		}
		assertInstalledDependencyOldTarget(t, old)
	})
	t.Run("invalid-selected-base-before-requests", func(t *testing.T) {
		f := newRegistryIdentityFixture(t)
		f.client.BaseURL = "https://foreign.invalid/api/skills"
		f.client.HTTPClient = &http.Client{Transport: registryIdentityForbiddenTransport{t: t}}
		r, e := f.install(nil)
		if !errors.Is(e, verify.ErrRegistryNotTrusted) || r != nil {
			t.Fatalf("foreign selected base not refused: %v", e)
		}
		if f.count("id:author@m3c")+f.count(registryDependencyID) != 0 {
			t.Fatal("invalid origin read identity")
		}
	})

	t.Run("live-proof-ignores-forged-stash", func(t *testing.T) {
		f := newRegistryIdentityFixture(t)
		r, e := f.install(nil)
		if e != nil || r == nil {
			t.Fatalf("signed live proof: %v", e)
		}
		if f.count(registryDependencyID) != 2 {
			t.Fatalf("dependency not fetched once in each phase: %d", f.count(registryDependencyID))
		}
		if r.Verify.GovernanceVerified {
			t.Fatal("unsigned advisory governance relabeled authenticated")
		}
	})
	for _, mode := range []string{"foreign-id", "key-drift", "revoked", "blank-auth", "missing", "unauthorized", "duplicate", "alias", "trailing", "conflicting-keys", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegistryIdentityFixture(t)
			f.setMode(mode)
			old := installedDependencyOldTarget(t, f.home)
			r, e := f.install(nil)
			if !errors.Is(e, verify.ErrDepsUnsatisfied) || r != nil {
				t.Fatalf("unusable live proof accepted: %v", e)
			}
			assertInstalledDependencyOldTarget(t, old)
			if strings.Contains(e.Error(), "synthetic reflected token") {
				t.Fatal("remote identity body reflected in dependency error")
			}
			if f.count(registryDependencyID) != 1 {
				t.Fatalf("failed phase retried or bypassed lookup: %d", f.count(registryDependencyID))
			}
		})
	}
	t.Run("root-foreign-id-same-key", func(t *testing.T) {
		f := newRegistryIdentityFixture(t)
		f.mu.Lock()
		f.rootResponse = true
		f.mode = "foreign-id"
		f.mu.Unlock()
		r, e := f.install(nil)
		if !errors.Is(e, verify.ErrAuthorSigInvalid) || r != nil {
			t.Fatalf("root mismatched ID accepted: %v", e)
		}
		if f.count(registryDependencyID) != 0 {
			t.Fatal("root denial proceeded to dependencies")
		}
	})
	t.Run("frozen-reader", func(t *testing.T) {
		f := newRegistryIdentityFixture(t)
		f.client.Token = "synthetic-bound-token"
		f.expectedToken = "synthetic-bound-token"
		reader, e := registry.NewBoundIdentityReader(f.client, f.policy.RegistryURL(), true)
		if e != nil {
			t.Fatal(e)
		}
		defer reader.Close()
		f.client.BaseURL = "https://foreign.invalid"
		f.client.Token = "changed-token"
		f.client.HTTPClient = &http.Client{Transport: registryIdentityForbiddenTransport{t: t}}
		t.Setenv("ER1_DEVICE_TOKEN", "ambient-changed")
		id, e := reader.NewPhase().GetIdentity(context.Background(), registryDependencyID)
		if e != nil || id == nil || id.ID != registryDependencyID || f.count(registryDependencyID) != 1 {
			t.Fatalf("reader did not retain authority: %v", e)
		}
		f.mu.Lock()
		wrong := f.wrongAuth
		f.mu.Unlock()
		if wrong != 0 {
			t.Fatalf("reader changed snapshotted token: %d", wrong)
		}
	})
}

type registryIdentityForbiddenTransport struct{ t *testing.T }

func (r registryIdentityForbiddenTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("mutated client transport used")
	return nil, errors.New("forbidden transport")
}
func TestProjectRegistryIdentityFinalRecheck(t *testing.T) {
	for _, shared := range []bool{false, true} {
		for _, mode := range []string{"valid", "key-drift", "revoked"} {
			name := "root-" + mode
			if shared {
				name = "shared-author-" + name
			}
			t.Run(name, func(t *testing.T) {
				f := newRegistryIdentityFixture(t)
				if shared {
					p := filepath.Join(f.home, installRoot, "required", offlineMetaFile)
					raw, e := os.ReadFile(p)
					if e != nil {
						t.Fatal(e)
					}
					var stash OfflineMeta
					if e = json.Unmarshal(raw, &stash); e != nil {
						t.Fatal(e)
					}
					stash.BundleMeta.Signatures[0].IdentityID = "id:author@m3c"
					raw, e = json.Marshal(stash)
					if e != nil {
						t.Fatal(e)
					}
					if e = os.WriteFile(p, raw, 0600); e != nil {
						t.Fatal(e)
					}
				}
				old := installedDependencyOldTarget(t, f.home)
				logger := &projectMutationLogger{mutate: func() { f.mu.Lock(); f.mode = mode; f.rootResponse = true; f.rootOnly = !shared; f.mu.Unlock() }}
				result, err := f.install(logger)
				if !logger.once {
					t.Fatal("final root mutation point not reached")
				}
				if mode == "valid" {
					if err != nil || result == nil {
						t.Fatalf("unchanged fresh root identity: %v", err)
					}
				} else {
					want := verify.ErrAuthorSigInvalid
					if mode == "revoked" {
						want = verify.ErrIdentityRevoked
					}
					if !errors.Is(err, want) || verify.ExitCode(err) != verify.ExitCode(want) || result != nil {
						t.Fatalf("root final classification masked: %v exit=%d", err, verify.ExitCode(err))
					}
					assertInstalledDependencyOldTarget(t, old)
				}
				wantCalls := 2
				if shared {
					wantCalls = 3
				}
				if f.count("id:author@m3c") != wantCalls {
					t.Fatalf("fresh root phase cache count=%d want=%d", f.count("id:author@m3c"), wantCalls)
				}
			})
		}
	}

	for _, mode := range []string{"key-drift", "revoked", "missing"} {
		t.Run("dependency-"+mode, func(t *testing.T) {
			f := newRegistryIdentityFixture(t)
			old := installedDependencyOldTarget(t, f.home)
			logger := &projectMutationLogger{mutate: func() { f.setMode(mode) }}
			r, e := f.install(logger)
			if !logger.once || !errors.Is(e, verify.ErrDepsUnsatisfied) || r != nil {
				t.Fatalf("final fresh lookup did not deny: %v", e)
			}
			if f.count(registryDependencyID) != 2 {
				t.Fatalf("final identity lookup not observed: %d", f.count(registryDependencyID))
			}
			assertInstalledDependencyOldTarget(t, old)
		})
	}
	t.Run("local-capability-absent", func(t *testing.T) {
		f := newRegistryIdentityFixture(t)
		r, e := InstallBundle(BundleOpts{ProjectPolicy: f.policy, TrustRoot: f.policy.TrustRoot(), HomeDir: f.home, BundlePath: writeBundle(t, f.root), Meta: f.meta})
		if e == nil || verify.ExitCode(e) != 1 || r != nil {
			t.Fatalf("offline from-registry missing-fetcher configuration classification: %v", e)
		}
		source := newInstalledSkillSource(f.policy)
		defer func() {
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
		}()
		candidates, sourceErr := source.Candidates(context.Background(), "skill", "required")
		if !errors.Is(sourceErr, verify.ErrDepsUnsatisfied) || len(candidates) != 0 {
			t.Fatalf("offline dependency capability classification: %v", sourceErr)
		}
		if f.count("id:author@m3c")+f.count(registryDependencyID) != 0 {
			t.Fatal("local route fetched hidden identity")
		}
	})
	t.Run("pinned-no-lookup", func(t *testing.T) {
		f := newRegistryIdentityFixture(t)
		f.home = snapshotTestHome(t)
		root := projectManagedRoot(t, f.root)
		root.RegistryURL = f.server.URL + "/api/skills"
		f.policy = installProjectProfile(t, f.home, root)
		enrollProject(t, f.home, f.policy.TrustRoot(), f.root)
		dir := filepath.Join(f.home, installRoot, "required")
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		installedDependencyTree(t, f.home, f.leaf, "required", "1.0.0")
		r, e := f.install(nil)
		if e != nil || r == nil {
			t.Fatalf("pinned route: %v", e)
		}
		if f.count("id:author@m3c")+f.count(registryDependencyID) != 0 {
			t.Fatal("pinned route fetched identity")
		}
	})
}
func TestRegistryIdentityGovernancePolicy(t *testing.T) {
	for _, mode := range []string{"advisory", "signed", "unsigned-green", "self-review"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegistryIdentityFixture(t)
			pub, priv, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			root := f.policy.TrustRoot()
			if mode != "advisory" {
				root.RequireSignedGovernance = true
				root.RequireIndependentReview = true
				root.Reviewers = []verify.AuthorKey{{ID: "id:reviewer@m3c", Pubkey: pub, PubkeyB64: base64.StdEncoding.EncodeToString(pub)}}
			}
			if mode == "signed" || mode == "self-review" {
				id := "id:reviewer@m3c"
				if mode == "self-review" {
					id = "id:author@m3c"
					root.Reviewers[0].ID = id
				}
				when := time.Now().UTC().Format(time.RFC3339)
				msg, e := signing.CanonicalizeAttestationMessage(f.root.digestStr, "green", when, id)
				if e != nil {
					t.Fatal(e)
				}
				f.meta.Attestations = []registry.AttestationRow{{ReviewerID: id, Level: "green", AttestedAt: when, SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), Status: "active"}}
			}

			f.home = snapshotTestHome(t)
			f.policy = installProjectProfile(t, f.home, root)
			enrollProject(t, f.home, f.policy.TrustRoot(), f.root)
			dir := installedDependencyTree(t, f.home, f.leaf, "required", "1.0.0")
			path := filepath.Join(dir, offlineMetaFile)
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			var stash OfflineMeta
			if e = json.Unmarshal(raw, &stash); e != nil {
				t.Fatal(e)
			}
			stash.BundleMeta.Signatures[0].IdentityID = registryDependencyID
			if mode == "signed" {
				when := time.Now().UTC().Format(time.RFC3339)
				msg, e := signing.CanonicalizeAttestationMessage(f.leaf.digestStr, "green", when, "id:reviewer@m3c")
				if e != nil {
					t.Fatal(e)
				}
				stash.BundleMeta.Attestations = []registry.AttestationRow{{ReviewerID: "id:reviewer@m3c", Level: "green", AttestedAt: when, SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), Status: "active"}}
			}
			raw, e = json.Marshal(stash)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			result, e := f.install(nil)
			if mode == "advisory" || mode == "signed" {
				if e != nil || result == nil {
					t.Fatalf("actual configured governance positive: %v", e)
				}
				if result.Verify.GovernanceVerified != (mode == "signed") {
					t.Fatal("governance provenance incorrect")
				}
			} else {
				want := verify.ErrGovernanceBelowMin
				if mode == "self-review" {
					want = verify.ErrSelfAttested
				}
				if !errors.Is(e, want) || result != nil {
					t.Fatalf("identity lookup bypassed governance floor: %v", e)
				}
			}

		})
	}
}
