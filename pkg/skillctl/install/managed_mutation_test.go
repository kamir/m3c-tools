package install

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/mutationstate"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func managedLibraryList(t *testing.T, fx *bundleFixture, root *verify.TrustRoot, issued time.Time, epoch int, revoked bool) []byte {
	t.Helper()
	var digests []string
	if revoked {
		digests = []string{fx.digestStr}
	}
	list, err := verify.NewSignedRevocationList(root.RegistryURL, issued.UTC().Format(time.RFC3339Nano), epoch, digests, fx.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func managedLibraryStore(t *testing.T, home string, root *verify.TrustRoot) *mutationstate.Store {
	t.Helper()
	store, err := mutationstate.New(filepath.Join(home, ".claude", "mutation-state"), root)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// A previous legitimate signed record can age on disk. Retain its real root
// fingerprint while replacing the evidence with an older, genuinely signed list.
func ageManagedLibraryRecord(t *testing.T, home string, raw []byte) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(home, ".claude", "mutation-state", "*", "record.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("record paths=%v err=%v", paths, err)
	}
	body, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	var list verify.RevocationList
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	record["full_list"] = base64.StdEncoding.EncodeToString(raw)
	record["evidence_fingerprint"] = hex.EncodeToString(sum[:])
	record["issued_at"] = list.IssuedAt
	record["last_seen"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	record["epoch"] = list.Epoch
	body, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[0], body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestManagedInstallLibraryMandatoryHistory(t *testing.T) {
	for _, route := range []string{"bundle", "registry"} {
		for _, state := range []string{"missing", "lost", "stale", "revoked", "fresh"} {
			t.Run(route+"/"+state, func(t *testing.T) {
				home := snapshotTestHome(t)
				t.Setenv("M3C_ER1_KEYCHAIN", "off")
				fx := mkBundleFixture(t)
				root := pinnedRoot(t, fx)
				srv, fr := newFakeRegistry(t)
				defer srv.Close()
				fillRegistry(t, fr, fx, "green")
				if route == "registry" {
					root = mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")
				}
				root.OfflinePolicy = &verify.OfflinePolicyBlock{Enterprise: true}
				store := managedLibraryStore(t, home, root)
				if state != "missing" {
					raw := managedLibraryList(t, fx, root, time.Now().Add(-time.Hour), 1, state == "revoked")
					if _, err := store.Enroll(context.Background(), raw); err != nil {
						t.Fatal(err)
					}
					if state == "lost" {
						paths, _ := filepath.Glob(filepath.Join(home, ".claude", "mutation-state", "*", "record.json"))
						if len(paths) != 1 {
							t.Fatal("enrollment record missing")
						}
						if err := os.Remove(paths[0]); err != nil {
							t.Fatal(err)
						}
					}
					if state == "stale" {
						ageManagedLibraryRecord(t, home, managedLibraryList(t, fx, root, time.Now().Add(-48*time.Hour), 1, false))
						if status, err := store.Status(context.Background()); err != nil || status.Epoch != 1 {
							t.Fatalf("aged signed record must remain structurally valid: %+v %v", status, err)
						}
					}
				}
				var result *Result
				var err error
				// No optional PostVerify callback is supplied in either public library path.
				if route == "bundle" {
					result, err = InstallBundle(BundleOpts{BundlePath: writeBundle(t, fx), Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home})
				} else {
					result, err = Install(Opts{Name: "fetch-contract", Client: registry.New(srv.URL+"/api/skills", srv.Client()), TrustRoot: root, HomeDir: home})
				}
				want := 22
				if state == "fresh" {
					want = 0
				}
				if state == "revoked" {
					want = 17
				}
				if state == "stale" && (!errors.Is(err, verify.ErrRevocationStale) || errors.Is(err, mutationstate.ErrInvalidState)) {
					t.Fatalf("stale evidence did not fail causally on freshness: %v", err)
				}
				if verify.ExitCode(err) != want {
					t.Fatalf("exit=%d want=%d err=%v", verify.ExitCode(err), want, err)
				}
				target := filepath.Join(home, installRoot, "fetch-contract")
				if want == 0 {
					if result == nil {
						t.Fatal("success missing result")
					}
					if _, err := os.Stat(filepath.Join(target, "SKILL.md")); err != nil {
						t.Fatal(err)
					}
				} else {
					if result != nil {
						t.Fatal("denial returned result")
					}
					if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("denial published target: %v", err)
					}
				}
				if state == "missing" {
					if _, err := store.Status(context.Background()); !errors.Is(err, mutationstate.ErrNotEnrolled) {
						t.Fatalf("install auto-enrolled: %v", err)
					}
				}
			})
		}
	}
}

func TestManagedInstallLibraryLearnsBeforeCallerDenial(t *testing.T) {
	home := snapshotTestHome(t)
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	fx := mkBundleFixture(t)
	root := pinnedRoot(t, fx)
	root.OfflinePolicy = &verify.OfflinePolicyBlock{Enterprise: true}
	store := managedLibraryStore(t, home, root)
	old := managedLibraryList(t, fx, root, time.Now().Add(-2*time.Hour), 1, false)
	newer := managedLibraryList(t, fx, root, time.Now().Add(-time.Hour), 2, false)
	if _, err := store.Enroll(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	denied := errors.New("synthetic caller refusal")
	calls := 0
	_, err := InstallBundle(BundleOpts{BundlePath: writeBundle(t, fx), Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home, MutationEvidence: newer, PostVerify: func(*verify.VerifyResult) error { calls++; return denied }})
	if !errors.Is(err, denied) || calls != 1 {
		t.Fatalf("callback denial=%v calls=%d", err, calls)
	}
	status, err := store.Status(context.Background())
	if err != nil || status.Epoch != 2 {
		t.Fatalf("new floor lost: %+v %v", status, err)
	}
	_, err = InstallBundle(BundleOpts{BundlePath: writeBundle(t, fx), Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home, MutationEvidence: old})
	if verify.ExitCode(err) != 22 {
		t.Fatalf("rollback not denied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, installRoot, "fetch-contract")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("denial published target: %v", err)
	}
}

func TestInstallStagingSameDigestAttemptsIndependent(t *testing.T) {
	home := snapshotTestHome(t)
	fx := mkBundleFixture(t)
	first, err := makeStagingDir(home, "fetch-contract", fx.digestStr)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(first, "verified.skb")
	if err := os.WriteFile(marker, fx.blob, 0600); err != nil {
		t.Fatal(err)
	}
	second, err := makeStagingDir(home, "fetch-contract", fx.digestStr)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("same-digest attempts share a staging directory")
	}
	if err := os.RemoveAll(second); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != string(fx.blob) {
		t.Fatalf("second attempt removed first snapshot: %v", err)
	}
}

func TestInstallLibraryMutationEvidenceSizeBeforeOtherInputs(t *testing.T) {
	for _, route := range []string{"bundle", "registry"} {
		t.Run(route, func(t *testing.T) {
			home := snapshotTestHome(t)
			t.Setenv("M3C_ER1_KEYCHAIN", "off")
			raw := make([]byte, mutationstate.MaxEvidenceBytes+1)
			var result *Result
			var err error
			// All other required inputs deliberately remain absent. Size enforcement
			// must precede metadata checks, target lookup and copying caller evidence.
			if route == "bundle" {
				result, err = InstallBundle(BundleOpts{HomeDir: home, MutationEvidence: raw})
			} else {
				result, err = Install(Opts{HomeDir: home, MutationEvidence: raw})
			}
			if result != nil || verify.ExitCode(err) != 12 || !errors.Is(err, verify.ErrRegistryNotTrusted) {
				t.Fatalf("oversize evidence did not fail first: result=%+v error=%v", result, err)
			}
			entries, readErr := os.ReadDir(home)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("early refusal created filesystem state: entries=%v error=%v", entries, readErr)
			}
		})
	}
}

func TestInstallLibraryUnmanagedExplicitEvidenceRefused(t *testing.T) {
	for _, route := range []string{"bundle", "registry"} {
		t.Run(route, func(t *testing.T) {
			home := snapshotTestHome(t)
			t.Setenv("M3C_ER1_KEYCHAIN", "off")
			fx := mkBundleFixture(t)
			root := pinnedRoot(t, fx)
			srv, fr := newFakeRegistry(t)
			defer srv.Close()
			fillRegistry(t, fr, fx, "green")
			if route == "registry" {
				root = mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")
			}
			if root.IsManaged() {
				t.Fatal("fixture must remain unmanaged")
			}
			raw := managedLibraryList(t, fx, root, time.Now().Add(-time.Hour), 1, false)
			var signed verify.RevocationList
			if err := json.Unmarshal(raw, &signed); err != nil {
				t.Fatal(err)
			}
			if _, err := verify.VerifyRevocationList(&signed, root, 0); err != nil {
				t.Fatalf("explicit list signature must be valid: %v", err)
			}
			target := filepath.Join(home, installRoot, "fetch-contract")
			if err := os.MkdirAll(target, 0700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(target, "SKILL.md")
			if err := os.WriteFile(marker, []byte("previous unmanaged skill"), 0600); err != nil {
				t.Fatal(err)
			}
			var result *Result
			var err error
			if route == "bundle" {
				result, err = InstallBundle(BundleOpts{BundlePath: writeBundle(t, fx), Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home, MutationEvidence: raw})
			} else {
				result, err = Install(Opts{Name: "fetch-contract", Client: registry.New(srv.URL+"/api/skills", srv.Client()), TrustRoot: root, HomeDir: home, MutationEvidence: raw})
			}
			if result != nil || verify.ExitCode(err) != 12 {
				t.Fatalf("unmanaged evidence was ignored: result=%+v error=%v", result, err)
			}
			got, readErr := os.ReadFile(marker)
			if readErr != nil || string(got) != "previous unmanaged skill" {
				t.Fatalf("refusal changed existing skill: %v", readErr)
			}
		})
	}
}
