package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

type retainedRootLogger struct {
	event  string
	mutate func() error
	fired  bool
	err    error
}

func (l *retainedRootLogger) Write(p []byte) (int, error) {
	if !l.fired && strings.Contains(string(p), "step="+l.event) {
		l.fired = true
		l.err = l.mutate()
	}
	return len(p), nil
}
func retainedRootStash(t *testing.T, target string, expected []byte) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(target, "*.skb"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("retained archive count: %v %v", paths, err)
	}
	got, err := os.ReadFile(paths[0])
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("installed archive differs from signed retained bytes: %v", err)
	}
}
func retainedRootStage(home string, replacement []byte, remove bool) error {
	count := 0
	err := filepath.WalkDir(filepath.Join(home, installRoot, StagingDirName), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".skb") {
			return nil
		}
		count++
		if remove {
			return os.Remove(path)
		}
		return os.WriteFile(path, replacement, 0600)
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("expected exactly one staged archive")
	}
	return nil
}
func TestRetainedRootLocalSnapshot(t *testing.T) {
	for _, remove := range []bool{true, false} {
		t.Run(map[bool]string{true: "remove", false: "replace"}[remove], func(t *testing.T) {
			home := snapshotTestHome(t)
			fx := projectFixture(t, `{"schema":"m3c-skill-bundle/v1","name":"fetch-contract","version":"1.0.0","data_dependencies":[{"id":"retained-signed","kind":"local_fs","access":"read","scope":"<cwd>/**"}]}`)
			policy := installProjectProfile(t, home, projectManagedRoot(t, fx))
			root := policy.TrustRoot()
			enrollProject(t, home, root, fx)
			path := writeBundle(t, fx)
			logger := &retainedRootLogger{event: "digest_ok", mutate: func() error {
				if remove {
					return os.Remove(path)
				}
				return os.WriteFile(path, []byte("not the signed archive"), 0600)
			}}
			result, err := InstallBundle(BundleOpts{ProjectPolicy: policy, BundlePath: path, Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home, Logger: logger})
			if err != nil || result == nil || !logger.fired || logger.err != nil {
				t.Fatalf("retained local verification: result=%v error=%v mutation=%v/%v", result, err, logger.fired, logger.err)
			}
			retainedRootStash(t, result.InstalledPath, fx.blob)
			signed := false
			for _, scope := range result.Verify.DataScopes {
				if scope.Provenance == verify.ScopeProvenanceSignedManifest && scope.Raw["id"] == "retained-signed" {
					signed = true
				}
			}
			if !signed {
				t.Fatal("signed retained scope lost after original path mutation")
			}
		})
	}
}
func TestRetainedRootHTTPStagingSnapshot(t *testing.T) {
	for _, mode := range []string{"remove", "replace", "wrong-retained"} {
		t.Run(mode, func(t *testing.T) {
			home := snapshotTestHome(t)
			fx := mkBundleFixture(t)
			srv, fr := newFakeRegistry(t)
			fillRegistry(t, fr, fx, "green")
			root := projectManagedRoot(t, fx)
			root.RegistryURL = srv.URL + "/api/skills"
			policy := installProjectProfile(t, home, root)
			root = policy.TrustRoot()
			enrollProject(t, home, root, fx)
			if mode == "wrong-retained" {
				fr.bundles[fx.digestStr] = []byte("unsigned retained download")
			}
			logger := &retainedRootLogger{event: "staged_blob", mutate: func() error {
				replacement := fx.blob
				if mode == "replace" {
					replacement = []byte("different staged bytes")
				}
				return retainedRootStage(home, replacement, mode == "remove")
			}}
			result, err := Install(Opts{ProjectPolicy: policy, Name: "fetch-contract", Client: registry.New(srv.URL+"/api/skills", srv.Client()), TrustRoot: root, HomeDir: home, Logger: logger})
			if !logger.fired || logger.err != nil {
				t.Fatalf("stage mutation did not execute: %v %v", logger.fired, logger.err)
			}
			if mode == "wrong-retained" {
				if !errors.Is(err, verify.ErrDigestMismatch) || result != nil {
					t.Fatalf("staged signed replacement authorized unsigned retained bytes: %v", err)
				}
				if _, e := os.Stat(filepath.Join(home, installRoot, "fetch-contract")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("invalid retained bytes published target")
				}
				return
			}
			if err != nil || result == nil {
				t.Fatalf("retained HTTP verification: %v", err)
			}
			retainedRootStash(t, result.InstalledPath, fx.blob)
		})
	}
}
func TestRetainedRootManifestAndAdoption(t *testing.T) {
	for _, field := range []string{`"Depends_On":[]`, `"Name":"other"`, `"extension":"` + string([]byte{0xff}) + `"`, `"oversize":"` + strings.Repeat("x", 1<<20) + `"`, `"nesting":` + strings.Repeat("[", 128) + `0` + strings.Repeat("]", 128)} {
		t.Run(field[:8], func(t *testing.T) {
			home := snapshotTestHome(t)
			fx := projectFixture(t, `{"schema":"m3c-skill-bundle/v1","version":"1.0.0","name":"fetch-contract",`+field+`}`)
			policy := installProjectProfile(t, home, projectManagedRoot(t, fx))
			root := policy.TrustRoot()
			enrollProject(t, home, root, fx)
			result, err := InstallBundle(BundleOpts{ProjectPolicy: policy, BundlePath: writeBundle(t, fx), Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home})
			if err == nil || result != nil {
				t.Fatal("invalid retained manifest accepted")
			}
			if _, e := os.Stat(filepath.Join(home, installRoot, "fetch-contract")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("invalid manifest published target")
			}
		})
	}
	home := snapshotTestHome(t)
	fx := mkBundleFixture(t)
	policy := installProjectProfile(t, home, projectManagedRoot(t, fx))
	root := policy.TrustRoot()
	enrollProject(t, home, root, fx)
	denied := errors.New("synthetic caller denial")
	calls := 0
	_, err := InstallBundle(BundleOpts{ProjectPolicy: policy, BundlePath: writeBundle(t, fx), Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home, MutationEvidence: managedLibraryList(t, fx, root, time.Now().Add(-30*time.Minute), 2, false), PostVerify: func(*verify.VerifyResult) error { calls++; return denied }})
	status, statusErr := managedLibraryStore(t, home, root).Status(context.Background())
	if !errors.Is(err, denied) || calls != 1 || statusErr != nil || status.Epoch != 2 {
		t.Fatalf("caller denial lost authenticated epoch: %v %d %+v %v", err, calls, status, statusErr)
	}
}
