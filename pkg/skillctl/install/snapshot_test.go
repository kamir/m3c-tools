package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func snapshotTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	return home
}

func TestInstallSnapshotGuardBeforePublication(t *testing.T) {
	for _, name := range []string{"same", "changed", "nil-result", "empty-verified", "malformed-verified", "empty-blob", "selected-mismatch", "empty-selected", "uppercase-hex"} {
		t.Run(name, func(t *testing.T) {
			home := snapshotTestHome(t)
			fx := mkBundleFixture(t)
			path := writeBundle(t, fx)
			verified, err := verify.Verify(verify.VerifyOpts{BundlePath: path, BundleMeta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: pinnedRoot(t, fx)})
			if err != nil {
				t.Fatalf("real signature fixture failed: %v", err)
			}
			blob, selected := fx.blob, fx.digestStr
			switch name {
			case "changed":
				blob = buildBundleTGZ(t, bundleSpec{name: "fetch-contract", version: "1.0.0", files: map[string]string{"SKILL.md": "synthetic substituted body"}})
			case "nil-result":
				verified = nil
			case "empty-verified":
				verified.Digest = ""
			case "malformed-verified":
				verified.Digest = "sha256:invalid"
			case "empty-blob":
				blob = nil
			case "selected-mismatch":
				selected = "sha256:" + strings.Repeat("0", 64)
			case "empty-selected":
				selected = ""
			case "uppercase-hex":
				selected = "sha256:" + strings.ToUpper(strings.TrimPrefix(selected, "sha256:"))
			}
			target := filepath.Join(home, installRoot, "fetch-contract")
			if err := os.MkdirAll(target, 0o700); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(target, "SKILL.md")
			if err := os.WriteFile(old, []byte("original installed body"), 0o600); err != nil {
				t.Fatal(err)
			}
			stage := filepath.Join(home, "uncreated-stage")
			res, err := finishInstall(finishOpts{blob: blob, blobPath: "snapshot.skb", stagingDir: stage, homeDir: home, name: "fetch-contract", digest: selected, verRes: verified, ctx: context.Background(), now: time.Now})
			if name == "same" || name == "uppercase-hex" {
				if err != nil || res == nil || res.ArchivedPath == "" {
					t.Fatalf("same verified bytes failed upgrade: %v", err)
				}
				return
			}
			if res != nil || !errors.Is(err, verify.ErrDigestMismatch) {
				t.Fatalf("unbound snapshot not rejected: %v", err)
			}
			body, readErr := os.ReadFile(old)
			if readErr != nil || string(body) != "original installed body" {
				t.Fatal("snapshot refusal changed previous installation")
			}
			for _, p := range []string{stage, filepath.Join(home, installRoot, ".archive")} {
				if _, err := os.Stat(p); !os.IsNotExist(err) {
					t.Fatalf("refusal performed publication scaffolding: %s", p)
				}
			}
		})
	}
}

type snapshotSwapLogger struct {
	stageRoot string
	verified  []byte
	swapped   bool
	err       error
}

func (l *snapshotSwapLogger) Write(p []byte) (int, error) {
	if !l.swapped && strings.Contains(string(p), "staged_blob") {
		l.swapped = true
		l.err = filepath.WalkDir(l.stageRoot, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && strings.HasSuffix(path, ".skb") {
				return os.WriteFile(path, l.verified, 0o600)
			}
			return nil
		})
		if l.err != nil {
			return 0, l.err
		}
	}
	return len(p), nil
}

func TestInstallSnapshotHTTPStagedSwap(t *testing.T) {
	home := snapshotTestHome(t)
	server, fr := newFakeRegistry(t)
	defer server.Close()
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "green")
	fr.bundles[fx.digestStr] = buildBundleTGZ(t, bundleSpec{name: "fetch-contract", version: "1.0.0", files: map[string]string{"SKILL.md": "synthetic substituted body"}})
	logger := &snapshotSwapLogger{stageRoot: filepath.Join(home, installRoot, StagingDirName), verified: fx.blob}
	res, err := Install(Opts{Name: "fetch-contract", Version: "1.0.0", HomeDir: home, Client: registry.New(server.URL+"/api/skills", server.Client()), TrustRoot: mkTrustRoot(t, fx.regPub, server.URL+"/api/skills", "green"), Logger: logger})
	if !logger.swapped || logger.err != nil {
		t.Fatalf("stage swap not exercised: %v", logger.err)
	}
	if res != nil || !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("unverified retained bytes published: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, installRoot, "fetch-contract")); !os.IsNotExist(err) {
		t.Fatal("retained mismatch wrote target")
	}
}

func TestInstallSnapshotHTTPResolvedIdentity(t *testing.T) {
	home := snapshotTestHome(t)
	server, fr := newFakeRegistry(t)
	defer server.Close()
	fx := mkBundleFixture(t)
	fillRegistry(t, fr, fx, "green")
	selected := "sha256:" + strings.Repeat("0", 64)
	fr.bundles[selected] = fx.blob
	fr.metas[selected] = fr.metas[fx.digestStr]
	res, err := Install(Opts{Name: "fetch-contract", Version: selected, HomeDir: home, Client: registry.New(server.URL+"/api/skills", server.Client()), TrustRoot: mkTrustRoot(t, fx.regPub, server.URL+"/api/skills", "green")})
	if res != nil || !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("selected digest relabeled verified bytes: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, installRoot, "fetch-contract")); !os.IsNotExist(err) {
		t.Fatal("identity mismatch wrote target")
	}
}

type localSnapshotFailureReader struct{ err error }

func (r localSnapshotFailureReader) Read([]byte) (int, error) { return 0, r.err }

func TestInstallSnapshotLocalReadBoundary(t *testing.T) {
	snapshotTestHome(t)
	fx := mkBundleFixture(t)
	got, err := readLocalInstallBytes(bytes.NewReader(fx.blob), int64(len(fx.blob)))
	if err != nil || !bytes.Equal(got, fx.blob) {
		t.Fatalf("exact cap changed input or refused: %v", err)
	}
	if got, err := readLocalInstallBytes(bytes.NewReader(fx.blob), int64(len(fx.blob)-1)); got != nil || err == nil || errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("cap+1 accepted or size failure mislabeled corruption: %v", err)
	}
	sentinel := errors.New("synthetic local read failure")
	if got, err := readLocalInstallBytes(io.MultiReader(bytes.NewReader(fx.blob[:10]), localSnapshotFailureReader{sentinel}), int64(len(fx.blob))); got != nil || !errors.Is(err, sentinel) || errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("partial read escaped or lost IO identity: %v", err)
	}
	if got, err := readLocalInstallSnapshot(filepath.Join(t.TempDir(), "missing.skb")); got != nil || !errors.Is(err, os.ErrNotExist) || errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("local open lost OS identity: %v", err)
	}
}
