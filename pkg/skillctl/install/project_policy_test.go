package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
	"gopkg.in/yaml.v3"
)

func installProjectProfile(t *testing.T, home string, root *verify.TrustRoot, tools ...dependencies.Tool) *projectpolicy.Policy {
	t.Helper()
	raw, err := yaml.Marshal(verify.TrustRoots{Roots: []verify.TrustRoot{*root}})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := json.Marshal(dependencies.Profile{Schema: dependencies.ProfileSchema, ProjectRoot: home, Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	ref := func(name string, raw []byte) map[string]string {
		if err := os.WriteFile(filepath.Join(home, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return map[string]string{"path": name, "sha256": hex.EncodeToString(sum[:])}
	}
	trust := ref("project-roots.yaml", raw)
	doc := map[string]any{"schema": projectpolicy.Schema, "project_root": home, "artifact_home": home, "registry_url": root.RegistryURL, "allow_loopback_http": true, "artifact_trust": trust, "revocation_trust": trust, "runtime": ref("project-runtime.json", runtime)}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "project.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	p, err := projectpolicy.Load(path, home, home)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func projectFixture(t *testing.T, manifest string) *bundleFixture {
	t.Helper()
	fx := mkBundleFixture(t)
	fx.blob = buildBundleTGZ(t, bundleSpec{name: "fetch-contract", version: "1.0.0", files: map[string]string{"bundle.json": manifest}})
	fx.digestRaw = sha256.Sum256(fx.blob)
	fx.digestStr = "sha256:" + hex.EncodeToString(fx.digestRaw[:])
	return fx
}
func projectManagedRoot(t *testing.T, fx *bundleFixture) *verify.TrustRoot {
	t.Helper()
	root := pinnedRoot(t, fx)
	root.RegistryURL = "https://registry.invalid/api/skills"
	root.OfflinePolicy = &verify.OfflinePolicyBlock{Enterprise: true}
	return root
}
func enrollProject(t *testing.T, home string, root *verify.TrustRoot, fx *bundleFixture) {
	t.Helper()
	if _, err := managedLibraryStore(t, home, root).Enroll(context.Background(), managedLibraryList(t, fx, root, time.Now().Add(-time.Hour), 1, false)); err != nil {
		t.Fatal(err)
	}
}

func TestProjectManagedInstallRequiresPolicyBeforeIO(t *testing.T) {
	home := snapshotTestHome(t)
	fx := mkBundleFixture(t)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer srv.Close()
	root := projectManagedRoot(t, fx)
	root.RegistryURL = srv.URL + "/api/skills"
	_, err := Install(Opts{Name: "fetch-contract", Client: registry.New(srv.URL+"/api/skills", srv.Client()), TrustRoot: root, HomeDir: home, AuditPoster: func(context.Context, AuditEntry) error { calls++; return nil }, IgnoreDeps: true})
	if !errors.Is(err, verify.ErrRegistryNotTrusted) || calls != 0 {
		t.Fatalf("missing policy accessed network/audit: %v calls=%d", err, calls)
	}
	_, err = InstallBundle(BundleOpts{BundlePath: filepath.Join(home, "missing.skb"), Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home})
	if !errors.Is(err, verify.ErrRegistryNotTrusted) {
		t.Fatalf("missing policy read input: %v", err)
	}
	policy := installProjectProfile(t, home, root)
	root = policy.TrustRoot()
	for _, opts := range []Opts{{Name: "fetch-contract", Client: registry.New(srv.URL+"/other", srv.Client()), TrustRoot: root, HomeDir: home, ProjectPolicy: policy}, {Name: "fetch-contract", Client: registry.New(srv.URL+"/api/skills", srv.Client()), TrustRoot: root, HomeDir: home, ProjectPolicy: policy, IgnoreDeps: true}} {
		if _, err := Install(opts); !errors.Is(err, verify.ErrRegistryNotTrusted) {
			t.Fatalf("selection bypass: %v", err)
		}
	}
	if calls != 0 {
		t.Fatal("conflicting selection contacted server")
	}
}
func TestProjectSignedDependenciesCannotBeHidden(t *testing.T) {
	for _, decl := range []string{`[{"kind":"skill","name":"required","constraint":">=1"}]`, `[{"kind":"agent","name":"required","constraint":">=1"}]`, `[{"kind":"unknown","name":"required"}]`, `[{"Kind":"skill","name":"required"}]`, `[{"kind":"skill","name":"bad\nname"}]`} {
		home := snapshotTestHome(t)
		fx := projectFixture(t, `{"schema":"m3c-skill-bundle/v1","name":"fetch-contract","version":"1.0.0","depends_on":`+decl+`}`)
		policy := installProjectProfile(t, home, projectManagedRoot(t, fx))
		root := policy.TrustRoot()
		enrollProject(t, home, root, fx)
		target := filepath.Join(home, installRoot, "fetch-contract")
		if err := os.MkdirAll(target, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("old installed content"), 0600); err != nil {
			t.Fatal(err)
		}
		meta := sidecarMeta(t, fx, "fetch-contract")
		meta.Manifest = map[string]any{"depends_on": []any{}}
		callbacks := 0
		_, err := InstallBundle(BundleOpts{ProjectPolicy: policy, BundlePath: writeBundle(t, fx), Meta: meta, TrustRoot: root, HomeDir: home, PostVerify: func(*verify.VerifyResult) error { callbacks++; return nil }})
		if !errors.Is(err, verify.ErrDepsUnsatisfied) || callbacks != 1 {
			t.Fatalf("signed dependency hidden: %v", err)
		}
		got, readErr := os.ReadFile(filepath.Join(target, "SKILL.md"))
		if readErr != nil || string(got) != "old installed content" {
			t.Fatal("denial changed old install")
		}
		if strings.Contains(err.Error(), "bad\nname") {
			t.Fatal("raw control character reflected")
		}
	}
}
func TestProjectSignedTopLevelDependencyAliases(t *testing.T) {
	cases := []struct{ name, field string }{
		{"dependency-alias", `"Depends_On":[{"kind":"skill","name":"required"}]`},
		{"mixed-dependencies", `"depends_on":[],"DEPENDS_ON":[{"kind":"agent","name":"required"}]`},
		{"kind", `"Kind":"agent"`}, {"schema", `"Schema":"unsupported-schema"`},
		{"name", `"Name":"foreign"`}, {"version", `"Version":"9.0.0"`},
		{"kelvin-kind", `"Kind":"agent"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := snapshotTestHome(t)
			fx := projectFixture(t, `{"schema":"m3c-skill-bundle/v1","name":"fetch-contract","version":"1.0.0",`+tc.field+`}`)
			policy := installProjectProfile(t, home, projectManagedRoot(t, fx))
			root := policy.TrustRoot()
			enrollProject(t, home, root, fx)
			meta := sidecarMeta(t, fx, "fetch-contract")
			meta.Manifest = map[string]any{"depends_on": []any{}}
			_, err := InstallBundle(BundleOpts{ProjectPolicy: policy, BundlePath: writeBundle(t, fx), Meta: meta, TrustRoot: root, HomeDir: home})
			if !errors.Is(err, verify.ErrDepsUnsatisfied) {
				t.Fatalf("signed alias accepted: %v", err)
			}
			if _, err := os.Stat(filepath.Join(home, installRoot, "fetch-contract")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("alias denial published installation")
			}
		})
	}
}

func TestProjectManagedInstallActualSignedRoutes(t *testing.T) {
	for _, route := range []string{"bundle", "http"} {
		t.Run(route, func(t *testing.T) {
			home := snapshotTestHome(t)
			fx := mkBundleFixture(t)
			srv, fr := newFakeRegistry(t)
			defer srv.Close()
			fillRegistry(t, fr, fx, "green")
			root := projectManagedRoot(t, fx)
			if route == "http" {
				root = mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")
				root.OfflinePolicy = &verify.OfflinePolicyBlock{Enterprise: true}
			}
			policy := installProjectProfile(t, home, root)
			root = policy.TrustRoot()
			enrollProject(t, home, root, fx)
			var result *Result
			var err error
			if route == "http" {
				result, err = Install(Opts{ProjectPolicy: policy, Name: "fetch-contract", TrustRoot: root, Client: registry.New(srv.URL+"/api/skills", srv.Client()), HomeDir: home})
			} else {
				result, err = InstallBundle(BundleOpts{ProjectPolicy: policy, BundlePath: writeBundle(t, fx), Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home})
			}
			if err != nil || result == nil {
				t.Fatalf("actual signed route: %v", err)
			}
			if _, err := os.Stat(filepath.Join(result.InstalledPath, "SKILL.md")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectRequestedVersionBindsSignedManifest(t *testing.T) {
	home := snapshotTestHome(t)
	fx := mkBundleFixture(t)
	srv, fr := newFakeRegistry(t)
	defer srv.Close()
	fillRegistry(t, fr, fx, "green")
	fr.versions[0].Version = "2.0.0"
	root := mkTrustRoot(t, fx.regPub, srv.URL+"/api/skills", "green")
	root.OfflinePolicy = &verify.OfflinePolicyBlock{Enterprise: true}
	policy := installProjectProfile(t, home, root)
	root = policy.TrustRoot()
	enrollProject(t, home, root, fx)
	result, err := Install(Opts{ProjectPolicy: policy, Name: "fetch-contract", Version: "2.0.0", Client: registry.New(srv.URL+"/api/skills", srv.Client()), TrustRoot: root, HomeDir: home})
	if !errors.Is(err, verify.ErrDigestMismatch) || result != nil {
		t.Fatalf("unsignedindex version overrode signedidentity: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, installRoot, "fetch-contract")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("version mismatch installedtarget")
	}
}

func TestProjectToolProbe(t *testing.T) {
	for _, arg := range os.Args {
		if arg == "project-tool-version" {
			fmt.Print("1.2.3")
			os.Exit(0)
		}
	}
}

type projectMutationLogger struct {
	mutate func()
	once   bool
}

func (w *projectMutationLogger) Write(p []byte) (int, error) {
	if !w.once && strings.Contains(string(p), "extracted") {
		w.once = true
		w.mutate()
	}
	return len(p), nil
}
func TestProjectRuntimeRecheckBeforeArchive(t *testing.T) {
	home := snapshotTestHome(t)
	fx := projectFixture(t, `{"schema":"m3c-skill-bundle/v1","name":"fetch-contract","version":"1.0.0","depends_on":[{"kind":"system","name":"tool","constraint":">=1"}]}`)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(home, filepath.Base(exe))
	src, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := os.OpenFile(tool, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	policy := installProjectProfile(t, home, projectManagedRoot(t, fx), dependencies.Tool{Name: "tool", Path: tool, Args: []string{"-test.run=^TestProjectToolProbe$", "--", "project-tool-version"}, VersionPattern: `^([0-9]+\.[0-9]+\.[0-9]+)$`})
	root := policy.TrustRoot()
	enrollProject(t, home, root, fx)
	target := filepath.Join(home, installRoot, "fetch-contract")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(target, "SKILL.md")
	if err := os.WriteFile(old, []byte("old payload"), 0600); err != nil {
		t.Fatal(err)
	}
	logger := &projectMutationLogger{mutate: func() {
		f, err := os.OpenFile(tool, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("drift")); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}}
	_, err = InstallBundle(BundleOpts{ProjectPolicy: policy, BundlePath: writeBundle(t, fx), Meta: sidecarMeta(t, fx, "fetch-contract"), TrustRoot: root, HomeDir: home, Logger: logger})
	if !logger.once || !errors.Is(err, verify.ErrDepsUnsatisfied) {
		t.Fatalf("runtime drift accepted: %v", err)
	}
	got, err := os.ReadFile(old)
	if err != nil || string(got) != "old payload" {
		t.Fatal("runtime failure archived or replaced old installation")
	}
}

type projectForbiddenMarshaler struct{ calls *int }

func (v projectForbiddenMarshaler) MarshalJSON() ([]byte, error) {
	*v.calls++
	return []byte(`"synthetic"`), nil
}

func TestProjectMetadataSnapshotBudget(t *testing.T) {
	calls := 0
	if _, err := snapshotProjectMeta(&registry.BundleMeta{Bundle: map[string]any{"custom": projectForbiddenMarshaler{calls: &calls}}}); !errors.Is(err, verify.ErrRegistryNotTrusted) || calls != 0 {
		t.Fatalf("caller custom marshal executed before validation: %v calls=%d", err, calls)
	}

	for _, meta := range []*registry.BundleMeta{{Bundle: map[string]any{"huge": strings.Repeat("x", (1<<20)+1)}}, {Bundle: map[string]any{"invalid": string([]byte{0xff})}}} {
		if _, err := snapshotProjectMeta(meta); !errors.Is(err, verify.ErrRegistryNotTrusted) {
			t.Fatal("unbounded metadata accepted")
		}
	}
	original := &registry.BundleMeta{Bundle: map[string]any{"name": "original"}, Attestations: []registry.AttestationRow{{SelfAttested: new(bool)}}}
	copy, err := snapshotProjectMeta(original)
	if err != nil {
		t.Fatal(err)
	}
	original.Bundle["name"] = "changed"
	*original.Attestations[0].SelfAttested = true
	if copy.Bundle["name"] != "original" || *copy.Attestations[0].SelfAttested {
		t.Fatal("metadata snapshot aliases caller")
	}
}
