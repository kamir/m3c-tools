package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

func installedDependencyBundle(t *testing.T, keys *bundleFixture, name, version, fields string) *bundleFixture {
	t.Helper()
	f := *keys
	manifest := fmt.Sprintf(`{"schema":"m3c-skill-bundle/v1","name":%q,"version":%q%s}`, name, version, fields)
	f.blob = buildBundleTGZ(t, bundleSpec{name: name, version: version, files: map[string]string{"bundle.json": manifest}})
	f.digestRaw = sha256.Sum256(f.blob)
	f.digestStr = "sha256:" + hex.EncodeToString(f.digestRaw[:])
	return &f
}

// Materialize genuine signed retained evidence independently of the installer.
// This also allows malformed signed declarations to reach the dependency reader.
func installedDependencyTree(t *testing.T, home string, f *bundleFixture, name, version string) string {
	t.Helper()
	dir := filepath.Join(home, installRoot, name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := skillbundle.Unpack(f.blob, skillbundle.UnpackOptions{StripWrapper: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Rel == "." {
			continue
		}
		p := filepath.Join(dir, filepath.FromSlash(e.Rel))
		if e.IsDir {
			err = os.MkdirAll(p, 0700)
		} else {
			if err = os.MkdirAll(filepath.Dir(p), 0700); err == nil {
				err = os.WriteFile(p, e.Content, 0600)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(filepath.Join(dir, "retained.skb"), f.blob, 0600); err != nil {
		t.Fatal(err)
	}
	meta := sidecarMeta(t, f, name)
	meta.Bundle["version"] = version
	raw, err := json.Marshal(OfflineMeta{BundleMeta: meta, Identities: map[string]*registry.Identity{}, StashedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, offlineMetaFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}
func installedDependencyPolicy(t *testing.T, home string, keys *bundleFixture) *projectpolicy.Policy {
	t.Helper()
	p := installProjectProfile(t, home, projectManagedRoot(t, keys))
	enrollProject(t, home, p.TrustRoot(), keys)
	return p
}
func installedDependencyInstall(t *testing.T, home string, p *projectpolicy.Policy, f *bundleFixture, logger io.Writer) error {
	t.Helper()
	_, err := InstallBundle(BundleOpts{ProjectPolicy: p, HomeDir: home, TrustRoot: p.TrustRoot(), BundlePath: writeBundle(t, f), Meta: sidecarMeta(t, f, "fetch-contract"), Logger: logger})
	return err
}
func installedDependencyOldTarget(t *testing.T, home string) string {
	t.Helper()
	target := filepath.Join(home, installRoot, "fetch-contract", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old target"), 0600); err != nil {
		t.Fatal(err)
	}
	return target
}
func assertInstalledDependencyOldTarget(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "old target" {
		t.Fatalf("refusal changed old target: %q %v", raw, err)
	}
}

func TestInstalledSkillSourceSignedActiveProof(t *testing.T) {
	for _, route := range []string{"bundle", "http"} {
		t.Run(route, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			leaf := installedDependencyBundle(t, keys, "required", "1.0.0", "")
			rootBundle := installedDependencyBundle(t, keys, "fetch-contract", "1.0.0", `,"depends_on":[{"kind":"skill","name":"required","constraint":">=1.0.0"}]`)
			root := projectManagedRoot(t, keys)
			if route == "http" {
				srv, fr := newFakeRegistry(t)
				fillRegistry(t, fr, rootBundle, "green")
				root.RegistryURL = srv.URL + "/api/skills"
				p := installProjectProfile(t, home, root)
				enrollProject(t, home, p.TrustRoot(), keys)
				installedDependencyTree(t, home, leaf, "required", "1.0.0")
				if _, err := Install(Opts{ProjectPolicy: p, HomeDir: home, TrustRoot: p.TrustRoot(), Client: registry.New(root.RegistryURL, srv.Client()), Name: "fetch-contract"}); err != nil {
					t.Fatal(err)
				}
			} else {
				p := installedDependencyPolicy(t, home, keys)
				installedDependencyTree(t, home, leaf, "required", "1.0.0")
				if err := installedDependencyInstall(t, home, p, rootBundle, nil); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := os.ReadFile(filepath.Join(home, installRoot, "fetch-contract", "SKILL.md"))
			if err != nil || !strings.Contains(string(raw), "fetch-contract") {
				t.Fatalf("missing actual installed root: %s %v", raw, err)
			}
		})
	}
}

func TestInstalledSkillSourceRejectsUnsignedAndLegacy(t *testing.T) {
	for _, mode := range []string{"missing", "body", "extra", "blob", "metadata", "signature", "unsigned-identity", "ambiguous", "nested-stash"} {
		t.Run(mode, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			p := installedDependencyPolicy(t, home, keys)
			leaf := installedDependencyBundle(t, keys, "required", "1.0.0", "")
			dir := installedDependencyTree(t, home, leaf, "required", "1.0.0")
			write := func(rel string, b []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, rel), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "missing":
				if err := os.Rename(dir, dir+"-inactive"); err != nil {
					t.Fatal(err)
				}
			case "body":
				write("SKILL.md", []byte("changed"))
			case "extra":
				write("payload.txt", []byte("unlisted"))
			case "blob":
				write("retained.skb", append(append([]byte{}, leaf.blob...), 1))
			case "metadata":
				if err := os.Remove(filepath.Join(dir, offlineMetaFile)); err != nil {
					t.Fatal(err)
				}
			case "signature":
				m := sidecarMeta(t, leaf, "required")
				m.Signatures[0].SignatureB64 = "AAAA"
				raw, _ := json.Marshal(OfflineMeta{BundleMeta: m})
				write(offlineMetaFile, raw)
			case "unsigned-identity":
				foreign := mkBundleFixture(t)
				substituted := *keys
				substituted.authorPub, substituted.authorPriv = foreign.authorPub, foreign.authorPriv
				other := installedDependencyBundle(t, &substituted, "required", "1.0.0", "")
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
				installedDependencyTree(t, home, other, "required", "1.0.0")
				forgedProjection := OfflineMeta{BundleMeta: sidecarMeta(t, other, "required"), Identities: map[string]*registry.Identity{"id:author@m3c": {ID: "id:author@m3c", PubkeyB64: base64.StdEncoding.EncodeToString(foreign.authorPub)}}}
				raw, err := json.Marshal(forgedProjection)
				if err != nil {
					t.Fatal(err)
				}
				write(offlineMetaFile, raw)
			case "ambiguous":
				write("second.skb", leaf.blob)
			case "nested-stash":
				if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0700); err != nil {
					t.Fatal(err)
				}
				write("scripts/payload.skb", leaf.blob)
			}
			old := installedDependencyOldTarget(t, home)
			f := installedDependencyBundle(t, keys, "fetch-contract", "1.0.0", `,"depends_on":[{"kind":"skill","name":"required"}]`)
			if err := installedDependencyInstall(t, home, p, f, nil); !errors.Is(err, verify.ErrDepsUnsatisfied) {
				t.Fatalf("%s accepted or wrong cause: %v", mode, err)
			}
			assertInstalledDependencyOldTarget(t, old)
		})
	}
}

func TestInstalledSkillSourceBindsIdentityVersionAndDeclarations(t *testing.T) {
	for _, tc := range []struct{ name, version, fields string }{
		{"version", "0.5.0", ""}, {"non-string-kind", "1.0.0", `,"kind":false`}, {"alias", "1.0.0", `,"Depends_On":[]`}, {"name-alias", "1.0.0", `,"Name":"other"`}, {"version-alias", "1.0.0", `,"Version":"9"`}, {"kind-alias", "1.0.0", `,"Kind":"skill"`}, {"schema-alias", "1.0.0", `,"Schema":"unsupported"`}, {"kelvin-kind", "1.0.0", `,"Kind":"skill"`}, {"duplicate-name", "1.0.0", `,"name":"required"`}, {"nested-constraint-alias", "1.0.0", `,"depends_on":[{"kind":"skill","name":"hidden","Constraint":">=1"}]`}, {"nested-alias", "1.0.0", `,"depends_on":[{"Kind":"skill","name":"hidden"}]`}, {"invalid-utf8", "1.0.0", ",\"extension\":\"\xff\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			p := installedDependencyPolicy(t, home, keys)
			leaf := installedDependencyBundle(t, keys, "required", tc.version, tc.fields)
			installedDependencyTree(t, home, leaf, "required", tc.version)
			f := installedDependencyBundle(t, keys, "fetch-contract", "1.0.0", `,"depends_on":[{"kind":"skill","name":"required","constraint":">=1.0.0"}]`)
			if err := installedDependencyInstall(t, home, p, f, nil); !errors.Is(err, verify.ErrDepsUnsatisfied) {
				t.Fatalf("invalid signed dependency accepted: %v", err)
			}
		})
	}
}

func TestInstalledSkillGraphTransitiveAndCycles(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		t.Run(fmt.Sprint(cycle), func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			p := installedDependencyPolicy(t, home, keys)
			fields := ""
			if cycle {
				fields = `,"depends_on":[{"kind":"skill","name":"required"}]`
			}
			c := installedDependencyBundle(t, keys, "transitive", "1.0.0", fields)
			installedDependencyTree(t, home, c, "transitive", "1.0.0")
			b := installedDependencyBundle(t, keys, "required", "1.0.0", `,"depends_on":[{"kind":"skill","name":"transitive"}]`)
			installedDependencyTree(t, home, b, "required", "1.0.0")
			f := installedDependencyBundle(t, keys, "fetch-contract", "1.0.0", `,"depends_on":[{"kind":"skill","name":"required"}]`)
			err := installedDependencyInstall(t, home, p, f, nil)
			if cycle {
				if !errors.Is(err, verify.ErrDepsUnsatisfied) {
					t.Fatalf("cycle: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstalledSkillRecheckBeforeArchive(t *testing.T) {
	for _, mode := range []string{"body", "stash", "extra", "active-replaced", "transitive-body"} {
		t.Run(mode, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			p := installedDependencyPolicy(t, home, keys)
			c := installedDependencyBundle(t, keys, "transitive", "1.0.0", "")
			cdir := installedDependencyTree(t, home, c, "transitive", "1.0.0")
			b := installedDependencyBundle(t, keys, "required", "1.0.0", `,"depends_on":[{"kind":"skill","name":"transitive"}]`)
			dir := installedDependencyTree(t, home, b, "required", "1.0.0")
			f := installedDependencyBundle(t, keys, "fetch-contract", "1.0.0", `,"depends_on":[{"kind":"skill","name":"required"}]`)
			old := installedDependencyOldTarget(t, home)
			logger := &projectMutationLogger{mutate: func() {
				switch mode {
				case "active-replaced":
					if err := os.Rename(dir, dir+"-old"); err != nil {
						t.Fatal(err)
					}
					installedDependencyTree(t, home, b, "required", "1.0.0")
					if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("replacement"), 0600); err != nil {
						t.Fatal(err)
					}
				case "transitive-body":
					if err := os.WriteFile(filepath.Join(cdir, "SKILL.md"), []byte("changed"), 0600); err != nil {
						t.Fatal(err)
					}
				default:
					file := "SKILL.md"
					if mode == "stash" {
						file = "retained.skb"
					}
					if mode == "extra" {
						file = "new.txt"
					}
					if err := os.WriteFile(filepath.Join(dir, file), []byte("changed"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}}
			if err := installedDependencyInstall(t, home, p, f, logger); !errors.Is(err, verify.ErrDepsUnsatisfied) {
				t.Fatalf("final proof drift: %v", err)
			}
			if !logger.once {
				t.Fatal("did not reach prepublication mutation boundary")
			}
			assertInstalledDependencyOldTarget(t, old)
		})
	}
}

func TestInstalledSkillSubjectRevocationAndClock(t *testing.T) {
	for _, mode := range []string{"direct-revoked", "transitive-revoked", "stale-history", "history-replaced"} {
		t.Run(mode, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			p := installedDependencyPolicy(t, home, keys)
			c := installedDependencyBundle(t, keys, "transitive", "1.0.0", "")
			installedDependencyTree(t, home, c, "transitive", "1.0.0")
			b := installedDependencyBundle(t, keys, "required", "1.0.0", `,"depends_on":[{"kind":"skill","name":"transitive"}]`)
			installedDependencyTree(t, home, b, "required", "1.0.0")
			f := installedDependencyBundle(t, keys, "fetch-contract", "1.0.0", `,"depends_on":[{"kind":"skill","name":"required"}]`)
			old := installedDependencyOldTarget(t, home)
			var revoked []string
			switch mode {
			case "direct-revoked":
				revoked = []string{b.digestStr}
			case "transitive-revoked":
				revoked = []string{c.digestStr}
			}
			list, err := verify.NewSignedRevocationList(p.RegistryURL(), time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), 2, revoked, keys.regPriv)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(list)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "stale-history" {
				raw = managedLibraryList(t, keys, p.TrustRoot(), time.Now().Add(-48*time.Hour), 1, false)
				ageManagedLibraryRecord(t, home, raw)
			} else if mode != "history-replaced" {
				if _, err := managedLibraryStore(t, home, p.TrustRoot()).Adopt(context.Background(), raw); err != nil {
					t.Fatal(err)
				}
			}
			var logger *projectMutationLogger
			if mode == "history-replaced" {
				logger = &projectMutationLogger{mutate: func() { ageManagedLibraryRecord(t, home, raw) }}
			}
			// Avoid a typed nil writer: the actual install logger must remain optional.
			var sink io.Writer
			if logger != nil {
				sink = logger
			}
			err = installedDependencyInstall(t, home, p, f, sink)
			want := verify.ErrIdentityRevoked
			if mode == "stale-history" || mode == "history-replaced" {
				want = verify.ErrRevocationStale
			}
			if !errors.Is(err, want) {
				t.Fatalf("%s: err=%v want=%v", mode, err, want)
			}
			if logger != nil && !logger.once {
				t.Fatal("did not reach held-session history replacement boundary")
			}
			assertInstalledDependencyOldTarget(t, old)
		})
	}
}

func TestInstalledSkillNoProvisioningOrIgnoreBypass(t *testing.T) {
	for _, mode := range []string{"agent", "missing-skill", "from-registry", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			root := projectManagedRoot(t, keys)
			if mode == "from-registry" {
				root.IdentityKeysAuthorized = "from-registry"
			}
			p := installProjectProfile(t, home, root)
			enrollProject(t, home, p.TrustRoot(), keys)
			leaf := installedDependencyBundle(t, keys, "required", "1.0.0", "")
			if mode != "missing-skill" {
				installedDependencyTree(t, home, leaf, "required", "1.0.0")
			}
			kind := "skill"
			if mode == "agent" {
				kind = "agent"
			}
			f := installedDependencyBundle(t, keys, "fetch-contract", "1.0.0", `,"depends_on":[{"kind":"`+kind+`","name":"required"}]`)
			old := installedDependencyOldTarget(t, home)
			_, err := InstallBundle(BundleOpts{ProjectPolicy: p, HomeDir: home, TrustRoot: p.TrustRoot(), BundlePath: writeBundle(t, f), Meta: sidecarMeta(t, f, "fetch-contract"), IgnoreDeps: mode == "ignore"})
			if err == nil {
				t.Fatal("unsupported or missing proof installed root")
			}
			if mode != "ignore" && mode != "from-registry" && !errors.Is(err, verify.ErrDepsUnsatisfied) {
				t.Fatalf("unexpected refusal cause: %v", err)
			}
			assertInstalledDependencyOldTarget(t, old)
			if mode == "missing-skill" {
				if _, err := os.Stat(filepath.Join(home, installRoot, "required")); !os.IsNotExist(err) {
					t.Fatalf("dependency was provisioned: %v", err)
				}
			}
		})
	}
}

func TestInstalledSkillGraphSelectedRuntime(t *testing.T) {
	home := snapshotTestHome(t)
	base := os.Getenv("M3C_DEPENDENCY_TEST_PYTHON")
	if base == "" || !filepath.IsAbs(base) {
		t.Fatal("explicit absolute fixture Python with packaging is required")
	}
	script := `
import importlib.metadata as m,json,os,pathlib,shutil,sys,venv
root=pathlib.Path(sys.argv[1]);venv.EnvBuilder(with_pip=False,symlinks=os.name!='nt').create(root)
exe=root/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
site=root/('Lib/site-packages' if os.name=='nt' else 'lib/python%d.%d/site-packages'%sys.version_info[:2])
import packaging
shutil.copytree(pathlib.Path(packaging.__file__).parent,site/'packaging',dirs_exist_ok=True)
dist=m.distribution('packaging');shutil.copytree(dist._path,site/pathlib.Path(dist._path).name,dirs_exist_ok=True)
(site/'sample_dep.py').write_text('raise RuntimeError("dependency module must never be imported")\n')
info=site/'sample_dep-1.2.3.dist-info';info.mkdir()
(info/'METADATA').write_text('Metadata-Version: 2.3\nName: sample-dep\nVersion: 1.2.3\nRequires-Python: >=3.9\n')
(info/'RECORD').write_text('sample_dep.py,,\nsample_dep-1.2.3.dist-info/METADATA,,\nsample_dep-1.2.3.dist-info/RECORD,,\n')
print(json.dumps({'path':str(exe),'site_packages':str(site)}))
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, base, "-I", "-B", "-c", script, filepath.Join(home, "runtime-env"))
	var stderr bytes.Buffer
	command.Stderr = &stderr
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("synthetic runtime prerequisite: %v: %s", err, stderr.String())
	}
	var python dependencies.Python
	if err := json.Unmarshal(raw, &python); err != nil {
		t.Fatal(err)
	}
	observation, err := dependencies.FingerprintTree(ctx, python.SitePackages)
	if err != nil {
		t.Fatal(err)
	}
	python.TreeDigest = observation.Digest
	if runtime.GOOS == "windows" {
		root, err := dependencies.FingerprintTree(ctx, filepath.Dir(filepath.Dir(python.Path)))
		if err != nil {
			t.Fatal(err)
		}
		python.InterpreterRootDigest = root.Digest
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	keys := mkBundleFixture(t)
	policy := installProjectProfile(t, home, projectManagedRoot(t, keys), dependencies.Tool{Name: "fixture-tool", Path: exe, Args: []string{"-test.run=^TestProjectToolProbe$", "--", "project-tool-version"}, VersionPattern: `^([0-9]+\.[0-9]+\.[0-9]+)$`})
	profile := policy.Runtime()
	profile.Python = &python
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	runtimePath := filepath.Join(home, "project-runtime.json")
	if err := os.WriteFile(runtimePath, body, 0600); err != nil {
		t.Fatal(err)
	}
	docPath := filepath.Join(home, "project.json")
	docRaw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(docRaw, &doc); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	doc["runtime"] = map[string]string{"path": "project-runtime.json", "sha256": hex.EncodeToString(sum[:])}
	docRaw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(docPath, docRaw, 0600); err != nil {
		t.Fatal(err)
	}
	policy, err = projectpolicy.Load(docPath, home, home)
	if err != nil {
		t.Fatal(err)
	}
	enrollProject(t, home, policy.TrustRoot(), keys)
	leaf := installedDependencyBundle(t, keys, "required", "1.0.0", `,"depends_on":[{"kind":"python","name":"sample-dep","constraint":">=1.2,<2"},{"kind":"system","name":"fixture-tool","constraint":">=1"}]`)
	installedDependencyTree(t, home, leaf, "required", "1.0.0")
	root := installedDependencyBundle(t, keys, "fetch-contract", "1.0.0", `,"depends_on":[{"kind":"skill","name":"required"}]`)
	if err := installedDependencyInstall(t, home, policy, root, nil); err != nil {
		t.Fatal(err)
	}
	old := installedDependencyOldTarget(t, home)
	if err := os.WriteFile(filepath.Join(python.SitePackages, "sample_dep.py"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installedDependencyInstall(t, home, policy, root, nil); !errors.Is(err, verify.ErrDepsUnsatisfied) {
		t.Fatalf("changed selected Python tree accepted: %v", err)
	}
	assertInstalledDependencyOldTarget(t, old)
}

func closeInstalledDependencyHandles(t *testing.T, source *installedSkillSource) {
	t.Helper()
	var held []*os.Root
	for _, p := range source.anchors {
		if p.root != nil {
			held = append(held, p.root)
		}
	}
	for _, p := range source.active {
		if p.root != nil {
			held = append(held, p.root)
		}
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	for i, root := range held {
		if _, err := root.Stat("."); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("descriptor %d remained usable after source Close: %v", i, err)
		}
	}
	if source.budget.handles != 0 {
		t.Fatalf("cleanup retained %d tracked handles", source.budget.handles)
	}
}

func TestInstalledSkillSourceBoundedInputs(t *testing.T) {
	for _, tc := range []string{"work", "entries", "path-bytes", "path-length", "depth", "handles", "canceled", "metadata-cap-plus-one", "archive-cap-plus-one"} {
		t.Run(tc, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			p := installedDependencyPolicy(t, home, keys)
			leaf := installedDependencyBundle(t, keys, "required", "1.0.0", "")
			leaf.blob = buildBundleTGZ(t, bundleSpec{name: "required", version: "1.0.0", files: map[string]string{"nested/deeper/payload.txt": "signed nested payload"}})
			leaf.digestRaw = sha256.Sum256(leaf.blob)
			leaf.digestStr = "sha256:" + hex.EncodeToString(leaf.digestRaw[:])
			installedDependencyTree(t, home, leaf, "required", "1.0.0")
			valid := newInstalledSkillSource(p)
			if artifacts, err := valid.Candidates(context.Background(), "skill", "required"); err != nil || len(artifacts) != 1 {
				t.Fatalf("uncapped control fixture: %v %v", artifacts, err)
			}
			if err := valid.Close(); err != nil {
				t.Fatal(err)
			}
			if tc == "metadata-cap-plus-one" {
				if err := os.WriteFile(filepath.Join(home, installRoot, "required", offlineMetaFile), make([]byte, (1<<20)+1), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc == "archive-cap-plus-one" {
				file, err := os.OpenFile(filepath.Join(home, installRoot, "required", "retained.skb"), os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(registry.MaxBlobSize + 1)
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatalf("sparse oversized retained-archive fixture: %v %v", err, closeErr)
				}
			}
			source := newInstalledSkillSource(p)
			switch tc {
			case "work":
				source.limits.WorkBytes = 1
			case "entries":
				source.limits.Entries = 1
			case "path-bytes":
				source.limits.PathBytes = 1
			case "path-length":
				source.limits.PathLength = 1
			case "depth":
				source.limits.Depth = 1
			case "handles":
				source.limits.Handles = 3
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc == "canceled" {
				cancel()
			}
			artifacts, err := source.Candidates(ctx, "skill", "required")
			if err == nil || len(artifacts) != 0 {
				t.Fatalf("%s cap returned authenticated candidate: %v %v", tc, artifacts, err)
			}
			// Restore the valid inputs and limits while the source remains open.
			// A second denial must be terminal state, not Close or persistent bad input.
			if tc == "metadata-cap-plus-one" || tc == "archive-cap-plus-one" {
				installedDependencyTree(t, home, leaf, "required", "1.0.0")
			}
			source.limits = defaultInstalledProofLimits
			if artifacts, err := source.Candidates(context.Background(), "skill", "required"); err == nil || len(artifacts) != 0 {
				t.Fatal("failed source reused as a successful source before Close")
			}
			closeInstalledDependencyHandles(t, source)
			if source.budget.handles != 0 {
				t.Fatalf("partial-error cleanup retained %d handles", source.budget.handles)
			}
		})
	}
	t.Run("actual-64-handle-limit", func(t *testing.T) {
		home := snapshotTestHome(t)
		keys := mkBundleFixture(t)
		p := installedDependencyPolicy(t, home, keys)
		source := newInstalledSkillSource(p)
		for i := 0; i < 62; i++ {
			name := fmt.Sprintf("held-%02d", i)
			if err := os.MkdirAll(filepath.Join(home, installRoot, name), 0700); err != nil {
				t.Fatal(err)
			}
			_, err := source.openActive(context.Background(), name)
			if i < 61 && err != nil {
				t.Fatalf("valid handle %d: %v", i, err)
			}
			if i == 61 && err == nil {
				t.Fatal("65th directory descriptor exceeded limit64")
			}
		}
		if source.budget.handles != 64 {
			t.Fatalf("held descriptors=%d want64", source.budget.handles)
		}
		closeInstalledDependencyHandles(t, source)
		if source.budget.handles != 0 {
			t.Fatal("Close retained directory descriptors")
		}
	})
}

type installedDependencyReadMutationContext struct {
	context.Context
	fire func()
	once bool
}

func (c *installedDependencyReadMutationContext) Err() error {
	if !c.once {
		var pcs [12]uintptr
		n := runtime.Callers(1, pcs[:])
		for _, pc := range pcs[:n] {
			function := runtime.FuncForPC(pc)
			if function != nil && strings.HasSuffix(function.Name(), ".(*installedProofRoot).read") {
				c.once = true
				c.fire()
				break
			}
		}
	}
	return c.Context.Err()
}

func TestInstalledSkillSourceRejectsAmbiguousOrForeignEvidence(t *testing.T) {
	for _, mode := range []string{"interior-link-after-inventory", "extra-after-inventory"} {
		t.Run(mode, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			policy := installedDependencyPolicy(t, home, keys)
			leaf := installedDependencyBundle(t, keys, "required", "1.0.0", "")
			leaf.blob = buildBundleTGZ(t, bundleSpec{name: "required", version: "1.0.0", files: map[string]string{"nested/payload.txt": "signed content"}})
			leaf.digestRaw = sha256.Sum256(leaf.blob)
			leaf.digestStr = "sha256:" + hex.EncodeToString(leaf.digestRaw[:])
			dir := installedDependencyTree(t, home, leaf, "required", "1.0.0")
			source := newInstalledSkillSource(policy)
			t.Cleanup(func() { closeInstalledDependencyHandles(t, source) })
			ctx := &installedDependencyReadMutationContext{Context: context.Background(), fire: func() {
				if mode == "interior-link-after-inventory" {
					if err := os.Rename(filepath.Join(dir, "nested"), filepath.Join(dir, "nested-moved")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("nested-moved", filepath.Join(dir, "nested")); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(filepath.Join(dir, "new-unlisted.txt"), []byte("new unsigned payload"), 0600); err != nil {
					t.Fatal(err)
				}
			}}
			candidates, err := source.Candidates(ctx, "skill", "required")
			if !ctx.once {
				t.Fatal("mutation never reached actual bounded read after inventory")
			}
			if mode == "interior-link-after-inventory" {
				info, statErr := os.Lstat(filepath.Join(dir, "nested"))
				if statErr != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatal("persistent intermediate symlink fixture was not established")
				}
			} else if raw, readErr := os.ReadFile(filepath.Join(dir, "new-unlisted.txt")); readErr != nil || string(raw) != "new unsigned payload" {
				t.Fatal("persistent extra-file fixture was not established")
			}
			if err == nil || len(candidates) != 0 {
				t.Fatal("authenticated candidate accepted a persistent post-inventory link or extra file")
			}
		})
	}
	t.Run("externally-closed-held-descriptor", func(t *testing.T) {
		home := snapshotTestHome(t)
		keys := mkBundleFixture(t)
		p := installedDependencyPolicy(t, home, keys)
		leaf := installedDependencyBundle(t, keys, "required", "1.0.0", "")
		installedDependencyTree(t, home, leaf, "required", "1.0.0")
		source := newInstalledSkillSource(p)
		held, err := source.openActive(context.Background(), "required")
		if err != nil {
			t.Fatal(err)
		}
		if err := held.root.Close(); err != nil {
			t.Fatal(err)
		}
		if err := source.Close(); err == nil {
			t.Fatal("unusable held directory descriptor was reported as healthy")
		}
		if source.budget.handles != 0 {
			t.Fatal("invalid-descriptor cleanup retained tracked handles")
		}
	})
	for _, replace := range []string{"active", "parent"} {
		t.Run("live-"+replace, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			p := installedDependencyPolicy(t, home, keys)
			leaf := installedDependencyBundle(t, keys, "required", "1.0.0", "")
			dir := installedDependencyTree(t, home, leaf, "required", "1.0.0")
			moved := dir
			if replace == "parent" {
				moved = filepath.Dir(dir)
			}
			parentBefore, err := os.Lstat(moved)
			if err != nil {
				t.Fatal(err)
			}
			childBefore, err := os.Lstat(dir)
			if err != nil {
				t.Fatal(err)
			}
			bodyBefore := make(map[string][]byte)
			for _, name := range []string{"SKILL.md", "bundle.json", "retained.skb", offlineMetaFile} {
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				bodyBefore[name] = raw
			}
			if runtime.GOOS == "windows" && replace == "parent" {
				if err := os.Rename(moved, moved+"-old"); err != nil {
					t.Fatalf("unheld parent rename preflight: %v", err)
				}
				if err := os.Rename(moved+"-old", moved); err != nil {
					t.Fatalf("unheld parent restore preflight: %v", err)
				}
			}
			source := newInstalledSkillSource(p)
			t.Cleanup(func() { closeInstalledDependencyHandles(t, source) })
			held, err := source.openActive(context.Background(), "required")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, moved+"-old"); err != nil {
				if runtime.GOOS == "windows" && replace == "parent" && errors.Is(err, syscall.Errno(5)) {
					parentAfter, statErr := os.Lstat(moved)
					if statErr != nil || !os.SameFile(parentBefore, parentAfter) {
						t.Fatal("denied rename changed parent identity")
					}
					childAfter, statErr := os.Lstat(dir)
					heldAfter, heldErr := held.root.Stat(".")
					if statErr != nil || heldErr != nil || !os.SameFile(childBefore, childAfter) || !os.SameFile(childAfter, heldAfter) {
						t.Fatal("denied rename changed active or held identity")
					}
					if _, statErr := os.Lstat(moved + "-old"); !os.IsNotExist(statErr) {
						t.Fatalf("denied rename created destination: %v", statErr)
					}
					entries, readErr := os.ReadDir(dir)
					if readErr != nil || len(entries) != len(bodyBefore) {
						t.Fatal("denied rename changed active inventory")
					}
					for name, before := range bodyBefore {
						after, readErr := os.ReadFile(filepath.Join(dir, name))
						if readErr != nil || !bytes.Equal(before, after) {
							t.Fatalf("denied rename changed retained body %q: %v", name, readErr)
						}
					}
					if err := source.validateLive(context.Background()); err != nil {
						t.Fatalf("denied rename invalidated live bindings: %v", err)
					}
					candidates, candidateErr := source.Candidates(context.Background(), "skill", "required")
					if candidateErr != nil || len(candidates) != 1 || candidates[0].Digest != leaf.digestStr || candidates[0].Authority != p.ProfileDigest() {
						t.Fatalf("unchanged signed proof after OS prevention: %v %v", candidates, candidateErr)
					}
					closeInstalledDependencyHandles(t, source)
					if err := os.Rename(moved, moved+"-old"); err != nil {
						t.Fatalf("parent rename still denied after checked descriptor release: %v", err)
					}
					if err := os.Rename(moved+"-old", moved); err != nil {
						t.Fatalf("parent restore after checked descriptor release: %v", err)
					}
					t.Log("Windows prevented ancestor rename while child descriptors were held; parent drift detector was not exercised")
					return
				}
				t.Fatalf("required directory-rename fixture unavailable: %v", err)
			}
			installedDependencyTree(t, home, leaf, "required", "1.0.0")
			// The old descriptor itself remains usable. Its live name is no longer bound.
			if _, err := held.root.Stat("SKILL.md"); err != nil {
				t.Fatalf("old descriptor fixture did not remain valid: %v", err)
			}
			if err := source.validateLive(context.Background()); err == nil {
				t.Fatal("stale descriptor accepted as the current active tree")
			}
			if artifacts, err := source.Candidates(context.Background(), "skill", "required"); err == nil || len(artifacts) != 0 {
				t.Fatal("replacement name reused old descriptor proof")
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			if source.budget.handles != 0 {
				t.Fatal("rename refusal leaked directory handles")
			}
		})
	}
	for _, name := range []string{offlineMetaFile, "retained.skb", ".DS_Store", registry.ProvenanceSidecarName, registry.AttestationStashName} {
		t.Run("symlink-"+name, func(t *testing.T) {
			home := snapshotTestHome(t)
			keys := mkBundleFixture(t)
			p := installedDependencyPolicy(t, home, keys)
			leaf := installedDependencyBundle(t, keys, "required", "1.0.0", "")
			dir := installedDependencyTree(t, home, leaf, "required", "1.0.0")
			dest := filepath.Join(home, "foreign-payload")
			if err := os.WriteFile(dest, []byte("untrusted"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := os.Symlink(dest, path); err != nil {
				t.Fatalf("required symlink fixture unavailable: %v", err)
			}
			source := newInstalledSkillSource(p)
			artifacts, err := source.Candidates(context.Background(), "skill", "required")
			if err == nil || len(artifacts) != 0 {
				t.Fatalf("exempt-name symlink returned proof: %v %v", artifacts, err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			if source.budget.handles != 0 {
				t.Fatal("symlink refusal leaked directory handles")
			}
		})
	}
}
