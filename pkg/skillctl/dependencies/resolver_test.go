package dependencies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

type fixtureSource map[string][]Artifact

func (s fixtureSource) Candidates(_ context.Context, kind, name string) ([]Artifact, error) {
	return s[kind+":"+name], nil
}
func artifact(name string, deps ...skillbundle.Dependency) Artifact {
	return Artifact{Authority: "synthetic", Kind: "skill", Name: name, Version: "1.0.0", Digest: digest([]byte(name)), Declarations: deps}
}
func dep(kind, name, constraint string) skillbundle.Dependency {
	return skillbundle.Dependency{Kind: kind, Name: name, Constraint: constraint}
}
func isolated(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	return home
}
func TestReleaseConstraints(t *testing.T) {
	for _, tc := range []struct {
		v, c    string
		ok, bad bool
	}{{"1.2.3", ">=1.0,<2", true, false}, {"1.2.3", "!=1.2.3", false, false}, {"1.2.3", "==1.2.3", true, false}, {"1.2.3", "", true, false}, {"1.2.3", ">=2", false, false}, {"1.2.3-rc1", "", false, true}, {"1.0", ">=01", false, true}, {"1.0", "^1", false, true}, {"1.0", ">=1||<3", false, true}, {"v1", "", false, true}, {"1.0", ">=18446744073709551616", false, true}} {
		t.Run(tc.v+tc.c, func(t *testing.T) {
			ok, e := matchRelease(tc.v, tc.c)
			if ok != tc.ok || (e != nil) != tc.bad {
				t.Fatalf("match=%v err=%v", ok, e)
			}
		})
	}
}
func TestProfileStrict(t *testing.T) {
	home := isolated(t)
	base := Profile{Schema: ProfileSchema, ProjectRoot: home, Tools: []Tool{}}
	b, _ := json.Marshal(base)
	if _, e := ParseProfile(b); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{`null`, `{}`, `{"schema":"x","Schema":"y"}`, string(b) + `{}`, strings.Replace(string(b), `"schema"`, `"Schema"`, 1), strings.Replace(string(b), `"tools":[]`, `"tools":[{"name":"x","path":"/x","args":[],"Version_pattern":"^(1)$"}]`, 1), strings.Replace(string(b), `"tools":[]`, `"tools":[],"unknown":true`, 1), strings.Repeat(" ", maxProfileBytes+1)} {
		if _, e := ParseProfile([]byte(raw)); !errors.Is(e, ErrInvalid) {
			t.Fatalf("accepted malformed profile")
		}
	}
	p := base
	p.Tools = []Tool{{Name: "tool", Path: "relative", VersionPattern: "^(1)$"}}
	if _, e := NewResolver(p, nil); e == nil {
		t.Fatal("relative executable accepted")
	}
}
func TestGraphAndLock(t *testing.T) {
	isolated(t)
	leaf := artifact("leaf")
	agent := artifact("worker", dep("skill", "leaf", ">=1"))
	agent.Kind = "agent"
	root := artifact("root", dep("agent", "worker", ">=1,<2"), dep("skill", "leaf", "==1"))
	src := fixtureSource{"agent:worker": {agent}, "skill:leaf": {leaf}}
	r, e := NewResolver(Profile{}, src)
	if e != nil {
		t.Fatal(e)
	}
	out, e := r.Resolve(context.Background(), root)
	if e != nil || !out.Complete || len(out.Artifacts) != 2 {
		t.Fatalf("%+v %v", out, e)
	}
	if _, e := r.Recheck(context.Background(), root, out.LockDigest); e != nil {
		t.Fatal(e)
	}
	leaf.Digest = digest([]byte("changed"))
	src["skill:leaf"] = []Artifact{leaf}
	if _, e := r.Recheck(context.Background(), root, out.LockDigest); !errors.Is(e, ErrDrift) {
		t.Fatalf("drift=%v", e)
	}
}
func TestGraphDenials(t *testing.T) {
	isolated(t)
	a := artifact("dep")
	root := artifact("root", dep("skill", "dep", ">=1"))
	cases := []struct {
		name   string
		root   Artifact
		source fixtureSource
	}{
		{"missing", root, fixtureSource{}},
		{"ambiguous", root, fixtureSource{"skill:dep": {a, func() Artifact { x := a; x.Digest = digest([]byte("other")); return x }()}}},
		{"foreign", root, fixtureSource{"skill:dep": {func() Artifact { x := a; x.Authority = "foreign"; return x }()}}},
		{"wrong-kind", root, fixtureSource{"skill:dep": {func() Artifact { x := a; x.Kind = "agent"; return x }()}}},
		{"cycle", root, fixtureSource{"skill:dep": {artifact("dep", dep("skill", "root", ">=1"))}, "skill:root": {root}}},
		{"bad-digest", root, fixtureSource{"skill:dep": {func() Artifact { x := a; x.Digest = "bad"; return x }()}}},
		{"unknown", artifact("root", dep("pip", "missing", "")), nil},
		{"conflicting", artifact("root", dep("skill", "dep", ">2")), fixtureSource{"skill:dep": {a}}},
		{"bad-constraint", artifact("root", dep("skill", "dep", "arbitrary")), nil},
		{"duplicate", artifact("root", dep("skill", "dep", ""), dep("skill", "dep", "")), nil},
		{"unprofiled-python", artifact("root", dep("python", "requests", ">=2")), nil},
		{"unprofiled-system", artifact("root", dep("system", "ffmpeg", ">=2")), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, e := NewResolver(Profile{}, tc.source)
			if e != nil {
				t.Fatal(e)
			}
			if out, e := r.Resolve(context.Background(), tc.root); e == nil || out != nil {
				t.Fatalf("false lock: %+v %v", out, e)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, _ := NewResolver(Profile{}, nil)
	if _, e := r.Resolve(ctx, artifact("root")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}
func TestToolHelper(t *testing.T) {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[len(os.Args)-2] {
	case "fixture-sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "fixture-large":
		_, _ = os.Stdout.WriteString(strings.Repeat("x", maxProbeBytes+1))
		os.Exit(0)
	case "fixture-version":
		b, e := os.ReadFile(os.Args[len(os.Args)-1])
		if e != nil {
			os.Exit(2)
		}
		_, _ = os.Stdout.Write(b)
		os.Exit(0)
	case "fixture-secret":
		if os.Getenv("SYNTHETIC_SECRET") != "" {
			os.Exit(3)
		}
		_, _ = os.Stdout.WriteString("1.2.3\n")
		os.Exit(0)
	case "fixture-error":
		_, _ = os.Stderr.WriteString("synthetic-credential-reflection")
		os.Exit(3)
	}
}
func TestSelectedSystemRuntime(t *testing.T) {
	home := isolated(t)
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	version := filepath.Join(home, "version")
	if e := os.WriteFile(version, []byte("tool 1.2.3\n"), 0600); e != nil {
		t.Fatal(e)
	}
	p := Profile{Schema: ProfileSchema, ProjectRoot: home, Tools: []Tool{{Name: "tool", Path: binary, Args: []string{"-test.run=^TestToolHelper$", "--", "fixture-version", version}, VersionPattern: `^tool ([0-9.]+)$`}}}
	r, e := NewResolver(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	root := artifact("root", dep("system", "tool", ">=1.2,<2"))
	out, e := r.Resolve(context.Background(), root)
	if e != nil || len(out.Runtime) != 1 {
		t.Fatalf("%+v %v", out, e)
	}
	if e := os.WriteFile(version, []byte("tool 1.3.0\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Recheck(context.Background(), root, out.LockDigest); !errors.Is(e, ErrDrift) {
		t.Fatal(e)
	}
	root.Declarations[0].Constraint = ">=9"
	if _, e := r.Resolve(context.Background(), root); !errors.Is(e, ErrUnresolved) {
		t.Fatal(e)
	}
	p.Tools[0].Args = []string{"-test.run=^TestToolHelper$", "--", "fixture-secret", "unused"}
	p.Tools[0].VersionPattern = `^([0-9.]+)$`
	t.Setenv("SYNTHETIC_SECRET", "synthetic-private-value")
	r, e = NewResolver(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	root.Declarations[0].Constraint = ">=1"
	if _, e := r.Resolve(context.Background(), root); e != nil {
		t.Fatal(e)
	}
	p.Tools[0].Args = []string{"-test.run=^TestToolHelper$", "--", "fixture-error", "unused"}
	r, _ = NewResolver(p, nil)
	_, e = r.Resolve(context.Background(), root)
	if e == nil || strings.Contains(e.Error(), "synthetic-credential-reflection") {
		t.Fatal("raw stderr exposed")
	}
}

func TestProbeLimitsAndCancellation(t *testing.T) {
	home := isolated(t)
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	p := Profile{Schema: ProfileSchema, ProjectRoot: home, Tools: []Tool{{Name: "tool", Path: binary, Args: []string{"-test.run=^TestToolHelper$", "--", "fixture-large", "unused"}, VersionPattern: `^([0-9.]+)$`}}}
	r, e := NewResolver(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	root := artifact("root", dep("system", "tool", ""))
	if _, e := r.Resolve(context.Background(), root); !errors.Is(e, ErrUnresolved) {
		t.Fatal(e)
	}
	p.Tools[0].Args = []string{"-test.run=^TestToolHelper$", "--", "fixture-sleep", "unused"}
	r, e = NewResolver(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, e := r.Resolve(ctx, root); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
}
func TestProfileSnapshotAndCaps(t *testing.T) {
	home := isolated(t)
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	p := Profile{Schema: ProfileSchema, ProjectRoot: home, Tools: []Tool{{Name: "tool", Path: binary, Args: []string{"-test.run=^TestToolHelper$", "--", "fixture-secret", "unused"}, VersionPattern: `^([0-9.]+)$`}}}
	r, e := NewResolver(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	p.Tools[0].Args[0] = "wrong"
	p.Tools[0].VersionPattern = "wrong"
	if _, e := r.Resolve(context.Background(), artifact("root", dep("system", "tool", ">=1"))); e != nil {
		t.Fatal(e)
	}
	chain := fixtureSource{}
	for i := 0; i < 35; i++ {
		name := fmt.Sprintf("node%d", i)
		next := fmt.Sprintf("node%d", i+1)
		chain["skill:"+name] = []Artifact{artifact(name, dep("skill", next, ""))}
	}
	r, _ = NewResolver(Profile{}, chain)
	if _, e := r.Resolve(context.Background(), artifact("root", dep("skill", "node0", ""))); !errors.Is(e, ErrUnresolved) {
		t.Fatal(e)
	}
}

func TestCatalogVersionBacktracking(t *testing.T) {
	isolated(t)
	low := artifact("a-shared")
	high := low
	high.Version = "2.0.0"
	high.Digest = digest([]byte("shared2"))
	peer := artifact("z-peer", dep("skill", "a-shared", "<2"))
	root := artifact("root", dep("skill", "a-shared", ">=1"), dep("skill", "z-peer", ""))
	src := fixtureSource{"skill:a-shared": {low, high}, "skill:z-peer": {peer}}
	r, _ := NewResolver(Profile{}, src)
	out, e := r.Resolve(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range out.Artifacts {
		if a.Name == "a-shared" && a.Version != "1.0.0" {
			t.Fatal("incoming constraint ignored")
		}
	}
	root.Declarations = []skillbundle.Dependency{dep("skill", "a-shared", ">=1")}
	out, e = r.Resolve(context.Background(), root)
	if e != nil || out.Artifacts[0].Version != "2.0.0" {
		t.Fatalf("highest not selected: %+v %v", out, e)
	}
	peer.Declarations = []skillbundle.Dependency{dep("skill", "a-shared", "<1")}
	src["skill:z-peer"] = []Artifact{peer}
	root.Declarations = append(root.Declarations, dep("skill", "z-peer", ""))
	if _, e := r.Resolve(context.Background(), root); !errors.Is(e, ErrUnresolved) {
		t.Fatal(e)
	}
}

func TestProfileByteBoundary(t *testing.T) {
	home := isolated(t)
	raw, e := json.Marshal(Profile{Schema: ProfileSchema, ProjectRoot: home, Tools: []Tool{}})
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, []byte(strings.Repeat(" ", maxProfileBytes-len(raw)))...)
	if _, e := ParseProfile(raw); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseProfile(append(raw, ' ')); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}

func TestPythonCanonicalDeclarationIdentity(t *testing.T) {
	isolated(t)
	for _, name := range []string{"demo-a", "demo.a", "demo__a", "DEMO_A"} {
		root := artifact("root", dep("python", "Demo_A", ">=1"), dep("python", name, "<2"))
		r, e := NewResolver(Profile{}, nil)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := r.Resolve(context.Background(), root); !errors.Is(e, ErrInvalid) {
			t.Fatalf("canonical alias accepted: %s %v", name, e)
		}
	}
	a := cloneArtifact(artifact("root", dep("python", "Demo__A", "")))
	if a.Declarations[0].Name != "demo-a" {
		t.Fatal("graph identity not normalized")
	}
}
func TestTypedProfilePreMarshalBounds(t *testing.T) {
	home := isolated(t)
	p := Profile{Schema: ProfileSchema, ProjectRoot: home, Tools: []Tool{}}
	huge := strings.Repeat("x", 2<<20)
	for _, bad := range []Profile{{Schema: ProfileSchema, ProjectRoot: huge}, {Schema: ProfileSchema, ProjectRoot: home, Tools: make([]Tool, 129)}, {Schema: ProfileSchema, ProjectRoot: home, Python: &Python{Path: huge, SitePackages: home, TreeDigest: strings.Repeat("a", 64)}}, {Schema: ProfileSchema, ProjectRoot: home, Tools: []Tool{{Name: "tool", Path: huge, VersionPattern: "^(1)$"}}}} {
		if typedProfileBudget(bad) {
			t.Fatal("oversized typed input precheck accepted")
		}
		if _, e := NewResolver(bad, nil); !errors.Is(e, ErrInvalid) {
			t.Fatal(e)
		}
	}
	for i := 0; i < 40; i++ {
		p.Tools = append(p.Tools, Tool{Name: fmt.Sprintf("tool%d", i), Path: filepath.Join(home, "tool"), Args: []string{strings.Repeat("a", 256)}, VersionPattern: "^(1)$"})
	}
	if typedProfileBudget(p) {
		t.Fatal("aggregate size precheck accepted")
	}
	if _, e := NewResolver(p, nil); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
}
func TestSiteTreeContract(t *testing.T) {
	home := isolated(t)
	site := filepath.Join(home, "site")
	if e := os.Mkdir(site, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(site, "empty"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(site, "a.py"), []byte("synthetic"), 0600); e != nil {
		t.Fatal(e)
	}
	_, h, e := siteFingerprint(context.Background(), site)
	if e != nil {
		t.Fatal(e)
	}
	_, again, e := siteFingerprint(context.Background(), site)
	if e != nil || again != h {
		t.Fatal("non-deterministic fingerprint")
	}
	if e := os.Remove(filepath.Join(site, "empty")); e != nil {
		t.Fatal(e)
	}
	_, changed, e := siteFingerprint(context.Background(), site)
	if e != nil || changed == h {
		t.Fatal("directory deletion not bound")
	}
	if e := os.WriteFile(filepath.Join(site, "unlisted.py"), []byte("unlisted"), 0600); e != nil {
		t.Fatal(e)
	}
	_, added, e := siteFingerprint(context.Background(), site)
	if e != nil || added == changed {
		t.Fatal("unlisted file not bound")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := siteFingerprint(ctx, site); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(site, "a.py"), filepath.Join(site, "alias")); e == nil {
		if _, _, e := siteFingerprint(context.Background(), site); !errors.Is(e, ErrUnresolved) {
			t.Fatal("symlink accepted")
		}
	}
}

func TestRuntimeReportWireField(t *testing.T) {
	isolated(t)
	r, e := NewResolver(Profile{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	report, e := r.Resolve(context.Background(), artifact("root"))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	var object map[string]json.RawMessage
	if e := json.Unmarshal(raw, &object); e != nil {
		t.Fatal(e)
	}
	if _, ok := object["runtime"]; !ok {
		t.Fatal("runtime field absent")
	}
	if _, ok := object["Runtime"]; ok {
		t.Fatal("unversioned Go field leaked")
	}
}

func TestSiteTreeGoldenAndBounds(t *testing.T) {
	home := isolated(t)
	site := filepath.Join(home, "site")
	if e := os.Mkdir(site, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(site, "a.py"), []byte("synthetic"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(site, "empty"), 0700); e != nil {
		t.Fatal(e)
	}
	expected := "m3c.python-site-tree/v1\n" + `{"path":".","kind":"dir","digest":"","size":0}` + "\n" + `{"path":"a.py","kind":"file","digest":"` + digest([]byte("synthetic")) + `","size":9}` + "\n" + `{"path":"empty","kind":"dir","digest":"","size":0}` + "\n"
	_, h, e := siteFingerprint(context.Background(), site)
	if e != nil || h != digest([]byte(expected)) {
		t.Fatalf("tree protocol drift: %v", e)
	}
	exact := treeLimits{Entries: 3, PathBytes: 10, PathLength: 5, Depth: 1, Bytes: 9}
	if _, h, e := siteFingerprintBounded(context.Background(), site, exact); e != nil || h != digest([]byte(expected)) {
		t.Fatalf("exact caps: %v", e)
	}
	for _, limit := range []treeLimits{{2, 10, 5, 1, 9}, {3, 9, 5, 1, 9}, {3, 10, 4, 1, 9}, {3, 10, 5, 0, 9}, {3, 10, 5, 1, 8}} {
		if _, _, e := siteFingerprintBounded(context.Background(), site, limit); !errors.Is(e, ErrUnresolved) {
			t.Fatalf("tree cap accepted: %+v %v", limit, e)
		}
	}
}

// countingSource keeps provider calls observable without allocating unbounded data.
type countingSource struct {
	fixtureSource
	calls int
}

func (s *countingSource) Candidates(ctx context.Context, kind, name string) ([]Artifact, error) {
	s.calls++
	return s.fixtureSource.Candidates(ctx, kind, name)
}

func TestGraphAggregateBudget(t *testing.T) {
	isolated(t)
	t.Run("retained-abandoned-pools", func(t *testing.T) {
		for _, abandoned := range []int{254, 255} {
			source := &countingSource{fixtureSource: fixtureSource{}}
			for i := 0; i < abandoned; i++ {
				name := fmt.Sprintf("leaf%d", i)
				candidate := artifact("chooser", dep("skill", name, ""))
				candidate.Version = fmt.Sprint(i + 2)
				source.fixtureSource["skill:chooser"] = append(source.fixtureSource["skill:chooser"], candidate)
				source.fixtureSource["skill:"+name] = []Artifact{artifact(name, dep("skill", "missing", ""))}
			}
			fallback := artifact("chooser")
			fallback.Version = "1"
			source.fixtureSource["skill:chooser"] = append(source.fixtureSource["skill:chooser"], fallback)
			resolver, err := NewResolver(Profile{}, source)
			if err != nil {
				t.Fatal(err)
			}
			out, err := resolver.Resolve(context.Background(), artifact("root", dep("skill", "chooser", "")))
			if abandoned == 254 {
				if err != nil || out == nil || !out.Complete || len(out.Artifacts) != 1 || out.Artifacts[0].Version != "1" {
					t.Fatalf("boundary fallback: report=%v err=%v", out, err)
				}
			} else if !errors.Is(err, ErrUnresolved) || out != nil {
				t.Fatalf("abandoned pools authorized: report=%v err=%v", out, err)
			}
			if source.calls != maxCatalogPools {
				t.Fatalf("provider calls=%d, want bounded %d", source.calls, maxCatalogPools)
			}
		}
	})
	t.Run("all-provider-candidates", func(t *testing.T) {
		for _, finalCount := range []int{255, 256} {
			source := fixtureSource{}
			root := artifact("root")
			for i := 0; i < 16; i++ {
				name := fmt.Sprintf("leaf%d", i)
				root.Declarations = append(root.Declarations, dep("skill", name, ""))
				count := 256
				if i == 15 {
					count = finalCount
				}
				for j := 0; j < count; j++ {
					candidate := artifact(name)
					candidate.Version = fmt.Sprint(j + 1)
					source["skill:"+name] = append(source["skill:"+name], candidate)
				}
			}
			resolver, err := NewResolver(Profile{}, source)
			if err != nil {
				t.Fatal(err)
			}
			out, err := resolver.Resolve(context.Background(), root)
			if finalCount == 255 {
				if err != nil || out == nil || !out.Complete {
					t.Fatalf("candidate boundary: %v", err)
				}
			} else if !errors.Is(err, ErrUnresolved) || out != nil {
				t.Fatalf("candidate cap+1 authorized: %v", err)
			}
		}
	})
	t.Run("unselected-declaration-slots", func(t *testing.T) {
		for _, finalCount := range []int{255, 256} {
			source := fixtureSource{"skill:chooser": {artifact("chooser")}}
			source["skill:chooser"][0].Version = "1000"
			for i := 0; i < 64; i++ {
				candidate := artifact("chooser")
				candidate.Version = fmt.Sprint(i + 1)
				count := 256
				if i == 63 {
					count = finalCount
				}
				for j := 0; j < count; j++ {
					candidate.Declarations = append(candidate.Declarations, dep("skill", fmt.Sprintf("unused%d", j), ""))
				}
				source["skill:chooser"] = append(source["skill:chooser"], candidate)
			}
			resolver, err := NewResolver(Profile{}, source)
			if err != nil {
				t.Fatal(err)
			}
			out, err := resolver.Resolve(context.Background(), artifact("root", dep("skill", "chooser", "")))
			if finalCount == 255 {
				if err != nil || out == nil || !out.Complete {
					t.Fatalf("declaration boundary: %v", err)
				}
			} else if !errors.Is(err, ErrUnresolved) || out != nil {
				t.Fatalf("declaration cap+1 authorized: %v", err)
			}
		}
	})
	t.Run("all-unselected-field-bytes", func(t *testing.T) {
		for _, count := range []int{25, 26} {
			source := fixtureSource{"skill:chooser": {artifact("chooser")}}
			source["skill:chooser"][0].Version = "1000"
			for i := 0; i < count; i++ {
				candidate := artifact("chooser")
				candidate.Version = fmt.Sprint(i + 1)
				for j := 0; j < 256; j++ {
					candidate.Declarations = append(candidate.Declarations, dep("python", fmt.Sprintf("p%0127d", j), strings.Repeat("x", 512)))
				}
				source["skill:chooser"] = append(source["skill:chooser"], candidate)
			}
			resolver, err := NewResolver(Profile{}, source)
			if err != nil {
				t.Fatal(err)
			}
			out, err := resolver.Resolve(context.Background(), artifact("root", dep("skill", "chooser", "")))
			if count == 25 {
				if err != nil || out == nil || !out.Complete {
					t.Fatalf("bounded field pool: %v", err)
				}
			} else if !errors.Is(err, ErrUnresolved) || out != nil {
				t.Fatalf("unselected fields escaped byte cap: %v", err)
			}
		}
	})
	t.Run("field-byte-boundary-and-invalid-utf8", func(t *testing.T) {
		a := artifact("root", dep("python", "demo", ">=1"))
		used := len(a.Authority) + len(a.Kind) + len(a.Name) + len(a.Version) + len(a.Digest)
		for _, d := range a.Declarations {
			used += len(d.Kind) + len(d.Name) + len(d.Constraint)
		}
		boundary := catalogBudget{fieldBytes: maxCatalogFieldBytes - used}
		if err := boundary.reserveArtifact(a); err != nil || boundary.fieldBytes != maxCatalogFieldBytes {
			t.Fatalf("field boundary: %v", err)
		}
		over := catalogBudget{fieldBytes: maxCatalogFieldBytes - used + 1}
		if err := over.reserveArtifact(a); !errors.Is(err, ErrUnresolved) {
			t.Fatalf("field cap+1: %v", err)
		}
		for _, bad := range []Artifact{
			{Authority: strings.Repeat("x", maxCatalogFieldBytes+1)},
			{Authority: string([]byte{0xff})},
		} {
			resolver, err := NewResolver(Profile{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if out, err := resolver.Resolve(context.Background(), bad); err == nil || out != nil {
				t.Fatalf("malformed or oversized fields authorized: %v", err)
			}
		}
	})
	t.Run("duplicate-candidates-charged-before-clone", func(t *testing.T) {
		budget := catalogBudget{candidates: maxCatalogCandidates - 1}
		a := artifact("duplicate")
		if err := budget.reserveArtifact(a); err != nil {
			t.Fatal(err)
		}
		if err := budget.reserveArtifact(a); !errors.Is(err, ErrUnresolved) {
			t.Fatalf("duplicate escaped candidate budget: %v", err)
		}
	})
	t.Run("version-byte-cap", func(t *testing.T) {
		maximum := strings.Repeat("18446744073709551615.", 3) + "18446744073709551615"
		if _, err := release(maximum); err != nil {
			t.Fatalf("maximum uint64 tuple rejected: %v", err)
		}
		if _, err := release(maximum + "0"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("overlong version accepted: %v", err)
		}
	})
}
