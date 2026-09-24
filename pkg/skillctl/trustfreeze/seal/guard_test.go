package seal

import (
	"errors"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const sealImportPath = "github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/seal"

// fileImports returns the import paths of one Go file.
func fileImports(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := make([]string, 0, len(f.Imports))
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

// SPEC-0470 section 4.8 (TF05-R2, TF05-R6): capture, compare, policy,
// report, the platform packages, probe and redact never import seal, in
// production code or tests, so no path besides the explicit approve command
// can create a baseline. Directories that do not exist yet are listed as
// such; the test checks whatever exists and logs what it checked.
func TestNoAutomaticBaselineImportGuard(t *testing.T) {
	dirs := []string{"../capture", "../compare", "../policy", "../report", "../platform", "../probe", "../redact"}
	total := 0
	for _, d := range dirs {
		if _, err := os.Stat(d); errors.Is(err, fs.ErrNotExist) {
			t.Logf("%s: does not exist yet, nothing to check", d)
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		n := 0
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() && e.Name() == "testdata" {
				return filepath.SkipDir
			}
			if e.IsDir() || !strings.HasSuffix(p, ".go") {
				return nil
			}
			n++
			for _, imp := range fileImports(t, p) {
				if imp == sealImportPath || strings.HasPrefix(imp, sealImportPath+"/") {
					t.Errorf("%s imports %s (SPEC-0470 section 4.8: only the CLI may wire approval)", filepath.ToSlash(p), imp)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: checked %d .go files", d, n)
		total += n
	}
	// The core cannot import seal (that would be a cycle); check it anyway so
	// the guard does not depend on the compiler's error message.
	core, err := filepath.Glob("../*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range core {
		for _, imp := range fileImports(t, p) {
			if imp == sealImportPath {
				t.Errorf("%s imports seal", p)
			}
		}
	}
	t.Logf("core: checked %d .go files; guarded packages: %d .go files in total", len(core), total)
}

// TF05-AC1: the seal package has no network code path. Its own imports
// contain no networking, TLS or process execution package.
func TestSealPackageHasNoNetworkImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		checked++
		for _, imp := range fileImports(t, f) {
			if imp == "net" || strings.HasPrefix(imp, "net/") || imp == "crypto/tls" || imp == "os/exec" || imp == "plugin" {
				t.Errorf("%s imports %s", f, imp)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no production files found")
	}
	t.Logf("checked the imports of %d production files", checked)
}

// sealForbidden reports whether a package seal must never reach, directly or
// transitively: HTTP, TLS, RPC, mail, process execution and plugins.
func sealForbidden(pkg string) bool {
	switch pkg {
	case "net/http", "crypto/tls", "os/exec", "net/rpc", "net/smtp", "plugin", "expvar":
		return true
	}
	return strings.HasPrefix(pkg, "net/http/") || strings.HasPrefix(pkg, "net/rpc/")
}

// sealThirdParty lists the only modules outside the repository and the
// standard library that seal's graph may import (see go.mod; no new
// dependencies). They are not scanned: a clean host may not have them.
var sealThirdParty = []string{"gopkg.in/yaml.v3", "golang.org/x/sys/"}

// moduleRoot returns the directory of go.mod above the package and the
// module path it declares.
func moduleRoot(t *testing.T) (string, string) {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if mod, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
					return dir, strings.Trim(strings.TrimSpace(mod), `"`)
				}
			}
			t.Fatalf("%s/go.mod declares no module", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the seal package")
		}
		dir = parent
	}
}

// depGraph is an import graph: package path to its imports.
type depGraph map[string][]string

// scanRepo adds pkg and every in-repository package it reaches to g. Every
// non-test .go file counts, whatever its build constraints, so the scan
// covers every platform at once. It returns the imports that leave the
// repository.
func scanRepo(t *testing.T, g depGraph, modRoot, modPath, pkg string) []string {
	t.Helper()
	var external []string
	queue := []string{pkg}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if _, done := g[p]; done {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, modPath), "/")
		files, err := filepath.Glob(filepath.Join(modRoot, filepath.FromSlash(rel), "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		g[p] = nil
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			for _, imp := range fileImports(t, f) {
				if seen[imp] || imp == "C" {
					continue
				}
				seen[imp] = true
				g[p] = append(g[p], imp)
				if imp == modPath || strings.HasPrefix(imp, modPath+"/") {
					queue = append(queue, imp)
				} else {
					external = append(external, imp)
				}
			}
		}
		if len(g[p]) == 0 && len(files) == 0 {
			t.Fatalf("package %s has no Go files under %s", p, modRoot)
		}
	}
	return external
}

// scanStd adds the standard library packages reachable from roots to g, as
// go/build selects their files for goos (cgo off). A path resolves to
// GOROOT/src/<path>, else to the standard library's vendor directory. Only
// ImportDir is used: go/build never runs the go command for a directory.
func scanStd(t *testing.T, g depGraph, goroot, goos string, roots []string) {
	t.Helper()
	ctx := build.Default
	ctx.GOROOT, ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = goroot, goos, "amd64", false
	queue := append([]string(nil), roots...)
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		key := goos + ":" + p
		if _, done := g[key]; done {
			continue
		}
		dir := filepath.Join(goroot, "src", filepath.FromSlash(p))
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			dir = filepath.Join(goroot, "src", "vendor", filepath.FromSlash(p))
		}
		bp, err := ctx.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("%s: standard library package %s: %v", goos, p, err)
		}
		g[key] = bp.Imports
		for _, imp := range bp.Imports {
			if imp != "C" {
				queue = append(queue, imp)
			}
		}
	}
}

// TF05-AC1: the same holds for the transitive dependency graph of the seal
// package (tests excluded): no net/http, TLS or process execution anywhere,
// the only importer of package net is crypto/x509 (which needs its IP
// address types to parse certificates, used here only for PEM key parsing),
// and no module outside the repository, the standard library and the
// allowed third-party list. The scan reads Go sources only: go/parser for
// the repository packages (every build constraint at once) and go/build for
// the standard library under GOROOT (linux, darwin and windows). It never
// runs the go command, so it needs no module cache and no network and works
// the same on a clean host.
func TestSealDependencyGraphHasNoNetworkPackages(t *testing.T) {
	modRoot, modPath := moduleRoot(t)
	repo := depGraph{}
	external := scanRepo(t, repo, modRoot, modPath, sealImportPath)
	var stdRoots []string
	for _, imp := range external {
		first, _, _ := strings.Cut(imp, "/")
		switch {
		case imp == "net" || strings.HasPrefix(imp, "golang.org/x/net") || sealForbidden(imp):
			t.Errorf("a repository package in seal's graph imports %s", imp)
		case !strings.Contains(first, "."):
			stdRoots = append(stdRoots, imp)
		case !slices.ContainsFunc(sealThirdParty, func(a string) bool { return imp == strings.TrimSuffix(a, "/") || strings.HasPrefix(imp, a) }):
			t.Errorf("seal's graph imports %s, which is neither in the repository, the standard library nor the allowed modules %v", imp, sealThirdParty)
		}
	}
	if len(repo) < 3 {
		t.Fatalf("scanned only %d repository packages: %v", len(repo), repo)
	}

	goroot := build.Default.GOROOT
	if fi, err := os.Stat(filepath.Join(goroot, "src", "crypto", "x509")); goroot == "" || err != nil || !fi.IsDir() {
		// The repository part above ran; say plainly what did not.
		t.Logf("standard library sources not found under GOROOT %q: the transitive standard library scan did not run", goroot)
		return
	}
	std := depGraph{}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		scanStd(t, std, goroot, goos, stdRoots)
	}
	var netImporters []string
	for key, imports := range std {
		_, pkg, _ := strings.Cut(key, ":")
		if sealForbidden(pkg) {
			t.Errorf("seal depends on %s (%s)", pkg, key)
		}
		if slices.Contains(imports, "net") && !slices.Contains(netImporters, pkg) {
			netImporters = append(netImporters, pkg)
		}
	}
	sort.Strings(netImporters)
	for _, p := range netImporters {
		if p != "crypto/x509" {
			t.Errorf("%s imports package net", p)
		}
	}
	if len(std) < 30 {
		t.Fatalf("the standard library scan reached only %d packages", len(std))
	}
	t.Logf("scanned %d repository packages and %d standard library packages (3 platforms); importers of net: %v", len(repo), len(std), netImporters)
}

// The scan finds what it must find: a planted forbidden import in a
// repository package, a planted importer of net, and a planted third-party
// module; and the standard library scan does reach net/http from a planted
// root that imports it.
func TestSealDependencyScanFindsPlantedImports(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.test/planted\n")
	write("a/a.go", "package a\nimport (\n_ \"example.test/planted/b\"\n_ \"os\"\n)\n")
	write("b/b_windows.go", "package b\nimport _ \"net/http\"\n")
	write("b/b.go", "package b\nimport _ \"github.com/evil/netlib\"\n")
	write("b/b_test.go", "package b\nimport _ \"os/exec\"\n")
	g := depGraph{}
	external := scanRepo(t, g, root, "example.test/planted", "example.test/planted/a")
	slices.Sort(external)
	if want := []string{"github.com/evil/netlib", "net/http", "os"}; !slices.Equal(external, want) {
		t.Fatalf("external imports %q, want %q (a build-constrained file counts, a test file does not)", external, want)
	}
	if !sealForbidden("net/http") || !sealForbidden("net/http/httptest") || sealForbidden("net/netip") {
		t.Fatal("sealForbidden misclassifies")
	}
	goroot := build.Default.GOROOT
	if _, err := os.Stat(filepath.Join(goroot, "src", "net", "http")); goroot == "" || err != nil {
		t.Logf("standard library sources not found under GOROOT %q: planted standard library check skipped", goroot)
		return
	}
	std := depGraph{}
	scanStd(t, std, goroot, "linux", []string{"expvar"})
	if _, ok := std["linux:net/http"]; !ok {
		t.Fatal("the standard library scan does not reach net/http from expvar")
	}
}
