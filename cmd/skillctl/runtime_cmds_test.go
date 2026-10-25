package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/dependencies"
)

func runtimeFingerprintCLI(t *testing.T, binary, home, cwd string, args ...string) ([]byte, []byte, int) {
	t.Helper()
	cmd := exec.Command(binary, append([]string{"runtime"}, args...)...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home, "M3C_TOKEN_STORE=file", "M3C_TEST_KEYCHAIN=0", "M3C_ER1_KEYCHAIN=off", "PATH="+filepath.Join(home, "decoy"), "PYTHONPATH="+filepath.Join(home, "not-selected"), "M3C_RUNTIME_CHILD_MARKER="+filepath.Join(home, "unexpected-child"))
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	err := cmd.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return out.Bytes(), errout.Bytes(), code
}

func runtimeInventory(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if entry.IsDir() {
			out[rel] = "directory"
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		out[rel] = hex.EncodeToString(h[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRuntimeFingerprintActualCLI(t *testing.T) {
	binary := skillctlBin(t)
	home := t.TempDir()
	venvRoot := filepath.Join(home, "env with space")
	tree := filepath.Join(venvRoot, "Lib", "site-packages")
	cwd := filepath.Join(home, "foreign")
	for _, p := range []string{tree, cwd, filepath.Join(tree, "empty"), filepath.Join(home, ".claude", "mutation-state"), filepath.Join(home, "decoy")} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tree, "a.py"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	// These existing records are deliberately opaque. Observation cannot rewrite,
	// approve, enroll or repair them.
	for _, p := range []string{"runtime-profile.json", "project-profile.json", ".claude/mutation-state/record.json"} {
		if err := os.WriteFile(filepath.Join(home, filepath.FromSlash(p)), []byte("existing unapproved record"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	decoySource := filepath.Join(t.TempDir(), "decoy.go")
	if err := os.WriteFile(decoySource, []byte("package main\nimport \"os\"\nfunc main(){if err:=os.WriteFile(os.Getenv(\"M3C_RUNTIME_CHILD_MARKER\"),[]byte(\"unexpected child\"),0600);err!=nil{os.Exit(98)};os.Exit(99)}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	decoyName := "python"
	if runtime.GOOS == "windows" {
		decoyName = "python.exe"
	}
	build := exec.Command("go", "build", "-o", filepath.Join(home, "decoy", decoyName), decoySource)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic PATH decoy: %v %s", err, output)
	}
	before := runtimeInventory(t, home)
	raw, stderr, code := runtimeFingerprintCLI(t, binary, home, cwd, "fingerprint", "--json", "--path", tree)
	if code != 0 {
		t.Fatalf("actual runtime CLI exit=%d stderr=%s output=%s", code, stderr, raw)
	}
	var result runtimeTreeResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	fileHash := sha256.Sum256([]byte("synthetic"))
	golden := "m3c.python-site-tree/v1\n" + `{"path":".","kind":"dir","digest":"","size":0}` + "\n" + `{"path":"a.py","kind":"file","digest":"` + hex.EncodeToString(fileHash[:]) + `","size":9}` + "\n" + `{"path":"empty","kind":"dir","digest":"","size":0}` + "\n"
	want := sha256.Sum256([]byte(golden))
	canonical, err := filepath.EvalSymlinks(tree)
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != "m3c.skillctl.runtime-tree-observation/v1" || result.Operation != "runtime_fingerprint" || !result.OK || result.ExitCode != 0 || result.TreeObservation == nil || result.Algorithm != "m3c.python-site-tree/v1" || result.Path != canonical || result.Digest != hex.EncodeToString(want[:]) || !result.Complete || result.Approved {
		t.Fatalf("observation contract differs: %+v", result)
	}
	if result.Limits.Entries != 100000 || result.Limits.PathBytes != 4<<20 || result.Limits.PathLength != 4096 || result.Limits.Depth != 128 || result.Limits.Bytes != 256<<20 {
		t.Fatalf("wrong observation limits: %+v", result.Limits)
	}
	human, _, humanCode := runtimeFingerprintCLI(t, binary, home, cwd, "fingerprint", "--path", tree)
	if humanCode != 0 || !bytes.Contains(human, []byte(strconv.Quote(canonical))) || !bytes.Contains(human, []byte("does not approve")) {
		t.Fatalf("human path/approval boundary missing: %s", human)
	}
	if !bytes.Contains(raw, []byte(`"approved":false`)) {
		t.Fatal("approval false omitted")
	}
	// A successful observation must not supply or learn an accepted baseline.
	profile := dependencies.Profile{Schema: dependencies.ProfileSchema, ProjectRoot: cwd, Python: &dependencies.Python{Path: binary, SitePackages: tree, TreeDigest: strings.Repeat("0", 64)}, Tools: []dependencies.Tool{}}
	if runtime.GOOS == "windows" {
		// A structurally valid explicit venv selection reaches the wrong site
		// baseline check before any interpreter or root-content read.
		profile.Python.Path = filepath.Join(venvRoot, "Scripts", "python.exe")
		profile.Python.InterpreterRootDigest = strings.Repeat("0", 64)
	}
	resolver, err := dependencies.NewResolver(profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.Resolve(context.Background(), dependencies.Artifact{Authority: "synthetic", Kind: "skill", Name: "root", Version: "1", Digest: strings.Repeat("1", 64), Declarations: []skillbundle.Dependency{{Kind: "python", Name: "demo", Constraint: ">=1"}}})
	if !errors.Is(err, dependencies.ErrDrift) {
		t.Fatalf("observation approved wrong baseline: %v", err)
	}
	again, _, code := runtimeFingerprintCLI(t, binary, home, cwd, "fingerprint", "--json", "--path", tree)
	if code != 0 || !bytes.Equal(raw, again) {
		t.Fatal("repeated observation changed output")
	}
	after := runtimeInventory(t, home)
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	if !bytes.Equal(b, a) {
		t.Fatal("read-only diagnostic changed the observed tree or persisted configuration inventory")
	}
}

func TestRuntimeFingerprintUsageBeforeReads(t *testing.T) {
	binary := skillctlBin(t)
	home := t.TempDir()
	cwd := t.TempDir()
	for _, args := range [][]string{{"fingerprint", "--json"}, {"fingerprint", "--json", "--path", "relative"}, {"fingerprint", "--json", "--unknown"}, {"fingerprint", "--json", "--path", filepath.Join(home, "missing"), "extra"}} {
		out, _, code := runtimeFingerprintCLI(t, binary, home, cwd, args...)
		if code != 2 {
			t.Fatalf("usage %v exit=%d output=%s", args, code, out)
		}
		var r runtimeTreeResult
		if json.Unmarshal(out, &r) != nil || r.OK || r.ExitCode != 2 || r.TreeObservation != nil {
			t.Fatalf("usage JSON claims observation: %s", out)
		}
	}
	out, _, code := runtimeFingerprintCLI(t, binary, home, cwd, "fingerprint", "--json", "--path", filepath.Join(home, "missing"))
	if code != 1 {
		t.Fatalf("missing tree exit=%d", code)
	}
	var r runtimeTreeResult
	if json.Unmarshal(out, &r) != nil || r.OK || r.ExitCode != 1 || r.TreeObservation != nil {
		t.Fatalf("failed tree claimed observation: %s", out)
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 0 {
		t.Fatal("usage or missing path created state")
	}
}

type runtimeBrokenWriter struct{ short bool }

func (w runtimeBrokenWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, io.ErrClosedPipe
}
func TestRuntimeFingerprintOutputFailure(t *testing.T) {
	tree := t.TempDir()
	for _, args := range [][]string{{"fingerprint", "--path", tree}, {"fingerprint", "--json", "--path", tree}, {"--help"}, {"fingerprint", "--help"}} {
		for _, short := range []bool{false, true} {
			if code := runRuntime(args, runtimeBrokenWriter{short}, io.Discard); code != 1 {
				t.Fatalf("writer failure exit=%d args=%v short=%v", code, args, short)
			}
		}
	}
}
