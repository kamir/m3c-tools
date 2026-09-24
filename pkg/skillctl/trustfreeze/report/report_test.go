package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/policy"
)

func TestCaptureReportGolden(t *testing.T) {
	b := writeCapture(t, t.TempDir(), "capture", trustfreeze.KindCapture, testTime, "24.04", 0)
	r, err := FromBundle(b)
	got := mustReport(t, r, err)
	if r.Approval != nil || r.Signature != nil || r.Diff != nil || r.Verdict != nil {
		t.Fatalf("capture report carries baseline or diff sections: %+v", r)
	}
	if r.Capture.Completeness.Status != trustfreeze.CompletenessComplete || len(r.Capture.ProbeResults) != 2 {
		t.Fatalf("capture section = %+v", r.Capture)
	}
	if bytes.Contains(got, []byte(b.Dir)) {
		t.Fatal("report contains the bundle directory")
	}
	checkGolden(t, "report_capture.golden", got)
}

func TestBaselineReportGolden(t *testing.T) {
	dir := t.TempDir()
	b := writeCapture(t, dir, "baseline", trustfreeze.KindBaseline, testTime, "24.04", 0)
	r, err := FromBundle(b)
	got := mustReport(t, r, err)
	// SPEC-0469 section 4.7: a projection evaluates no signature, trust or
	// expiry; it says so and names the command that does.
	if r.Signature == nil || *r.Signature != (SignatureStatus{Result: SignatureNotEvaluated, VerifyWith: SignatureVerifyWith}) {
		t.Fatalf("signature = %+v", r.Signature)
	}
	if r.Approval["reviewer"] != "id:charlie@example" || r.Approval["schema_version"] != trustfreeze.SchemaApproval {
		t.Fatalf("approval = %v", r.Approval)
	}
	checkGolden(t, "report_baseline.golden", got)
}

// The diff report projects diff and verdict unchanged: same bytes whether it
// comes from memory or from a stored diff bundle, and no decision of its own.
func TestDiffReportGolden(t *testing.T) {
	dir := t.TempDir()
	_, _, d, v := scenario(t, dir)
	r, err := FromDiff(d, &v)
	got := mustReport(t, r, err)
	checkGolden(t, "report_diff.golden", got)

	want, err := trustfreeze.MarshalCanonical(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compactField(t, got, "verdict"), want) {
		t.Fatal("report verdict differs from the evaluated verdict")
	}

	rb, err := FromBundle(writeDiffBundle(t, dir, d, &v))
	if err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string][2]any{"diff": {rb.Diff, r.Diff}, "verdict": {rb.Verdict, r.Verdict}} {
		a, err := trustfreeze.MarshalCanonical(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := trustfreeze.MarshalCanonical(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("%s from the diff bundle differs from the in-memory one", name)
		}
	}
	if rb.Input.Kind != trustfreeze.KindDiff || rb.Input.ContentDigest == "" || rb.Input.DiffDigest != r.Input.DiffDigest {
		t.Fatalf("diff bundle input = %+v", rb.Input)
	}
}

// compactField returns the compact bytes of one top-level field of doc, for a
// byte comparison with MarshalCanonical output.
func compactField(t *testing.T, doc []byte, field string) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := json.Compact(&out, m[field]); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// TF04-R9: the same inputs give byte-identical reports, also from bundles
// written to different directories.
func TestReportsByteIdentical(t *testing.T) {
	var caps, bases, diffs [][]byte
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		bl, cur, d, v := scenario(t, dir)
		r, err := FromBundle(cur)
		caps = append(caps, mustReport(t, r, err))
		r, err = FromBundle(bl)
		bases = append(bases, mustReport(t, r, err))
		r, err = FromBundle(writeDiffBundle(t, dir, d, &v))
		diffs = append(diffs, mustReport(t, r, err))
	}
	for name, pair := range map[string][][]byte{"capture": caps, "baseline": bases, "diff": diffs} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Errorf("%s reports differ between runs", name)
		}
	}
}

func TestReportRejects(t *testing.T) {
	dir := t.TempDir()
	_, _, d, v := scenario(t, dir)

	if _, err := FromBundle(nil); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("nil: %v", err)
	}
	if _, err := FromBundle(&trustfreeze.Bundle{Integrity: trustfreeze.IntegrityResult{OK: false}}); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("unverified: %v", err)
	}

	// A verdict that judged another diff is refused.
	other := d
	other.Changes = []compare.Change{}
	other.Counts = map[string]int{}
	for _, k := range compare.ChangeKinds() {
		other.Counts[string(k)] = 0
	}
	if _, err := FromDiff(other, &v); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("foreign verdict: %v", err)
	}
	// A verdict whose own arithmetic is broken is refused.
	bad := v
	bad.ThresholdExceeded = !v.ThresholdExceeded
	if _, err := FromDiff(d, &bad); !errors.Is(err, policy.ErrInvalidVerdict) {
		t.Fatalf("broken verdict: %v", err)
	}
	// A diff without verdict is a valid, smaller report.
	if r, err := FromDiff(d, nil); err != nil || r.Verdict != nil {
		t.Fatalf("diff only: %v", err)
	}
	// An unknown kind is refused.
	if _, err := FromBundle(&trustfreeze.Bundle{Integrity: trustfreeze.IntegrityResult{OK: true}, Manifest: trustfreeze.Manifest{Kind: "snapshot"}}); !errors.Is(err, ErrUnsupportedInput) {
		t.Fatalf("unknown kind: %v", err)
	}
}

func TestApprovalProjectionNumbers(t *testing.T) {
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"a":[1,{"b":2}],"c":"x"}`))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		t.Fatal(err)
	}
	v, err := integersOnly(obj)
	if err != nil {
		t.Fatal(err)
	}
	b, err := trustfreeze.MarshalCanonical(v)
	if err != nil || string(b) != `{"a":[1,{"b":2}],"c":"x"}` {
		t.Fatalf("%s %v", b, err)
	}
	dec = json.NewDecoder(strings.NewReader(`{"a":1.5}`))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		t.Fatal(err)
	}
	if _, err := integersOnly(obj); !errors.Is(err, ErrUnsupportedInput) {
		t.Fatalf("float accepted: %v", err)
	}
}

const (
	testModule = "github.com/kamir/m3c-tools"
	testTree   = testModule + "/pkg/skillctl/trustfreeze"
)

// forbiddenFromReport are the packages compare, policy and report must never
// reach: signing (SPEC-0470 section 4.8) and probe execution.
var forbiddenFromReport = []string{testTree + "/seal", testTree + "/probe", testTree + "/capture", testTree + "/platform"}

// SPEC-0470 section 4.8 and TF05-R2: compare, policy and report never reach
// seal, nor probe execution, neither directly nor through another trustfreeze
// package.
func TestNoSealOrProbeImport(t *testing.T) {
	seen, hit := reachable(t, moduleRoot(t), []string{testTree + "/compare", testTree + "/policy", testTree + "/report"})
	if hit != "" {
		t.Fatalf("%s is reachable from compare, policy or report", hit)
	}
	// The walk must have followed imports into the core, otherwise it proves
	// nothing.
	if !seen[testTree] || !seen[testTree+"/redact"] {
		t.Fatalf("walk did not reach the core: %v", seen)
	}
}

// The guard finds a planted seal import two packages deep.
func TestNoSealImportGuardFindsPlantedImport(t *testing.T) {
	root := t.TempDir()
	plant := func(pkg, imp string) {
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(pkg, testModule+"/")))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		src := "package x\n"
		if imp != "" {
			src += "import _ \"" + imp + "\"\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plant(testTree+"/report", testTree+"/policy")
	plant(testTree+"/policy", testTree+"/seal")
	plant(testTree+"/seal", "")
	if _, hit := reachable(t, root, []string{testTree + "/report"}); hit != testTree+"/seal" {
		t.Fatalf("planted seal import not found (hit %q)", hit)
	}
}

// reachable walks the module-internal imports of the non-test Go files of
// starts and returns every visited package and the first forbidden one.
func reachable(t *testing.T, root string, starts []string) (map[string]bool, string) {
	t.Helper()
	seen := map[string]bool{}
	queue := slices.Clone(starts)
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		for _, f := range forbiddenFromReport {
			if pkg == f || strings.HasPrefix(pkg, f+"/") {
				return seen, pkg
			}
		}
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(pkg, testModule+"/")))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		files := 0
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			files++
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(p, testModule+"/") {
					queue = append(queue, p)
				}
			}
		}
		if files == 0 {
			t.Fatalf("no Go files in %s", dir)
		}
	}
	return seen, ""
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
