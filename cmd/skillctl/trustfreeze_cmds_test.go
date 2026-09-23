package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/homeroot"
)

// tfSubcommandFlags pins the flag surface of every subcommand to the CLI
// contract (SPEC-0466 section 5.9, SPEC-0469 section 3.6, SPEC-0470 section
// 4.9).
var tfSubcommandFlags = map[string][]string{
	"doctor":           {"profile", "output", "format"},
	"capture":          {"profile", "output", "actor", "force", "project", "policy", "probe", "exclude-probe", "timeout", "format"},
	"diff":             {"baseline", "current", "trust-policy", "trusted-key", "policy", "fail-on", "allow-subject-mismatch", "output", "format"},
	"baseline approve": {"capture", "output", "reviewer", "change-id", "reason", "key", "expires-at", "self-approval", "format"},
	"verify":           {"bundle", "trust-policy", "trusted-key", "format"},
	"report":           {"input", "output", "format"},
}

// tfSupportedWord matches "supported" as a claim, not inside "unsupported".
var tfSupportedWord = regexp.MustCompile(`(^|[^a-z])supported`)

func tfRun(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := runTrustFreeze(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestTrustFreezeUsage(t *testing.T) {
	code, out, errOut := tfRun()
	if code != exitUsage || out != "" || !strings.Contains(errOut, "Usage: skillctl trust-freeze") {
		t.Fatalf("no args: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
	for _, h := range []string{"help", "-h", "--help"} {
		code, out, _ = tfRun(h)
		if code != exitOK {
			t.Fatalf("%s: exit %d", h, code)
		}
		for _, sub := range []string{"doctor", "capture", "baseline approve", "verify", "diff", "report"} {
			if !strings.Contains(out, "  "+sub+" ") {
				t.Fatalf("%s: usage does not list %q:\n%s", h, sub, out)
			}
		}
		if !strings.Contains(out, "Full platform support is not established") {
			t.Fatalf("%s: usage makes no platform statement", h)
		}
	}
	for _, args := range [][]string{{"bogus"}, {"baseline"}, {"baseline", "show"}, {"approve"}} {
		if code, _, _ := tfRun(args...); code != exitUsage {
			t.Fatalf("%v: exit %d, want %d", args, code, exitUsage)
		}
	}
}

// TestTrustFreezeSubcommandFlags checks --help per subcommand and that the
// registered flags are exactly the contract's.
func TestTrustFreezeSubcommandFlags(t *testing.T) {
	for sub, want := range tfSubcommandFlags {
		args := append(strings.Fields(sub), "--help")
		code, _, errOut := tfRun(args...)
		if code != exitOK {
			t.Fatalf("%s --help: exit %d", sub, code)
		}
		if !strings.Contains(errOut, "Usage: skillctl trust-freeze "+sub) {
			t.Fatalf("%s --help: no usage line:\n%s", sub, errOut)
		}
		for _, f := range want {
			if !strings.Contains(errOut, "-"+f+" ") && !strings.Contains(errOut, "-"+f+"\n") {
				t.Fatalf("%s --help does not show -%s:\n%s", sub, f, errOut)
			}
		}
		// Exactly these flags: count the flag lines flag.PrintDefaults wrote.
		n := 0
		for _, line := range strings.Split(errOut, "\n") {
			if strings.HasPrefix(line, "  -") {
				n++
			}
		}
		if n != len(want) {
			t.Fatalf("%s: %d flags registered, contract has %d:\n%s", sub, n, len(want), errOut)
		}
	}
}

func TestTrustFreezeFlagErrors(t *testing.T) {
	dir := t.TempDir()
	notJSON := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(notJSON, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string // substring of stderr
	}{
		{"unknown flag", []string{"verify", "--bogus"}, "flag provided but not defined"},
		{"stray argument", []string{"verify", "--bundle", dir, "extra"}, "unexpected argument"},
		{"bad format", []string{"verify", "--bundle", dir, "--format", "yaml"}, "--format"},
		{"diff markdown", []string{"diff", "--baseline", dir, "--current", dir, "--format", "markdown"}, "not implemented in this version"},
		{"diff sarif", []string{"diff", "--baseline", dir, "--current", dir, "--format", "sarif"}, "not implemented in this version"},
		{"report markdown", []string{"report", "--input", dir, "--output", dir, "--format", "markdown"}, "not implemented in this version"},
		{"report sarif", []string{"report", "--input", dir, "--output", dir, "--format", "sarif"}, "not implemented in this version"},
		{"capture --project", []string{"capture", "--profile", "walking-skeleton", "--output", dir, "--project", dir}, "--project: not implemented in this version"},
		{"capture --policy", []string{"capture", "--profile", "walking-skeleton", "--output", dir, "--policy", notJSON}, "--policy: not implemented in this version"},
		{"capture no profile", []string{"capture", "--output", dir}, "--profile is required"},
		{"capture no output", []string{"capture", "--profile", "walking-skeleton"}, "--output is required"},
		{"capture negative timeout", []string{"capture", "--profile", "walking-skeleton", "--output", dir, "--timeout", "-1s"}, "--timeout"},
		{"capture unknown profile", []string{"capture", "--profile", "no-such-profile", "--output", dir}, "unknown profile"},
		{"doctor unknown profile", []string{"doctor", "--profile", "no-such-profile"}, "unknown profile"},
		{"approve no capture", []string{"baseline", "approve", "--output", dir, "--key", notJSON}, "--capture is required"},
		{"approve no output", []string{"baseline", "approve", "--capture", dir, "--key", notJSON}, "--output is required"},
		{"approve no key", []string{"baseline", "approve", "--capture", dir, "--output", dir}, "--key is required"},
		{"approve bad expiry", []string{"baseline", "approve", "--capture", dir, "--output", dir, "--key", notJSON, "--expires-at", "tomorrow"}, "--expires-at"},
		{"approve bad self-approval", []string{"baseline", "approve", "--capture", dir, "--output", dir, "--key", notJSON, "--self-approval", "sometimes"}, "--self-approval"},
		{"approve no reviewer", []string{"baseline", "approve", "--capture", dir, "--output", dir, "--key", notJSON, "--change-id", "c", "--reason", "r"}, "reviewer"},
		{"approve empty reason file", []string{"baseline", "approve", "--capture", dir, "--output", dir, "--key", notJSON, "--reviewer", "alice", "--change-id", "c", "--reason", "@"}, "empty file name"},
		{"approve missing reason file", []string{"baseline", "approve", "--capture", dir, "--output", dir, "--key", notJSON, "--reviewer", "alice", "--change-id", "c", "--reason", "@" + filepath.Join(dir, "absent.txt")}, "--reason"},
		{"verify no bundle", []string{"verify"}, "--bundle is required"},
		{"verify bad trust policy", []string{"verify", "--bundle", dir, "--trust-policy", notJSON}, "--trust-policy"},
		{"verify bad trusted key", []string{"verify", "--bundle", dir, "--trusted-key", notJSON}, "--trusted-key"},
		{"diff no baseline", []string{"diff", "--current", dir}, "--baseline is required"},
		{"diff no current", []string{"diff", "--baseline", dir}, "--current is required"},
		{"diff bad fail-on", []string{"diff", "--baseline", dir, "--current", dir, "--fail-on", "severe"}, "--fail-on"},
		{"diff bad policy", []string{"diff", "--baseline", dir, "--current", dir, "--policy", notJSON}, "--policy"},
		{"report no input", []string{"report", "--output", dir}, "--input is required"},
		{"report no output", []string{"report", "--input", dir}, "--output is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := tfRun(tc.args...)
			if code != exitUsage {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, exitUsage, out, errOut)
			}
			if !strings.Contains(errOut, tc.want) {
				t.Fatalf("stderr %q does not contain %q", errOut, tc.want)
			}
		})
	}
	// Nothing above may have written into the directory it was pointed at.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("usage errors wrote into %s: %v", dir, entries)
	}
}

// TestTrustFreezeUsageErrorJSON: a usage error in JSON mode is a JSON document
// with result_class usage_error (SPEC-0466 section 5.9), also when the flag
// package rejects the command line (unknown flag, malformed value, stray
// argument), whichever spelling of --format json it carries.
func TestTrustFreezeUsageErrorJSON(t *testing.T) {
	for _, args := range [][]string{
		{"capture", "--profile", "walking-skeleton", "--format", "json"},
		{"verify", "--format", "json"},
		{"diff", "--baseline", "b", "--format", "json"},
		{"baseline", "approve", "--format", "json"},
		{"report", "--input", "x", "--format", "json"},
		{"doctor", "--profile", "no-such-profile", "--format", "json"},
		{"capture", "--format", "json", "--profile", "walking-skeleton", "--output", "x", "--timeout", "5x"},
		{"verify", "--format", "json", "--bundle", "b", "--bogus"},
		{"verify", "--format=json", "--bundle", "b", "extra"},
		{"diff", "-format", "json", "--baseline", "b", "--current", "c", "--fail-on"},
		{"baseline", "approve", "-format=json", "--no-such-flag"},
		{"report", "--bogus", "--format", "json"},
		{"doctor", "--format", "json", "stray"},
	} {
		code, out, _ := tfRun(args...)
		if code != exitUsage {
			t.Fatalf("%v: exit %d", args, code)
		}
		doc := decodeTFJSON(t, out)
		if doc["result_class"] != tfResultUsage || doc["error"] == "" {
			t.Fatalf("%v: %v", args, doc)
		}
	}
	// Without --format json a flag error writes nothing to stdout.
	if code, out, _ := tfRun("verify", "--bogus"); code != exitUsage || out != "" {
		t.Fatalf("text mode: exit %d stdout %q", code, out)
	}
}

// TestTrustFreezeDoctor: doctor states the evidence level per platform and
// never claims support (SPEC-0471 TF06-R6, section 4).
func TestTrustFreezeDoctor(t *testing.T) {
	e := newTFEnv(t)
	doc := e.runJSON(exitOK, tfResultOK, "doctor")
	if doc["platform_support"] != "not_established" || doc["expected_complete"] != true {
		t.Fatalf("doctor: %v", doc)
	}
	matrix, _ := doc["support_matrix"].([]any)
	perPlatform := map[string]int{}
	identity := map[string]bool{}
	for _, row := range matrix {
		m, _ := row.(map[string]any)
		platform, _ := m["platform"].(string)
		perPlatform[platform]++
		if m["probe_id"] == "common.identity" {
			identity[platform] = true
		}
		ev, _ := m["evidence"].([]any)
		for _, l := range ev {
			if l != "fixture-tested" && l != "cross-compiled" {
				t.Fatalf("support matrix claims %v", l)
			}
		}
	}
	// One row per probe and platform, and the identity probe on all three.
	if len(perPlatform) != 3 || len(identity) != 3 {
		t.Fatalf("support matrix covers %v, identity rows %v", perPlatform, identity)
	}
	for _, p := range []string{"darwin", "linux", "windows"} {
		if perPlatform[p]*3 != len(matrix) {
			t.Fatalf("support matrix has %d rows for %s of %d", perPlatform[p], p, len(matrix))
		}
	}
	code, out, _ := e.run("doctor")
	if code != exitOK || !strings.Contains(out, "full platform support is not established") {
		t.Fatalf("doctor text: exit %d\n%s", code, out)
	}
	if strings.Contains(out, "real-platform-tested") || tfSupportedWord.MatchString(out) {
		t.Fatalf("doctor text claims more than the build can prove:\n%s", out)
	}

	doc = e.runJSON(exitOK, tfResultOK, "doctor", "--profile", "agentic-workstation")
	gaps, _ := doc["expected_gaps"].([]any)
	if doc["expected_complete"] != false || len(gaps) != 8 {
		t.Fatalf("agentic-workstation: expected_complete %v, gaps %v", doc["expected_complete"], gaps)
	}
}

// TestTrustFreezeCaptureNeverApproves: the capture and doctor paths of the
// CLI do not reference the seal package at all, and seal.Seal is called from
// baseline approve only (SPEC-0470 TF05-R2, TF05-R6, section 4.8).
func TestTrustFreezeCaptureNeverApproves(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "trustfreeze_cmds.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	sealUse := map[string]bool{}
	sealCalls := map[string]int{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "seal" {
				sealUse[fn.Name.Name] = true
				if sel.Sel.Name == "Seal" {
					sealCalls[fn.Name.Name]++
				}
			}
			return true
		})
	}
	for _, fn := range []string{"tfCapture", "tfDoctor", "runTrustFreeze", "runTrustFreezeWith"} {
		if sealUse[fn] {
			t.Errorf("%s references the seal package", fn)
		}
	}
	if len(sealCalls) != 1 || sealCalls["tfApprove"] != 1 {
		t.Errorf("seal.Seal call sites %v, want exactly one in tfApprove", sealCalls)
	}
	// A planted reference must be found, or the scan proves nothing.
	planted, err := parser.ParseFile(token.NewFileSet(), "planted.go", "package main\nfunc tfCapture() { _ = seal.Seal }\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(planted, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "seal" {
				found = true
			}
		}
		return true
	})
	if !found {
		t.Fatal("the scan does not find a planted seal reference")
	}
}

// TestTrustFreezeHomeRootFollowsHomeroot: the CLI resolves the home root
// through homeroot (%USERPROFILE% on a shipping Windows build, never $HOME
// there). No GOOS skip, so Windows and Linux run the same test count.
func TestTrustFreezeHomeRootFollowsHomeroot(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	got, err := defaultTFDeps().HomeRoot()
	if err != nil {
		t.Fatal(err)
	}
	if homeroot.OverrideAllowed(runtime.GOOS, homeroot.CompiledIn) {
		if got != tmp {
			t.Fatalf("home root %q, want %q (override allowed on %s)", got, tmp, runtime.GOOS)
		}
	} else if want, _ := os.UserHomeDir(); got != want {
		t.Fatalf("home root %q, want %q (override not allowed on %s)", got, want, runtime.GOOS)
	}
}

// TestTrustFreezeHelpIsNotAnError: --help answers 0 through the flag
// package's ErrHelp, every other parse error 2.
func TestTrustFreezeHelpIsNotAnError(t *testing.T) {
	fs := tfFlagSet("verify", "verify", &bytes.Buffer{})
	fs.String("bundle", "", "")
	if code, done := tfParse(fs, []string{"-h"}); !done || code != exitOK {
		t.Fatalf("-h: code %d done %v", code, done)
	}
	fs = tfFlagSet("verify", "verify", &bytes.Buffer{})
	if code, done := tfParse(fs, []string{"--nope"}); !done || code != exitUsage {
		t.Fatalf("--nope: code %d done %v", code, done)
	}
}
