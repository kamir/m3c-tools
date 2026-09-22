package common

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// swVersFixture is one sw_vers output in testdata/darwin plus the kernel
// release uname -r prints on that release.
type swVersFixture struct {
	file string
	// uname is the uname -r output; unameFile, when set, holds it instead.
	uname     string
	unameFile string
	want      OSInfo
	// origin: "captured" for bytes from a real run on a macOS host,
	// "reconstructed" for bytes written from the sw_vers(1) layout.
	origin string
}

var swVersFixtures = []swVersFixture{
	{file: "sw_vers-macos-26.txt", uname: "25.0.0", want: OSInfo{Name: "macOS", Version: "26.0.1", Build: "25A362"}, origin: "reconstructed"},
	{file: "sw_vers-macos-15-local.txt", unameFile: "uname-r-macos-15-local.txt", want: OSInfo{Name: "macOS", Version: "15.7.9", Build: "24G830"}, origin: "captured (macOS 15, 2026-09-22)"},
	{file: "sw_vers-macos-14.txt", uname: "23.5.0", want: OSInfo{Name: "macOS", Version: "14.5", Build: "23F79"}, origin: "reconstructed"},
	{file: "sw_vers-macos-13-rsr.txt", uname: "22.5.0", want: OSInfo{Name: "macOS", Version: "13.4.1 (c)", Build: "22F770820d"}, origin: "reconstructed"},
	{file: "sw_vers-macos-11.txt", uname: "20.6.0", want: OSInfo{Name: "macOS", Version: "11.7.10", Build: "20G1427"}, origin: "reconstructed"},
	{file: "sw_vers-macosx-10.15.txt", uname: "19.6.0", want: OSInfo{Name: "Mac OS X", Version: "10.15.7", Build: "19H15"}, origin: "reconstructed"},
}

// swVersTestdata reads testdata/darwin/name with CRLF folded to LF, so the
// tests do not depend on how the checkout converted line ends.
func swVersTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "darwin", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

func (f swVersFixture) unameOutput(t *testing.T) string {
	t.Helper()
	if f.unameFile != "" {
		return firstLine(swVersTestdata(t, f.unameFile))
	}
	return f.uname
}

type swVersVariant struct {
	name string
	b    []byte
}

// swVersLayouts returns lf in every layout ParseSwVers must accept.
func swVersLayouts(lf []byte) []swVersVariant {
	s := string(lf)
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	return []swVersVariant{
		{"lf", lf},
		{"crlf", []byte(strings.ReplaceAll(s, "\n", "\r\n"))},
		{"one-space", []byte(strings.ReplaceAll(s, "\t", " "))},
		{"wide-spaces", []byte(strings.ReplaceAll(s, "\t", "    "))},
		{"space-then-tab", []byte(strings.ReplaceAll(s, ":\t", ": \t"))},
		{"no-final-eol", []byte(strings.TrimSuffix(s, "\n"))},
		{"bom", append([]byte("\xef\xbb\xbf"), lf...)},
		{"blank-lines", []byte("\n" + strings.ReplaceAll(s, "\n", "\n\n"))},
		{"trailing-blanks", []byte(strings.Join(lines, " \t\n") + " \t\n")},
		{"crlf-spaces-no-eol", []byte(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSuffix(s, "\n"), "\n", "\r\n"), "\t", "  "))},
	}
}

// TestSwVersFixtures: every fixture parses in every accepted layout to the
// same identity; the parser never reports a kernel release (that is uname).
func TestSwVersFixtures(t *testing.T) {
	for _, f := range swVersFixtures {
		raw := swVersTestdata(t, f.file)
		for _, v := range swVersLayouts(raw) {
			got, err := ParseSwVers(v.b)
			if err != nil {
				t.Errorf("%s (%s) %s: %v", f.file, f.origin, v.name, err)
				continue
			}
			if got != f.want {
				t.Errorf("%s (%s) %s: got %+v, want %+v", f.file, f.origin, v.name, got, f.want)
			}
		}
	}
}

// TestSwVersFixtureOrigins keeps the fixture table honest: every file in
// testdata/darwin is listed, and exactly one sw_vers fixture claims to come
// from a real run.
func TestSwVersFixtureOrigins(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "darwin"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	captured := 0
	for _, f := range swVersFixtures {
		listed[f.file] = true
		if f.unameFile != "" {
			listed[f.unameFile] = true
		}
		if strings.HasPrefix(f.origin, "captured") {
			captured++
		} else if f.origin != "reconstructed" {
			t.Errorf("%s: origin %q", f.file, f.origin)
		}
	}
	for _, e := range entries {
		if !listed[e.Name()] {
			t.Errorf("testdata/darwin/%s is not in the fixture table", e.Name())
		}
	}
	if captured != 1 {
		t.Errorf("%d captured fixtures, want 1", captured)
	}
}

// TestSwVersRapidSecurityResponse: ProductVersionExtra (sw_vers(1)) is kept
// with the version it belongs to, whatever the line order, and never shown
// as a version of its own.
func TestSwVersRapidSecurityResponse(t *testing.T) {
	cases := []struct {
		name, in string
		want     OSInfo
	}{
		{"after version", "ProductName:\t\tmacOS\nProductVersion:\t\t13.4.1\nProductVersionExtra:\t(a)\nBuildVersion:\t\t22F770820b\n",
			OSInfo{Name: "macOS", Version: "13.4.1 (a)", Build: "22F770820b"}},
		{"before version", "ProductVersionExtra:\t(c)\nProductName:\t\tmacOS\nBuildVersion:\t\t22F770820d\nProductVersion:\t\t13.4.1\n",
			OSInfo{Name: "macOS", Version: "13.4.1 (c)", Build: "22F770820d"}},
		{"empty extra", "ProductName:\t\tmacOS\nProductVersion:\t\t15.7.9\nProductVersionExtra:\t\nBuildVersion:\t\t24G830\n",
			OSInfo{Name: "macOS", Version: "15.7.9", Build: "24G830"}},
		{"extra without version", "ProductName:\t\tmacOS\nProductVersionExtra:\t(a)\nBuildVersion:\t\t22F770820b\n",
			OSInfo{Name: "macOS", Build: "22F770820b"}},
	}
	for _, c := range cases {
		got, err := ParseSwVers([]byte(c.in))
		if err != nil || got != c.want {
			t.Errorf("%s: got %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
}

// TestSwVersMissingKeysReported: a property that is not printed stays empty;
// nothing is filled in from another property or from a default.
func TestSwVersMissingKeysReported(t *testing.T) {
	full := OSInfo{Name: "macOS", Version: "15.7.9", Build: "24G830"}
	lines := map[string]string{
		swVersProductName:    "ProductName:\t\tmacOS\n",
		swVersProductVersion: "ProductVersion:\t\t15.7.9\n",
		swVersBuildVersion:   "BuildVersion:\t\t24G830\n",
	}
	order := []string{swVersProductName, swVersProductVersion, swVersBuildVersion}
	for _, drop := range order {
		var in strings.Builder
		for _, k := range order {
			if k != drop {
				in.WriteString(lines[k])
			}
		}
		want := full
		switch drop {
		case swVersProductName:
			want.Name = ""
		case swVersProductVersion:
			want.Version = ""
		case swVersBuildVersion:
			want.Build = ""
		}
		got, err := ParseSwVers([]byte(in.String()))
		if err != nil || got != want {
			t.Errorf("without %s: got %+v %v, want %+v", drop, got, err, want)
		}
	}
	// A key printed with an empty value is not a value either.
	got, err := ParseSwVers([]byte("ProductName:\t\tmacOS\nProductVersion:\t\t\nBuildVersion:\t\t24G830\n"))
	if err != nil || got != (OSInfo{Name: "macOS", Build: "24G830"}) {
		t.Fatalf("empty version: %+v %v", got, err)
	}
}

// TestSwVersUnknownKeysAndNoise: unknown keys, keys in the wrong case,
// lines without a colon and values with colons do not change the result.
func TestSwVersUnknownKeysAndNoise(t *testing.T) {
	base := string(swVersTestdata(t, "sw_vers-macos-15-local.txt"))
	want := OSInfo{Name: "macOS", Version: "15.7.9", Build: "24G830"}
	noise := []string{
		"SomeFutureKey:\t\tvalue\n",
		"productname:\t\tLinux\n",
		"PRODUCTVERSION:\t\t99.0\n",
		"Product Name:\t\tOther\n",
		"ProductNameX:\t\tOther\n",
		"BuildVersionExtra:\t(z)\n",
		"no colon on this line\n",
		":\t\tvalue without key\n",
		"SomeFutureKey:\t\tcontrol \x1b[31m value\n",
		"Note:\t\tsee https://support.example/kb\n",
	}
	for _, n := range noise {
		for _, in := range []string{n + base, base + n} {
			got, err := ParseSwVers([]byte(in))
			if err != nil || got != want {
				t.Errorf("noise %q: got %+v %v", n, got, err)
			}
		}
	}
	got, err := ParseSwVers([]byte("ProductName:\tmacOS: Server\nProductVersion:\t15.7.9\n"))
	if err != nil || got.Name != "macOS: Server" {
		t.Fatalf("colon in value: %+v %v", got, err)
	}
}

// TestSwVersNoFields: output without any mapped value is ErrNoFields, also
// the single-value output of "sw_vers --productVersion".
func TestSwVersNoFields(t *testing.T) {
	for _, in := range []string{
		"",
		"\n\n",
		"\xef\xbb\xbf",
		"garbage\n",
		"15.7.9\n",
		"ProductName:\nProductVersion:\t\nBuildVersion: \n",
		"ProductVersionExtra:\t(a)\n",
		"SomeFutureKey:\tvalue\n",
	} {
		info, err := ParseSwVers([]byte(in))
		if !errors.Is(err, ErrNoFields) || info != (OSInfo{}) {
			t.Errorf("%q: got %+v %v, want ErrNoFields", in, info, err)
		}
	}
	if _, err := ParseSwVers(nil); !errors.Is(err, ErrNoFields) {
		t.Errorf("nil: %v", err)
	}
}

// TestSwVersMalformed: conflicting duplicates and values no sw_vers prints
// are refused instead of guessed; the error names the key, not the value.
func TestSwVersMalformed(t *testing.T) {
	long := strings.Repeat("9", swVersMaxValueLen+1)
	for _, c := range []struct{ name, in string }{
		{"conflicting version", "ProductName:\tmacOS\nProductVersion:\t15.7.9\nProductVersion:\t15.7.8\n"},
		{"conflicting build", "BuildVersion:\t24G830\nProductName:\tmacOS\nBuildVersion:\t24G831\n"},
		{"conflicting extra", "ProductVersion:\t13.4.1\nProductVersionExtra:\t(a)\nProductVersionExtra:\t(c)\n"},
		{"empty then value", "ProductVersion:\t\nProductVersion:\t15.7.9\n"},
		{"escape", "ProductName:\tmac\x1b[0mOS\n"},
		{"nul", "BuildVersion:\t24G\x00830\n"},
		{"c1 control", "ProductName:\tmac\u0085OS\n"},
		{"invalid utf-8", "ProductName:\tmac\xffOS\n"},
		{"too long", "ProductVersion:\t" + long + "\n"},
		{"secret-bearing", "ProductName:\t" + testSecret + "\x07\n"},
	} {
		info, err := ParseSwVers([]byte(c.in))
		if !errors.Is(err, ErrSwVersMalformed) || errors.Is(err, ErrNoFields) || info != (OSInfo{}) {
			t.Errorf("%s: got %+v %v, want ErrSwVersMalformed", c.name, info, err)
			continue
		}
		if strings.Contains(err.Error(), testSecret) || strings.Contains(err.Error(), long) {
			t.Errorf("%s: error echoes the value: %v", c.name, err)
		}
	}
	// The same value twice is not a conflict.
	got, err := ParseSwVers([]byte("ProductVersion:\t15.7.9\nProductName:\tmacOS\nProductVersion:  15.7.9\r\n"))
	if err != nil || got != (OSInfo{Name: "macOS", Version: "15.7.9"}) {
		t.Fatalf("identical duplicate: %+v %v", got, err)
	}
}

// swVersFileSpy records every file read and finds nothing.
type swVersFileSpy struct {
	mu    sync.Mutex
	names []string
}

func (s *swVersFileSpy) ReadFile(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names = append(s.names, name)
	return nil, fs.ErrNotExist
}

func (s *swVersFileSpy) reads() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.names...)
}

// swVersCollect runs the identity probe for darwin with a file spy.
func swVersCollect(t *testing.T, runner *probe.FakeRunner) (trustfreeze.ProbeResult, *swVersFileSpy, *probe.EvidenceBuffer) {
	t.Helper()
	cc, ev := collectCtx("darwin", probe.FakeFiles{}, runner)
	spy := &swVersFileSpy{}
	cc.Files = spy
	return NewIdentityProbe().Collect(context.Background(), cc), spy, ev
}

// TestSwVersIdentityDarwinOnly: on darwin the identity probe asks sw_vers,
// uname -r and uname -m (sysctl only when uname -m says x86_64) and nothing
// else. It reads no file, so a missing os-release
// or registry cannot turn into a finding on macOS (SPEC-0471 TF06-R5), and
// every fixture release is captured with provenance (TF06-AC3 at fixture
// level; the real run is recorded outside the code).
func TestSwVersIdentityDarwinOnly(t *testing.T) {
	for _, f := range swVersFixtures {
		uname := f.unameOutput(t)
		runner := unameRunner(uname).AddTool("sw_vers", "/usr/bin/sw_vers").
			Script("sw_vers", nil, probe.FakeResponse{Stdout: swVersTestdata(t, f.file)})
		r, spy, ev := swVersCollect(t, runner)
		if r.Status != trustfreeze.StatusCaptured || r.Reason != "" || len(r.Warnings) != 0 || r.Error != nil {
			t.Errorf("%s: status %s %q %+v %+v", f.file, r.Status, r.Reason, r.Warnings, r.Error)
			continue
		}
		osArt := artifact(t, r, ArtifactOS)
		wantAttrs(t, osArt, map[string]string{
			AttrOSFamily: "darwin", AttrArch: "arm64",
			AttrOSName: f.want.Name, AttrOSVersion: f.want.Version, AttrOSBuild: f.want.Build, AttrKernelRelease: uname,
		})
		if got := strings.Join(osArt.Provenance.Sources, ","); got != "command:sw_vers,command:uname -m,command:uname -r,runtime:GOOS" {
			t.Errorf("%s: sources %s", f.file, got)
		}
		if osArt.Provenance.Method != "command" || osArt.Provenance.Confidence != trustfreeze.ConfidenceProven {
			t.Errorf("%s: provenance %+v", f.file, osArt.Provenance)
		}
		if reads := spy.reads(); len(reads) != 0 {
			t.Errorf("%s: darwin path read files %v", f.file, reads)
		}
		var calls []string
		for _, c := range runner.Calls() {
			calls = append(calls, strings.Join(append([]string{c.Executable}, c.Args...), " "))
			if len(c.Env) != 0 {
				t.Errorf("%s: %s passes environment %v", f.file, c.Executable, c.Env)
			}
		}
		sort.Strings(calls)
		if strings.Join(calls, ",") != "sw_vers,uname -m,uname -r" {
			t.Errorf("%s: calls %v", f.file, calls)
		}
		var names []string
		for _, it := range ev.Close() {
			names = append(names, it.Name)
		}
		if strings.Join(names, ",") != "sw_vers.stdout,uname-m.stdout,uname-r.stdout" {
			t.Errorf("%s: evidence %v", f.file, names)
		}
		b, err := trustfreeze.MarshalCanonical(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, foreign := range []string{"os-release", "registry", "linux", "windows", "CurrentVersion"} {
			if bytes.Contains(bytes.ToLower(b), []byte(strings.ToLower(foreign))) {
				t.Errorf("%s: darwin result mentions %q: %s", f.file, foreign, b)
			}
		}
	}
}

// TestSwVersIdentityMissingBuild: a BuildVersion that sw_vers did not print
// is a field_missing diagnostic and a partial result, not an invented value.
func TestSwVersIdentityMissingBuild(t *testing.T) {
	runner := unameRunner("24.6.0").Script("sw_vers", nil, probe.FakeResponse{Stdout: []byte("ProductName:\t\tmacOS\nProductVersion:\t\t15.7.9\n")})
	r, _, _ := swVersCollect(t, runner)
	if r.Status != trustfreeze.StatusPartial || !warning(r, trustfreeze.DiagFieldMissing, AttrOSBuild) || len(r.Warnings) != 1 {
		t.Fatalf("status %s %+v", r.Status, r.Warnings)
	}
	wantAttrs(t, artifact(t, r, ArtifactOS), map[string]string{
		AttrOSFamily: "darwin", AttrArch: "arm64", AttrOSName: "macOS", AttrOSVersion: "15.7.9", AttrKernelRelease: "24.6.0",
	})
}

// TestSwVersIdentityMalformed: malformed sw_vers output fails the three OS
// fields (partial), keeps the kernel release and keeps the output as
// evidence for the reviewer.
func TestSwVersIdentityMalformed(t *testing.T) {
	out := []byte("ProductName:\tmacOS\nProductVersion:\t15.7.9\nProductVersion:\t15.7.8\nBuildVersion:\t24G830\n")
	runner := unameRunner("24.6.0").Script("sw_vers", nil, probe.FakeResponse{Stdout: out})
	r, _, ev := swVersCollect(t, runner)
	if r.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %s %+v", r.Status, r.Warnings)
	}
	for _, f := range []string{AttrOSName, AttrOSVersion, AttrOSBuild} {
		if !warning(r, probe.DiagFieldFailed, f) {
			t.Errorf("no field_failed for %s: %+v", f, r.Warnings)
		}
	}
	wantAttrs(t, artifact(t, r, ArtifactOS), map[string]string{AttrOSFamily: "darwin", AttrArch: "arm64", AttrKernelRelease: "24.6.0"})
	items := ev.Close()
	if len(items) != 3 || !bytes.Equal(items[0].Data.Bytes(), out) {
		t.Fatalf("evidence %+v", items)
	}
}

// TestSwVersIdentityToolStates: sw_vers missing is unavailable and denied is
// permission_denied, per field and for the probe (SPEC-0471 TF06-R2); the
// kernel release from uname is still captured.
func TestSwVersIdentityToolStates(t *testing.T) {
	cases := []struct {
		name   string
		runner *probe.FakeRunner
		status trustfreeze.ProbeStatus
		code   string
	}{
		{"missing", unameRunner("24.6.0"), trustfreeze.StatusUnavailable, probe.DiagFieldUnavailable},
		{"denied", unameRunner("24.6.0").DenyTool("sw_vers", "/usr/bin/sw_vers"), trustfreeze.StatusPermissionDenied, probe.DiagFieldPermissionDenied},
	}
	for _, c := range cases {
		r, spy, _ := swVersCollect(t, c.runner)
		if r.Status != c.status {
			t.Errorf("%s: status %s %+v", c.name, r.Status, r.Warnings)
		}
		for _, f := range []string{AttrOSName, AttrOSVersion, AttrOSBuild} {
			if !warning(r, c.code, f) {
				t.Errorf("%s: no %s for %s: %+v", c.name, c.code, f, r.Warnings)
			}
		}
		if got := artifact(t, r, ArtifactOS).Attributes[AttrKernelRelease]; got != "24.6.0" {
			t.Errorf("%s: kernel release %q", c.name, got)
		}
		if reads := spy.reads(); len(reads) != 0 {
			t.Errorf("%s: fallback read files %v", c.name, reads)
		}
	}
}

// TestSwVersRealHost runs the identity probe against the real sw_vers and
// uname of a macOS host. It is opt-in (TF_TEST_REAL_MACOS=1) because unit
// tests must not depend on installed tools (SPEC-0467 R9). The host name is
// synthetic; nothing is written.
func TestSwVersRealHost(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("TF_TEST_REAL_MACOS") != "1" {
		t.Skip("opt-in: set TF_TEST_REAL_MACOS=1 on a macOS host")
	}
	cc, ev := collectCtx("darwin", probe.FakeFiles{}, nil)
	cc.GOARCH = runtime.GOARCH
	cc.Runner = probe.NewExecRunner()
	spy := &swVersFileSpy{}
	cc.Files = spy
	r := NewIdentityProbe().Collect(context.Background(), cc)
	// Under Rosetta 2 the architecture is derived (and says so); nothing
	// else may warn.
	translated := warning(r, DiagValueDerived, AttrArch)
	wantWarnings := 0
	if translated {
		wantWarnings = 1
	}
	if r.Status != trustfreeze.StatusCaptured || len(r.Warnings) != wantWarnings {
		t.Fatalf("status %s %q %+v", r.Status, r.Reason, r.Warnings)
	}
	a := artifact(t, r, ArtifactOS).Attributes
	for _, k := range []string{AttrArch, AttrOSName, AttrOSVersion, AttrOSBuild, AttrKernelRelease} {
		if a[k] == "" {
			t.Errorf("%s empty", k)
		}
	}
	paths := map[string]string{}
	for _, inv := range r.Tools {
		paths[inv.Name] = inv.Path
		// sysctl.proc_translated is an unknown oid on an Intel Mac (exit 1).
		if (inv.ExitCode != 0 && inv.Name != "sysctl") || inv.Error != "" || inv.StdoutTruncated {
			t.Errorf("tool %+v", inv)
		}
	}
	if paths["sw_vers"] != "/usr/bin/sw_vers" || paths["uname"] != "/usr/bin/uname" {
		t.Errorf("tool paths %v", paths)
	}
	if reads := spy.reads(); len(reads) != 0 {
		t.Errorf("file reads %v", reads)
	}
	// sw_vers, uname -r, uname -m, and the sysctl answer when it was one.
	if n := len(ev.Close()); n != 3 && n != 4 {
		t.Errorf("%d evidence items", n)
	}
	t.Logf("real host: os_name=%q os_version=%q os_build=%q kernel_release=%q arch=%q tools=%v",
		a[AttrOSName], a[AttrOSVersion], a[AttrOSBuild], a[AttrKernelRelease], a[AttrArch], paths)
}
