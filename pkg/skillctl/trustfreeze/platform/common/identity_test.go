package common

import (
	"context"
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// Synthetic fixtures (public plane rule: no real hosts or users).
const (
	ubuntuOSRelease = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\nHOME_URL=\"https://www.ubuntu.com/\"\n"
	archOSRelease   = "NAME=\"Arch Linux\"\nPRETTY_NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\nVERSION_ID=20260101.0.0\n"
	swVersOutput    = "ProductName:\t\tmacOS\nProductVersion:\t\t14.5\nBuildVersion:\t\t23F79\n"
	testHostname    = "host-a.example"
	testSecret      = "s3cr3t-ZXCVBNM-0123456789"
)

var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

type fakeWindows struct {
	info OSInfo
	err  error
	// arch and archErr answer nativeArch; an empty arch answers "arm64",
	// the machine of the synthetic hosts of these tests.
	arch    string
	archErr error
}

func (f fakeWindows) Read() (OSInfo, error) { return f.info, f.err }

func (f fakeWindows) nativeArch() (string, error) {
	if f.archErr != nil {
		return "", f.archErr
	}
	if f.arch == "" {
		return "arm64", nil
	}
	return f.arch, nil
}

// collectCtx builds a CollectContext for goos with the given fakes and an
// evidence buffer.
func collectCtx(goos string, files probe.FakeFiles, runner *probe.FakeRunner) (probe.CollectContext, *probe.EvidenceBuffer) {
	ev := probe.NewEvidenceBuffer(IdentityProbeID, probe.Limits{})
	return probe.CollectContext{
		HostContext: probe.HostContext{
			GOOS: goos, GOARCH: "arm64",
			Hostname:  func() (string, error) { return testHostname, nil },
			Files:     files,
			Runner:    runner,
			Clock:     trustfreeze.FixedClock{T: testTime},
			Privilege: probe.PrivilegeUser,
		},
		ProbeID:  IdentityProbeID,
		Redactor: redact.Default(),
		Evidence: ev,
		Support:  probe.Supported(),
	}, ev
}

func linuxFiles(osRelease string) probe.FakeFiles {
	return probe.FakeFiles{Files: map[string][]byte{OSReleasePath: []byte(osRelease)}}
}

// unameRunner scripts uname -r and uname -m. The synthetic hosts of these
// tests are arm64 machines.
func unameRunner(release string) *probe.FakeRunner {
	return probe.NewFakeRunner().AddTool("uname", "/usr/bin/uname").
		Script("uname", []string{"-r"}, probe.FakeResponse{Stdout: []byte(release + "\n")}).
		Script("uname", []string{"-m"}, probe.FakeResponse{Stdout: []byte("arm64\n")})
}

func artifact(t *testing.T, r trustfreeze.ProbeResult, id string) trustfreeze.Artifact {
	t.Helper()
	for _, a := range r.NormalizedState {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no artifact %s in %+v", id, r.NormalizedState)
	return trustfreeze.Artifact{}
}

func hasArtifact(r trustfreeze.ProbeResult, id string) bool {
	for _, a := range r.NormalizedState {
		if a.ID == id {
			return true
		}
	}
	return false
}

func warning(r trustfreeze.ProbeResult, code, field string) bool {
	for _, w := range r.Warnings {
		if w.Code == code && w.Field == field {
			return true
		}
	}
	return false
}

func wantAttrs(t *testing.T, a trustfreeze.Artifact, want map[string]string) {
	t.Helper()
	if len(a.Attributes) != len(want) {
		t.Fatalf("attributes %v, want %v", a.Attributes, want)
	}
	for k, v := range want {
		if a.Attributes[k] != v {
			t.Fatalf("attribute %s = %q, want %q (all %v)", k, a.Attributes[k], v, a.Attributes)
		}
	}
}

// TestIdentityLinuxFixture: the linux path on any host (SPEC-0467
// section 5.5).
func TestIdentityLinuxFixture(t *testing.T) {
	cc, ev := collectCtx("linux", linuxFiles(ubuntuOSRelease), unameRunner("6.8.0-45-generic"))
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusCaptured || r.Reason != "" || r.Error != nil {
		t.Fatalf("status %s reason %q error %v warnings %+v", r.Status, r.Reason, r.Error, r.Warnings)
	}
	osArt := artifact(t, r, ArtifactOS)
	wantAttrs(t, osArt, map[string]string{
		AttrOSFamily: "linux", AttrArch: "arm64", AttrOSName: "Ubuntu", AttrOSVersion: "24.04", AttrKernelRelease: "6.8.0-45-generic",
	})
	// Ubuntu defines no BUILD_ID: not applicable, not missing.
	if !warning(r, probe.DiagFieldNotApplicable, AttrOSBuild) {
		t.Fatalf("no not-applicable diagnostic for os_build: %+v", r.Warnings)
	}
	if osArt.Sensitivity != trustfreeze.SensitivityPublic || osArt.State != trustfreeze.StateObserved || osArt.Provenance.Confidence != trustfreeze.ConfidenceProven {
		t.Fatalf("os artifact %+v", osArt)
	}
	// The architecture comes from the OS (uname -m), never from the build
	// of the collector (runtime.GOARCH).
	if got := strings.Join(osArt.Provenance.Sources, ","); got != "command:uname -m,command:uname -r,file:/etc/os-release,runtime:GOOS" {
		t.Fatalf("sources %s", got)
	}
	if d, _ := trustfreeze.ComputeArtifactDigest(osArt); osArt.Digest != d {
		t.Fatal("artifact digest is not the computed digest")
	}
	host := artifact(t, r, ArtifactHost)
	wantAttrs(t, host, map[string]string{AttrHostname: testHostname})
	if host.Sensitivity != trustfreeze.SensitivityInternal {
		t.Fatalf("hostname sensitivity %s, want internal (SPEC-0466 section 5.8)", host.Sensitivity)
	}
	items := ev.Close()
	if len(items) != 3 || items[0].Ref.Path != "evidence/common.identity/os-release" || items[1].Ref.Path != "evidence/common.identity/uname-m.stdout" || items[2].Ref.Path != "evidence/common.identity/uname-r.stdout" {
		t.Fatalf("evidence %+v", items)
	}
	if string(items[0].Data.Bytes()) != ubuntuOSRelease {
		t.Fatalf("os-release evidence changed: %q", items[0].Data.Bytes())
	}
	if len(r.Tools) != 2 || r.Tools[0].Name != "uname" || r.Tools[0].Path != "/usr/bin/uname" || strings.Join(r.Tools[0].Args, " ") != "-r" || strings.Join(r.Tools[1].Args, " ") != "-m" {
		t.Fatalf("tools %+v", r.Tools)
	}
}

// TestIdentityLinuxBuildIDAndFallback: BUILD_ID is kept when defined, and
// /usr/lib/os-release is read only when /etc/os-release does not exist.
func TestIdentityLinuxBuildIDAndFallback(t *testing.T) {
	files := probe.FakeFiles{Files: map[string][]byte{UsrLibOSReleasePath: []byte(archOSRelease)}}
	cc, _ := collectCtx("linux", files, unameRunner("6.12.1-arch1-1"))
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s %+v", r.Status, r.Warnings)
	}
	a := artifact(t, r, ArtifactOS)
	if a.Attributes[AttrOSName] != "Arch Linux" || a.Attributes[AttrOSBuild] != "rolling" || a.Attributes[AttrOSVersion] != "20260101.0.0" {
		t.Fatalf("attrs %v", a.Attributes)
	}
	if !strings.Contains(strings.Join(a.Provenance.Sources, ","), "file:/usr/lib/os-release") {
		t.Fatalf("sources %v", a.Provenance.Sources)
	}
}

// TestIdentityMissingToolUnavailable: TF02-AC4 equivalent. A missing uname
// makes kernel_release unavailable; everything else is still collected and
// the probe says unavailable, never captured.
func TestIdentityMissingToolUnavailable(t *testing.T) {
	cc, _ := collectCtx("linux", linuxFiles(ubuntuOSRelease), probe.NewFakeRunner())
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusUnavailable || r.Error == nil || r.Error.Class != probe.ClassToolMissing {
		t.Fatalf("status %s error %+v", r.Status, r.Error)
	}
	if !warning(r, probe.DiagFieldUnavailable, AttrKernelRelease) {
		t.Fatalf("warnings %+v", r.Warnings)
	}
	a := artifact(t, r, ArtifactOS)
	if a.Attributes[AttrOSName] != "Ubuntu" || a.Attributes[AttrKernelRelease] != "" {
		t.Fatalf("attrs %v", a.Attributes)
	}
	if !hasArtifact(r, ArtifactHost) {
		t.Fatal("host artifact lost")
	}
}

// TestIdentityPermissionDenied: a permission error is permission_denied,
// distinct from unavailable (SPEC-0471 TF06-R2).
func TestIdentityPermissionDenied(t *testing.T) {
	files := probe.FakeFiles{Errs: map[string]error{OSReleasePath: fs.ErrPermission}}
	cc, _ := collectCtx("linux", files, unameRunner("6.8.0"))
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusPermissionDenied || r.Error.Class != probe.ClassPermissionDenied {
		t.Fatalf("status %s error %+v", r.Status, r.Error)
	}
	for _, f := range []string{AttrOSName, AttrOSVersion, AttrOSBuild} {
		if !warning(r, probe.DiagFieldPermissionDenied, f) {
			t.Fatalf("no permission diagnostic for %s: %+v", f, r.Warnings)
		}
	}
	if a := artifact(t, r, ArtifactOS); a.Attributes[AttrKernelRelease] != "6.8.0" {
		t.Fatalf("kernel release lost: %v", a.Attributes)
	}

	// The same class from the runner (tool exists but is not executable).
	denied := probe.NewFakeRunner().DenyTool("uname", "/usr/bin/uname")
	cc, _ = collectCtx("linux", linuxFiles(ubuntuOSRelease), denied)
	if r := NewIdentityProbe().Collect(context.Background(), cc); r.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("runner permission: %s", r.Status)
	}
}

// TestIdentityPartialOnMissingField: one diagnostic per missing field.
func TestIdentityPartialOnMissingField(t *testing.T) {
	cc, _ := collectCtx("linux", linuxFiles("NAME=\"Ubuntu\"\nID=ubuntu\n"), unameRunner("6.8.0"))
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusPartial || !warning(r, trustfreeze.DiagFieldMissing, AttrOSVersion) {
		t.Fatalf("status %s warnings %+v", r.Status, r.Warnings)
	}
	missing := 0
	for _, w := range r.Warnings {
		if w.Code == trustfreeze.DiagFieldMissing {
			missing++
		}
	}
	if missing != 1 {
		t.Fatalf("%d field_missing diagnostics, want 1: %+v", missing, r.Warnings)
	}
}

// TestIdentityDarwinFixture: the darwin path on any host (SPEC-0467
// section 5.5).
func TestIdentityDarwinFixture(t *testing.T) {
	runner := unameRunner("23.5.0").Script("sw_vers", nil, probe.FakeResponse{Stdout: []byte(swVersOutput)})
	cc, ev := collectCtx("darwin", probe.FakeFiles{}, runner)
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s %+v", r.Status, r.Warnings)
	}
	wantAttrs(t, artifact(t, r, ArtifactOS), map[string]string{
		AttrOSFamily: "darwin", AttrArch: "arm64", AttrOSName: "macOS", AttrOSVersion: "14.5", AttrOSBuild: "23F79", AttrKernelRelease: "23.5.0",
	})
	if len(r.Warnings) != 0 {
		t.Fatalf("warnings %+v", r.Warnings)
	}
	if items := ev.Close(); len(items) != 3 || items[0].Name != "sw_vers.stdout" || items[1].Name != "uname-m.stdout" {
		t.Fatalf("evidence %+v", items)
	}
	if artifact(t, r, ArtifactOS).Provenance.Method != "command" {
		t.Fatal("darwin method")
	}
}

// TestIdentityDarwinFailures: sw_vers timeout is timeout; a non-zero exit is
// a failed field and a partial result.
func TestIdentityDarwinFailures(t *testing.T) {
	runner := unameRunner("23.5.0").Script("sw_vers", nil, probe.FakeResponse{TimedOut: true})
	cc, _ := collectCtx("darwin", probe.FakeFiles{}, runner)
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusTimeout || !warning(r, probe.DiagFieldTimeout, AttrOSName) {
		t.Fatalf("timeout: %s %+v", r.Status, r.Warnings)
	}
	runner = unameRunner("23.5.0").Script("sw_vers", nil, probe.FakeResponse{ExitCode: 1, Stderr: []byte("boom\n")})
	cc, _ = collectCtx("darwin", probe.FakeFiles{}, runner)
	r = NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusPartial || !warning(r, probe.DiagFieldFailed, AttrOSVersion) {
		t.Fatalf("exit 1: %s %+v", r.Status, r.Warnings)
	}
}

// TestIdentityWindowsFixture: the windows path on any host (SPEC-0467
// section 5.5); there is
// no kernel release on windows, which is not applicable, not missing.
func TestIdentityWindowsFixture(t *testing.T) {
	cc, ev := collectCtx("windows", probe.FakeFiles{}, probe.NewFakeRunner())
	p := &IdentityProbe{Windows: fakeWindows{info: OSInfo{Name: "Windows 11 Pro", Version: "23H2", Build: "22631.4317"}}}
	r := p.Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s %+v", r.Status, r.Warnings)
	}
	wantAttrs(t, artifact(t, r, ArtifactOS), map[string]string{
		AttrOSFamily: "windows", AttrArch: "arm64", AttrOSName: "Windows 11 Pro", AttrOSVersion: "23H2", AttrOSBuild: "22631.4317",
	})
	if !warning(r, probe.DiagFieldNotApplicable, AttrKernelRelease) {
		t.Fatalf("warnings %+v", r.Warnings)
	}
	if items := ev.Close(); len(items) != 1 || items[0].Name != "registry-currentversion.json" {
		t.Fatalf("evidence %+v", items)
	}
	if len(r.Tools) != 0 {
		t.Fatalf("the windows source runs no command: %+v", r.Tools)
	}
}

// TestIdentityWindowsFailures: registry permission error, a missing value
// and the non-windows stub.
func TestIdentityWindowsFailures(t *testing.T) {
	cc, _ := collectCtx("windows", probe.FakeFiles{}, probe.NewFakeRunner())
	r := (&IdentityProbe{Windows: fakeWindows{err: fs.ErrPermission}}).Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("permission: %s", r.Status)
	}
	r = (&IdentityProbe{Windows: fakeWindows{info: OSInfo{Name: "Windows 10 Pro", Build: "19045.1"}}}).Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusPartial || !warning(r, trustfreeze.DiagFieldMissing, AttrOSVersion) {
		t.Fatalf("missing DisplayVersion: %s %+v", r.Status, r.Warnings)
	}
	r = (&IdentityProbe{Windows: fakeWindows{err: ErrNotApplicable}}).Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusUnsupported || r.Reason == "" {
		t.Fatalf("no OS field read must not be captured: %s %q", r.Status, r.Reason)
	}
	if runtime.GOOS != "windows" {
		if _, err := DefaultWindowsVersionReader().Read(); !errors.Is(err, ErrNotApplicable) {
			t.Fatalf("stub reader: %v", err)
		}
	}
	r = (&IdentityProbe{}).Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusUnavailable {
		t.Fatalf("nil reader: %s", r.Status)
	}
}

// TestIdentityHostnameFailure: without a hostname there is no device/host
// artifact and the result is partial.
func TestIdentityHostnameFailure(t *testing.T) {
	cc, _ := collectCtx("linux", linuxFiles(ubuntuOSRelease), unameRunner("6.8.0"))
	cc.Hostname = func() (string, error) { return "", errors.New("no name") }
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusPartial || hasArtifact(r, ArtifactHost) || !warning(r, probe.DiagFieldFailed, AttrHostname) {
		t.Fatalf("status %s artifacts %d warnings %+v", r.Status, len(r.NormalizedState), r.Warnings)
	}
}

// TestIdentityRedactsSourceContent: a secret inside os-release never reaches
// the evidence, and a redaction failure drops the evidence (fail-closed).
func TestIdentityRedactsSourceContent(t *testing.T) {
	cc, ev := collectCtx("linux", linuxFiles(ubuntuOSRelease+"API_TOKEN="+testSecret+"\n"), unameRunner("6.8.0"))
	r := NewIdentityProbe().Collect(context.Background(), cc)
	items := ev.Close()
	if r.Status != trustfreeze.StatusCaptured || len(items) != 3 || strings.Contains(string(items[0].Data.Bytes()), testSecret) {
		t.Fatalf("status %s evidence %q", r.Status, items[0].Data.Bytes())
	}
	small, err := redact.New(redact.WithMaxInputBytes(16))
	if err != nil {
		t.Fatal(err)
	}
	cc, ev = collectCtx("linux", linuxFiles(ubuntuOSRelease), unameRunner("6.8.0"))
	cc.Redactor = small
	r = NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusPartial || !warning(r, trustfreeze.DiagRedactionFailed, AttrOSName) {
		t.Fatalf("status %s warnings %+v", r.Status, r.Warnings)
	}
	for _, item := range ev.Close() {
		if item.Name == "os-release" {
			t.Fatal("os-release evidence persisted although its redaction failed")
		}
	}
}

// TestIdentityDescriptorAndSupport: descriptor, claims, support and
// registration.
func TestIdentityDescriptorAndSupport(t *testing.T) {
	p := NewIdentityProbe()
	if err := p.Descriptor().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		if s := p.Support(context.Background(), probe.HostContext{GOOS: goos}); !s.Available {
			t.Fatalf("%s: %+v", goos, s)
		}
	}
	if s := p.Support(context.Background(), probe.HostContext{GOOS: "plan9"}); s.Available || s.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("plan9: %+v", s)
	}
	cc, _ := collectCtx("plan9", probe.FakeFiles{}, probe.NewFakeRunner())
	if r := p.Collect(context.Background(), cc); r.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("plan9 collect: %s", r.Status)
	}
	reg := probe.NewRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := Register(reg); !errors.Is(err, probe.ErrDuplicateProbe) {
		t.Fatalf("second Register: %v", err)
	}
	for _, row := range probe.SupportMatrix(reg, nil) {
		if row.State != probe.Implemented || len(row.Evidence) != 2 {
			t.Fatalf("matrix row %+v", row)
		}
	}
	if got := AllowedRoots("linux"); len(got) != 2 || AllowedRoots("darwin") != nil {
		t.Fatalf("allowed roots %v", got)
	}
}

// TestParsersFirstVersion pins the minimal parser contract of SPEC-0467
// section 5.5; the
// platform owners extend it in their own test files.
func TestParsersFirstVersion(t *testing.T) {
	info, err := ParseOSRelease([]byte("# c\nNAME='Debian GNU/Linux'\nVERSION_ID=\"12\"\nBUILD_ID=\"a\\\"b\"\nbad line\nlower=x\n"))
	if err != nil || info.Name != "Debian GNU/Linux" || info.Version != "12" || info.Build != `a"b` {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := ParseOSRelease([]byte("# only a comment\n")); !errors.Is(err, ErrNoFields) {
		t.Fatalf("empty: %v", err)
	}
	info, err = ParseSwVers([]byte(swVersOutput))
	if err != nil || info.Name != "macOS" || info.Version != "14.5" || info.Build != "23F79" {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := ParseSwVers([]byte("garbage\n")); !errors.Is(err, ErrNoFields) {
		t.Fatalf("garbage: %v", err)
	}
}

// onlyRead is a WindowsVersionReader without a native machine source.
type onlyRead struct{ info OSInfo }

func (o onlyRead) Read() (OSInfo, error) { return o.info, nil }

// TestIdentityArchFromTheOS: device/os arch is an observed fact about the
// machine, so it comes from the OS and never from the build of the collector
// (runtime.GOARCH): an amd64 build runs on an arm64 Mac under Rosetta 2 and
// on arm64 Windows under emulation (SPEC-0468 R5: nothing
// declared or inferred is recorded as observed).
func TestIdentityArchFromTheOS(t *testing.T) {
	linux := func(uname probe.FakeResponse) trustfreeze.ProbeResult {
		runner := probe.NewFakeRunner().AddTool("uname", "/usr/bin/uname").
			Script("uname", []string{"-r"}, probe.FakeResponse{Stdout: []byte("6.8.0\n")}).
			Script("uname", []string{"-m"}, uname)
		cc, _ := collectCtx("linux", linuxFiles(ubuntuOSRelease), runner)
		cc.GOARCH = "amd64" // the build; the machine says otherwise
		return NewIdentityProbe().Collect(context.Background(), cc)
	}
	r := linux(probe.FakeResponse{Stdout: []byte("aarch64\n")})
	if r.Status != trustfreeze.StatusCaptured || artifact(t, r, ArtifactOS).Attributes[AttrArch] != "arm64" {
		t.Fatalf("linux aarch64: %s %v %+v", r.Status, artifact(t, r, ArtifactOS).Attributes, r.Warnings)
	}
	for _, src := range artifact(t, r, ArtifactOS).Provenance.Sources {
		if src == "runtime:GOARCH" {
			t.Fatal("the build architecture is still named as a source")
		}
	}
	r = linux(probe.FakeResponse{ExitCode: 1, Stderr: []byte("boom\n")})
	if r.Status != trustfreeze.StatusPartial || !warning(r, probe.DiagFieldFailed, AttrArch) {
		t.Fatalf("uname -m failed: %s %+v", r.Status, r.Warnings)
	}
	if _, ok := artifact(t, r, ArtifactOS).Attributes[AttrArch]; ok {
		t.Fatal("arch reported although uname -m failed: GOARCH must not stand in")
	}
	r = linux(probe.FakeResponse{Stdout: []byte("\n")})
	if r.Status != trustfreeze.StatusPartial || !warning(r, trustfreeze.DiagFieldMissing, AttrArch) {
		t.Fatalf("empty uname -m: %s %+v", r.Status, r.Warnings)
	}

	darwin := func(sysctl *probe.FakeResponse) (trustfreeze.ProbeResult, *probe.FakeRunner) {
		runner := probe.NewFakeRunner().AddTool("uname", "/usr/bin/uname").
			Script("uname", []string{"-r"}, probe.FakeResponse{Stdout: []byte("24.6.0\n")}).
			Script("uname", []string{"-m"}, probe.FakeResponse{Stdout: []byte("x86_64\n")}).
			Script("sw_vers", nil, probe.FakeResponse{Stdout: []byte(swVersOutput)})
		if sysctl != nil {
			runner.Script("sysctl", []string{"-n", "sysctl.proc_translated"}, *sysctl)
		}
		cc, _ := collectCtx("darwin", probe.FakeFiles{}, runner)
		cc.GOARCH = "amd64"
		return NewIdentityProbe().Collect(context.Background(), cc), runner
	}
	cases := []struct {
		name    string
		sysctl  *probe.FakeResponse
		status  trustfreeze.ProbeStatus
		arch    string
		derived bool
		code    string
	}{
		{"rosetta", &probe.FakeResponse{Stdout: []byte("1\n")}, trustfreeze.StatusCaptured, "arm64", true, ""},
		{"native amd64 on apple silicon", &probe.FakeResponse{Stdout: []byte("0\n")}, trustfreeze.StatusCaptured, "amd64", false, ""},
		{"intel mac", &probe.FakeResponse{ExitCode: 1, Stderr: []byte("sysctl: unknown oid 'sysctl.proc_translated'\n")}, trustfreeze.StatusCaptured, "amd64", false, ""},
		{"sysctl fails otherwise", &probe.FakeResponse{ExitCode: 1, Stderr: []byte("sysctl: boom\n")}, trustfreeze.StatusPartial, "", false, probe.DiagFieldFailed},
		{"sysctl prints nonsense", &probe.FakeResponse{Stdout: []byte("maybe\n")}, trustfreeze.StatusPartial, "", false, probe.DiagFieldFailed},
		{"sysctl missing", nil, trustfreeze.StatusUnavailable, "", false, probe.DiagFieldUnavailable},
	}
	for _, tc := range cases {
		r, runner := darwin(tc.sysctl)
		if r.Status != tc.status || artifact(t, r, ArtifactOS).Attributes[AttrArch] != tc.arch || warning(r, DiagValueDerived, AttrArch) != tc.derived {
			t.Errorf("%s: status %s attrs %v warnings %+v", tc.name, r.Status, artifact(t, r, ArtifactOS).Attributes, r.Warnings)
		}
		if tc.code != "" && !warning(r, tc.code, AttrArch) {
			t.Errorf("%s: no %s for arch: %+v", tc.name, tc.code, r.Warnings)
		}
		asked := false
		for _, c := range runner.Calls() {
			asked = asked || c.Executable == "sysctl"
		}
		if !asked {
			t.Errorf("%s: an x86_64 answer was not checked for Rosetta 2", tc.name)
		}
	}
	// An arm64 answer needs no Rosetta check.
	runner := unameRunner("24.6.0").Script("sw_vers", nil, probe.FakeResponse{Stdout: []byte(swVersOutput)})
	cc, _ := collectCtx("darwin", probe.FakeFiles{}, runner)
	cc.GOARCH = "amd64"
	if r := NewIdentityProbe().Collect(context.Background(), cc); artifact(t, r, ArtifactOS).Attributes[AttrArch] != "arm64" {
		t.Fatalf("darwin arm64: %v", artifact(t, r, ArtifactOS).Attributes)
	}
	for _, c := range runner.Calls() {
		if c.Executable == "sysctl" {
			t.Fatal("sysctl asked although uname -m said arm64")
		}
	}

	win := func(w WindowsVersionReader) trustfreeze.ProbeResult {
		cc, _ := collectCtx("windows", probe.FakeFiles{}, probe.NewFakeRunner())
		cc.GOARCH = "amd64"
		return (&IdentityProbe{Windows: w}).Collect(context.Background(), cc)
	}
	info := OSInfo{Name: "Windows 11 Pro", Version: "23H2", Build: "22631.4317"}
	r = win(fakeWindows{info: info, arch: "arm64"})
	if r.Status != trustfreeze.StatusCaptured || artifact(t, r, ArtifactOS).Attributes[AttrArch] != "arm64" {
		t.Fatalf("windows arm64 host, amd64 build: %s %v", r.Status, artifact(t, r, ArtifactOS).Attributes)
	}
	r = win(fakeWindows{info: info, archErr: fs.ErrPermission})
	if r.Status != trustfreeze.StatusPermissionDenied || !warning(r, probe.DiagFieldPermissionDenied, AttrArch) {
		t.Fatalf("windows denied: %s %+v", r.Status, r.Warnings)
	}
	r = win(onlyRead{info: info})
	if r.Status != trustfreeze.StatusUnavailable || !warning(r, probe.DiagFieldUnavailable, AttrArch) {
		t.Fatalf("windows without a machine source: %s %+v", r.Status, r.Warnings)
	}
}

// TestNormalizeMachine pins the GOARCH spelling of machine names.
func TestNormalizeMachine(t *testing.T) {
	for in, want := range map[string]string{
		"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64", "arm64": "arm64", "i686": "386",
		"armv7l": "arm", "armv8l": "arm", "loongarch64": "loong64", "riscv64": "riscv64", " s390x\n": "s390x",
	} {
		if got := NormalizeMachine(in); got != want {
			t.Errorf("NormalizeMachine(%q) = %q, want %q", in, got, want)
		}
	}
	for m, want := range map[uint16]string{0x8664: "amd64", 0xaa64: "arm64", 0x014c: "386", 0x01c4: "arm"} {
		if got, err := winMachineArch(m); err != nil || got != want {
			t.Errorf("winMachineArch(%#x) = %q, %v", m, got, err)
		}
	}
	if got, err := winMachineArch(0x0200); err == nil {
		t.Errorf("an unknown machine type became %q", got)
	}
}
