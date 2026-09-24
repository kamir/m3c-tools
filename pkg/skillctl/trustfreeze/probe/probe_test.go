package probe

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

type stubProbe struct {
	d ProbeDescriptor
}

func (s stubProbe) Descriptor() ProbeDescriptor                        { return s.d }
func (s stubProbe) Support(context.Context, HostContext) SupportResult { return Supported() }
func (s stubProbe) Collect(context.Context, CollectContext) trustfreeze.ProbeResult {
	return trustfreeze.ProbeResult{}
}

type claimingProbe struct {
	stubProbe
	claims map[Platform][]EvidenceLevel
}

func (c claimingProbe) EvidenceClaims() map[Platform][]EvidenceLevel { return c.claims }

func desc(id string, plats ...Platform) ProbeDescriptor {
	return ProbeDescriptor{
		ID: id, Version: "1", Platforms: plats, RequiredPrivilege: PrivilegeUser,
		Sensitivity: trustfreeze.SensitivityPublic, Provides: []string{"device/x"},
	}
}

// TestRegistryDuplicateAndOrder: a duplicate id is an error and nothing is
// replaced; ids come back sorted whatever the registration order (SPEC-0467
// section 5.1).
func TestRegistryDuplicateAndOrder(t *testing.T) {
	reg := NewRegistry()
	for _, id := range []string{"linux.users", "common.identity", "darwin.launchd"} {
		if err := reg.Register(stubProbe{desc(id, PlatformLinux)}); err != nil {
			t.Fatal(err)
		}
	}
	first, _ := reg.Get("common.identity")
	if err := reg.Register(stubProbe{desc("common.identity", PlatformDarwin)}); !errors.Is(err, ErrDuplicateProbe) {
		t.Fatalf("duplicate: %v", err)
	}
	if again, _ := reg.Get("common.identity"); again.Descriptor().Platforms[0] != first.Descriptor().Platforms[0] {
		t.Fatal("duplicate registration replaced the probe")
	}
	if got := strings.Join(reg.IDs(), ","); got != "common.identity,darwin.launchd,linux.users" {
		t.Fatalf("ids %s", got)
	}
	ps := reg.Probes()
	if len(ps) != 3 || ps[0].Descriptor().ID != "common.identity" {
		t.Fatalf("probes %v", ps)
	}
	if err := reg.Register(nil); err == nil {
		t.Fatal("nil probe accepted")
	}
}

// TestDescriptorValidate: SPEC-0467 R1, every declared property is checked.
func TestDescriptorValidate(t *testing.T) {
	good := desc("common.identity", PlatformLinux)
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(d *ProbeDescriptor){
		"id":          func(d *ProbeDescriptor) { d.ID = "Common/identity" },
		"version":     func(d *ProbeDescriptor) { d.Version = " " },
		"no_platform": func(d *ProbeDescriptor) { d.Platforms = nil },
		"platform":    func(d *ProbeDescriptor) { d.Platforms = []Platform{"plan9"} },
		"dup_plat":    func(d *ProbeDescriptor) { d.Platforms = []Platform{PlatformLinux, PlatformLinux} },
		"privilege":   func(d *ProbeDescriptor) { d.RequiredPrivilege = "root" },
		"timeout":     func(d *ProbeDescriptor) { d.DefaultTimeout = -time.Second },
		"sensitivity": func(d *ProbeDescriptor) { d.Sensitivity = "secret" },
		"provides":    func(d *ProbeDescriptor) { d.Provides = []string{""} },
	}
	for name, mutate := range bad {
		d := good
		d.Platforms = append([]Platform(nil), good.Platforms...)
		mutate(&d)
		if err := d.Validate(); !errors.Is(err, ErrInvalidDescriptor) {
			t.Errorf("%s: %v", name, err)
		}
		if err := NewRegistry().Register(stubProbe{d}); err == nil {
			t.Errorf("%s: registry accepted an invalid descriptor", name)
		}
	}
}

// TestSupportResultValidate: only the four non-available statuses are
// allowed, and they stay distinct (SPEC-0471 TF06-R2).
func TestSupportResultValidate(t *testing.T) {
	for _, s := range []SupportResult{Supported(), Unsupported("x"), Unavailable("x"), NotApplicable("x"), PermissionDenied("x")} {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
	for _, s := range []SupportResult{{}, {Status: trustfreeze.StatusCaptured}, {Status: trustfreeze.StatusFailed}, {Available: true, Status: trustfreeze.StatusPartial}} {
		if err := s.Validate(); !errors.Is(err, ErrInvalidSupport) {
			t.Errorf("%+v accepted", s)
		}
	}
	if r := Unavailable("nft missing").Record(); r.Available || r.Reason != "nft missing" {
		t.Fatalf("%+v", r)
	}
}

// TestHostContextSubject: the subject comes from trustfreeze.SubjectID; a
// host without a usable hostname has no subject.
func TestHostContextSubject(t *testing.T) {
	h := testHost()
	s, name, err := h.Subject()
	if err != nil || name != "host-a.example" || s.ID != trustfreeze.SubjectID("linux", "host-a.example") || s.OSFamily != "linux" {
		t.Fatalf("%+v %q %v", s, name, err)
	}
	h.Hostname = func() (string, error) { return " ", nil }
	if _, _, err := h.Subject(); err == nil {
		t.Fatal("empty hostname accepted")
	}
	h.Hostname = func() (string, error) { return "", errors.New("boom") }
	if _, _, err := h.Subject(); err == nil {
		t.Fatal("hostname error ignored")
	}
	if err := (HostContext{}).Validate(); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("empty host: %v", err)
	}
	if err := testHost().Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := (HostContext{}).ReadFile("/etc/os-release"); !errors.Is(err, ErrNoFileReader) {
		t.Fatalf("no reader: %v", err)
	}
}

func testHost() HostContext {
	return HostContext{
		GOOS: "linux", GOARCH: "amd64",
		Hostname:  func() (string, error) { return "host-a.example", nil },
		Files:     FakeFiles{},
		Runner:    NewFakeRunner(),
		Clock:     trustfreeze.FixedClock{T: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		Privilege: PrivilegeUser,
	}
}

func redactedOf(t *testing.T, s string) redact.Redacted {
	t.Helper()
	rr, err := redact.Default().RedactBytes(context.Background(), redact.EvidenceDescriptor{}, []byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return rr.Data
}

// TestEvidenceBuffer: names are validated, duplicates (also by case) and
// limits refused, adds after Close fail, items come back sorted.
func TestEvidenceBuffer(t *testing.T) {
	b := NewEvidenceBuffer("common.identity", Limits{MaxFiles: 2, MaxFileBytes: 10})
	ref, err := b.Add("uname-r.stdout", "stdout:uname", redactedOf(t, "6.8.0\n"), false)
	if err != nil || ref.Path != "evidence/common.identity/uname-r.stdout" || ref.Size != 6 || ref.SHA256 != trustfreeze.SHA256Hex([]byte("6.8.0\n")) {
		t.Fatalf("%+v %v", ref, err)
	}
	if _, err := b.Add("UNAME-R.stdout", "", redactedOf(t, "x"), false); !errors.Is(err, ErrEvidenceDuplicate) {
		t.Fatalf("case duplicate: %v", err)
	}
	if _, err := b.Add("../escape", "", redactedOf(t, "x"), false); !errors.Is(err, trustfreeze.ErrBadPath) {
		t.Fatalf("bad name: %v", err)
	}
	if _, err := b.Add("big", "", redactedOf(t, "01234567890"), false); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("size: %v", err)
	}
	if _, err := b.Add("a-first", "", redactedOf(t, "a"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Add("third", "", redactedOf(t, "c"), false); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("count: %v", err)
	}
	// Four refusals so far: case duplicate, bad name, size, count
	// (SPEC-0467 section 5.3: the engine caps such a probe at partial).
	if n := b.Refused(); n != 4 {
		t.Fatalf("Refused() = %d, want 4", n)
	}
	items := b.Close()
	if len(items) != 2 || items[0].Name != "a-first" || !items[0].Truncated {
		t.Fatalf("items %+v", items)
	}
	if _, err := b.Add("late", "", redactedOf(t, "x"), false); !errors.Is(err, ErrEvidenceClosed) {
		t.Fatalf("after close: %v", err)
	}
	if n := b.Refused(); n != 4 {
		t.Fatalf("an add after Close (an abandoned probe) counted as a refusal: %d", n)
	}
	cc := CollectContext{ProbeID: "common.identity"}
	if ref, err := cc.AddEvidence("x", "s", redactedOf(t, "y"), false); err != nil || ref.Path != "evidence/common.identity/x" {
		t.Fatalf("sinkless add: %+v %v", ref, err)
	}
}

// TestLimitsClamp: a request can ask for less than the limit, never more
// (SPEC-0467 R7).
func TestLimitsClamp(t *testing.T) {
	l := Limits{Timeout: time.Second, MaxStdoutBytes: 100, MaxStderrBytes: 10}
	r := l.clampRequest(CommandRequest{Timeout: time.Hour, MaxStdoutBytes: 1 << 30, MaxStderrBytes: 5})
	if r.Timeout != time.Second || r.MaxStdoutBytes != 100 || r.MaxStderrBytes != 5 {
		t.Fatalf("%+v", r)
	}
	r = l.clampRequest(CommandRequest{})
	if r.Timeout != time.Second || r.MaxStdoutBytes != 100 || r.MaxStderrBytes != 10 {
		t.Fatalf("zero request: %+v", r)
	}
	if d := (Limits{}).WithDefaults(); d != DefaultLimits() {
		t.Fatalf("defaults %+v", d)
	}
	if err := (Limits{MaxFiles: -1}).Validate(); err == nil {
		t.Fatal("negative limit accepted")
	}
}

// TestRecordingRunner: invocations are recorded from the redacted result,
// requests are clamped, truncation and redaction failure are reported, and
// nothing runs after Close.
func TestRecordingRunner(t *testing.T) {
	f := NewFakeRunner().
		Script("a", []string{"--token", testSecret}, FakeResponse{Stdout: []byte("ok\n")}).
		Script("b", nil, FakeResponse{Stdout: []byte(strings.Repeat("x\n", 100))})
	small, err := redact.New(redact.WithMaxInputBytes(64))
	if err != nil {
		t.Fatal(err)
	}
	rec := NewRecordingRunner(f, Limits{MaxStdoutBytes: 150, Timeout: time.Second}, small)
	rec.Run(context.Background(), CommandRequest{Executable: "a", Args: []string{"--token", testSecret}, MaxStdoutBytes: 1 << 20})
	res := rec.Run(context.Background(), CommandRequest{Executable: "b"})
	if !res.StdoutTruncated || !res.RedactionFailed || len(res.Stdout.Bytes()) != 0 {
		t.Fatalf("want truncated and fail-closed output: %+v", res)
	}
	invs, redFailed, truncated := rec.Close()
	if len(invs) != 2 || !redFailed || strings.Join(truncated, ",") != "stdout:b" {
		t.Fatalf("invs=%d redFailed=%v truncated=%v", len(invs), redFailed, truncated)
	}
	if strings.Contains(strings.Join(invs[0].Args, " "), testSecret) {
		t.Fatalf("recorded args %q", invs[0].Args)
	}
	calls := f.Calls()
	if calls[0].MaxStdout != 150 || calls[0].Timeout != time.Second {
		t.Fatalf("request not clamped: %+v", calls[0])
	}
	late := rec.Run(context.Background(), CommandRequest{Executable: "a", Args: []string{"--token", testSecret}})
	if !errors.Is(late.Err, ErrCanceled) || len(f.Calls()) != 2 {
		t.Fatalf("run after Close: %v (calls %d)", late.Err, len(f.Calls()))
	}
}

// TestRootedFileReader: reads inside the roots, refuses paths outside,
// relative paths, symlink escapes (TF02-AC6), non-regular files and files
// over the size limit.
func TestRootedFileReader(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "ok"), "inside")
	write(filepath.Join(root, "big"), strings.Repeat("x", 11))
	write(filepath.Join(outside, "secret"), "outside")
	r := NewRootedFileReader([]string{root, "relative/root"}, 10)

	if b, err := r.ReadFile(filepath.Join(root, "ok")); err != nil || string(b) != "inside" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := r.ReadFile(filepath.Join(outside, "secret")); !errors.Is(err, ErrOutsideRoots) {
		t.Fatalf("outside: %v", err)
	}
	if _, err := r.ReadFile(filepath.Join(root, "..", "outside", "secret")); !errors.Is(err, ErrOutsideRoots) {
		t.Fatalf("dotdot: %v", err)
	}
	if _, err := r.ReadFile("relative/root/ok"); !errors.Is(err, ErrOutsideRoots) {
		t.Fatalf("relative: %v", err)
	}
	if _, err := r.ReadFile(filepath.Join(root, "big")); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("size: %v", err)
	}
	if _, err := r.ReadFile(filepath.Join(root, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := r.ReadFile(root); !errors.Is(err, ErrNotRegularFile) {
		t.Fatalf("directory: %v", err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(filepath.Join(outside, "secret"), link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("windows: creating a symlink needs a privilege this runner lacks: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := r.ReadFile(link); !errors.Is(err, ErrOutsideRoots) {
		t.Fatalf("symlink escape: %v", err)
	}
}

// TestSupportMatrix: SPEC-0471 section 4 and TF06-R6. Implementation state per
// probe and platform, only build-time evidence levels, never a claim for an
// unregistered probe or an undeclared platform.
func TestSupportMatrix(t *testing.T) {
	reg := NewRegistry()
	p := claimingProbe{
		stubProbe: stubProbe{desc("common.identity", PlatformLinux, PlatformDarwin)},
		claims: map[Platform][]EvidenceLevel{
			PlatformLinux:   {CrossCompiled, FixtureTested, FixtureTested, "real-platform-tested"},
			PlatformWindows: {FixtureTested},
		},
	}
	if err := reg.Register(p); err != nil {
		t.Fatal(err)
	}
	rows := SupportMatrix(reg, []string{"linux.firewall", "common.identity"})
	if len(rows) != 6 {
		t.Fatalf("%d rows", len(rows))
	}
	got := map[string]SupportEntry{}
	for _, r := range rows {
		got[r.ProbeID+"/"+string(r.Platform)] = r
		for _, e := range r.Evidence {
			if e != FixtureTested && e != CrossCompiled {
				t.Fatalf("level %q claimed in code", e)
			}
		}
	}
	if e := got["common.identity/linux"]; e.State != Implemented || len(e.Evidence) != 2 || e.Evidence[0] != CrossCompiled {
		t.Fatalf("linux row %+v", e)
	}
	if e := got["common.identity/darwin"]; e.State != Implemented || len(e.Evidence) != 0 {
		t.Fatalf("darwin row %+v (no claim means no evidence)", e)
	}
	if e := got["common.identity/windows"]; e.State != NotImplemented || len(e.Evidence) != 0 {
		t.Fatalf("windows row %+v (undeclared platform)", e)
	}
	if e := got["linux.firewall/linux"]; e.State != NotImplemented || e.Evidence == nil {
		t.Fatalf("unregistered row %+v", e)
	}
	if rows[0].ProbeID != "common.identity" || rows[0].Platform != PlatformDarwin {
		t.Fatalf("rows not sorted: %+v", rows[0])
	}
}
