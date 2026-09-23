package capture

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/platform/common"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// Synthetic values only (public plane rule).
const (
	testHostname    = "host-a.example"
	ubuntuOSRelease = "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\n"
	tokenPattern    = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
	tokenOpaque     = "opaque-S3CR3T-value-0123456789"
)

// testTime is the test clock default (SPEC-0466 section 5.2).
var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// fakeProbe is a configurable probe for engine tests.
type fakeProbe struct {
	d       probe.ProbeDescriptor
	support func(context.Context, probe.HostContext) probe.SupportResult
	collect func(context.Context, probe.CollectContext) trustfreeze.ProbeResult
}

func (f *fakeProbe) Descriptor() probe.ProbeDescriptor { return f.d }

func (f *fakeProbe) Support(ctx context.Context, h probe.HostContext) probe.SupportResult {
	if f.support != nil {
		return f.support(ctx, h)
	}
	return probe.Supported()
}

func (f *fakeProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	return f.collect(ctx, cc)
}

func newFake(id string, collect func(context.Context, probe.CollectContext) trustfreeze.ProbeResult) *fakeProbe {
	return &fakeProbe{
		d: probe.ProbeDescriptor{
			ID: id, Version: "7", Platforms: []probe.Platform{probe.PlatformLinux},
			RequiredPrivilege: probe.PrivilegeUser, Sensitivity: trustfreeze.SensitivityPublic,
		},
		collect: collect,
	}
}

func captured(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
	return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
}

// fixtureHost is a linux host made of fakes: nothing on the real host is
// read or run.
func fixtureHost(runner *probe.FakeRunner) probe.HostContext {
	return probe.HostContext{
		GOOS: "linux", GOARCH: "amd64",
		Hostname:  func() (string, error) { return testHostname, nil },
		Files:     probe.FakeFiles{Files: map[string][]byte{common.OSReleasePath: []byte(ubuntuOSRelease)}},
		Runner:    runner,
		Clock:     trustfreeze.FixedClock{T: testTime},
		Privilege: probe.PrivilegeUser,
	}
}

func identityRunner() *probe.FakeRunner {
	return probe.NewFakeRunner().AddTool("uname", "/usr/bin/uname").
		Script("uname", []string{"-r"}, probe.FakeResponse{Stdout: []byte("6.8.0-45-generic\n")}).
		Script("uname", []string{"-m"}, probe.FakeResponse{Stdout: []byte("x86_64\n")})
}

func registry(t *testing.T, extra ...probe.Probe) *probe.Registry {
	t.Helper()
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range extra {
		if err := reg.Register(p); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func profile(t *testing.T, required, optional []string) Profile {
	t.Helper()
	y := "schema_version: trust-freeze/profile/v1\nid: test-profile\nversion: \"3\"\nfail_if_required_missing: true\nredaction_policy: default-v1\nrequired:\n"
	for _, r := range required {
		y += "  - " + r + "\n"
	}
	y += "optional:\n"
	for _, o := range optional {
		y += "  - " + o + "\n"
	}
	if len(optional) == 0 {
		y = strings.Replace(y, "optional:\n", "optional: []\n", 1)
	}
	p, err := ParseProfile([]byte(y))
	if err != nil {
		t.Fatalf("profile: %v\n%s", err, y)
	}
	return p
}

func baseOptions(t *testing.T, p Profile, reg *probe.Registry, runner *probe.FakeRunner) Options {
	t.Helper()
	return Options{
		Profile:     p,
		Registry:    reg,
		Host:        fixtureHost(runner),
		Output:      filepath.Join(t.TempDir(), "bundle"),
		ToolVersion: "0.0.0-test",
		Actor:       "id:alice@example",
	}
}

func mustRun(t *testing.T, opts Options) *Result {
	t.Helper()
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func resultFor(t *testing.T, res *Result, id string) trustfreeze.ProbeResult {
	t.Helper()
	for _, r := range res.Results {
		if r.ProbeID == id {
			return r
		}
	}
	t.Fatalf("no result for %s", id)
	return trustfreeze.ProbeResult{}
}

func hasWarn(r trustfreeze.ProbeResult, code string) bool {
	for _, w := range r.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// readTree returns path -> bytes of every regular file below dir.
func readTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(dir, p)
			out[filepath.ToSlash(rel)] = b
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// verifyBundle proves the written bundle with the core reader: VerifyDir
// passes, capture.json parses and its completeness recomputes, and every
// probe result reads back in canonical form.
func verifyBundle(t *testing.T, res *Result) *trustfreeze.Bundle {
	t.Helper()
	if v := trustfreeze.VerifyDir(res.Dir); !v.OK {
		t.Fatalf("VerifyDir: %v", v.Failures)
	}
	b, err := trustfreeze.ReadBundle(res.Dir)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if b.Manifest.Kind != trustfreeze.KindCapture || b.Capture == nil || b.State == nil {
		t.Fatalf("bundle %+v", b)
	}
	if b.Has(trustfreeze.ApprovalFile) {
		t.Fatal("a capture must never contain approval.json (SPEC-0470 TF05-R2)")
	}
	back, err := b.ReadProbeResults()
	if err != nil {
		t.Fatalf("ReadProbeResults: %v", err)
	}
	if len(back) != len(res.Results) {
		t.Fatalf("%d probe files, %d results", len(back), len(res.Results))
	}
	return b
}

// TestCaptureWalkingSkeletonComplete: the walking-skeleton profile completes on
// a fixture host and the bundle passes the core VerifyDir (SPEC-0467 section
// 5.6).
func TestCaptureWalkingSkeletonComplete(t *testing.T) {
	p, err := BuiltinProfile("walking-skeleton")
	if err != nil {
		t.Fatal(err)
	}
	res := mustRun(t, baseOptions(t, p, registry(t), identityRunner()))
	if !res.Complete() {
		t.Fatalf("incomplete: %+v", res.Capture.Completeness)
	}
	b := verifyBundle(t, res)
	raw, err := builtinProfiles.ReadFile("profiles/walking-skeleton.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ref := b.Capture.Capture.Profile
	if ref.ID != "walking-skeleton" || ref.Version != "1" || ref.Digest != trustfreeze.Digest(raw) {
		t.Fatalf("profile ref %+v", ref)
	}
	if b.Capture.Subject.ID != trustfreeze.SubjectID("linux", testHostname) || b.Manifest.Subject != b.Capture.Subject {
		t.Fatalf("subject %+v", b.Capture.Subject)
	}
	meta := b.Capture.Capture
	if meta.Tool != trustfreeze.CaptureTool || meta.ToolVersion != "0.0.0-test" || meta.Actor != "id:alice@example" || meta.StartedAt != "2026-01-02T03:04:05Z" {
		t.Fatalf("capture meta %+v", meta)
	}
	ids := []string{}
	for _, a := range b.State.Artifacts {
		ids = append(ids, a.ID)
	}
	if strings.Join(ids, ",") != "device/host,device/os" {
		t.Fatalf("state artifacts %v", ids)
	}
	for _, want := range []string{"probes/common.identity.json", "evidence/common.identity/os-release", "evidence/common.identity/uname-m.stdout", "evidence/common.identity/uname-r.stdout", "state/device.json", "capture.json"} {
		if !b.Has(want) {
			t.Errorf("bundle lacks %s", want)
		}
	}
	r := resultFor(t, res, common.IdentityProbeID)
	if len(r.Tools) != 2 || r.Tools[0].Name != "uname" || r.Tools[1].Name != "uname" || len(r.RawEvidence) != 3 || r.RawEvidence[0].Source != "file:/etc/os-release" {
		t.Fatalf("identity result tools %+v evidence %+v", r.Tools, r.RawEvidence)
	}
	// The architecture is the machine's (uname -m x86_64), spelled like GOARCH.
	for _, a := range b.State.Artifacts {
		if a.ID == common.ArtifactOS && a.Attributes[common.AttrArch] != "amd64" {
			t.Fatalf("device/os arch %q", a.Attributes[common.AttrArch])
		}
	}
}

// TestCaptureDeterministic: the same inputs, clock and fakes give a
// byte-identical bundle (SPEC-0466 R5).
func TestCaptureDeterministic(t *testing.T) {
	p, err := BuiltinProfile("agentic-workstation")
	if err != nil {
		t.Fatal(err)
	}
	a := mustRun(t, baseOptions(t, p, registry(t), identityRunner()))
	b := mustRun(t, baseOptions(t, p, registry(t), identityRunner()))
	ta, tb := readTree(t, a.Dir), readTree(t, b.Dir)
	if len(ta) != len(tb) || len(ta) < 5 {
		t.Fatalf("file counts %d and %d", len(ta), len(tb))
	}
	for path, ba := range ta {
		if !bytes.Equal(ba, tb[path]) {
			t.Fatalf("%s differs between two identical captures", path)
		}
	}
	if a.Manifest.ContentDigest != b.Manifest.ContentDigest {
		t.Fatal("content digests differ")
	}
}

// TestCaptureUnimplementedProbesHonest: every probe of a built-in profile
// that this build lacks is unsupported with reason not_implemented, a probe
// this build does have never claims that, and a profile whose required
// probes cannot all succeed here is incomplete (SPEC-0467 section 5.6).
func TestCaptureUnimplementedProbesHonest(t *testing.T) {
	for _, id := range BuiltinProfileIDs() {
		if id == "walking-skeleton" {
			continue
		}
		t.Run(id, func(t *testing.T) {
			p, err := BuiltinProfile(id)
			if err != nil {
				t.Fatal(err)
			}
			reg := registry(t)
			res := mustRun(t, baseOptions(t, p, reg, identityRunner()))
			if res.Complete() {
				t.Fatal("a profile with unimplemented required probes reported complete")
			}
			verifyBundle(t, res)
			implemented := 0
			for _, r := range res.Results {
				if r.ProbeID == common.IdentityProbeID {
					if r.Status != trustfreeze.StatusCaptured {
						t.Fatalf("identity %s", r.Status)
					}
					continue
				}
				if _, ok := reg.Get(r.ProbeID); ok {
					// A registered probe reports what it observed on the
					// fixture host (no tool resolves there), never that it
					// does not exist in this build.
					implemented++
					if r.Status == trustfreeze.StatusUnsupported && r.Reason == trustfreeze.ReasonNotImplemented {
						t.Fatalf("%s is registered but reported %s", r.ProbeID, trustfreeze.ReasonNotImplemented)
					}
					continue
				}
				if r.Status != trustfreeze.StatusUnsupported || r.Reason != trustfreeze.ReasonNotImplemented || r.Support.Available {
					t.Fatalf("%s: %s %q", r.ProbeID, r.Status, r.Reason)
				}
			}
			if len(res.Results) != len(p.ProbeIDs()) {
				t.Fatalf("%d results for %d probes", len(res.Results), len(p.ProbeIDs()))
			}
			if id == "ubuntu-bastion" && implemented != len(p.ProbeIDs())-3 {
				// ubuntu-bastion: every probe but common.identity (counted
				// separately), common.git and common.claude is implemented.
				t.Fatalf("%d implemented probes of %d", implemented, len(p.ProbeIDs()))
			}
			if len(res.Capture.Completeness.Gaps) == 0 {
				t.Fatal("an incomplete capture without a gap")
			}
			for _, g := range res.Capture.Completeness.Gaps {
				if !p.IsRequired(g.ProbeID) {
					t.Fatalf("gap for the optional probe %s", g.ProbeID)
				}
			}
		})
	}
}

// TestCaptureMissingToolContinues: TF02-AC4 equivalent. A missing tool makes
// the identity field unavailable while every other probe still runs.
func TestCaptureMissingToolContinues(t *testing.T) {
	ran := false
	other := newFake("test.after", func(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
		ran = true
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
	})
	p := profile(t, []string{common.IdentityProbeID, "test.after"}, nil)
	res := mustRun(t, baseOptions(t, p, registry(t, other), probe.NewFakeRunner()))
	id := resultFor(t, res, common.IdentityProbeID)
	if id.Status != trustfreeze.StatusUnavailable || !hasWarn(id, probe.DiagFieldUnavailable) {
		t.Fatalf("identity %s %+v", id.Status, id.Warnings)
	}
	if !ran || resultFor(t, res, "test.after").Status != trustfreeze.StatusCaptured {
		t.Fatal("the capture stopped after a missing tool")
	}
	if res.Complete() || res.Capture.Completeness.Gaps[0].ProbeID != common.IdentityProbeID {
		t.Fatalf("completeness %+v", res.Capture.Completeness)
	}
	verifyBundle(t, res)
}

// TestCapturePermissionDeniedNeverComplete: a permission_denied probe (from
// the probe or from the privilege check) cannot yield a complete capture
// (SPEC-0466 TF01-AC6, SPEC-0467 R6).
func TestCapturePermissionDeniedNeverComplete(t *testing.T) {
	denied := newFake("test.denied", func(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusPermissionDenied, Reason: "needs root"}
	})
	collected := false
	elevated := newFake("test.elevated", func(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
		collected = true
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
	})
	elevated.d.RequiredPrivilege = probe.PrivilegeElevated
	for _, id := range []string{"test.denied", "test.elevated"} {
		p := profile(t, []string{common.IdentityProbeID, id}, nil)
		res := mustRun(t, baseOptions(t, p, registry(t, denied, elevated), identityRunner()))
		if res.Complete() {
			t.Fatalf("%s: complete despite permission_denied", id)
		}
		r := resultFor(t, res, id)
		if r.Status != trustfreeze.StatusPermissionDenied {
			t.Fatalf("%s: %s", id, r.Status)
		}
		gap := res.Capture.Completeness.Gaps[0]
		if gap.ProbeID != id || gap.Status != trustfreeze.StatusPermissionDenied || gap.Reason != trustfreeze.GapNotCaptured {
			t.Fatalf("%s: gap %+v", id, gap)
		}
		verifyBundle(t, res)
	}
	if collected {
		t.Fatal("a probe that needs elevation was run without it (Trust Freeze never elevates)")
	}
}

// TestCapturePanicBecomesFailed: a panic in Collect or Support is recovered
// as failed, its message is redacted, and the capture goes on (SPEC-0467
// section 5.6).
func TestCapturePanicBecomesFailed(t *testing.T) {
	inCollect := newFake("test.panic", func(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
		panic("boom password=" + tokenOpaque)
	})
	inSupport := newFake("test.panicsupport", captured)
	inSupport.support = func(context.Context, probe.HostContext) probe.SupportResult { panic("support boom") }
	p := profile(t, []string{common.IdentityProbeID, "test.panic", "test.panicsupport"}, nil)
	res := mustRun(t, baseOptions(t, p, registry(t, inCollect, inSupport), identityRunner()))
	for _, id := range []string{"test.panic", "test.panicsupport"} {
		r := resultFor(t, res, id)
		if r.Status != trustfreeze.StatusFailed || r.Error == nil || r.Error.Class != probe.ClassPanic {
			t.Fatalf("%s: %s %+v", id, r.Status, r.Error)
		}
	}
	if resultFor(t, res, common.IdentityProbeID).Status != trustfreeze.StatusCaptured || res.Complete() {
		t.Fatal("panic handling broke the capture")
	}
	assertNotPersisted(t, res.Dir, tokenOpaque)
	verifyBundle(t, res)
}

// TestCaptureProbeTimeout: a probe that ignores its context is abandoned at
// its timeout and recorded as timeout; the capture finishes.
func TestCaptureProbeTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	hang := newFake("test.hang", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		<-release
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
	})
	p := profile(t, []string{common.IdentityProbeID}, []string{"test.hang"})
	opts := baseOptions(t, p, registry(t, hang), identityRunner())
	opts.ProbeTimeout = 100 * time.Millisecond
	res := mustRun(t, opts)
	r := resultFor(t, res, "test.hang")
	if r.Status != trustfreeze.StatusTimeout || r.Error == nil || r.Error.Class != probe.ClassTimeout {
		t.Fatalf("status %s error %+v", r.Status, r.Error)
	}
	// An optional probe timing out does not block completeness, and the
	// timeout stays visible in the probes list.
	if !res.Complete() {
		t.Fatalf("completeness %+v", res.Capture.Completeness)
	}
	verifyBundle(t, res)
}

// assertNotPersisted scans every byte of every file in the bundle.
func assertNotPersisted(t *testing.T, dir string, secrets ...string) {
	t.Helper()
	for path, b := range readTree(t, dir) {
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Fatalf("secret %q persisted in %s:\n%s", s[:8], path, b)
			}
		}
	}
}

// TestCaptureNoSecretPersisted: TF02-AC3. A token in stdout, stderr, a JSON
// value and a command argument appears in no persisted byte of the bundle,
// including when a probe copies it into result fields.
func TestCaptureNoSecretPersisted(t *testing.T) {
	args := []string{"--token", tokenOpaque, "--password=" + tokenOpaque, tokenPattern}
	runner := identityRunner().
		Script("leaky", args, probe.FakeResponse{
			Stdout: []byte("api_key=" + tokenOpaque + "\n" + tokenPattern + "\nechoed " + tokenOpaque + "\n"),
			Stderr: []byte("Authorization: Bearer " + tokenOpaque + "\npassword: " + tokenOpaque + "\n"),
		}).
		Script("leaky-json", nil, probe.FakeResponse{
			Stdout: []byte(`{"client_secret": "` + tokenOpaque + `", "items": ["` + tokenPattern + `"], "ok": "fine"}` + "\n"),
		})
	leaky := newFake("test.leaky", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		r1 := cc.Runner.Run(ctx, probe.CommandRequest{Executable: "leaky", Args: args})
		r2 := cc.Runner.Run(ctx, probe.CommandRequest{Executable: "leaky-json"})
		for name, data := range map[string]redact.Redacted{"leaky.stdout": r1.Stdout, "leaky.stderr": r1.Stderr, "leaky-json.stdout": r2.Stdout} {
			if _, err := cc.AddEvidence(name, "command:"+name+" "+tokenOpaque, data, false); err != nil {
				panic(err)
			}
		}
		a := trustfreeze.Artifact{
			ID: "service/test/leaky", Type: "service", Scope: "device", Source: "test.leaky",
			State: trustfreeze.StateObserved, Sensitivity: trustfreeze.SensitivityInternal,
			Attributes: map[string]string{
				"token":       tokenOpaque,                                   // sensitive key
				"config_line": "password=" + tokenOpaque,                     // key/value text
				"remote":      "https://bob:" + tokenOpaque + "@git.example", // URL credential
				"note":        tokenOpaque,                                   // copied from an argument
				"pattern":     "found " + tokenPattern,                       // token shape
				"plain":       "kept",
			},
			Provenance: trustfreeze.Provenance{Method: "command", Confidence: trustfreeze.ConfidenceProven, ObservedAt: trustfreeze.FormatTime(cc.Now()), Sources: []string{"command:leaky --token " + tokenOpaque}},
		}
		return trustfreeze.ProbeResult{
			Status:          trustfreeze.StatusPartial,
			Reason:          "partial because password=" + tokenOpaque,
			NormalizedState: []trustfreeze.Artifact{a},
			Warnings:        []trustfreeze.Diagnostic{{Code: "note", Message: "saw " + tokenPattern}},
			Error:           &trustfreeze.ProbeError{Class: "failed", Message: "Authorization: Bearer " + tokenOpaque},
		}
	})
	p := profile(t, []string{common.IdentityProbeID, "test.leaky"}, nil)
	res := mustRun(t, baseOptions(t, p, registry(t, leaky), runner))
	b := verifyBundle(t, res)
	assertNotPersisted(t, res.Dir, tokenOpaque, tokenPattern)

	r := resultFor(t, res, "test.leaky")
	if len(r.Tools) != 2 || r.Tools[0].Args[1] != redact.Marker("token") {
		t.Fatalf("tools %+v", r.Tools)
	}
	if !hasWarn(r, probe.DiagValueRedacted) || len(r.RawEvidence) != 3 {
		t.Fatalf("warnings %+v evidence %d", r.Warnings, len(r.RawEvidence))
	}
	a := r.NormalizedState[0]
	if a.Attributes["plain"] != "kept" || !strings.Contains(a.Attributes["note"], "[REDACTED_") {
		t.Fatalf("attributes %v", a.Attributes)
	}
	if d, _ := trustfreeze.ComputeArtifactDigest(a); a.Digest != d {
		t.Fatal("artifact digest was not recomputed after redaction")
	}
	for _, f := range []string{"evidence/test.leaky/leaky.stdout", "evidence/test.leaky/leaky.stderr", "evidence/test.leaky/leaky-json.stdout"} {
		raw, err := b.ReadFile(f)
		if err != nil || !bytes.Contains(raw, []byte("[REDACTED_")) {
			t.Fatalf("%s: %q %v", f, raw, err)
		}
	}
}

// TestCaptureEvidenceReRedacted: TF02-AC3, SPEC-0467 sections 2.3 and 5.2.
// redact.Redacted proves that some redactor ran, not the capture's own: the
// engine re-redacts every evidence file with the capture redactor plus every
// argument secret of the probe run before it is written. Two leaks it closes:
// a secret that one command takes as an argument and another command prints
// without key context, and file content a probe redacted with
// redact.Default(), which does not know the home root.
func TestCaptureEvidenceReRedacted(t *testing.T) {
	const (
		argSecret = "opaque-argument-secret-7788"
		home      = "/home/alice-review"
	)
	runner := identityRunner().
		Script("tool", []string{"login", "--password", argSecret}, probe.FakeResponse{Stdout: []byte("logged in\n")}).
		Script("tool", []string{"status"}, probe.FakeResponse{Stdout: []byte("session for " + argSecret + "\nuser " + argSecret + "\n")})
	twoCmd := newFake("test.twocmd", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		cc.Runner.Run(ctx, probe.CommandRequest{Executable: "tool", Args: []string{"login", "--password", argSecret}})
		st := cc.Runner.Run(ctx, probe.CommandRequest{Executable: "tool", Args: []string{"status"}})
		if _, err := cc.AddEvidence("status.stdout", "stdout:tool", st.Stdout, false); err != nil {
			panic(err)
		}
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
	})
	homeLeak := newFake("test.homeleak", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		// The probe redacts with the wrong redactor: the home root survives.
		rr, err := redact.Default().RedactBytes(ctx, redact.EvidenceDescriptor{}, []byte("config "+home+"/.config/tool.json\n"))
		if err != nil {
			panic(err)
		}
		if _, err := cc.AddEvidence("config.txt", "file:config", rr.Data, false); err != nil {
			panic(err)
		}
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
	})
	p := profile(t, []string{common.IdentityProbeID, "test.homeleak", "test.twocmd"}, nil)
	opts := baseOptions(t, p, registry(t, twoCmd, homeLeak), runner)
	opts.HomeRoot = home
	res := mustRun(t, opts)
	b := verifyBundle(t, res)
	assertNotPersisted(t, res.Dir, argSecret, home)

	for id, file := range map[string]string{"test.twocmd": "evidence/test.twocmd/status.stdout", "test.homeleak": "evidence/test.homeleak/config.txt"} {
		r := resultFor(t, res, id)
		if r.Status != trustfreeze.StatusCaptured || !hasWarn(r, probe.DiagValueRedacted) || len(r.RawEvidence) != 1 {
			t.Fatalf("%s: status %s warnings %+v evidence %+v", id, r.Status, r.Warnings, r.RawEvidence)
		}
		raw, err := b.ReadFile(file)
		if err != nil || !bytes.Contains(raw, []byte("[REDACTED_")) {
			t.Fatalf("%s: %q %v", file, raw, err)
		}
		if ref := r.RawEvidence[0]; ref.Path != file || ref.Size != int64(len(raw)) || ref.SHA256 != trustfreeze.SHA256Hex(raw) {
			t.Fatalf("%s: reference %+v does not describe the written bytes", id, ref)
		}
	}
}

// TestCaptureEvidenceLimitLowersToPartial: SPEC-0467 section 5.3, TF02-R7.
// Evidence the sink refuses (file size or file count limit) caps the probe
// at partial, whether or not the probe reported the refusal itself.
func TestCaptureEvidenceLimitLowersToPartial(t *testing.T) {
	quiet := newFake("test.quiet", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		// Ignores the error of an evidence file over the limit.
		_, _ = cc.AddEvidence("big.txt", "x", redactedBytes(t, strings.Repeat("x", 64)), false)
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
	})
	many := newFake("test.many", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		for _, n := range []string{"a", "b", "c"} {
			_, _ = cc.AddEvidence(n, "x", redactedBytes(t, "small"), false)
		}
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
	})
	p := profile(t, []string{common.IdentityProbeID, "test.many", "test.quiet"}, nil)
	opts := baseOptions(t, p, registry(t, quiet, many), identityRunner())
	opts.Limits = probe.Limits{MaxFileBytes: 16, MaxFiles: 2}
	res := mustRun(t, opts)
	verifyBundle(t, res)
	for _, id := range []string{common.IdentityProbeID, "test.quiet", "test.many"} {
		r := resultFor(t, res, id)
		if r.Status != trustfreeze.StatusPartial || !hasWarn(r, probe.DiagEvidenceDropped) {
			t.Fatalf("%s: status %s warnings %+v, want partial with evidence_dropped", id, r.Status, r.Warnings)
		}
	}
	if res.Complete() {
		t.Fatal("a capture whose evidence was refused by a limit must not be complete")
	}
}

// TestCaptureOutputTruncatedVisible: TF02-AC2. Output over the limit yields
// a visible truncation diagnostic, the tool record says so, and a probe that
// claimed captured is lowered to partial.
func TestCaptureOutputTruncatedVisible(t *testing.T) {
	runner := identityRunner().Script("chatty", nil, probe.FakeResponse{Stdout: bytes.Repeat([]byte("row of output\n"), 200)})
	chatty := newFake("test.chatty", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		res := cc.Runner.Run(ctx, probe.CommandRequest{Executable: "chatty", MaxStdoutBytes: 1 << 30})
		if _, err := cc.AddEvidence("chatty.stdout", "stdout:chatty", res.Stdout, res.StdoutTruncated); err != nil {
			panic(err)
		}
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
	})
	p := profile(t, []string{common.IdentityProbeID, "test.chatty"}, nil)
	opts := baseOptions(t, p, registry(t, chatty), runner)
	opts.Limits = probe.Limits{MaxStdoutBytes: 100}
	res := mustRun(t, opts)
	b := verifyBundle(t, res)
	back, err := b.ReadProbeResults()
	if err != nil {
		t.Fatal(err)
	}
	var r trustfreeze.ProbeResult
	for _, x := range back {
		if x.ProbeID == "test.chatty" {
			r = x
		}
	}
	if r.Status != trustfreeze.StatusPartial || !hasWarn(r, trustfreeze.DiagOutputTruncated) {
		t.Fatalf("persisted status %s warnings %+v", r.Status, r.Warnings)
	}
	if len(r.Tools) != 1 || !r.Tools[0].StdoutTruncated || r.Tools[0].StdoutBytes != 200*14 {
		t.Fatalf("tool record %+v", r.Tools)
	}
	if len(r.RawEvidence) != 1 || !r.RawEvidence[0].Truncated || r.RawEvidence[0].Size > 100 {
		t.Fatalf("evidence %+v", r.RawEvidence)
	}
	if res.Complete() {
		t.Fatal("a truncated required probe must not be complete")
	}
}

// TestCaptureRedactionFailClosed: when redaction fails, the affected bytes
// are dropped and the probe is at least partial; when the final pass over a
// probe result fails, nothing of that probe is persisted (SPEC-0467
// section 5.2).
func TestCaptureRedactionFailClosed(t *testing.T) {
	const rawMarker = "UNIQUE-RAW-OUTPUT-MARKER"
	big := strings.Repeat(rawMarker+"\n", 40)
	runner := identityRunner().Script("big", nil, probe.FakeResponse{Stdout: []byte(big)})
	outputProbe := newFake("test.output", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		res := cc.Runner.Run(ctx, probe.CommandRequest{Executable: "big"})
		if _, err := cc.AddEvidence("big.stdout", "stdout:big", res.Stdout, false); err != nil {
			panic(err)
		}
		return trustfreeze.ProbeResult{Status: trustfreeze.StatusCaptured}
	})
	resultProbe := newFake("test.result", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		if _, err := cc.AddEvidence("small", "x", redactedBytes(t, "fine"), false); err != nil {
			panic(err)
		}
		return trustfreeze.ProbeResult{
			Status: trustfreeze.StatusCaptured,
			NormalizedState: []trustfreeze.Artifact{{
				ID: "device/test", Type: "t", Scope: "device", Source: "test.result", State: trustfreeze.StateObserved,
				Sensitivity: trustfreeze.SensitivityPublic, Provenance: trustfreeze.Provenance{Method: "x", Confidence: trustfreeze.ConfidenceProven, ObservedAt: "x"},
				Attributes: map[string]string{"blob": strings.Repeat(rawMarker, 20)},
			}},
		}
	})
	small, err := redact.New(redact.WithMaxInputBytes(300))
	if err != nil {
		t.Fatal(err)
	}
	p := profile(t, []string{common.IdentityProbeID, "test.output", "test.result"}, nil)
	opts := baseOptions(t, p, registry(t, outputProbe, resultProbe), runner)
	opts.Redactor = small
	res := mustRun(t, opts)
	verifyBundle(t, res)
	assertNotPersisted(t, res.Dir, rawMarker)

	out := resultFor(t, res, "test.output")
	if out.Status != trustfreeze.StatusPartial || !hasWarn(out, trustfreeze.DiagRedactionFailed) {
		t.Fatalf("output probe %s %+v", out.Status, out.Warnings)
	}
	if len(out.RawEvidence) != 1 || out.RawEvidence[0].Size != 0 {
		t.Fatalf("output evidence %+v", out.RawEvidence)
	}
	rr := resultFor(t, res, "test.result")
	if rr.Status != trustfreeze.StatusFailed || rr.Error == nil || rr.Error.Class != probe.ClassRedactionFailed || len(rr.NormalizedState) != 0 || len(rr.RawEvidence) != 0 {
		t.Fatalf("result probe %+v", rr)
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "evidence", "test.result")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("evidence of a dropped result was written: %v", err)
	}
}

func redactedBytes(t *testing.T, s string) redact.Redacted {
	rr, err := redact.Default().RedactBytes(context.Background(), redact.EvidenceDescriptor{}, []byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return rr.Data
}

// TestCaptureEngineAuthority: the engine, not the probe, sets identity,
// timing, privilege, tools and evidence; invalid statuses, support results,
// artifacts and duplicates are handled without crashing the capture.
func TestCaptureEngineAuthority(t *testing.T) {
	liar := newFake("test.liar", func(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
		return trustfreeze.ProbeResult{
			ProbeID: "other.id", ProbeVersion: "99", Status: trustfreeze.StatusCaptured, StartedAt: "yesterday",
			Privilege:   trustfreeze.PrivilegeElevated,
			Tools:       []trustfreeze.ToolInvocation{{Name: "invented", Args: []string{}}},
			RawEvidence: []trustfreeze.EvidenceRef{{Path: "evidence/test.liar/ghost", SHA256: strings.Repeat("0", 64)}},
			NormalizedState: []trustfreeze.Artifact{
				{ID: "/Users/alice/secret", Type: "x", Scope: "device", Source: "x", State: trustfreeze.StateObserved, Sensitivity: trustfreeze.SensitivityPublic, Provenance: trustfreeze.Provenance{Confidence: trustfreeze.ConfidenceProven}},
				{ID: "device/os", Type: "x", Scope: "device", Source: "x", State: trustfreeze.StateObserved, Sensitivity: trustfreeze.SensitivityPublic, Provenance: trustfreeze.Provenance{Confidence: trustfreeze.ConfidenceProven}},
				{ID: "device/bad-state", Type: "x", Scope: "device", Source: "x", State: "loaded", Sensitivity: trustfreeze.SensitivityPublic, Provenance: trustfreeze.Provenance{Confidence: trustfreeze.ConfidenceProven}},
			},
		}
	})
	badStatus := newFake("test.badstatus", func(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
		return trustfreeze.ProbeResult{Status: "green"}
	})
	badSupport := newFake("test.badsupport", captured)
	badSupport.support = func(context.Context, probe.HostContext) probe.SupportResult {
		return probe.SupportResult{Status: trustfreeze.StatusCaptured}
	}
	unavailable := newFake("test.unavailable", captured)
	unavailable.support = func(context.Context, probe.HostContext) probe.SupportResult { return probe.Unavailable("nft missing") }
	windowsOnly := newFake("test.windowsonly", captured)
	windowsOnly.d.Platforms = []probe.Platform{probe.PlatformWindows}

	p := profile(t, []string{common.IdentityProbeID, "test.liar", "test.badstatus", "test.badsupport", "test.unavailable", "test.windowsonly"}, nil)
	res := mustRun(t, baseOptions(t, p, registry(t, liar, badStatus, badSupport, unavailable, windowsOnly), identityRunner()))
	verifyBundle(t, res)

	l := resultFor(t, res, "test.liar")
	if l.ProbeVersion != "7" || l.StartedAt != "2026-01-02T03:04:05Z" || l.Privilege != trustfreeze.PrivilegeUser || l.Tools != nil || l.RawEvidence != nil {
		t.Fatalf("engine fields not enforced: %+v", l)
	}
	if l.Status != trustfreeze.StatusPartial || len(l.NormalizedState) != 0 {
		t.Fatalf("invalid and duplicate artifacts must be dropped: %s %+v", l.Status, l.NormalizedState)
	}
	drops := 0
	for _, w := range l.Warnings {
		if w.Code == probe.DiagArtifactDropped {
			drops++
		}
	}
	if drops != 3 {
		t.Fatalf("%d artifact_dropped diagnostics, want 3: %+v", drops, l.Warnings)
	}
	checks := map[string]struct {
		status trustfreeze.ProbeStatus
		class  string
	}{
		"test.badstatus":   {trustfreeze.StatusFailed, ClassInvalidStatus},
		"test.badsupport":  {trustfreeze.StatusFailed, ClassInvalidSupport},
		"test.unavailable": {trustfreeze.StatusUnavailable, ""},
		"test.windowsonly": {trustfreeze.StatusUnsupported, ""},
	}
	for id, want := range checks {
		r := resultFor(t, res, id)
		if r.Status != want.status || (want.class != "" && (r.Error == nil || r.Error.Class != want.class)) {
			t.Fatalf("%s: %s %+v", id, r.Status, r.Error)
		}
	}
	if r := resultFor(t, res, "test.windowsonly"); !strings.HasPrefix(r.Reason, ReasonPlatformNotSupported) {
		t.Fatalf("reason %q", r.Reason)
	}
	if r := resultFor(t, res, "test.unavailable"); r.Reason != "nft missing" || r.Support.Available {
		t.Fatalf("%+v", r)
	}
}

// TestCaptureProbeSelection: --probe and --exclude-probe only select from the
// profile, and every profile probe that was not run is recorded (SPEC-0469
// section 4.2): status unsupported, reason excluded_by_operator. A skipped
// required probe therefore leaves a not_captured gap, and a skipped optional
// probe stays visible to compare as a collection gap.
func TestCaptureProbeSelection(t *testing.T) {
	p := profile(t, []string{common.IdentityProbeID, "test.a"}, []string{"test.b"})
	a, b := newFake("test.a", captured), newFake("test.b", captured)
	requireExcluded := func(t *testing.T, res *Result, id string) {
		t.Helper()
		r := resultFor(t, res, id)
		if r.Status != trustfreeze.StatusUnsupported || r.Reason != trustfreeze.ReasonExcludedByOperator || r.Support.Available || r.ProbeVersion != "7" {
			t.Fatalf("%s recorded as %+v, want unsupported/excluded_by_operator", id, r)
		}
		found := false
		for _, s := range res.Capture.Probes {
			if s.ProbeID == id {
				found = s.Status == trustfreeze.StatusUnsupported && s.Reason == trustfreeze.ReasonExcludedByOperator
			}
		}
		if !found {
			t.Fatalf("capture.json probes %+v do not record %s as excluded", res.Capture.Probes, id)
		}
		if _, err := os.Stat(filepath.Join(res.Dir, "probes", id+".json")); err != nil {
			t.Fatalf("no probe result file for the excluded %s: %v", id, err)
		}
	}

	opts := baseOptions(t, p, registry(t, a, b), identityRunner())
	opts.ExcludeProbes = []string{"test.a"}
	res := mustRun(t, opts)
	if res.Complete() || len(res.Results) != 3 {
		t.Fatalf("results %d completeness %+v", len(res.Results), res.Capture.Completeness)
	}
	if g := res.Capture.Completeness.Gaps; len(g) != 1 || g[0].ProbeID != "test.a" || g[0].Reason != trustfreeze.GapNotCaptured || g[0].Status != trustfreeze.StatusUnsupported {
		t.Fatalf("gaps %+v", g)
	}
	requireExcluded(t, res, "test.a")
	if _, err := trustfreeze.ReadBundle(res.Dir); err != nil {
		t.Fatalf("bundle with an excluded probe does not read back: %v", err)
	}

	// An excluded optional probe keeps the capture complete, but is recorded.
	opts = baseOptions(t, p, registry(t, a, b), identityRunner())
	opts.ExcludeProbes = []string{"test.b"}
	res = mustRun(t, opts)
	if !res.Complete() || len(res.Results) != 3 {
		t.Fatalf("results %d completeness %+v", len(res.Results), res.Capture.Completeness)
	}
	requireExcluded(t, res, "test.b")

	opts = baseOptions(t, p, registry(t, a, b), identityRunner())
	opts.Probes = []string{"test.b"}
	res = mustRun(t, opts)
	if len(res.Results) != 3 || res.Complete() || resultFor(t, res, "test.b").Status != trustfreeze.StatusCaptured {
		t.Fatalf("results %+v", res.Results)
	}
	requireExcluded(t, res, "test.a")
	if r := resultFor(t, res, common.IdentityProbeID); r.Status != trustfreeze.StatusUnsupported || r.Reason != trustfreeze.ReasonExcludedByOperator {
		t.Fatalf("identity %+v, want excluded", r)
	}

	opts = baseOptions(t, p, registry(t, a, b), identityRunner())
	opts.Probes = []string{"linux.firewall"}
	if _, err := Run(context.Background(), opts); !errors.Is(err, ErrUnknownProbe) {
		t.Fatalf("unknown probe: %v", err)
	}
	if _, err := os.Stat(opts.Output); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("output written despite a usage error")
	}
}

// TestCaptureRefusals: invalid options, a canceled context and a non-empty
// target write nothing.
func TestCaptureRefusals(t *testing.T) {
	p, err := BuiltinProfile("walking-skeleton")
	if err != nil {
		t.Fatal(err)
	}
	opts := baseOptions(t, p, registry(t), identityRunner())
	if err := os.MkdirAll(opts.Output, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(opts.Output, "keep.txt"), []byte("user data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), opts); !errors.Is(err, trustfreeze.ErrTargetNotEmpty) {
		t.Fatalf("non-empty target: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(opts.Output, "keep.txt")); err != nil || string(b) != "user data" {
		t.Fatal("existing content was touched")
	}

	for name, mutate := range map[string]func(o *Options){
		"no_registry":  func(o *Options) { o.Registry = nil },
		"no_version":   func(o *Options) { o.ToolVersion = "" },
		"no_output":    func(o *Options) { o.Output = "" },
		"raw_profile":  func(o *Options) { o.Profile = Profile{ID: "x"} },
		"no_clock":     func(o *Options) { o.Host.Clock = nil },
		"no_hostname":  func(o *Options) { o.Host.Hostname = func() (string, error) { return "", errors.New("x") } },
		"neg_timeout":  func(o *Options) { o.ProbeTimeout = -1 },
		"neg_limits":   func(o *Options) { o.Limits.MaxFiles = -1 },
		"bad_priv":     func(o *Options) { o.Host.Privilege = "root" },
		"short_output": func(o *Options) { o.Output = " " },
	} {
		o := baseOptions(t, p, registry(t), identityRunner())
		mutate(&o)
		if _, err := Run(context.Background(), o); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if o.Output != "" && strings.TrimSpace(o.Output) != "" {
			if _, err := os.Stat(o.Output); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s: output written", name)
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := baseOptions(t, p, registry(t), identityRunner())
	if _, err := Run(ctx, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(o.Output))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("canceled capture left %v behind", entries)
	}
}

// TestCaptureForceReplacesOnlyCapture: --force replaces a previous capture
// bundle and nothing else (SPEC-0467 section 5.6).
func TestCaptureForceReplacesOnlyCapture(t *testing.T) {
	p, err := BuiltinProfile("walking-skeleton")
	if err != nil {
		t.Fatal(err)
	}
	opts := baseOptions(t, p, registry(t), identityRunner())
	first := mustRun(t, opts)
	if _, err := Run(context.Background(), opts); !errors.Is(err, trustfreeze.ErrTargetNotEmpty) {
		t.Fatalf("second run without force: %v", err)
	}
	opts.Force = true
	second := mustRun(t, opts)
	if second.Manifest.ContentDigest != first.Manifest.ContentDigest {
		t.Fatal("same inputs, different digest after --force")
	}
	verifyBundle(t, second)
}

// TestPlan: doctor's view runs only Support and reports unimplemented
// probes honestly.
func TestPlan(t *testing.T) {
	p, err := BuiltinProfile("ubuntu-bastion")
	if err != nil {
		t.Fatal(err)
	}
	panicky := newFake("common.git", captured)
	panicky.support = func(context.Context, probe.HostContext) probe.SupportResult { panic("x") }
	rows := Plan(context.Background(), p, registry(t, panicky), fixtureHost(identityRunner()))
	if len(rows) != len(p.ProbeIDs()) {
		t.Fatalf("%d rows", len(rows))
	}
	byID := map[string]PlannedProbe{}
	for _, r := range rows {
		byID[r.ProbeID] = r
	}
	if r := byID[common.IdentityProbeID]; !r.Registered || !r.Required || !r.Support.Available {
		t.Fatalf("identity %+v", r)
	}
	// A probe this build implements is registered, and doctor resolves the
	// executables it names without running one: on the fixture host neither
	// nft nor ufw is in the runner search path.
	if r := byID["linux.firewall"]; !r.Registered || !r.ToolsDeclared || len(r.Tools) != 2 || r.Tools[0].OK() || r.Tools[1].OK() {
		t.Fatalf("firewall %+v", r)
	}
	// A probe of the profile that this build does not have stays honest.
	if r := byID["common.claude"]; r.Registered || r.Support.Status != trustfreeze.StatusUnsupported || r.Support.Reason != trustfreeze.ReasonNotImplemented {
		t.Fatalf("common.claude %+v", r)
	}
	if r := byID["common.git"]; r.Required || r.Support.Available || r.Support.Status != trustfreeze.StatusFailed {
		t.Fatalf("panicking support %+v", r)
	}
	if !sort.SliceIsSorted(rows, func(i, j int) bool { return rows[i].ProbeID < rows[j].ProbeID }) {
		t.Fatal("plan not sorted")
	}
}
