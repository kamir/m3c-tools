package common

import (
	"context"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

func warningMessage(r trustfreeze.ProbeResult, code, field string) string {
	for _, w := range r.Warnings {
		if w.Code == code && w.Field == field {
			return w.Message
		}
	}
	return ""
}

// TestIdentityLinuxRollingRelease: real Arch ships BUILD_ID=rolling and no
// VERSION_ID. os_version is not applicable there, so the probe is captured;
// a distribution with neither key (Debian testing) stays partial (SPEC-0467
// section 5.5).
func TestIdentityLinuxRollingRelease(t *testing.T) {
	cc, _ := collectCtx("linux", linuxFiles(string(readLinuxFixture(t, "arch.os-release"))), unameRunner("6.12.1-arch1-1"))
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusCaptured {
		t.Fatalf("arch: status %s %+v", r.Status, r.Warnings)
	}
	if msg := warningMessage(r, probe.DiagFieldNotApplicable, AttrOSVersion); !strings.Contains(msg, "rolling release") {
		t.Fatalf("arch: os_version diagnostic %q", msg)
	}
	a := artifact(t, r, ArtifactOS)
	if a.Attributes[AttrOSBuild] != "rolling" || a.Attributes[AttrOSVersion] != "" {
		t.Fatalf("arch: attributes %v", a.Attributes)
	}

	sid := "PRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\nNAME=\"Debian GNU/Linux\"\nID=debian\n"
	cc, _ = collectCtx("linux", linuxFiles(sid), unameRunner("6.8.0-45-generic"))
	r = NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusPartial || !warning(r, trustfreeze.DiagFieldMissing, AttrOSVersion) {
		t.Fatalf("sid: status %s %+v", r.Status, r.Warnings)
	}
}

// TestIdentityLinuxMalformedKeyFails: a key whose only assignment is
// malformed is field_failed with the line and the reason, not missing.
func TestIdentityLinuxMalformedKeyFails(t *testing.T) {
	cc, _ := collectCtx("linux", linuxFiles(string(readLinuxFixture(t, "malformed.os-release"))), unameRunner("6.8.0-45-generic"))
	r := NewIdentityProbe().Collect(context.Background(), cc)
	if r.Status == trustfreeze.StatusCaptured {
		t.Fatalf("malformed os-release captured: %+v", r.Warnings)
	}
	if msg := warningMessage(r, probe.DiagFieldFailed, AttrOSName); msg != "os-release line 2: "+OSReleaseIssueUnterminated {
		t.Fatalf("os_name diagnostic %q, want the line and the reason (warnings %+v)", msg, r.Warnings)
	}
	if warning(r, trustfreeze.DiagFieldMissing, AttrOSName) {
		t.Fatal("a malformed NAME is reported as missing")
	}
}

// TestIdentityWindowsEvidenceIsTheRawValueSet: the evidence of a Windows 11
// capture is what the registry returned (ProductName "Windows 10 Pro"),
// while os_name is the derived "Windows 11 Pro" with a value_derived
// diagnostic stating the rule.
func TestIdentityWindowsEvidenceIsTheRawValueSet(t *testing.T) {
	cc, ev := collectCtx("windows", probe.FakeFiles{}, probe.NewFakeRunner())
	r := (&IdentityProbe{Windows: winValuesReader{values: winRegQuery(t, winFixtureBytes(t, "win11-23h2-pro.txt"))}}).Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s %+v", r.Status, r.Warnings)
	}
	if a := artifact(t, r, ArtifactOS); a.Attributes[AttrOSName] != "Windows 11 Pro" {
		t.Fatalf("os_name %q", a.Attributes[AttrOSName])
	}
	if msg := warningMessage(r, DiagValueDerived, AttrOSName); !strings.Contains(msg, "Windows 10 Pro") {
		t.Fatalf("value_derived diagnostic %q", msg)
	}
	var evidence string
	for _, it := range ev.Close() {
		if it.Name == "registry-currentversion.json" {
			evidence = string(it.Data.Bytes())
		}
	}
	if !strings.Contains(evidence, `"ProductName": "Windows 10 Pro"`) || !strings.Contains(evidence, `"CurrentBuild": "22631"`) {
		t.Fatalf("evidence is not the raw value set:\n%s", evidence)
	}
}

// TestIdentityWindowsPerFieldErrors: each field carries its own error. A
// denied CurrentBuild without DisplayVersion or ReleaseId gives os_build
// permission_denied, os_name failed (a "Windows 10" ProductName needs the
// build to tell 10 from 11) and os_version missing.
func TestIdentityWindowsPerFieldErrors(t *testing.T) {
	cc, _ := collectCtx("windows", probe.FakeFiles{}, probe.NewFakeRunner())
	values := map[string]winRegValue{
		winValueProductName:  winSZ("Windows 10 Pro"),
		winValueCurrentBuild: winDenied(winRegSZ),
	}
	r := (&IdentityProbe{Windows: winValuesReader{values: values}}).Collect(context.Background(), cc)
	if r.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("status %s %+v", r.Status, r.Warnings)
	}
	for _, want := range []struct{ code, field string }{
		{probe.DiagFieldPermissionDenied, AttrOSBuild},
		{probe.DiagFieldFailed, AttrOSName},
		{trustfreeze.DiagFieldMissing, AttrOSVersion},
	} {
		if !warning(r, want.code, want.field) {
			t.Errorf("no %s for %s: %+v", want.code, want.field, r.Warnings)
		}
	}
	if warning(r, probe.DiagFieldPermissionDenied, AttrOSName) || warning(r, probe.DiagFieldPermissionDenied, AttrOSVersion) {
		t.Errorf("the denied build leaked into other fields: %+v", r.Warnings)
	}
}
