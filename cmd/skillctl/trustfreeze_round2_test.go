package main

// Tests of the second decision round on T-03: the capabilities a capture and a
// report must name (R-T3), the policy version a diff bundle records (R-T4) and
// the directory doctor is allowed to touch (O-T1). Same synthetic environment
// as the acceptance test (newTFEnv).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/platform/linux"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// tfSudoRule is the artifact linux.sudo writes for a rule that grants every
// command as root. The capability resolver turns it into a root capability, so
// a scripted capture can carry one. The NOPASSWD tag is left out on purpose:
// the redactor treats the attribute name "nopasswd" as a password key and
// replaces its value, so a fixture that set it would assert the wrong
// privilege here instead of naming that defect where it belongs.
func tfSudoRule(line, users string) trustfreeze.Artifact {
	return trustfreeze.Artifact{
		ID: linux.SudoRulePrefix + "sudoers/" + line, Type: linux.SudoRuleType, Scope: "host",
		Source: "linux.sudo", State: trustfreeze.StateDeclared,
		Attributes: map[string]string{
			"file": "/etc/sudoers", "line": line, "users": users,
			"all_commands": "true", "runas_root": "true",
		},
		Provenance: trustfreeze.Provenance{
			Method: "file", Confidence: trustfreeze.ConfidenceProven,
			Sources: []string{"file:/etc/sudoers"}, ObservedAt: trustfreeze.FormatTime(tfTestTime),
		},
		Sensitivity: trustfreeze.SensitivityInternal,
	}
}

// R-T3: capture names the capabilities a reader must see, not only a count.
// The JSON keeps the shape it had and gains the same list.
func TestTrustFreezeCaptureNamesCriticalCapabilities(t *testing.T) {
	e, s := tfScriptedEnv(t)
	s.set("linux.sudo", tfScripted{
		support: probe.Supported(), status: trustfreeze.StatusCaptured,
		arts: []trustfreeze.Artifact{tfSudoRule("12", "remote-maint")},
	})
	capDir := e.path("cap")
	code, out, _ := e.run("capture", "--profile", "ubuntu-bastion", "--output", capDir)
	if code != exitOK {
		t.Fatalf("exit %d, want 0: every probe of the scripted profile was captured", code)
	}
	wantID := linux.CapExecuteHostPrefix + "user/remote-maint"
	for _, want := range []string{wantID, "root-via-sudo"} {
		if !strings.Contains(out, want) {
			t.Fatalf("capture text does not name %q:\n%s", want, out)
		}
	}

	doc := e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--output", e.path("cap2"), "--format", "json")
	caps, _ := doc["capabilities"].(map[string]any)
	if caps == nil {
		t.Fatalf("capture JSON lost its capabilities object: %v", doc)
	}
	for _, k := range []string{"resolver", "resolved", "diagnostics"} {
		if _, ok := caps[k]; !ok {
			t.Fatalf("capture JSON dropped %q from capabilities: %v", k, caps)
		}
	}
	critical, _ := caps["critical"].([]any)
	if len(critical) != 1 || critical[0] != wantID {
		t.Fatalf("capabilities.critical = %v, want [%s]", caps["critical"], wantID)
	}
}

// R-T3: report projects state/capabilities.json. The capability statement lives
// in the bundle; before this, no command rendered it.
func TestTrustFreezeReportProjectsCapabilities(t *testing.T) {
	e, s := tfScriptedEnv(t)
	s.set("linux.sudo", tfScripted{
		support: probe.Supported(), status: trustfreeze.StatusCaptured,
		arts: []trustfreeze.Artifact{tfSudoRule("12", "remote-maint")},
	})
	capDir, report := e.path("cap"), e.path("report.json")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--output", capDir, "--format", "json")
	e.runJSON(exitOK, tfResultOK, "report", "--input", capDir, "--output", report)

	doc := tfReadJSONFile(t, report)
	section, _ := doc["capture"].(map[string]any)
	caps, _ := section["capabilities"].(map[string]any)
	if caps == nil {
		t.Fatalf("the report has no capabilities section: %v", section)
	}
	list, _ := caps["capabilities"].([]any)
	if len(list) == 0 {
		t.Fatalf("the report projects no capability: %v", caps)
	}
	first, _ := list[0].(map[string]any)
	for _, k := range []string{"id", "subject_id", "action", "resource", "effect", "privilege", "state", "confidence", "sources"} {
		if _, ok := first[k]; !ok {
			t.Fatalf("the projected capability lacks %q: %v", k, first)
		}
	}
	if first["subject_id"] != "user/remote-maint" || first["privilege"] != "root-via-sudo" {
		t.Fatalf("projected capability %v", first)
	}
	if caps["resolver"] != "linux.privilege/v1" {
		t.Fatalf("the report does not name the resolver: %v", caps["resolver"])
	}
	// Two reports of the same bundle are byte-identical: the projection reads
	// no clock and decides nothing.
	second := e.path("report2.json")
	e.runJSON(exitOK, tfResultOK, "report", "--input", capDir, "--output", second)
	a, err := os.ReadFile(report) // #nosec G304 -- written by this test under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second) // #nosec G304 -- written by this test under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("two reports of the same bundle differ")
	}
}

// R-T4: the diff bundle records which policy judged it, and an operator can
// reproduce an older verdict by naming a built-in policy id.
func TestTrustFreezeDiffBundleRecordsPolicyID(t *testing.T) {
	e, _ := tfScriptedEnv(t)
	capDir, base := e.path("cap"), e.path("base")
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--output", capDir, "--format", "json")
	e.approveBastion(capDir, base)

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"default", nil, "trust-freeze/policy/default-v1"},
		{"named built-in", []string{"--policy", "trust-freeze/policy/default-v1"}, "trust-freeze/policy/default-v1"},
		{"named built-in v0", []string{"--policy", "trust-freeze/policy/default-v0"}, "trust-freeze/policy/default-v0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := e.path("diff-" + tc.name)
			args := append([]string{"diff", "--baseline", base, "--current", capDir, "--trusted-key", e.pub, "--output", out}, tc.args...)
			e.runJSON(exitOK, tfResultOK, args...)
			v := tfReadJSONFile(t, filepath.Join(out, "verdict.json"))
			pol, _ := v["policy"].(map[string]any)
			if pol["id"] != tc.want {
				t.Fatalf("verdict.json names policy %v, want %s", pol["id"], tc.want)
			}
			if pol["rules_digest"] == "" || pol["rules_digest"] == nil {
				t.Fatalf("verdict.json names no rules digest: %v", pol)
			}
			evaluated := tfReadJSONFile(t, filepath.Join(out, "policy", "evaluated-policy.json"))
			if evaluated["id"] != tc.want {
				t.Fatalf("the evaluated policy in the bundle is %v, want %s", evaluated["id"], tc.want)
			}
		})
	}
}

// O-T1: the writable probe of doctor runs against the parent of the named
// target and nowhere else. A target whose parent does not exist is a problem,
// not a probe file written two levels up.
func TestTrustFreezeDoctorOutputProbesOnlyTheParent(t *testing.T) {
	e, _ := tfScriptedEnv(t)
	root := e.path("out")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	check := func(target string) map[string]any {
		t.Helper()
		doc := e.runJSON(exitOK, tfResultOK, "doctor", "--output", target, "--format", "json")
		checks, _ := doc["checks"].([]any)
		for _, c := range checks {
			m, _ := c.(map[string]any)
			if m["item"] == "output_location" {
				return m
			}
		}
		t.Fatalf("no output_location check: %v", doc)
		return nil
	}

	// The parent exists: the probe runs there and leaves it as it found it.
	got := check(filepath.Join(root, "bundle"))
	if got["status"] != "ok" {
		t.Fatalf("a target whose parent exists: %v", got)
	}
	if detail, _ := got["detail"].(string); !strings.Contains(detail, root) {
		t.Fatalf("the check does not name the touched directory: %v", got)
	}
	left, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("the probe left %d entries behind", len(left))
	}

	// The parent does not exist: nothing above it is touched.
	missing := filepath.Join(root, "absent", "bundle")
	got = check(missing)
	if got["status"] != "problem" {
		t.Fatalf("a target whose parent does not exist: %v", got)
	}
	if detail, _ := got["detail"].(string); !strings.Contains(detail, filepath.Join(root, "absent")) {
		t.Fatalf("the check does not name the missing parent: %v", got)
	}
	left, err = os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("doctor wrote into the nearest existing ancestor: %v", left)
	}
}

// R-T1, R-T3: the text output of diff names the capability of a capability
// entry. Without it a reader sees the change kind and a blank.
func TestTrustFreezeDiffTextNamesCapabilities(t *testing.T) {
	e, s := tfScriptedEnv(t)
	capDir, base, cur := e.path("cap"), e.path("base"), e.path("cur")
	// The baseline could not read the sudo rules; the current capture could.
	s.set("linux.sudo", tfScripted{support: probe.PermissionDenied("permission denied reading the sudoers files")})
	e.runJSON(exitGeneric, tfResultIncomplete, "capture", "--profile", "ubuntu-bastion", "--output", capDir, "--format", "json")
	e.approveBastion(capDir, base)
	s.set("linux.sudo", tfScripted{
		support: probe.Supported(), status: trustfreeze.StatusCaptured,
		arts: []trustfreeze.Artifact{tfSudoRule("12", "remote-maint")},
	})
	e.runJSON(exitOK, tfResultOK, "capture", "--profile", "ubuntu-bastion", "--output", cur, "--format", "json")

	_, out, _ := e.run("diff", "--baseline", base, "--current", cur, "--trusted-key", e.pub)
	wantID := linux.CapExecuteHostPrefix + "user/remote-maint"
	for _, want := range []string{"coverage_increased " + wantID, "linux.sudo", "root-via-sudo"} {
		if !strings.Contains(out, want) {
			t.Fatalf("diff text does not carry %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "capability_added") {
		t.Fatalf("the baseline never read the sudo rules, so nothing is capability_added:\n%s", out)
	}
}
