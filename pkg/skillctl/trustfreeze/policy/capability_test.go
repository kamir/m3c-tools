package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
)

// capability is a synthetic capability of the privilege resolver.
func capability(id, privilege string, sources ...string) trustfreeze.Capability {
	return trustfreeze.Capability{
		ID: id, SubjectID: "user/alice", Action: "execute", Resource: "host",
		Effect: "allowed", State: trustfreeze.StateDeclared, Scope: "host",
		Exposure: "local", Privilege: privilege, Sources: sources,
		Confidence: trustfreeze.ConfidenceCorroborated,
	}
}

// capabilityDiff compares two identical captures whose capability documents
// differ, so every entry of the diff is a capability entry.
func capabilityDiff(t *testing.T, before, after []trustfreeze.Capability) compare.Diff {
	t.Helper()
	b := identityCapture(testTime, "24.04", 0).bundle(t, trustfreeze.KindBaseline)
	c := identityCapture(testTime, "24.04", 0).bundle(t, trustfreeze.KindCapture)
	b.Capabilities = &trustfreeze.CapabilitiesDoc{Resolver: "linux.privilege/v1", Capabilities: before}
	c.Capabilities = &trustfreeze.CapabilitiesDoc{Resolver: "linux.privilege/v1", Capabilities: after}
	d, err := compare.Compare(context.Background(), b, c, compare.CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// SPEC-0469 AC3: a new root capability is critical and blocks at fail_on
// high; any other new capability is high; a capability that is gone is low.
// The privilege is the only condition that separates the first two rules.
func TestCapabilityFindings(t *testing.T) {
	root := capability("capability/execute/host/user/alice", "root-via-sudo-nopasswd", "device/os")
	plain := capability("capability/remote.shell.public-key/alice/ab12", "user", "device/host")
	weaker := root
	weaker.Privilege = "user"

	for _, tc := range []struct {
		name          string
		before, after []trustfreeze.Capability
		want          string
		highest       trustfreeze.Severity
		blocks        bool
	}{
		{
			"a new root capability", nil, []trustfreeze.Capability{root},
			"capability_added:capability/execute/host/user/alice=critical@TF-POL-CAPABILITY-ROOT",
			trustfreeze.SeverityCritical, true,
		},
		{
			"a new capability without root", nil, []trustfreeze.Capability{plain},
			"capability_added:capability/remote.shell.public-key/alice/ab12=high@TF-POL-CAPABILITY-ADDED",
			trustfreeze.SeverityHigh, true,
		},
		{
			"an existing capability that is root now",
			[]trustfreeze.Capability{weaker}, []trustfreeze.Capability{root},
			"capability_changed:capability/execute/host/user/alice=critical@TF-POL-CAPABILITY-ROOT",
			trustfreeze.SeverityCritical, true,
		},
		{
			"a capability that lost its root privilege",
			[]trustfreeze.Capability{root}, []trustfreeze.Capability{weaker},
			"capability_changed:capability/execute/host/user/alice=medium@TF-POL-CAPABILITY-CHANGED",
			trustfreeze.SeverityMedium, false,
		},
		{
			"a root capability that is gone", []trustfreeze.Capability{root}, nil,
			"capability_removed:capability/execute/host/user/alice=low@TF-POL-CAPABILITY-GONE",
			trustfreeze.SeverityLow, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := evaluate(t, capabilityDiff(t, tc.before, tc.after), defaultPolicy(t))
			var got []string
			for _, f := range v.Findings {
				got = append(got, f.ID+"="+string(f.Severity)+"@"+f.RuleID)
			}
			if strings.Join(got, ",") != tc.want {
				t.Fatalf("findings %q, want %q", got, tc.want)
			}
			if v.HighestSeverity != tc.highest || v.ThresholdExceeded != tc.blocks {
				t.Fatalf("highest %q, threshold exceeded %v", v.HighestSeverity, v.ThresholdExceeded)
			}
			for _, f := range v.Findings {
				if !strings.Contains(f.Message, "capability") {
					t.Fatalf("message %q names no capability", f.Message)
				}
			}
		})
	}
}

// A rule that matches privileges must not be written for artifact entries,
// and a capability rule never matches by artifact id.
func TestPrivilegeMatchIsCapabilityOnly(t *testing.T) {
	p := defaultPolicy(t)
	p.Rules = append(p.Rules, Rule{
		ID: "TF-POL-TEST", Severity: trustfreeze.SeverityLow,
		Match: Match{ChangeKinds: []compare.ChangeKind{compare.ChangeAdded}, Privileges: []string{"root"}},
	})
	if err := p.Validate(); err == nil {
		t.Fatal("privileges on an artifact rule accepted")
	}
	p = defaultPolicy(t)
	p.Rules = append(p.Rules, Rule{
		ID: "TF-POL-TEST", Severity: trustfreeze.SeverityLow,
		Match: Match{ChangeKinds: []compare.ChangeKind{compare.ChangeCapabilityAdded}, ArtifactIDs: []string{"device/os"}},
	})
	if err := p.Validate(); err == nil {
		t.Fatal("artifact ids on a capability rule accepted")
	}
}

// coverageDiff compares a baseline whose linux.sudo probe was refused with a
// current capture that read it, so a capability resting on a sudo artifact is
// coverage_increased and not capability_added (R-T1).
func coverageDiff(t *testing.T, after []trustfreeze.Capability) compare.Diff {
	t.Helper()
	bc := identityCapture(testTime, "24.04", 0)
	bc.results = append(bc.results, result("linux.sudo", trustfreeze.StatusPermissionDenied, testTime, 5))
	cc := identityCapture(testTime, "24.04", 0)
	cc.results = append(cc.results, result("linux.sudo", trustfreeze.StatusCaptured, testTime, 5))
	cc.arts = append(cc.arts, trustfreeze.Artifact{
		ID: "sudo/rule/sudoers/12", Type: "sudo-rule", Scope: "host", Source: "linux.sudo",
		State: trustfreeze.StateDeclared, Attributes: map[string]string{"users": "alice"},
		Provenance: trustfreeze.Provenance{
			Method: "file", Confidence: trustfreeze.ConfidenceProven,
			Sources: []string{"file:/etc/sudoers"}, ObservedAt: trustfreeze.FormatTime(testTime),
		},
		Sensitivity: trustfreeze.SensitivityInternal,
	})
	b := bc.bundle(t, trustfreeze.KindBaseline)
	c := cc.bundle(t, trustfreeze.KindCapture)
	b.Capabilities = &trustfreeze.CapabilitiesDoc{Resolver: "linux.privilege/v1"}
	c.Capabilities = &trustfreeze.CapabilitiesDoc{Resolver: "linux.privilege/v1", Capabilities: after}
	d, err := compare.Compare(context.Background(), b, c, compare.CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// R-T4 (b): the two container privileges are root on the host, and the default
// policy rates them as such. Under the frozen default-v0 the root rule does not
// exist at all, so a container grant came out with the default severity.
func TestDefaultPolicyRatesContainerPrivilegesCritical(t *testing.T) {
	for _, priv := range []string{
		trustfreeze.PrivilegeValueRootViaContainerRuntime,
		trustfreeze.PrivilegeValueRootViaPrivilegedContainer,
	} {
		t.Run(priv, func(t *testing.T) {
			c := capability("capability/execute/host/user/alice", priv, "device/os")
			v, err := Evaluate(context.Background(), capabilityDiff(t, nil, []trustfreeze.Capability{c}), defaultPolicy(t))
			if err != nil {
				t.Fatal(err)
			}
			if len(v.Findings) != 1 {
				t.Fatalf("findings %+v", v.Findings)
			}
			f := v.Findings[0]
			if f.Severity != trustfreeze.SeverityCritical || f.RuleID != "TF-POL-CAPABILITY-ROOT" {
				t.Fatalf("finding %s rated %s by %s, want critical by TF-POL-CAPABILITY-ROOT", f.ID, f.Severity, f.RuleID)
			}
		})
	}
}

// R-T1: a capability the baseline could not have seen is rated info, by a rule
// of its own, even when it grants root. A privilege upgrade of the capture
// account is not drift, and it must not fail a diff.
func TestDefaultPolicyRatesCoverageIncreasedInfo(t *testing.T) {
	c := capability("capability/execute/host/user/alice", "root-via-sudo-nopasswd", "sudo/rule/sudoers/12")
	d := coverageDiff(t, []trustfreeze.Capability{c})
	if n := d.Counts[string(compare.ChangeCoverageIncreased)]; n != 1 {
		t.Fatalf("the fixture produced %d coverage_increased entries: %+v", n, d.Changes)
	}
	v, err := Evaluate(context.Background(), d, defaultPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	var f trustfreeze.Finding
	for _, got := range v.Findings {
		if got.Kind == string(compare.ChangeCoverageIncreased) {
			f = got
		}
	}
	switch {
	case f.ID == "":
		t.Fatalf("no coverage_increased finding: %+v", v.Findings)
	case f.Severity != trustfreeze.SeverityInfo:
		t.Errorf("severity %s, want info", f.Severity)
	case f.RuleID != "TF-POL-COVERAGE-INCREASED":
		t.Errorf("rule %q, want the coverage rule and not the default severity", f.RuleID)
	case !strings.Contains(f.Message, "linux.sudo"):
		t.Errorf("message %q does not name the probe the baseline was missing", f.Message)
	}
	if v.ThresholdExceeded {
		t.Error("a capture that looked where the baseline was blind must not exceed the threshold")
	}
}

// R-T5: a coverage_increased entry that came from a capability_changed says
// what it is. The capability was in the baseline, so a message that calls it
// new would be false; the honest sentence names the fields that differ and
// the probe the baseline did not capture.
func TestCoverageIncreasedMessageOfADowngradedChange(t *testing.T) {
	c := compare.Change{
		Kind: compare.ChangeCoverageIncreased, CapabilityID: "capability/execute/host/user/alice",
		ChangedFields:     []string{"privilege", "sources"},
		BaselineGapProbes: []string{"linux.sudo"},
		BeforePrivilege:   "root-via-group", AfterPrivilege: "root-via-sudo-nopasswd",
		BeforeDigest: "sha256:aa", AfterDigest: "sha256:bb",
	}
	msg := message(c)
	switch {
	case strings.Contains(msg, "could not have been in the baseline"):
		t.Errorf("the message calls a capability the baseline carried new: %q", msg)
	case !strings.Contains(msg, "privilege, sources"):
		t.Errorf("the message does not name the fields that differ: %q", msg)
	case !strings.Contains(msg, "linux.sudo"):
		t.Errorf("the message does not name the probe the baseline was missing: %q", msg)
	}
	// The added direction keeps its own sentence.
	added := compare.Change{
		Kind: compare.ChangeCoverageIncreased, CapabilityID: c.CapabilityID,
		BaselineGapProbes: []string{"linux.ssh"}, AfterPrivilege: "user", AfterDigest: "sha256:bb",
	}
	if got := message(added); !strings.Contains(got, "could not have been in the baseline") {
		t.Errorf("the added direction lost its sentence: %q", got)
	}
}
