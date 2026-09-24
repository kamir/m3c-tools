package compare

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// testCapability is a synthetic capability. sources are artifact ids.
func testCapability(id, privilege string, sources ...string) trustfreeze.Capability {
	return trustfreeze.Capability{
		ID: id, SubjectID: "user/alice", Action: "execute", Resource: "host",
		Effect: "allowed", State: trustfreeze.StateDeclared, Scope: "host",
		Exposure: "local", Privilege: privilege, Sources: sources,
		Confidence: trustfreeze.ConfidenceCorroborated,
	}
}

func capabilitiesDoc(caps ...trustfreeze.Capability) *trustfreeze.CapabilitiesDoc {
	return &trustfreeze.CapabilitiesDoc{Resolver: "linux.privilege/v1", Capabilities: caps}
}

// capabilityDiff compares two walking-skeleton fixtures whose capability
// documents are set by the caller.
func capabilityDiff(t *testing.T, before, after *trustfreeze.CapabilitiesDoc) Diff {
	t.Helper()
	b := memBundle(t, trustfreeze.KindBaseline, baseFixture(testTime, 0))
	c := memBundle(t, trustfreeze.KindCapture, baseFixture(testTime, 1))
	b.Capabilities, c.Capabilities = before, after
	d, err := Compare(context.Background(), b, c, CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func capabilityKeys(d Diff) []string {
	var out []string
	for _, c := range d.Changes {
		if c.Kind.IsCapability() {
			out = append(out, string(c.Kind)+":"+c.CapabilityID)
		}
	}
	return out
}

// SPEC-0469 R2: capabilities are compared separately from artifacts, and only
// as far as both bundles resolved them.
func TestCompareCapabilities(t *testing.T) {
	root := testCapability("capability/execute/host/user/alice", "root-via-sudo-nopasswd", "device/os")
	// The same capability, now with a password.
	weaker := root
	weaker.Privilege = "root-via-sudo"
	// A capability whose source artifact the current bundle does not carry.
	unseen := testCapability("capability/execute/host/user/deploy", "root-via-sudo", "sudo/rule/sudoers/12")
	fresh := testCapability("capability/remote.shell.public-key/alice/ab12", "user", "device/host")

	for _, tc := range []struct {
		name          string
		before, after *trustfreeze.CapabilitiesDoc
		want          []string
	}{
		{"no document on either side", nil, nil, nil},
		{"only the current bundle resolved: nothing can be called new", nil, capabilitiesDoc(root), nil},
		{
			"only the baseline resolved: not observed, never removed",
			capabilitiesDoc(root), nil,
			[]string{"capability_not_observed:capability/execute/host/user/alice"},
		},
		{
			"added",
			capabilitiesDoc(root), capabilitiesDoc(root, fresh),
			[]string{"capability_added:capability/remote.shell.public-key/alice/ab12"},
		},
		{
			"removed: every source artifact was observed again",
			capabilitiesDoc(root), capabilitiesDoc(),
			[]string{"capability_removed:capability/execute/host/user/alice"},
		},
		{
			"not observed: the source artifact is missing from the current bundle",
			capabilitiesDoc(unseen), capabilitiesDoc(),
			[]string{"capability_not_observed:capability/execute/host/user/deploy"},
		},
		{
			"changed",
			capabilitiesDoc(root), capabilitiesDoc(weaker),
			[]string{"capability_changed:capability/execute/host/user/alice"},
		},
		{"equal", capabilitiesDoc(root), capabilitiesDoc(root), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := capabilityDiff(t, tc.before, tc.after)
			got := capabilityKeys(d)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("capability entries %q, want %q", got, tc.want)
			}
			for _, c := range d.Changes {
				if c.Kind == ChangeCapabilityChanged && strings.Join(c.ChangedFields, ",") != "privilege" {
					t.Fatalf("changed fields %q, want privilege", c.ChangedFields)
				}
			}
			if n := d.Counts[string(ChangeCapabilityAdded)] + d.Counts[string(ChangeCapabilityRemoved)] +
				d.Counts[string(ChangeCapabilityChanged)] + d.Counts[string(ChangeCapabilityNotObserved)]; n != len(tc.want) {
				t.Fatalf("counts say %d capability entries, the list has %d", n, len(tc.want))
			}
		})
	}
}

// A capability entry never carries artifact fields, and an unreadable
// capability document is refused instead of compared.
func TestCapabilityEntryContract(t *testing.T) {
	d := capabilityDiff(t, capabilitiesDoc(), capabilitiesDoc(testCapability("capability/execute/host/user/alice", "root", "device/os")))
	if len(d.Changes) == 0 {
		t.Fatal("no changes")
	}
	for i, c := range d.Changes {
		if !c.Kind.IsCapability() {
			continue
		}
		if c.ArtifactID != "" || c.ProbeID != "" || c.CapabilityID == "" {
			t.Fatalf("change %d: %+v", i, c)
		}
		bad := c
		bad.ArtifactID = "device/os"
		if err := validateChange(bad); err == nil {
			t.Fatalf("change %d with an artifact id accepted", i)
		}
	}
	dup := capabilitiesDoc(testCapability("capability/execute/host/user/alice", "root", "device/os"),
		testCapability("capability/execute/host/user/alice", "user", "device/os"))
	b := memBundle(t, trustfreeze.KindBaseline, baseFixture(testTime, 0))
	c := memBundle(t, trustfreeze.KindCapture, baseFixture(testTime, 1))
	b.Capabilities = dup
	c.Capabilities = capabilitiesDoc()
	if _, err := Compare(context.Background(), b, c, CompareOptions{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate capability id: %v", err)
	}
}

// coverageFixture is a walking-skeleton capture plus the sudo rule artifact of
// probe linux.sudo, recorded with status st. A status other than captured
// leaves the artifact out: that is what a blind capture looks like.
func coverageFixture(noise int, st trustfreeze.ProbeStatus) fixture {
	f := baseFixture(testTime, noise)
	reason := ""
	switch st {
	case trustfreeze.StatusCaptured:
	case trustfreeze.StatusPartial:
		reason = "one sudoers drop-in could not be read"
	default:
		reason = "permission denied reading the sudoers files"
	}
	f.results = append(f.results, probeResult("linux.sudo", st, reason, testTime, 7))
	if st == trustfreeze.StatusCaptured {
		a := artifact("sudo/rule/sudoers/12", "sudo-rule", trustfreeze.StateDeclared,
			trustfreeze.ConfidenceProven, trustfreeze.FormatTime(testTime),
			map[string]string{"users": "alice", "all_commands": "true"})
		a.Source = "linux.sudo"
		f.arts = append(f.arts, a)
	}
	return f
}

// withoutArtifact removes one artifact from a fixture while keeping the probe
// result that produced it. It is how a test says "the probe ran and this
// object did not exist yet".
func (f fixture) withoutArtifact(id string) fixture {
	out := make([]trustfreeze.Artifact, 0, len(f.arts))
	for _, a := range f.arts {
		if a.ID != id {
			out = append(out, a)
		}
	}
	f.arts = out
	return f
}

// withRuleAttribute adds an attribute to the sudo rule artifact of
// coverageFixture, so a test can let the rule itself change on ground both
// runs could read.
func (f fixture) withRuleAttribute(key, value string) fixture {
	out := append([]trustfreeze.Artifact(nil), f.arts...)
	for i, a := range out {
		if a.ID != "sudo/rule/sudoers/12" {
			continue
		}
		attrs := map[string]string{}
		for k, v := range a.Attributes {
			attrs[k] = v
		}
		attrs[key] = value
		out[i].Attributes = attrs
	}
	f.arts = out
	return f
}

// coverageDiff compares two fixtures with their capability documents set.
func coverageDiff(t *testing.T, bf, cf fixture, before, after *trustfreeze.CapabilitiesDoc) Diff {
	t.Helper()
	b := memBundle(t, trustfreeze.KindBaseline, bf)
	c := memBundle(t, trustfreeze.KindCapture, cf)
	b.Capabilities, c.Capabilities = before, after
	d, err := Compare(context.Background(), b, c, CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func changeOfKind(d Diff, k ChangeKind) (Change, bool) {
	for _, c := range d.Changes {
		if c.Kind == k {
			return c, true
		}
	}
	return Change{}, false
}

// R-T1 (SPEC-0469): a capability the baseline could not have seen is not
// capability_added. The probe that produced its source was not captured in the
// baseline, so the diff says coverage_increased and names that probe. It is
// the mirror of capability_not_observed.
func TestCompareCapabilityAddedNeedsBaselineCoverage(t *testing.T) {
	root := testCapability("capability/execute/host/user/alice", "root-via-sudo-nopasswd", "sudo/rule/sudoers/12")
	d := coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusPermissionDenied),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(), capabilitiesDoc(root))

	if _, ok := changeOfKind(d, ChangeCapabilityAdded); ok {
		t.Fatalf("capability_added although the baseline never saw probe linux.sudo: %v", capabilityKeys(d))
	}
	c, ok := changeOfKind(d, ChangeCoverageIncreased)
	if !ok {
		t.Fatalf("no coverage_increased entry: %v", capabilityKeys(d))
	}
	switch {
	case c.CapabilityID != root.ID:
		t.Errorf("coverage_increased names capability %q, want %q", c.CapabilityID, root.ID)
	case len(c.BaselineGapProbes) != 1 || c.BaselineGapProbes[0] != "linux.sudo":
		t.Errorf("baseline_gap_probes = %v, want [linux.sudo]", c.BaselineGapProbes)
	case c.AfterPrivilege != root.Privilege:
		t.Errorf("after_privilege = %q, want %q", c.AfterPrivilege, root.Privilege)
	case c.AfterDigest == "" || c.BeforeDigest != "":
		t.Errorf("coverage_increased carries digests before %q after %q", c.BeforeDigest, c.AfterDigest)
	}
	if n := d.Counts[string(ChangeCoverageIncreased)]; n != 1 {
		t.Errorf("counts[coverage_increased] = %d, want 1", n)
	}
}

// R-T1: where the baseline did collect the source probe, a new capability
// stays capability_added. The guard must not swallow real drift.
func TestCompareCapabilityAddedWithBaselineCoverage(t *testing.T) {
	root := testCapability("capability/execute/host/user/alice", "root-via-sudo-nopasswd", "sudo/rule/sudoers/12")
	d := coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusCaptured),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(), capabilitiesDoc(root))

	if _, ok := changeOfKind(d, ChangeCoverageIncreased); ok {
		t.Fatalf("coverage_increased although the baseline captured linux.sudo: %v", capabilityKeys(d))
	}
	if _, ok := changeOfKind(d, ChangeCapabilityAdded); !ok {
		t.Fatalf("no capability_added: %v", capabilityKeys(d))
	}
}

// R-T1: a capability whose sources name no artifact cannot be tied to a probe.
// Nothing is then known about the baseline's coverage, and the entry stays
// capability_added: the guard never invents a gap.
func TestCompareCapabilityAddedWithoutArtifactSources(t *testing.T) {
	c := testCapability("capability/execute/host/user/alice", "root-via-sudo", "file:/etc/sudoers")
	d := coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusPermissionDenied),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(), capabilitiesDoc(c))

	if _, ok := changeOfKind(d, ChangeCapabilityAdded); !ok {
		t.Fatalf("no capability_added: %v", capabilityKeys(d))
	}
}

// R-T1 (a): a baseline probe that reported PARTIALLY did look and did report.
// A capability that is new on ground such a probe covered stays
// capability_added at its normal severity; the entry names the partial probe
// in coverage_caveat_probes, so the uncertainty is visible without the finding
// dropping to info. What the guard reads is the baseline's probe status, not
// which artifacts the baseline happened to keep.
func TestCompareCapabilityAddedOnPartialBaselineKeepsItsKind(t *testing.T) {
	root := testCapability("capability/execute/host/user/alice", "root-via-sudo-nopasswd", "sudo/rule/sudoers/12")
	d := coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusPartial),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(), capabilitiesDoc(root))

	if c, ok := changeOfKind(d, ChangeCoverageIncreased); ok {
		t.Fatalf("coverage_increased although the baseline reported partially: %+v", c)
	}
	c, ok := changeOfKind(d, ChangeCapabilityAdded)
	if !ok {
		t.Fatalf("no capability_added: %v", capabilityKeys(d))
	}
	switch {
	case c.CapabilityID != root.ID:
		t.Errorf("capability_added names %q, want %q", c.CapabilityID, root.ID)
	case len(c.CoverageCaveatProbes) != 1 || c.CoverageCaveatProbes[0] != "linux.sudo":
		t.Errorf("coverage_caveat_probes = %v, want [linux.sudo]", c.CoverageCaveatProbes)
	case len(c.BaselineGapProbes) != 0:
		t.Errorf("baseline_gap_probes = %v, want none on a capability_added entry", c.BaselineGapProbes)
	case c.AfterPrivilege != root.Privilege:
		t.Errorf("after_privilege = %q, want %q", c.AfterPrivilege, root.Privilege)
	}
	if n := d.Counts[string(ChangeCapabilityAdded)]; n != 1 {
		t.Errorf("counts[capability_added] = %d, want 1", n)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("the diff does not validate: %v", err)
	}
}

// R-T5 supersedes the coarser rule this test used to pin. Until 2026-09-23 a
// capability with one source from a probe the baseline HAD captured stayed
// capability_added, whatever that source did. Measured on real data, that
// rated five findings critical that were not drift: the covered source had
// not moved at all, and the capability appeared only because the current run
// could read ground the baseline could not. The rule now reads the DECISIVE
// sources, so a covered source that did not move no longer holds the entry at
// full severity; a covered source that DID move still does, which is
// TestCompareCapabilityAddedKeepsKindWhenANewSourceWasVisible.
//
// Here device/os is in both bundles unchanged and only the sudo rule is new,
// so the entry is coverage_increased and names linux.sudo alone.
func TestCompareCapabilityAddedWithOneCoveredUnchangedSource(t *testing.T) {
	root := testCapability("capability/execute/host/user/alice", "root-via-sudo-nopasswd",
		"device/os", "sudo/rule/sudoers/12")
	d := coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusPermissionDenied),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(), capabilitiesDoc(root))

	if c, ok := changeOfKind(d, ChangeCapabilityAdded); ok {
		t.Fatalf("capability_added although nothing moved on the ground the baseline covered: %+v", c)
	}
	c, ok := changeOfKind(d, ChangeCoverageIncreased)
	if !ok {
		t.Fatalf("no coverage_increased: %v", capabilityKeys(d))
	}
	switch {
	case c.CapabilityID != root.ID:
		t.Errorf("coverage_increased names %q, want %q", c.CapabilityID, root.ID)
	case len(c.BaselineGapProbes) != 1 || c.BaselineGapProbes[0] != "linux.sudo":
		t.Errorf("baseline_gap_probes = %v, want [linux.sudo]: common.identity was captured in the baseline", c.BaselineGapProbes)
	case len(c.CoverageCaveatProbes) != 0:
		t.Errorf("coverage_caveat_probes = %v, want none on a coverage_increased entry", c.CoverageCaveatProbes)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("the diff does not validate: %v", err)
	}
	// The pure case is unchanged: every source probe blind, so
	// coverage_increased whether or not the comparison moved anything.
	only := testCapability(root.ID, root.Privilege, "sudo/rule/sudoers/12")
	d = coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusPermissionDenied),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(), capabilitiesDoc(only))
	cov, ok := changeOfKind(d, ChangeCoverageIncreased)
	if !ok {
		t.Fatalf("no coverage_increased when every source probe was blind: %v", capabilityKeys(d))
	}
	if len(cov.CoverageCaveatProbes) != 0 {
		t.Errorf("coverage_caveat_probes = %v, want none on a coverage_increased entry", cov.CoverageCaveatProbes)
	}
}

// R-T1: a capability_added entry must not carry coverage caveat probes that
// are not sorted or not probe ids, and no other kind may carry them at all.
func TestCoverageCaveatProbesContract(t *testing.T) {
	root := testCapability("capability/execute/host/user/alice", "root-via-sudo", "sudo/rule/sudoers/12")
	d := coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusPartial),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(), capabilitiesDoc(root))
	c, ok := changeOfKind(d, ChangeCapabilityAdded)
	if !ok {
		t.Fatalf("no capability_added: %v", capabilityKeys(d))
	}
	unsorted := c
	unsorted.CoverageCaveatProbes = []string{"linux.sudo", "common.identity"}
	if err := validateChange(unsorted); err == nil {
		t.Error("unsorted coverage caveat probes accepted")
	}
	notAProbe := c
	notAProbe.CoverageCaveatProbes = []string{"Linux.Sudo"}
	if err := validateChange(notAProbe); err == nil {
		t.Error("a coverage caveat entry that is not a probe id accepted")
	}
	wrongKind, ok := changeOfKind(d, ChangeAdded)
	if !ok {
		t.Fatal("the fixture produced no added entry to test the kind guard with")
	}
	wrongKind.CoverageCaveatProbes = []string{"linux.sudo"}
	if err := validateChange(wrongKind); err == nil {
		t.Error("an added entry with coverage caveat probes accepted")
	}
}

// keyFixture is a walking-skeleton capture plus the two artifacts a public
// key capability rests on: the account, from probe linux.users, and the
// authorized key, from probe linux.ssh. linux.users is always captured; the
// ssh status is the parameter, and a status other than captured leaves the
// key artifact out, which is what a blind capture looks like.
func keyFixture(noise int, ssh trustfreeze.ProbeStatus) fixture {
	f := baseFixture(testTime, noise)
	f.results = append(f.results, probeResult("linux.users", trustfreeze.StatusCaptured, "", testTime, 5))
	user := artifact("user/alice", "account", trustfreeze.StateObserved,
		trustfreeze.ConfidenceProven, trustfreeze.FormatTime(testTime),
		map[string]string{"name": "alice", "uid": "1000", "shell": "/bin/bash"})
	user.Source = "linux.users"
	f.arts = append(f.arts, user)

	reason := ""
	if ssh != trustfreeze.StatusCaptured {
		reason = "permission denied reading the authorized_keys file"
	}
	f.results = append(f.results, probeResult("linux.ssh", ssh, reason, testTime, 6))
	if ssh == trustfreeze.StatusCaptured {
		key := artifact("ssh/authorized-key/alice/ab12", "ssh-authorized-key", trustfreeze.StateDeclared,
			trustfreeze.ConfidenceProven, trustfreeze.FormatTime(testTime),
			map[string]string{"account": "alice", "key_type": "ssh-ed25519", "fingerprint": "SHA256:ab12"})
		key.Source = "linux.ssh"
		f.arts = append(f.arts, key)
	}
	return f
}

// keyCapability is the capability the measured elevated run resolved: a named
// account may log in over ssh with a named key. It rests on two sources from
// two probes.
func keyCapability(sources ...string) trustfreeze.Capability {
	c := testCapability("capability/remote.shell.public-key/alice/ab12", "user", sources...)
	c.Action = "remote.shell"
	c.Resource = "host"
	c.Exposure = "network"
	return c
}

// R-T5 (SPEC-0469), the measured case: the capability
// remote.shell.public-key/<account>/<fingerprint> rests on a source from
// linux.users, which the baseline captured, and on a source from linux.ssh,
// which the baseline could not read. Only the second source is new in this
// comparison, and it comes from a probe the baseline did not capture, so the
// finding is coverage_increased and not a critical capability_added. The
// account was there before; what is new is that somebody could read
// authorized_keys.
func TestCompareCapabilityAddedJudgesTheDecisiveSources(t *testing.T) {
	cap := keyCapability("user/alice", "ssh/authorized-key/alice/ab12")
	d := coverageDiff(t,
		keyFixture(0, trustfreeze.StatusPermissionDenied),
		keyFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(), capabilitiesDoc(cap))

	if c, ok := changeOfKind(d, ChangeCapabilityAdded); ok {
		t.Fatalf("capability_added although the only new source comes from a probe the baseline did not capture: %+v", c)
	}
	c, ok := changeOfKind(d, ChangeCoverageIncreased)
	if !ok {
		t.Fatalf("no coverage_increased entry: %v", capabilityKeys(d))
	}
	switch {
	case c.CapabilityID != cap.ID:
		t.Errorf("coverage_increased names %q, want %q", c.CapabilityID, cap.ID)
	case len(c.BaselineGapProbes) != 1 || c.BaselineGapProbes[0] != "linux.ssh":
		t.Errorf("baseline_gap_probes = %v, want [linux.ssh]: linux.users was captured in the baseline", c.BaselineGapProbes)
	case len(c.CoverageCaveatProbes) != 0:
		t.Errorf("coverage_caveat_probes = %v, want none on a coverage_increased entry", c.CoverageCaveatProbes)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("the diff does not validate: %v", err)
	}
}

// R-T5: the guard reads the DECISIVE sources, and a source that sits on
// ground both runs could see is decisive. A capability whose new source comes
// from a probe the baseline captured stays capability_added at full severity,
// even when another of its sources comes from a blind probe.
func TestCompareCapabilityAddedKeepsKindWhenANewSourceWasVisible(t *testing.T) {
	// The baseline read the sudoers files and the current run did too; the
	// rule artifact is new, so the new privilege is a fact about the host.
	root := testCapability("capability/execute/host/user/alice", "root-via-sudo-nopasswd",
		"device/os", "sudo/rule/sudoers/12")
	d := coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusCaptured).withoutArtifact("sudo/rule/sudoers/12"),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(), capabilitiesDoc(root))

	if c, ok := changeOfKind(d, ChangeCoverageIncreased); ok {
		t.Fatalf("coverage_increased although the baseline could read the sudoers files: %+v", c)
	}
	c, ok := changeOfKind(d, ChangeCapabilityAdded)
	if !ok {
		t.Fatalf("no capability_added: %v", capabilityKeys(d))
	}
	if c.AfterPrivilege != root.Privilege {
		t.Errorf("after_privilege = %q, want %q", c.AfterPrivilege, root.Privilege)
	}
}

// R-T5: the rule applies to capability_changed as well, which had no guard at
// all. The capability was known; it only gained a source from the sudoers
// files the baseline could not read, so the difference is coverage, not
// drift.
func TestCompareCapabilityChangedIsDowngradedWhenEveryChangedSourceWasBlind(t *testing.T) {
	before := testCapability("capability/execute/host/user/alice", "root-via-group", "device/os")
	after := testCapability("capability/execute/host/user/alice", "root-via-sudo-nopasswd",
		"device/os", "sudo/rule/sudoers/12")
	d := coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusPermissionDenied),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(before), capabilitiesDoc(after))

	if c, ok := changeOfKind(d, ChangeCapabilityChanged); ok {
		t.Fatalf("capability_changed although the only changed source comes from a blind probe: %+v", c)
	}
	c, ok := changeOfKind(d, ChangeCoverageIncreased)
	if !ok {
		t.Fatalf("no coverage_increased entry: %v", capabilityKeys(d))
	}
	switch {
	case len(c.BaselineGapProbes) != 1 || c.BaselineGapProbes[0] != "linux.sudo":
		t.Errorf("baseline_gap_probes = %v, want [linux.sudo]", c.BaselineGapProbes)
	case c.BeforeDigest == "" || c.AfterDigest == "":
		t.Errorf("a downgraded capability_changed keeps both digests: before %q after %q", c.BeforeDigest, c.AfterDigest)
	case len(c.ChangedFields) == 0:
		t.Error("a downgraded capability_changed still names the fields that differ")
	case c.BeforePrivilege != before.Privilege || c.AfterPrivilege != after.Privilege:
		t.Errorf("privileges = %q and %q, want %q and %q", c.BeforePrivilege, c.AfterPrivilege, before.Privilege, after.Privilege)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("the diff does not validate: %v", err)
	}
}

// R-T5: the mirror of the test above. The changed source sits on ground both
// runs could see, so the capability_changed stays at full severity and names
// the thin coverage instead of dropping to info.
func TestCompareCapabilityChangedKeepsKindWhenTheChangedSourceWasVisible(t *testing.T) {
	before := testCapability("capability/execute/host/user/alice", "root-via-sudo", "sudo/rule/sudoers/12")
	after := testCapability("capability/execute/host/user/alice", "root-via-sudo-nopasswd", "sudo/rule/sudoers/12")
	// Both runs read the sudoers files; the rule itself changed.
	bf := coverageFixture(0, trustfreeze.StatusCaptured)
	cf := coverageFixture(1, trustfreeze.StatusCaptured).withRuleAttribute("nopasswd", "true")
	d := coverageDiff(t, bf, cf, capabilitiesDoc(before), capabilitiesDoc(after))

	if c, ok := changeOfKind(d, ChangeCoverageIncreased); ok {
		t.Fatalf("coverage_increased although the changed source was visible in the baseline: %+v", c)
	}
	c, ok := changeOfKind(d, ChangeCapabilityChanged)
	if !ok {
		t.Fatalf("no capability_changed: %v", capabilityKeys(d))
	}
	if c.AfterPrivilege != after.Privilege {
		t.Errorf("after_privilege = %q, want %q", c.AfterPrivilege, after.Privilege)
	}
}

// R-T5: a capability_changed on ground nothing moved on is not downgraded.
// No source of it is new or changed in this comparison, so there is nothing
// to attribute to increased coverage, and the entry keeps its kind.
func TestCompareCapabilityChangedWithoutAChangedSourceKeepsItsKind(t *testing.T) {
	before := testCapability("capability/execute/host/user/alice", "root-via-sudo", "device/os")
	after := testCapability("capability/execute/host/user/alice", "root-via-sudo-nopasswd", "device/os")
	d := coverageDiff(t,
		coverageFixture(0, trustfreeze.StatusPermissionDenied),
		coverageFixture(1, trustfreeze.StatusCaptured),
		capabilitiesDoc(before), capabilitiesDoc(after))

	if c, ok := changeOfKind(d, ChangeCoverageIncreased); ok {
		t.Fatalf("coverage_increased although no source of the capability moved: %+v", c)
	}
	if _, ok := changeOfKind(d, ChangeCapabilityChanged); !ok {
		t.Fatalf("no capability_changed: %v", capabilityKeys(d))
	}
}
