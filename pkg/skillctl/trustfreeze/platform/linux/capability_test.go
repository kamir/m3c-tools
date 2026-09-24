package linux

import (
	"context"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// The resolver is pure, so every case here is a table of artifacts in and
// capabilities out. The artifacts are built the way the probes build them:
// linux.sudo for the rule and file artifacts, linux.ssh for the keys and
// linux.users for the accounts and groups.

func capTestArtifact(id, typ string, attrs map[string]string) trustfreeze.Artifact {
	return trustfreeze.Artifact{
		ID: id, Type: typ, Scope: "host", State: trustfreeze.StateDeclared,
		Attributes: attrs, Sensitivity: trustfreeze.SensitivityInternal,
	}
}

func capTestRule(id, users string, noPasswd bool) trustfreeze.Artifact {
	return capTestArtifact(SudoRulePrefix+id, SudoRuleType, map[string]string{
		sudoAttrUsers:       users,
		sudoAttrAllCommands: "true",
		sudoAttrRunAsRoot:   "true",
		sudoAttrNoPasswd:    privBool(noPasswd),
	})
}

func capTestSudoFile(name string, readable bool) trustfreeze.Artifact {
	return capTestArtifact(SudoFilePrefix+name, SudoFileType, map[string]string{
		privAttrPath:     "/etc/" + name,
		privAttrReadable: privBool(readable),
	})
}

// capTestGroup builds the artifact linux.users writes for a group.
func capTestGroup(gid, name string, members ...string) trustfreeze.Artifact {
	attrs := map[string]string{
		"name": name, "gid": gid, "member_count": itoa(len(members)),
	}
	if len(members) > 0 {
		attrs["members"] = strings.Join(members, ",")
	}
	a := capTestArtifact("device/group/"+gid, "group", attrs)
	a.Scope = "device"
	a.State = trustfreeze.StateObserved
	return a
}

// capTestUser builds the artifact linux.users writes for an account.
func capTestUser(uid, name, primary, supplementary string) trustfreeze.Artifact {
	attrs := map[string]string{"name": name, "uid": uid}
	if primary != "" {
		attrs["primary_group"] = primary
	}
	if supplementary != "" {
		attrs["supplementary"] = supplementary
	}
	a := capTestArtifact("device/user/"+uid, "user", attrs)
	a.Scope = "device"
	a.State = trustfreeze.StateObserved
	return a
}

func capTestKey(account, slug, fingerprint string) trustfreeze.Artifact {
	a := capTestArtifact(ArtifactSSHAuthorizedKeyPrefix+account+"/"+slug, SSHAuthorizedKeyType, map[string]string{
		privAttrAccount:    account,
		sshAttrKeyType:     "ssh-ed25519",
		sshAttrFingerprint: fingerprint,
	})
	a.Scope = "user"
	return a
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func capByID(t *testing.T, caps []trustfreeze.Capability, id string) trustfreeze.Capability {
	t.Helper()
	for _, c := range caps {
		if c.ID == id {
			return c
		}
	}
	ids := make([]string, 0, len(caps))
	for _, c := range caps {
		ids = append(ids, c.ID)
	}
	t.Fatalf("no capability %q in %v", id, ids)
	return trustfreeze.Capability{}
}

func capHasDiag(diags []trustfreeze.Diagnostic, code string) bool {
	for _, d := range diags {
		if d.Code == code {
			return true
		}
	}
	return false
}

// TestResolveCapabilitiesNoPasswdRule: the case the report must be able to
// state in words, "alice may execute any command as root without a password".
func TestResolveCapabilitiesNoPasswdRule(t *testing.T) {
	arts := []trustfreeze.Artifact{capTestRule("sudoers.d/alice-nopasswd/1", "alice", true)}
	caps, _ := ResolveCapabilities(arts)
	if len(caps) != 1 {
		t.Fatalf("capabilities %+v", caps)
	}
	c := caps[0]
	if c.ID != CapExecuteHostPrefix+"user/alice" || c.SubjectID != "user/alice" {
		t.Fatalf("capability %+v", c)
	}
	if c.Action != CapActionExecute || c.Resource != CapResourceHost || c.Effect != CapEffectAllowed {
		t.Fatalf("capability %+v", c)
	}
	if c.Privilege != CapPrivilegeRootViaSudoNoPassword {
		t.Fatalf("privilege %q", c.Privilege)
	}
	if c.State != trustfreeze.StateDeclared || c.Confidence != trustfreeze.ConfidenceProven {
		t.Fatalf("state %q confidence %q", c.State, c.Confidence)
	}
	if c.Exposure != CapExposureLocal || c.Scope != CapScopeHost {
		t.Fatalf("exposure %q scope %q", c.Exposure, c.Scope)
	}
	if len(c.Sources) != 1 || c.Sources[0] != SudoRulePrefix+"sudoers.d/alice-nopasswd/1" {
		t.Fatalf("sources %v", c.Sources)
	}
}

// TestResolveCapabilitiesPasswordIsTheDefault: without NOPASSWD the privilege
// says that a password is needed.
func TestResolveCapabilitiesPasswordIsTheDefault(t *testing.T) {
	caps, _ := ResolveCapabilities([]trustfreeze.Artifact{capTestRule("sudoers/1", "alice", false)})
	if caps[0].Privilege != CapPrivilegeRootViaSudo {
		t.Fatalf("privilege %q", caps[0].Privilege)
	}
}

// TestResolveCapabilitiesGroupRuleExpandsMembers: a readable rule for %sudo
// plus the membership gives every member the capability, with both sources.
func TestResolveCapabilitiesGroupRuleExpandsMembers(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestRule("sudoers/4", "%sudo", false),
		capTestGroup("27", "sudo", "alice", "deploy"),
	}
	caps, _ := ResolveCapabilities(arts)
	group := capByID(t, caps, CapExecuteHostPrefix+"group/sudo")
	if group.State != trustfreeze.StateDeclared || group.Confidence != trustfreeze.ConfidenceProven {
		t.Fatalf("group capability %+v", group)
	}
	alice := capByID(t, caps, CapExecuteHostPrefix+"user/alice")
	if alice.State != trustfreeze.StateInferred || alice.Confidence != trustfreeze.ConfidenceCorroborated {
		t.Fatalf("member capability %+v", alice)
	}
	if len(alice.Sources) != 2 {
		t.Fatalf("a member capability rests on the rule and the membership: %v", alice.Sources)
	}
	if alice.Privilege != CapPrivilegeRootViaSudo {
		t.Fatalf("privilege %q", alice.Privilege)
	}
	capByID(t, caps, CapExecuteHostPrefix+"user/deploy")
}

// TestResolveCapabilitiesInferredFromGroup is the trial host: the rule file
// exists and could not be read, so the membership alone carries the statement
// and says so (playbook L1, L3).
func TestResolveCapabilitiesInferredFromGroup(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestSudoFile("sudoers", false),
		capTestSudoFile("sudoers.d/alice-nopasswd", false),
		capTestGroup("27", "sudo", "alice"),
		capTestGroup("984", "docker", "alice"),
	}
	caps, diags := ResolveCapabilities(arts)
	if len(caps) != 2 {
		t.Fatalf("capabilities %+v", caps)
	}
	c := capByID(t, caps, CapExecuteHostPrefix+"user/alice")
	if c.SubjectID != "user/alice" || c.Privilege != CapPrivilegeRootViaSudo {
		t.Fatalf("capability %+v", c)
	}
	if c.State != trustfreeze.StateInferred || c.Confidence != trustfreeze.ConfidenceReported {
		t.Fatalf("an unproven statement must not look proven: %+v", c)
	}
	// The unreadable rule files are named as sources: they say where the
	// missing proof would be.
	if len(c.Sources) != 3 {
		t.Fatalf("sources %v", c.Sources)
	}
	if !capHasDiag(diags, capDiagInferredFromGroup) {
		t.Fatalf("the inference was not reported: %+v", diags)
	}
	// The docker group is not a sudo group, and it is a root path all the
	// same: the socket it reaches is root-equivalent. It therefore yields a
	// capability of its own, with its own privilege wording and a rationale
	// that says why. (This assertion was inverted for review finding F3; the
	// earlier version required the docker membership to produce nothing and
	// therefore held that gap in place.)
	d := capByID(t, caps, CapExecuteHostViaRuntimePrefix+"docker/user/alice")
	if d.Privilege != CapPrivilegeRootViaContainerRuntime {
		t.Fatalf("docker capability %+v", d)
	}
	if d.Attributes[CapAttrRationale] == "" || !strings.Contains(d.Attributes[CapAttrRationale], "socket") {
		t.Fatalf("the capability does not say why the group grants root: %+v", d.Attributes)
	}
	if d.Attributes[CapAttrRuntimeObserved] != "false" {
		t.Fatalf("no container runtime was observed in this input: %+v", d.Attributes)
	}
	if !capHasDiag(diags, capDiagRuntimeGroup) {
		t.Fatalf("the runtime group inference was not reported: %+v", diags)
	}
}

// TestResolveCapabilitiesPrimaryGroupCounts: an account whose primary group is
// sudo does not appear in that group's member list.
func TestResolveCapabilitiesPrimaryGroupCounts(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestGroup("27", "sudo"),
		capTestUser("1000", "alice", "sudo", ""),
		capTestUser("1001", "deploy", "deploy", "docker"),
	}
	caps, _ := ResolveCapabilities(arts)
	capByID(t, caps, CapExecuteHostPrefix+"user/alice")
	// deploy is in the docker group, which is a root path of its own (F3).
	capByID(t, caps, CapExecuteHostViaRuntimePrefix+"docker/user/deploy")
	if len(caps) != 2 {
		t.Fatalf("capabilities %+v", caps)
	}
}

// TestResolveCapabilitiesSupplementaryGroup reads the account artifact of
// linux.users, which lists the supplementary groups by name.
func TestResolveCapabilitiesSupplementaryGroup(t *testing.T) {
	arts := []trustfreeze.Artifact{capTestUser("1000", "alice", "alice", "adm,sudo,docker")}
	caps, _ := ResolveCapabilities(arts)
	c := capByID(t, caps, CapExecuteHostPrefix+"user/alice")
	if c.Sources[0] != "device/user/1000" {
		t.Fatalf("sources %v", c.Sources)
	}
}

// TestResolveCapabilitiesReadableRuleBeatsInference: where both exist, the
// proven statement wins and the membership only adds a source.
func TestResolveCapabilitiesReadableRuleBeatsInference(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestRule("sudoers.d/alice-nopasswd/1", "alice", true),
		capTestSudoFile("sudoers", false),
		capTestGroup("27", "sudo", "alice"),
	}
	caps, _ := ResolveCapabilities(arts)
	c := capByID(t, caps, CapExecuteHostPrefix+"user/alice")
	if c.Privilege != CapPrivilegeRootViaSudoNoPassword {
		t.Fatalf("the proven NOPASSWD rule was overwritten: %+v", c)
	}
	if c.State != trustfreeze.StateDeclared {
		t.Fatalf("state %q", c.State)
	}
	if len(c.Sources) != 2 {
		t.Fatalf("sources %v, want the rule and the membership", c.Sources)
	}
}

// TestResolveCapabilitiesIgnoresNarrowRules: only a rule that grants every
// command as root becomes a root capability.
func TestResolveCapabilitiesIgnoresNarrowRules(t *testing.T) {
	narrow := capTestArtifact(SudoRulePrefix+"sudoers/9", SudoRuleType, map[string]string{
		sudoAttrUsers:       "deploy",
		sudoAttrCommands:    "/usr/bin/systemctl restart app",
		sudoAttrAllCommands: "false",
		sudoAttrRunAsRoot:   "true",
		sudoAttrNoPasswd:    "true",
	})
	notRoot := capTestArtifact(SudoRulePrefix+"sudoers/10", SudoRuleType, map[string]string{
		sudoAttrUsers:       "deploy",
		sudoAttrAllCommands: "true",
		sudoAttrRunAsRoot:   "false",
	})
	caps, _ := ResolveCapabilities([]trustfreeze.Artifact{narrow, notRoot})
	if len(caps) != 0 {
		t.Fatalf("capabilities %+v", caps)
	}
}

// TestResolveCapabilitiesAlias: an alias the capture could not resolve is
// visible, and the gap is named.
func TestResolveCapabilitiesAlias(t *testing.T) {
	caps, diags := ResolveCapabilities([]trustfreeze.Artifact{capTestRule("sudoers/7", "ADMINS", true)})
	c := capByID(t, caps, CapExecuteHostPrefix+"alias/ADMINS")
	if c.SubjectID != "alias/ADMINS" {
		t.Fatalf("capability %+v", c)
	}
	if !capHasDiag(diags, capDiagAliasUnresolved) {
		t.Fatalf("the unresolved alias was not reported: %+v", diags)
	}
}

// TestResolveCapabilitiesEveryone: a rule for ALL is a statement about
// everybody, not about a user called ALL.
func TestResolveCapabilitiesEveryone(t *testing.T) {
	caps, _ := ResolveCapabilities([]trustfreeze.Artifact{capTestRule("sudoers/8", "ALL", true)})
	if caps[0].SubjectID != CapSubjectEveryone {
		t.Fatalf("subject %q", caps[0].SubjectID)
	}
}

// TestResolveCapabilitiesAuthorizedKey: a key on a privileged account carries
// that privilege and the sources of both facts.
func TestResolveCapabilitiesAuthorizedKey(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestRule("sudoers.d/alice-nopasswd/1", "alice", true),
		capTestKey("alice", "7def39264223a3c5", "SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8"),
		capTestKey("root", "e00f63c9904e8672", "SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4"),
		capTestKey("backup", "aaaabbbbccccdddd", "SHA256:aaaa"),
	}
	caps, _ := ResolveCapabilities(arts)
	alice := capByID(t, caps, CapRemoteShellPublicKeyPrefix+"alice/7def39264223a3c5")
	if alice.Action != CapActionAccess || alice.Resource != CapResourceRemoteShell {
		t.Fatalf("capability %+v", alice)
	}
	if alice.Exposure != CapExposureNetwork {
		t.Fatalf("a key grants access over the network: %+v", alice)
	}
	if alice.State != trustfreeze.StateDeclared {
		t.Fatalf("a key that was never seen in use is declared, not %q", alice.State)
	}
	if alice.Privilege != CapPrivilegeRootViaSudoNoPassword {
		t.Fatalf("the key on a privileged account lost its privilege: %+v", alice)
	}
	if len(alice.Sources) != 2 {
		t.Fatalf("sources %v, want the key and the sudo rule", alice.Sources)
	}
	root := capByID(t, caps, CapRemoteShellPublicKeyPrefix+"root/e00f63c9904e8672")
	if root.Privilege != CapPrivilegeRoot {
		t.Fatalf("root key privilege %q", root.Privilege)
	}
	plain := capByID(t, caps, CapRemoteShellPublicKeyPrefix+"backup/aaaabbbbccccdddd")
	if plain.Privilege != CapPrivilegeUser {
		t.Fatalf("plain key privilege %q", plain.Privilege)
	}
}

// TestResolveCapabilitiesKeyWithoutAccount: a capability whose subject cannot
// be derived is dropped, and the drop is reported.
func TestResolveCapabilitiesKeyWithoutAccount(t *testing.T) {
	a := capTestKey("alice", "slug", "SHA256:x")
	delete(a.Attributes, privAttrAccount)
	caps, diags := ResolveCapabilities([]trustfreeze.Artifact{a})
	if len(caps) != 0 {
		t.Fatalf("capabilities %+v", caps)
	}
	if !capHasDiag(diags, capDiagNoSource) {
		t.Fatalf("diagnostics %+v", diags)
	}
}

// TestResolveCapabilitiesEverySourceIsNamed is the invariant of SPEC-0468 R7.
func TestResolveCapabilitiesEverySourceIsNamed(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestRule("sudoers/4", "%sudo", false),
		capTestRule("sudoers.d/alice-nopasswd/1", "alice", true),
		capTestSudoFile("sudoers", false),
		capTestGroup("27", "sudo", "alice", "deploy"),
		capTestUser("1000", "alice", "alice", "sudo,docker"),
		capTestKey("alice", "7def39264223a3c5", "SHA256:fe85"),
	}
	caps, _ := ResolveCapabilities(arts)
	if len(caps) == 0 {
		t.Fatalf("no capability was resolved")
	}
	for _, c := range caps {
		if err := ValidateCapability(c); err != nil {
			t.Fatalf("invalid capability: %v", err)
		}
		for i := 1; i < len(c.Sources); i++ {
			if c.Sources[i-1] >= c.Sources[i] {
				t.Fatalf("sources are not sorted and unique: %v", c.Sources)
			}
		}
	}
}

// TestResolveCapabilitiesDeterministic: the order of the input artifacts
// changes nothing (SPEC-0469 AC7, playbook L8).
func TestResolveCapabilitiesDeterministic(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestRule("sudoers/4", "%sudo", false),
		capTestSudoFile("sudoers", false),
		capTestGroup("27", "sudo", "deploy", "alice"),
		capTestUser("1000", "alice", "alice", "sudo"),
		capTestKey("alice", "7def39264223a3c5", "SHA256:fe85"),
	}
	first, _ := ResolveCapabilities(arts)
	reversed := make([]trustfreeze.Artifact, 0, len(arts))
	for i := len(arts) - 1; i >= 0; i-- {
		reversed = append(reversed, arts[i])
	}
	second, _ := ResolveCapabilities(reversed)
	if len(first) != len(second) {
		t.Fatalf("%d capabilities against %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID || strings.Join(first[i].Sources, ",") != strings.Join(second[i].Sources, ",") {
			t.Fatalf("capability %d differs: %+v against %+v", i, first[i], second[i])
		}
		if i > 0 && first[i-1].ID >= first[i].ID {
			t.Fatalf("capabilities are not sorted by id: %q before %q", first[i-1].ID, first[i].ID)
		}
	}
}

// TestResolveCapabilitiesNoInput: an empty capability list must not read as
// "this host grants nothing".
func TestResolveCapabilitiesNoInput(t *testing.T) {
	caps, diags := ResolveCapabilities(nil)
	if len(caps) != 0 {
		t.Fatalf("capabilities %+v", caps)
	}
	if !capHasDiag(diags, capDiagNoInput) {
		t.Fatalf("diagnostics %+v", diags)
	}
}

// TestResolveCapabilitiesTruncatedMembership: a member list the account probe
// had to cut is a gap in the capability list, and it is named.
func TestResolveCapabilitiesTruncatedMembership(t *testing.T) {
	g := capTestGroup("27", "sudo", "alice")
	g.Attributes["member_count"] = "80"
	_, diags := ResolveCapabilities([]trustfreeze.Artifact{g})
	if !capHasDiag(diags, capDiagMembershipTruncated) {
		t.Fatalf("diagnostics %+v", diags)
	}
}

// TestCapabilityResolverInterface covers the seam shape of SPEC-0466 section
// 4.6 and the configurable group list.
func TestCapabilityResolverInterface(t *testing.T) {
	r := CapabilityResolver{PrivilegedGroups: []string{"operators"}}
	caps, diags, err := r.Resolve(context.Background(), []trustfreeze.Artifact{
		capTestGroup("500", "operators", "alice"),
		capTestGroup("27", "sudo", "deploy"),
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	capByID(t, caps, CapExecuteHostPrefix+"user/alice")
	if len(caps) != 1 {
		t.Fatalf("the built-in group list was not replaced: %+v", caps)
	}
	if len(diags) == 0 {
		t.Fatalf("the inference was not reported")
	}
}

func TestValidateCapability(t *testing.T) {
	valid := trustfreeze.Capability{
		ID: "capability/execute/host/user/alice", SubjectID: "user/alice",
		Action: CapActionExecute, Resource: CapResourceHost, Effect: CapEffectAllowed,
		State: trustfreeze.StateDeclared, Sources: []string{"sudo/rule/sudoers/1"},
		Confidence: trustfreeze.ConfidenceProven,
	}
	if err := ValidateCapability(valid); err != nil {
		t.Fatalf("valid capability rejected: %v", err)
	}
	cases := map[string]func(c *trustfreeze.Capability){
		"no id":          func(c *trustfreeze.Capability) { c.ID = "" },
		"no subject":     func(c *trustfreeze.Capability) { c.SubjectID = " " },
		"no action":      func(c *trustfreeze.Capability) { c.Action = "" },
		"no resource":    func(c *trustfreeze.Capability) { c.Resource = "" },
		"no source":      func(c *trustfreeze.Capability) { c.Sources = nil },
		"empty source":   func(c *trustfreeze.Capability) { c.Sources = []string{" "} },
		"bad state":      func(c *trustfreeze.Capability) { c.State = "made up" },
		"bad confidence": func(c *trustfreeze.Capability) { c.Confidence = "certain" },
	}
	for name, mutate := range cases {
		c := valid
		c.Sources = append([]string(nil), valid.Sources...)
		mutate(&c)
		if err := ValidateCapability(c); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestCapSubjectOf pins the mapping of a sudoers user entry to a subject.
func TestCapSubjectOf(t *testing.T) {
	cases := []struct {
		in      string
		subject string
		kind    capSubjectKind
	}{
		{"alice", "user/alice", capSubjectUser},
		{"%sudo", "group/sudo", capSubjectGroup},
		{"%#27", "group/gid:27", capSubjectGroup},
		{"#1000", "user/uid:1000", capSubjectUser},
		{"+admins", "alias/admins", capSubjectNetgroup},
		{"ADMINS", "alias/ADMINS", capSubjectAlias},
		{"ALL", CapSubjectEveryone, capSubjectAll},
	}
	for _, c := range cases {
		subject, kind := capSubjectOf(c.in)
		if subject != c.subject || kind != c.kind {
			t.Fatalf("capSubjectOf(%q) = %q, %v; want %q, %v", c.in, subject, kind, c.subject, c.kind)
		}
	}
}

func TestCapNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"sudo": "sudo", "%sudo": "sudo", "27(sudo)": "sudo", " sudo ": "sudo", "": "",
	} {
		if got := capNormalizeName(in); got != want {
			t.Fatalf("capNormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestResolveCapabilitiesFromProbeArtifacts closes the loop: the artifacts the
// sudo probe really produces are the ones the resolver reads.
func TestResolveCapabilitiesFromProbeArtifacts(t *testing.T) {
	files := probe.FakeFiles{Files: map[string][]byte{
		SudoersPath:                    []byte("root\tALL=(ALL:ALL) ALL\n%sudo\tALL=(ALL:ALL) ALL\n"),
		SudoersDir + "/README":         []byte("# readme\n"),
		SudoersDir + "/alice-nopasswd": []byte("alice ALL=(ALL) NOPASSWD: ALL\n"),
	}}
	res, _ := privRunProbe(t, NewSudoProbe(), sudoFixtureRunner(t), files)
	arts := append([]trustfreeze.Artifact(nil), res.NormalizedState...)
	arts = append(arts, capTestGroup("27", "sudo", "alice", "deploy"))
	caps, _ := ResolveCapabilities(arts)

	alice := capByID(t, caps, CapExecuteHostPrefix+"user/alice")
	if alice.Privilege != CapPrivilegeRootViaSudoNoPassword {
		t.Fatalf("alice %+v", alice)
	}
	deploy := capByID(t, caps, CapExecuteHostPrefix+"user/deploy")
	if deploy.Privilege != CapPrivilegeRootViaSudo || deploy.State != trustfreeze.StateInferred {
		t.Fatalf("deploy %+v", deploy)
	}
	capByID(t, caps, CapExecuteHostPrefix+"user/root")
	capByID(t, caps, CapExecuteHostPrefix+"group/sudo")
	for _, c := range caps {
		if err := ValidateCapability(c); err != nil {
			t.Fatalf("invalid capability: %v", err)
		}
	}
}

// TestResolveCapabilitiesGroupArtifactWithoutName falls back to the id, so a
// group artifact of another shape still contributes its membership.
func TestResolveCapabilitiesGroupArtifactWithoutName(t *testing.T) {
	a := capTestArtifact("device/group/sudo", "group", map[string]string{"members": "alice"})
	caps, _ := ResolveCapabilities([]trustfreeze.Artifact{a})
	capByID(t, caps, CapExecuteHostPrefix+"user/alice")
}

// capTestContainer builds the artifact linux.containers writes for a running
// container, with the two attributes the inspect call adds.
func capTestContainer(runtime, name string, privileged bool) trustfreeze.Artifact {
	a := capTestArtifact(ArtifactContainerPrefix+"/"+runtime+"/"+name, artifactTypeContainer, map[string]string{
		"runtime": runtime, "name": name, "container_id": "c0ffee" + name,
		"image": "example/" + name + ":1", "container_state": "running",
		"exposure": ExposureNone, "published_ports": "",
		"declared_restart_policy": "always",
		"declared_privileged":     privBool(privileged),
	})
	a.Scope = "device"
	a.Source = ContainersProbeID
	a.State = trustfreeze.StateObserved
	return a
}

// R-T4 (a): a container the runtime reports as privileged reaches the host
// devices and the host filesystem, so it holds an execute capability on the
// host. Its subject is the container, not a principal: nobody has to be logged
// in for it to hold.
func TestResolveCapabilitiesPrivilegedContainer(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestContainer("docker", "maint", true),
		capTestContainer("docker", "web", false),
	}
	caps, diags := ResolveCapabilities(arts)
	c := capByID(t, caps, CapExecuteHostPrefix+ArtifactContainerPrefix+"/docker/maint")
	switch {
	case c.SubjectID != ArtifactContainerPrefix+"/docker/maint":
		t.Errorf("subject %q, want the container", c.SubjectID)
	case c.Action != CapActionExecute || c.Resource != CapResourceHost:
		t.Errorf("action %q resource %q", c.Action, c.Resource)
	case c.State != trustfreeze.StateDeclared:
		t.Errorf("state %q, want declared: the runtime reports the flag, nobody watched it being used", c.State)
	case c.Privilege != CapPrivilegeRootViaPrivilegedContainer:
		t.Errorf("privilege %q", c.Privilege)
	case len(c.Sources) != 1 || c.Sources[0] != ArtifactContainerPrefix+"/docker/maint":
		t.Errorf("sources %v, want the container artifact", c.Sources)
	case c.Attributes[CapAttrRationale] == "" ||
		!strings.Contains(c.Attributes[CapAttrRationale], "host filesystem") ||
		!strings.Contains(c.Attributes[CapAttrRationale], "device"):
		t.Errorf("the capability does not say why a privileged container is root: %+v", c.Attributes)
	case c.Attributes[CapAttrGrantPath] != capGrantPathPrivilegedContainer:
		t.Errorf("grant_path %q", c.Attributes[CapAttrGrantPath])
	}
	// The unprivileged container is not a capability, and the resolver says
	// nothing about it.
	for _, got := range caps {
		if strings.Contains(got.ID, "/web") {
			t.Fatalf("the unprivileged container produced a capability: %+v", got)
		}
	}
	if len(caps) != 1 {
		t.Fatalf("capabilities %+v (diags %+v)", caps, diags)
	}
}

// R-T4 (a): a container whose privileged flag was never read (the inspect call
// did not answer) is not claimed either way.
func TestResolveCapabilitiesContainerWithoutInspect(t *testing.T) {
	a := capTestContainer("docker", "maint", false)
	delete(a.Attributes, "declared_privileged")
	delete(a.Attributes, "declared_restart_policy")
	caps, _ := ResolveCapabilities([]trustfreeze.Artifact{a})
	if len(caps) != 0 {
		t.Fatalf("a container without a read privileged flag produced %+v", caps)
	}
}

// O-T2: an account that the group artifact and its own supplementary list both
// name is one member of that group, so the runtime-group rule reports it once.
// The capability is merged by id; the diagnostic must be merged with it.
func TestResolveCapabilitiesRuntimeGroupDiagnosticOncePerCapability(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestGroup("984", "docker", "alice"),
		capTestUser("1000", "alice", "alice", "docker"),
	}
	caps, diags := ResolveCapabilities(arts)
	id := CapExecuteHostViaRuntimePrefix + "docker/user/alice"
	c := capByID(t, caps, id)
	if len(c.Sources) != 2 {
		t.Fatalf("both artifacts are sources of the one capability: %v", c.Sources)
	}
	n := 0
	for _, d := range diags {
		if d.Code == capDiagRuntimeGroup {
			n++
			if d.Field != id {
				t.Errorf("diagnostic names %q, want the capability id", d.Field)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d runtime group diagnostics for one capability: %+v", n, diags)
	}
}

// R-T3, R-T4: the resolver and the core share one privilege vocabulary. capture
// names the root capabilities and report orders them by that list, so a
// privilege this resolver invents without adding it there would be reported as
// harmless.
func TestCapabilityPrivilegesAreInTheCoreVocabulary(t *testing.T) {
	for _, p := range []string{
		CapPrivilegeRoot, CapPrivilegeRootViaSudo, CapPrivilegeRootViaSudoNoPassword,
		CapPrivilegeRootViaContainerRuntime, CapPrivilegeRootViaPrivilegedContainer,
	} {
		if !trustfreeze.IsRootPrivilege(p) {
			t.Errorf("privilege %q is root here and not in trustfreeze.RootPrivileges %v", p, trustfreeze.RootPrivileges())
		}
		if trustfreeze.PrivilegeRank(p) < trustfreeze.PrivilegeRank(CapPrivilegeUser) {
			t.Errorf("privilege %q ranks below %q", p, CapPrivilegeUser)
		}
	}
	if trustfreeze.IsRootPrivilege(CapPrivilegeUser) || trustfreeze.PrivilegeRank(CapPrivilegeUser) != 0 {
		t.Errorf("%q must not count as root", CapPrivilegeUser)
	}
}
