package capture

import (
	"context"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/platform/common"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/platform/linux"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// These tests hold the second half of the redaction contract: a value that
// cannot be a secret must not be replaced. The first half (a secret is
// replaced) is held by the tests around them and is asserted here again, so
// that the guard cannot be widened without the protection failing.
//
// The three cases come from an elevated capture of an Ubuntu bastion, where
// the artifact attributes read:
//
//	ssh/sshd/effective  passwordauthentication = [REDACTED_password]
//	ssh/sshd/effective  permitemptypasswords   = [REDACTED_password]
//	sudo/rule/...       nopasswd               = [REDACTED_password]
//
// The key names match the secret vocabulary, the values are the answer a
// security review needs.

// policySSHConfig is a declared configuration with both keywords set.
const policySSHConfig = "PasswordAuthentication yes\nPermitEmptyPasswords no\nUsePAM yes\n"

// policySudoers grants one account every command without a password and one
// group every command with a password, so both answers appear in one run.
const policySudoers = "Defaults\tenv_reset\n" +
	"root\tALL=(ALL:ALL) ALL\n" +
	"%sudo\tALL=(ALL:ALL) ALL\n" +
	"@includedir /etc/sudoers.d\n"

const policySudoDropIn = "alice ALL=(ALL) NOPASSWD: ALL\n"

// policyHostFiles is the file table of the fixture host.
func policyHostFiles(sshConfig string) probe.FakeFiles {
	return probe.FakeFiles{Files: map[string][]byte{
		common.OSReleasePath:           []byte(ubuntuOSRelease),
		linux.SSHDConfigPath:           []byte(sshConfig),
		linux.SudoersPath:              []byte(policySudoers),
		linux.SudoersDir + "/10-alice": []byte(policySudoDropIn),
	}}
}

// policyRunner scripts every command linux.ssh and linux.sudo run, with an
// observable "sshd -T": the elevated run of the measured capture.
func policyRunner() *probe.FakeRunner {
	r := identityRunner()
	r.Script("ls", []string{"--version"}, probe.FakeResponse{Stdout: []byte("ls (GNU coreutils) 9.4\n")})
	r.Script("stat", []string{"--version"}, probe.FakeResponse{Stdout: []byte("stat (GNU coreutils) 9.4\n")})
	r.Script("getent", []string{"--version"}, probe.FakeResponse{Stdout: []byte("getent (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39\n")})
	r.Script("getent", []string{"passwd"}, probe.FakeResponse{Stdout: []byte(
		"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")})
	r.Script("sshd", []string{"-V"}, probe.FakeResponse{Stderr: []byte("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\n")})
	r.Script("sshd", []string{"-T"}, probe.FakeResponse{Stdout: []byte(
		"port 22\npasswordauthentication yes\npermitemptypasswords no\nusepam yes\nlogingracetime 120\n")})
	r.Script("ls", []string{"-la", linux.SSHDir}, probe.FakeResponse{Stdout: []byte(
		"total 8\n" +
			"drwxr-xr-x 2 root root 4096 Sep 23 06:15 .\n" +
			"drwxr-xr-x 4 root root 4096 Sep 23 06:15 ..\n" +
			"-rw-r--r-- 1 root root 3257 Sep 23 06:15 sshd_config\n")})
	r.Script("ls", []string{"-la", linux.SSHDConfigDir}, probe.FakeResponse{Stdout: []byte(
		"total 0\n" +
			"drwxr-xr-x 2 root root 4096 Sep 23 06:15 .\n" +
			"drwxr-xr-x 4 root root 4096 Sep 23 06:15 ..\n")})
	r.Script("ls", []string{"-la", linux.SudoersDir}, probe.FakeResponse{Stdout: []byte(
		"total 4\n" +
			"drwxr-xr-x 2 root root 4096 Sep 23 06:15 .\n" +
			"drwxr-xr-x 4 root root 4096 Sep 23 06:15 ..\n" +
			"-r--r----- 1 root root 29 Sep 23 06:15 10-alice\n")})
	r.Script("stat", []string{"-c", "%n %a %U %G %s", linux.SudoersPath, linux.SudoersDir, linux.SudoersDir + "/10-alice"},
		probe.FakeResponse{Stdout: []byte(
			"/etc/sudoers 440 root root 1800\n" +
				"/etc/sudoers.d 755 root root 4096\n" +
				"/etc/sudoers.d/10-alice 440 root root 29\n")})
	return r
}

// policyCapture runs a capture of the two privilege probes on the fixture
// host and returns the written bundle.
func policyCapture(t *testing.T) *trustfreeze.Bundle {
	t.Helper()
	return policyCaptureWith(t, policySSHConfig)
}

func policyCaptureWith(t *testing.T, sshConfig string) *trustfreeze.Bundle {
	t.Helper()
	p := profile(t, []string{linux.SSHProbeID, linux.SudoProbeID}, nil)
	opts := baseOptions(t, p, registry(t), policyRunner())
	opts.Host.Files = policyHostFiles(sshConfig)
	return verifyBundle(t, mustRun(t, opts))
}

// policyArtifact returns one artifact of the written state document.
func policyArtifact(t *testing.T, b *trustfreeze.Bundle, id string) trustfreeze.Artifact {
	t.Helper()
	for _, a := range b.State.Artifacts {
		if a.ID == id {
			return a
		}
	}
	ids := make([]string, 0, len(b.State.Artifacts))
	for _, a := range b.State.Artifacts {
		ids = append(ids, a.ID)
	}
	t.Fatalf("no artifact %q in %v", id, ids)
	return trustfreeze.Artifact{}
}

func policyWantAttr(t *testing.T, a trustfreeze.Artifact, name, want string) {
	t.Helper()
	if got := a.Attributes[name]; got != want {
		t.Fatalf("artifact %s attribute %s = %q, want %q", a.ID, name, got, want)
	}
}

// TestCaptureKeepsSSHDPolicyAnswers: the two sshd keywords a review asks
// about survive the bundle. Measured defect: both came out as the password
// marker, so the bundle could not say whether password login is allowed.
func TestCaptureKeepsSSHDPolicyAnswers(t *testing.T) {
	b := policyCapture(t)
	eff := policyArtifact(t, b, linux.ArtifactSSHEffective)
	if eff.State != trustfreeze.StateObserved {
		t.Fatalf("effective artifact state %q", eff.State)
	}
	policyWantAttr(t, eff, "passwordauthentication", "yes")
	policyWantAttr(t, eff, "permitemptypasswords", "no")
	declared := policyArtifact(t, b, linux.ArtifactSSHDeclared)
	policyWantAttr(t, declared, "passwordauthentication", "yes")
	policyWantAttr(t, declared, "permitemptypasswords", "no")
}

// TestCaptureKeepsSudoNoPasswdFlag: the nopasswd flag of a sudo rule is the
// answer, not a credential. Measured defect: it came out as the password
// marker, and the capability resolver, which reads that attribute, then
// rated an unrestricted passwordless root grant as root-via-sudo.
func TestCaptureKeepsSudoNoPasswdFlag(t *testing.T) {
	b := policyCapture(t)
	rule := policyArtifact(t, b, linux.SudoRulePrefix+"sudoers.d/10-alice/1")
	policyWantAttr(t, rule, "nopasswd", "true")
	policyWantAttr(t, rule, "all_commands", "true")
	group := policyArtifact(t, b, linux.SudoRulePrefix+"sudoers/3")
	policyWantAttr(t, group, "nopasswd", "false")
	if b.Capabilities == nil {
		t.Fatal("no capability document")
	}
	var privilege string
	for _, c := range b.Capabilities.Capabilities {
		if c.ID == linux.CapExecuteHostPrefix+"user/alice" {
			privilege = c.Privilege
		}
	}
	if privilege != linux.CapPrivilegeRootViaSudoNoPassword {
		t.Fatalf("capability privilege %q, want %q", privilege, linux.CapPrivilegeRootViaSudoNoPassword)
	}
}

// TestCaptureRedactsLongValueUnderPolicyKey: the guard is about the shape of
// the value, not about the key. A 60 character value under the same key name
// is still replaced, and a probe that declares a field policy cannot carry a
// key body into the bundle with it, because every value pattern still runs.
func TestCaptureRedactsLongValueUnderPolicyKey(t *testing.T) {
	const hash = "$6$rounds=656000$abcdefghijklmnop$0123456789ABCDEFGHIJKLMNOPQRSTUV"
	const keyBody = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB"
	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + keyBody + "\n-----END OPENSSH PRIVATE KEY-----"
	p := profile(t, []string{"test.policy"}, nil)
	fake := newFake("test.policy", func(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
		return trustfreeze.ProbeResult{
			Status: trustfreeze.StatusCaptured,
			NormalizedState: []trustfreeze.Artifact{{
				ID: "test/policy", Type: "test", Scope: "host", Source: "test.policy",
				State: trustfreeze.StateDeclared,
				Attributes: map[string]string{
					"passwordauthentication": "yes",
					"password_hash":          hash,
					"permitemptypasswords":   pem,
				},
				AttributeClasses: map[string]trustfreeze.AttributeClass{
					"passwordauthentication": trustfreeze.AttributeClassPolicy,
					"permitemptypasswords":   trustfreeze.AttributeClassPolicy,
				},
				Provenance:  trustfreeze.Provenance{Method: "file", Confidence: trustfreeze.ConfidenceProven, ObservedAt: trustfreeze.FormatTime(testTime)},
				Sensitivity: trustfreeze.SensitivityInternal,
			}},
		}
	})
	b := verifyBundle(t, mustRun(t, baseOptions(t, p, registry(t, fake), identityRunner())))
	a := policyArtifact(t, b, "test/policy")
	policyWantAttr(t, a, "passwordauthentication", "yes")
	policyWantAttr(t, a, "password_hash", redact.Marker("password"))
	if strings.Contains(a.Attributes["permitemptypasswords"], keyBody) {
		t.Fatalf("a key body survived under a declared policy field: %q", a.Attributes["permitemptypasswords"])
	}
	for path, f := range readTree(t, b.Dir) {
		if strings.Contains(string(f), hash) || strings.Contains(string(f), keyBody) {
			t.Fatalf("%s carries the secret", path)
		}
	}
}

// TestCaptureKeepsADirectiveOutsideTheAnswerSet proves the second mechanism
// on its own. The value is not in the closed set of policy answers, so only
// the probe's own statement about its field keeps it. A declared
// configuration is recorded as it stands: a reviewer has to see the odd
// value, not a marker that hides that somebody wrote something sshd does not
// accept.
func TestCaptureKeepsADirectiveOutsideTheAnswerSet(t *testing.T) {
	const odd = "yes-if-pam-says-so"
	if redact.IsPolicyAnswer(odd) {
		t.Fatalf("%q is a policy answer, so this test would not prove the declaration", odd)
	}
	b := policyCaptureWith(t, "PasswordAuthentication "+odd+"\nPermitEmptyPasswords no\n")
	declared := policyArtifact(t, b, linux.ArtifactSSHDeclared)
	policyWantAttr(t, declared, "passwordauthentication", odd)
	if declared.AttributeClasses["passwordauthentication"] != trustfreeze.AttributeClassPolicy {
		t.Fatalf("the declared artifact does not classify passwordauthentication: %+v", declared.AttributeClasses)
	}
	// The declaration names only the fields the generic rule would take for
	// a credential, so it stays small.
	if _, ok := declared.AttributeClasses["usepam"]; ok {
		t.Fatalf("a field the key name rule never touches was classified: %+v", declared.AttributeClasses)
	}
}

// TestCaptureDeclaresTheSudoRuleFlag: the rule artifact carries the probe's
// statement about nopasswd into the bundle, so a reader of the bundle can
// see why the value is there in clear.
func TestCaptureDeclaresTheSudoRuleFlag(t *testing.T) {
	b := policyCapture(t)
	rule := policyArtifact(t, b, linux.SudoRulePrefix+"sudoers.d/10-alice/1")
	if rule.AttributeClasses["nopasswd"] != trustfreeze.AttributeClassPolicy {
		t.Fatalf("the rule artifact does not classify nopasswd: %+v", rule.AttributeClasses)
	}
	if _, ok := rule.AttributeClasses["commands"]; ok {
		t.Fatalf("a field the key name rule never touches was classified: %+v", rule.AttributeClasses)
	}
}

// TestCaptureReplacesADeclaredSensitiveAttribute is the other direction of
// the same mechanism: a probe that knows its field carries key material says
// so, and the value is replaced although the key name says nothing.
func TestCaptureReplacesADeclaredSensitiveAttribute(t *testing.T) {
	const material = "AAAAC3NzaC1lZDI1NTE5AAAAIIqI4910CfGV"
	p := profile(t, []string{"test.sensitive"}, nil)
	fake := newFake("test.sensitive", func(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
		return trustfreeze.ProbeResult{
			Status: trustfreeze.StatusCaptured,
			NormalizedState: []trustfreeze.Artifact{{
				ID: "test/sensitive", Type: "test", Scope: "host", Source: "test.sensitive",
				State:      trustfreeze.StateDeclared,
				Attributes: map[string]string{"key_material": material, "key_type": "ssh-ed25519"},
				AttributeClasses: map[string]trustfreeze.AttributeClass{
					"key_material": trustfreeze.AttributeClassSensitive,
				},
				Provenance:  trustfreeze.Provenance{Method: "file", Confidence: trustfreeze.ConfidenceProven, ObservedAt: trustfreeze.FormatTime(testTime)},
				Sensitivity: trustfreeze.SensitivityInternal,
			}},
		}
	})
	res := mustRun(t, baseOptions(t, p, registry(t, fake), identityRunner()))
	b := verifyBundle(t, res)
	a := policyArtifact(t, b, "test/sensitive")
	policyWantAttr(t, a, "key_material", redact.Marker(redact.ClassDeclaredSensitive))
	policyWantAttr(t, a, "key_type", "ssh-ed25519")
	for path, f := range readTree(t, res.Dir) {
		if strings.Contains(string(f), material) {
			t.Fatalf("%s carries the key material", path)
		}
	}
}

// TestCaptureDropsAnArtifactWithAnInvalidAttributeClass: a class for an
// attribute that does not exist would exempt that name everywhere in the
// probe result, so the artifact is refused instead (fail-closed).
func TestCaptureDropsAnArtifactWithAnInvalidAttributeClass(t *testing.T) {
	p := profile(t, []string{"test.stale"}, nil)
	fake := newFake("test.stale", func(context.Context, probe.CollectContext) trustfreeze.ProbeResult {
		return trustfreeze.ProbeResult{
			Status: trustfreeze.StatusCaptured,
			NormalizedState: []trustfreeze.Artifact{{
				ID: "test/stale", Type: "test", Scope: "host", Source: "test.stale",
				State:      trustfreeze.StateDeclared,
				Attributes: map[string]string{"api_key": "opaque-S3CR3T-value-0123456789"},
				AttributeClasses: map[string]trustfreeze.AttributeClass{
					"apikey": trustfreeze.AttributeClassPolicy,
				},
				Provenance:  trustfreeze.Provenance{Method: "file", Confidence: trustfreeze.ConfidenceProven, ObservedAt: trustfreeze.FormatTime(testTime)},
				Sensitivity: trustfreeze.SensitivityInternal,
			}},
		}
	})
	res := mustRun(t, baseOptions(t, p, registry(t, fake), identityRunner()))
	r := resultFor(t, res, "test.stale")
	if r.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %s (%s), want partial", r.Status, r.Reason)
	}
	if len(r.NormalizedState) != 0 {
		t.Fatalf("the artifact was kept: %+v", r.NormalizedState)
	}
	if !hasWarn(r, probe.DiagArtifactDropped) {
		t.Fatalf("no artifact_dropped diagnostic: %+v", r.Warnings)
	}
}
