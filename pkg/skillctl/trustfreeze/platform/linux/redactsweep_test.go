package linux

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// The sweep over the whole probe family for the over-redaction measured on
// an Ubuntu bastion: an attribute whose KEY sounds like a credential lost
// its value, although the value was the answer a security review needs.
//
// Every probe of this package runs against the fixtures its own tests use,
// and every artifact attribute then goes through the redaction pass of the
// capture engine: redact.RedactValue over the attribute map, with the key
// classes the probe declared. An attribute that comes back as a marker is
// reported by name. The test keeps the list empty, so a new attribute whose
// key trips the secret vocabulary is a decision somebody makes, not a value
// that quietly disappears from the next bastion capture.

// sweepRun is one probe with the inputs of its own fixture tests.
type sweepRun struct {
	name   string
	probe  probe.Probe
	runner probe.CommandRunner
	files  probe.FileReader
}

// sweepSudoers is a readable rule set: the trial host refused the file, and
// a sweep over attributes that are never built proves nothing.
const sweepSudoers = "Defaults\tenv_reset\n" +
	"root\tALL=(ALL:ALL) ALL\n" +
	"%sudo\tALL=(ALL:ALL) ALL\n" +
	"@includedir /etc/sudoers.d\n"

func sweepRuns(t *testing.T) []sweepRun {
	t.Helper()

	sshRunner := sshFixtureRunner(t)
	sshRunner.Script(sshdExe, []string{"-T"}, probe.FakeResponse{Stdout: []byte(
		"port 22\npasswordauthentication yes\npermitemptypasswords no\n" +
			"permitrootlogin prohibit-password\nusepam yes\nlogingracetime 120\n")})
	sshFiles := probe.FakeFiles{Files: map[string][]byte{
		SSHDConfigPath: privFixture(t, "ssh/sshd_config.txt"),
	}}

	sudoFiles := probe.FakeFiles{Files: map[string][]byte{
		SudoersPath:                    []byte(sweepSudoers),
		SudoersDir + "/README":         []byte("# just a readme\n"),
		SudoersDir + "/alice-nopasswd": []byte("alice ALL=(ALL) NOPASSWD: ALL\n"),
	}}

	systemdRunner := systemdRunnerWithVersion(t)
	systemdRunner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
		probe.FakeResponse{Stdout: systemdFixture(t, "systemd/systemctl-list-unit-files.txt")})
	showArgs := append([]string{"show", "--no-pager", "-p", systemdShowProperties}, systemdSelectedUnits...)
	systemdRunner.Script(systemctlExe, showArgs, probe.FakeResponse{ExitCode: 1, Stderr: []byte("")})
	for _, u := range systemdSelectedUnits {
		systemdRunner.Script(systemctlExe, []string{"show", "--no-pager", "-p", systemdShowProperties, u},
			probe.FakeResponse{ExitCode: 1, Stderr: []byte("")})
	}

	mountsRunner := mountsRunnerWithVersion(t)
	mountsRunner.Script(findmntExe, mountsTableArgs,
		probe.FakeResponse{Stdout: systemdFixture(t, "mounts/findmnt-json.json")})

	// linux.executables hashes files, so its sweep needs a tree on disk. The
	// tree is the bastion case of executables_test.go: one program a unit
	// starts, which also holds a listening socket, and no package owns it.
	const sweepNgrok = "/usr/local/bin/ngrok"
	execReader, _ := execTestTree(t, map[string]execTestFile{
		sweepNgrok:       {Size: 32911522},
		"/proc/2698/exe": {Link: sweepNgrok},
	})
	execSweepRunner := execRunner(t).
		Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: execFixture(t, "systemctl-list-unit-files-subset-2204.txt")}).
		Script(systemctlExe, execShowArgs("ngrok-host-a.service", "ssh.socket"),
			probe.FakeResponse{Stdout: execFixture(t, "systemctl-show-execstart-2204.txt")}).
		Script(ListenersTool, []string{"-H", "-lntup"},
			probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-H-lntup.txt")}).
		Script(ExecutablesToolStat, execStatArgs(sweepNgrok),
			probe.FakeResponse{Stdout: []byte("/usr/local/bin/ngrok 755 root root 32911522\n")}).
		Script(ExecutablesToolDpkg, execDpkgArgs(sweepNgrok), probe.FakeResponse{
			ExitCode: 1,
			Stderr:   execFixture(t, "dpkg-search-2204.stderr.txt"),
		})

	return []sweepRun{
		{PackagesProbeID, NewPackagesProbe(), invPackagesRunner(t), probe.FakeFiles{}},
		{UsersProbeID, NewUsersProbe(), invUsersRunner(t), probe.FakeFiles{}},
		{SudoProbeID, NewSudoProbe(), sudoFixtureRunner(t), sudoFiles},
		{SSHProbeID, NewSSHProbe(), sshRunner, sshFiles},
		{SystemdProbeID, NewSystemdProbe(), systemdRunner, probe.FakeFiles{}},
		{MountsProbeID, NewMountsProbe(), mountsRunner, probe.FakeFiles{}},
		{ListenersProbeID, NewListenersProbe(), netListenersRunner(t), probe.FakeFiles{}},
		{RoutesProbeID, NewRoutesProbe(), routesRunner(t, ""), probe.FakeFiles{}},
		{DNSProbeID, NewDNSProbe(), dnsRunner(t, ""), dnsFiles(t)},
		{FirewallProbeID, NewFirewallProbe(), netFirewallRunner(t), probe.FakeFiles{}},
		{ContainersProbeID, NewContainersProbe(), netDockerRunner(t), probe.FakeFiles{}},
		{ExecutablesProbeID, NewExecutablesProbeWithReader(execReader), execSweepRunner, probe.FakeFiles{}},
	}
}

// TestSweepCoversEveryProbeOfThisPackage: the sweep is only a guard while it
// runs over every probe. A probe added to the registry without a sweep entry
// fails here instead of quietly losing an attribute in the next capture.
func TestSweepCoversEveryProbeOfThisPackage(t *testing.T) {
	swept := map[string]bool{}
	for _, run := range sweepRuns(t) {
		swept[run.name] = true
	}
	for _, p := range Probes() {
		if id := p.Descriptor().ID; !swept[id] {
			t.Errorf("probe %s is registered but not in the redaction sweep", id)
		}
	}
}

// sweepDeclaredKeys mirrors what the capture engine does with the classes a
// probe declared: they hold for the whole probe result.
func sweepDeclaredKeys(res trustfreeze.ProbeResult) (policy, sensitive []string) {
	seenPolicy, seenSensitive := map[string]bool{}, map[string]bool{}
	for _, a := range res.NormalizedState {
		for _, k := range a.AttributeKeysByClass(trustfreeze.AttributeClassPolicy) {
			seenPolicy[k] = true
		}
		for _, k := range a.AttributeKeysByClass(trustfreeze.AttributeClassSensitive) {
			seenSensitive[k] = true
		}
	}
	for k := range seenPolicy {
		if !seenSensitive[k] {
			policy = append(policy, k)
		}
	}
	for k := range seenSensitive {
		sensitive = append(sensitive, k)
	}
	sort.Strings(policy)
	sort.Strings(sensitive)
	return policy, sensitive
}

// TestNoArtifactAttributeIsLostToItsKeyName runs the sweep. It fails with the
// probe, the artifact and the attribute name, so that the report of a
// failure is the list of what would be missing from the next capture.
func TestNoArtifactAttributeIsLostToItsKeyName(t *testing.T) {
	var lost []string
	for _, run := range sweepRuns(t) {
		res, _ := privRunProbe(t, run.probe, run.runner, run.files)
		if len(res.NormalizedState) == 0 {
			t.Fatalf("%s produced no artifact, so it sweeps nothing (status %s: %s)", run.name, res.Status, res.Reason)
		}
		policy, sensitive := sweepDeclaredKeys(res)
		vc := redact.ValueContext{ProbeID: run.name, PolicyKeys: policy, SensitiveKeys: sensitive}
		for _, a := range res.NormalizedState {
			if len(a.Attributes) == 0 {
				continue
			}
			out, _, err := redact.Default().RedactValue(context.Background(), vc, a.Attributes)
			if err != nil {
				t.Fatalf("%s %s: RedactValue: %v", run.name, a.ID, err)
			}
			clean, ok := out.(map[string]string)
			if !ok {
				t.Fatalf("%s %s: result type %T", run.name, a.ID, out)
			}
			for _, k := range sortedNames(a.Attributes) {
				if clean[k] != a.Attributes[k] {
					lost = append(lost, run.name+" "+a.ID+" "+k+"="+a.Attributes[k]+" became "+clean[k])
				}
			}
		}
	}
	if len(lost) > 0 {
		t.Fatalf("%d attribute(s) lost to the key name rule:\n%s", len(lost), strings.Join(lost, "\n"))
	}
}

// TestTheSweepWouldSeeAnOverRedaction plants what the sweep hunts: an
// attribute whose key trips the secret vocabulary and whose value is a
// policy answer the probe did not declare. A search that finds nothing
// proves nothing until it has been shown to find a planted occurrence.
func TestTheSweepWouldSeeAnOverRedaction(t *testing.T) {
	attrs := map[string]string{"passwordauthentication": "yes-if-pam-says-so"}
	out, _, err := redact.Default().RedactValue(context.Background(), redact.ValueContext{}, attrs)
	if err != nil {
		t.Fatalf("RedactValue: %v", err)
	}
	if got := out.(map[string]string)["passwordauthentication"]; got != redact.Marker("password") {
		t.Fatalf("the planted value came back as %q, so the sweep measures nothing", got)
	}
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
