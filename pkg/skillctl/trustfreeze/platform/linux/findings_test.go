package linux

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// The tests in this file were written for the findings of the adversarial
// T-03 review (F1 to F18). Each one names the finding it covers and fails
// against the code as the review measured it. They run on any operating
// system: every command goes through the fake runner and every file through
// the fake file reader (SPEC-0467 R9).

// tfCap is the output limit the truncation tests run with. It is small enough
// to cut every listing below and large enough to leave whole records.
const tfCap = 2048

// tfLimitedCollect builds a collect context whose runner clamps the output to
// limits, exactly as the capture engine wires it (engine.go: one
// RecordingRunner per probe run, the same Limits in the context).
func tfLimitedCollect(probeID string, runner probe.CommandRunner, files probe.FileReader, limits probe.Limits) (probe.CollectContext, *probe.EvidenceBuffer) {
	ev := probe.NewEvidenceBuffer(probeID, limits)
	rec := probe.NewRecordingRunner(runner, limits, redact.Default())
	return probe.CollectContext{
		HostContext: probe.HostContext{
			GOOS: "linux", GOARCH: "amd64",
			Hostname:  func() (string, error) { return netTestHostname, nil },
			Files:     files,
			Runner:    rec,
			Clock:     trustfreeze.FixedClock{T: netTestTime},
			Privilege: probe.PrivilegeUser,
		},
		ProbeID:  probeID,
		Redactor: redact.Default(),
		Limits:   limits,
		Evidence: ev,
		Support:  probe.Supported(),
	}, ev
}

// tfWarning returns the first warning with code, or fails.
func tfWarning(t *testing.T, res trustfreeze.ProbeResult, code string) trustfreeze.Diagnostic {
	t.Helper()
	for _, w := range res.Warnings {
		if w.Code == code {
			return w
		}
	}
	t.Fatalf("no %s diagnostic in %+v", code, res.Warnings)
	return trustfreeze.Diagnostic{}
}

// tfTruncationDiagnostic asserts the shape every truncation diagnostic must
// have: it names the stream it lost and the cap that cut it.
func tfTruncationDiagnostic(t *testing.T, res trustfreeze.ProbeResult, stream string) {
	t.Helper()
	w := tfWarning(t, res, trustfreeze.DiagOutputTruncated)
	if !strings.Contains(w.Message, stream) {
		t.Fatalf("the truncation diagnostic does not name the stream %q: %q", stream, w.Message)
	}
	if !strings.Contains(w.Message, strconv.Itoa(tfCap)) {
		t.Fatalf("the truncation diagnostic does not name the cap %d: %q", tfCap, w.Message)
	}
}

// tfSSLines builds n listener rows of ss output, all of the same length, so
// the number of rows that survive a byte cap is computable.
func tfSSLines(n int) []byte {
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "tcp   LISTEN 0      4096       0.0.0.0:%05d      0.0.0.0:*    users:((\"svc-app\",pid=%06d,fd=6))\n", 10000+i, i+2)
	}
	return b.Bytes()
}

// F1 CRITICAL. A listing the output cap cut must never be reported as
// captured, and the diagnostic must name the stream and the cap.
func TestListenersProbeTruncatedListingIsPartial(t *testing.T) {
	runner := probe.NewFakeRunner().AddTool(ListenersTool, "/usr/bin/ss").
		Script(ListenersTool, []string{"-V"}, probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-version.txt")}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: tfSSLines(400)})
	cc, _ := tfLimitedCollect(ListenersProbeID, runner, probe.FakeFiles{}, probe.Limits{MaxStdoutBytes: tfCap})
	res := NewListenersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q over a cut listener list, want partial (reason %q)", res.Status, res.Reason)
	}
	if res.Reason == "" {
		t.Fatal("a partial result must say what is missing")
	}
	tfTruncationDiagnostic(t, res, "stdout")
	set := netArtifact(t, res, ArtifactListeners)
	if set.Attributes["listener_count"] == "400" {
		t.Fatal("the set artifact counted rows the cap removed")
	}
	if set.Attributes["listener_list_truncated"] != "true" {
		t.Fatalf("the set artifact claims a complete count over a cut list: %v", set.Attributes)
	}
}

// tfDockerPS builds n docker ps rows in the format the probe asks for (id,
// image, name, state, status, ports), all of the same length, and returns the
// rows together with the ids that survive a stdout cap of cap bytes.
func tfDockerPS(n, cap int) ([]byte, []string) {
	var (
		b    bytes.Buffer
		kept []string
	)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%012d%052d", i, i)
		row := fmt.Sprintf("%s\texample/app:1.0\tapp-%05d\trunning\tUp 2 hours\t\n", id, i)
		if cap > 0 && b.Len()+len(row) <= cap {
			kept = append(kept, id)
		}
		b.WriteString(row)
	}
	sort.Strings(kept)
	return b.Bytes(), kept
}

// F2 CRITICAL. The container listing has the same duty as the listener list.
func TestContainersProbeTruncatedListingIsPartial(t *testing.T) {
	spec := containerRuntimeSpecs()[0]
	ps, kept := tfDockerPS(400, tfCap)
	inspect := make([]string, 0, len(kept))
	for _, id := range kept {
		inspect = append(inspect, id+"\tunless-stopped\tfalse")
	}
	runner := probe.NewFakeRunner().AddTool(ContainerRuntimeDocker, "/usr/bin/docker").
		Script(ContainerRuntimeDocker, spec.versionArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-version.txt")}).
		Script(ContainerRuntimeDocker, spec.infoArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-info.txt")}).
		Script(ContainerRuntimeDocker, spec.psArgs, probe.FakeResponse{Stdout: ps}).
		Script(ContainerRuntimeDocker, append(append([]string{}, spec.inspectArgs...), kept...),
			probe.FakeResponse{Stdout: []byte(strings.Join(inspect, "\n") + "\n")})
	cc, _ := tfLimitedCollect(ContainersProbeID, runner, probe.FakeFiles{}, probe.Limits{MaxStdoutBytes: tfCap})
	res := NewContainersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q over a cut container list, want partial (reason %q)", res.Status, res.Reason)
	}
	tfTruncationDiagnostic(t, res, "stdout")
	rt := netArtifact(t, res, ArtifactContainerRuntimePrefix+"/"+ContainerRuntimeDocker)
	if rt.Attributes["container_list_truncated"] != "true" {
		t.Fatalf("the runtime artifact claims a complete count over a cut list: %v", rt.Attributes)
	}
}

// The same duty for the firewall probe: a cut ufw table must not read as the
// whole rule set.
func TestFirewallProbeTruncatedStatusIsPartial(t *testing.T) {
	var table bytes.Buffer
	table.WriteString("Status: active\n\nTo                         Action      From\n--                         ------      ----\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&table, "%05d                      ALLOW       Anywhere\n", 1000+i)
	}
	runner := probe.NewFakeRunner().
		AddTool(FirewallToolUfw, "/usr/sbin/ufw").
		Script(FirewallToolUfw, []string{"--version"}, probe.FakeResponse{Stdout: netFixture(t, "firewall/ufw-version.txt")}).
		Script(FirewallToolUfw, []string{"status"}, probe.FakeResponse{Stdout: table.Bytes()})
	cc, _ := tfLimitedCollect(FirewallProbeID, runner, probe.FakeFiles{}, probe.Limits{MaxStdoutBytes: tfCap})
	res := NewFirewallProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q over a cut ufw table, want partial (reason %q)", res.Status, res.Reason)
	}
	tfTruncationDiagnostic(t, res, "stdout")
}

// The same duty for linux.sudo: a cut drop-in listing hides rule files.
func TestSudoProbeTruncatedListingIsPartial(t *testing.T) {
	var listing bytes.Buffer
	listing.WriteString("total 16\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&listing, "-r--r----- 1 root root   29 Sep 23 06:15 rule-%05d\n", i)
	}
	r := probe.NewFakeRunner()
	r.Script("stat", []string{"--version"}, probe.FakeResponse{Stdout: []byte("stat (GNU coreutils) 9.4\n")})
	r.Script("ls", []string{"--version"}, probe.FakeResponse{Stdout: []byte("ls (GNU coreutils) 9.4\n")})
	r.Script("ls", []string{"-la", SudoersDir}, probe.FakeResponse{Stdout: listing.Bytes()})
	files := probe.FakeFiles{Files: map[string][]byte{SudoersPath: []byte("root ALL=(ALL:ALL) ALL\n")}}
	cc, _ := tfLimitedCollect(SudoProbeID, r, files, probe.Limits{MaxStdoutBytes: tfCap})
	res := NewSudoProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q over a cut drop-in listing, want partial (reason %q)", res.Status, res.Reason)
	}
	tfTruncationDiagnostic(t, res, "stdout")
}

// The same duty for linux.ssh: a cut account list hides accounts whose
// authorized_keys were never looked at.
func TestSSHProbeTruncatedAccountListIsPartial(t *testing.T) {
	var passwd bytes.Buffer
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&passwd, "user%04d:x:%d:%d::/home/user%04d:/bin/bash\n", i, 2000+i, 2000+i, i)
	}
	r := probe.NewFakeRunner()
	r.Script(sshdExe, []string{"-V"}, probe.FakeResponse{Stderr: privFixture(t, "ssh/sshd-version.stderr.txt")})
	r.Script("ls", []string{"--version"}, probe.FakeResponse{Stdout: []byte("ls (GNU coreutils) 9.4\n")})
	r.Script(getentExe, []string{"--version"}, probe.FakeResponse{Stdout: privFixture(t, "users/getent-version.txt")})
	r.Script("ls", []string{"-la", SSHDir}, probe.FakeResponse{Stdout: privFixture(t, "ssh/ls-la-etc-ssh.txt")})
	r.Script("ls", []string{"-la", SSHDConfigDir}, probe.FakeResponse{Stdout: privFixture(t, "ssh/ls-la-sshd-config-d.txt")})
	r.Script(sshdExe, []string{"-T"}, probe.FakeResponse{Stdout: []byte("port 22\nusepam yes\n")})
	r.Script(getentExe, []string{"passwd"}, probe.FakeResponse{Stdout: passwd.Bytes()})
	files := probe.FakeFiles{Files: map[string][]byte{SSHDConfigPath: privFixture(t, "ssh/sshd_config.txt")}}
	cc, _ := tfLimitedCollect(SSHProbeID, r, files, probe.Limits{MaxStdoutBytes: tfCap})
	res := NewSSHProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q over a cut account list, want partial (reason %q)", res.Status, res.Reason)
	}
	tfTruncationDiagnostic(t, res, "stdout")
}

// The same duty for linux.users: a cut id line would compare the session
// against a group set that was never fully read.
func TestUsersProbeTruncatedSessionIsPartial(t *testing.T) {
	var groups bytes.Buffer
	groups.WriteString("uid=1000(alice) gid=1000(alice) groups=1000(alice)")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&groups, ",%d(grp%05d)", 2000+i, i)
	}
	groups.WriteString("\n")
	r := probe.NewFakeRunner().AddTool(getentTool, "/usr/bin/getent").AddTool(idTool, "/usr/bin/id")
	invScript(t, r, "users/getent-passwd.txt")
	invScript(t, r, "users/getent-group.txt")
	invScript(t, r, "users/getent-version.txt")
	invScript(t, r, "users/id-version.txt")
	r.Script(idTool, nil, probe.FakeResponse{Stdout: groups.Bytes()})
	cc, _ := tfLimitedCollect(UsersProbeID, r, probe.FakeFiles{}, probe.Limits{MaxStdoutBytes: tfCap})
	res := NewUsersProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q over a cut id line, want partial (reason %q)", res.Status, res.Reason)
	}
	tfTruncationDiagnostic(t, res, "stdout")
}

// F3 HIGH. Membership in the docker group is a root path on this host: the
// socket is root-equivalent. It becomes a capability of its own, with its own
// privilege wording, and the attributes say why it grants root.
func TestResolveCapabilitiesDockerGroupGrantsRoot(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestGroup("984", "docker", "alice"),
		capTestUser("1000", "alice", "alice", "docker"),
	}
	caps, diags := ResolveCapabilities(arts)
	c := capByID(t, caps, "capability/execute/host/via/docker/user/alice")
	if c.Privilege != "root-via-container-runtime" {
		t.Fatalf("privilege %q, want its own root wording: %+v", c.Privilege, c)
	}
	if c.State != trustfreeze.StateInferred || c.Confidence != trustfreeze.ConfidenceReported {
		t.Fatalf("an inferred statement must not look proven: %+v", c)
	}
	if len(c.Sources) == 0 {
		t.Fatalf("a capability without a source: %+v", c)
	}
	// The reason is part of the document, not of a comment in the source.
	b, err := trustfreeze.MarshalCanonical(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{"attributes", "socket", "docker"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("the capability does not say why it grants root (%q missing): %s", want, b)
		}
	}
	if len(diags) == 0 {
		t.Fatal("a runtime mediated escalation must be reported, not stated silently")
	}
}

// F8 MEDIUM. Where the rule files were readable and none of them grants the
// group, the diagnostic must not claim that no readable rule file exists.
func TestResolveCapabilitiesGroupInferenceNamesTheEvidence(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestSudoFile("sudoers", true),
		capTestRule("sudoers/1", "root", false),
		capTestGroup("27", "sudo", "alice"),
	}
	_, diags := ResolveCapabilities(arts)
	d := trustfreeze.Diagnostic{}
	for _, x := range diags {
		if x.Code == capDiagInferredFromGroup {
			d = x
		}
	}
	if d.Code == "" {
		t.Fatalf("the inference was not reported: %+v", diags)
	}
	if strings.Contains(d.Message, "no readable rule file confirms it") {
		t.Fatalf("the diagnostic contradicts the evidence it was built from: %q", d.Message)
	}
	if !strings.Contains(d.Message, "read") {
		t.Fatalf("the diagnostic does not say what was read: %q", d.Message)
	}
}

// F9 MEDIUM. An upper case account name is a legal Linux account name. Where
// an artifact of that name exists, the rule is about that account, not about
// a sudoers alias.
func TestCapSubjectOfUpperCaseAccount(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestRule("sudoers/5", "DEPLOY", true),
		capTestUser("1001", "DEPLOY", "deploy", ""),
	}
	caps, _ := ResolveCapabilities(arts)
	c := capByID(t, caps, CapExecuteHostPrefix+"user/DEPLOY")
	if c.Privilege != CapPrivilegeRootViaSudoNoPassword {
		t.Fatalf("capability %+v", c)
	}
	for _, got := range caps {
		if strings.HasPrefix(got.SubjectID, CapSubjectAliasPrefix) {
			t.Fatalf("an existing account was reported as an alias: %+v", got)
		}
	}
}

// F7 MEDIUM. An equals sign inside a command is not a second host
// specification, and the rule must survive it.
func TestParseSudoRuleKeepsCommandWithEqualsSign(t *testing.T) {
	doc := ParseSudoers([]byte("alice ALL=(root) NOPASSWD: /usr/bin/systemctl restart x, /usr/bin/env FOO=bar\n"))
	if len(doc.Rules) != 1 {
		t.Fatalf("rules %+v issues %+v", doc.Rules, doc.Issues)
	}
	r := doc.Rules[0]
	if len(r.Commands) != 2 || r.Commands[1] != "/usr/bin/env FOO=bar" {
		t.Fatalf("commands %q", r.Commands)
	}
	if !r.HasTag(SudoTagNoPasswd) || !r.RunsAsRoot() {
		t.Fatalf("rule %+v", r)
	}
	// The shape the parser must still refuse: two host specifications.
	two := ParseSudoers([]byte("alice host-a = /bin/ls : host-b = /bin/cat\n"))
	if len(two.Rules) != 0 || len(two.Issues) != 1 {
		t.Fatalf("rules %+v issues %+v", two.Rules, two.Issues)
	}
}

// F13 LOW. A quoted value that carries commas is one setting, not three.
func TestParseSudoDefaultsKeepsQuotedCommas(t *testing.T) {
	doc := ParseSudoers([]byte("Defaults env_keep += \"LANG,LC_ALL,LC_TIME\"\n"))
	if len(doc.Defaults) != 1 {
		t.Fatalf("defaults %+v", doc.Defaults)
	}
	if doc.Defaults[0].Name != "env_keep" {
		t.Fatalf("default %+v", doc.Defaults[0])
	}
	// Two settings on one line are still two.
	two := ParseSudoers([]byte("Defaults env_reset, timestamp_timeout=5\n"))
	if len(two.Defaults) != 2 {
		t.Fatalf("defaults %+v", two.Defaults)
	}
}

// F12 LOW. The diagnostic counts accounts, not the attempts per account.
func TestSSHOutsideRootCountsAccounts(t *testing.T) {
	r := sshFixtureRunner(t)
	r.Script(getentExe, []string{"passwd"}, probe.FakeResponse{Stdout: []byte(
		"alice:x:1000:1000::/mnt/elsewhere/alice:/bin/bash\n" +
			"bob:x:1001:1001::/mnt/elsewhere/bob:/bin/bash\n")})
	files := probe.FakeFiles{
		Files: map[string][]byte{SSHDConfigPath: privFixture(t, "ssh/sshd_config.txt")},
		Errs: map[string]error{
			"/mnt/elsewhere/alice/.ssh/authorized_keys":  probe.ErrOutsideRoots,
			"/mnt/elsewhere/alice/.ssh/authorized_keys2": probe.ErrOutsideRoots,
			"/mnt/elsewhere/bob/.ssh/authorized_keys":    probe.ErrOutsideRoots,
			"/mnt/elsewhere/bob/.ssh/authorized_keys2":   probe.ErrOutsideRoots,
		},
	}
	res, _ := privRunProbe(t, NewSSHProbe(), r, files)
	for _, w := range res.Warnings {
		if w.Code == probe.DiagFieldNotApplicable && strings.Contains(w.Message, "home outside") {
			if !strings.Contains(w.Message, "2 accounts") {
				t.Fatalf("the diagnostic counts attempts, not accounts: %q", w.Message)
			}
			return
		}
	}
	t.Fatalf("no diagnostic about the homes outside the roots: %+v", res.Warnings)
}

// F18 LOW. One missing tool must not turn a probe that read everything else
// into unavailable: playbook L1 reserves unavailable for a missing source
// that leaves nothing behind.
func TestPrivStatusUnavailableNeedsAnEmptyResult(t *testing.T) {
	st, reason, perr := privStatus([]privState{privOK, privUnavailable}, "the ssh server state")
	if st != trustfreeze.StatusPartial {
		t.Fatalf("status %q with one read and one missing source, want partial (reason %q)", st, reason)
	}
	if perr != nil {
		t.Fatalf("a partial result carries no error class: %+v", perr)
	}
	if st, _, _ := privStatus([]privState{privUnavailable}, "x"); st != trustfreeze.StatusUnavailable {
		t.Fatalf("status %q with nothing read, want unavailable", st)
	}
}

// The sudo probe reads a file that stat saw and the read then refused: that
// is a gap in one input, not a missing tool (F18, second half).
func TestSudoProbeMissingFileAfterStatIsPartial(t *testing.T) {
	r := sudoFixtureRunner(t)
	files := probe.FakeFiles{
		Files: map[string][]byte{SudoersDir + "/alice-nopasswd": []byte("alice ALL=(ALL) NOPASSWD: ALL\n")},
		Errs:  map[string]error{SudoersPath: fs.ErrNotExist},
	}
	res, _ := privRunProbe(t, NewSudoProbe(), r, files)
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial (reason %q)", res.Status, res.Reason)
	}
	privArtifact(t, res, SudoRulePrefix+"sudoers.d/alice-nopasswd/1")
}

// F15 LOW. The listener artifacts are bounded like every other family of this
// package, and the cut is a diagnostic, not a silent short list.
func TestListenersProbeCapsTheArtifactCount(t *testing.T) {
	runner := probe.NewFakeRunner().AddTool(ListenersTool, "/usr/bin/ss").
		Script(ListenersTool, []string{"-V"}, probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-version.txt")}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: tfSSLines(listenersMaxRecords + 10)})
	cc, _ := netTestCollect(ListenersProbeID, runner)
	res := NewListenersProbe().Collect(context.Background(), cc)

	if len(res.NormalizedState) > listenersMaxRecords+1 {
		t.Fatalf("%d artifacts, want at most %d listeners plus the set", len(res.NormalizedState), listenersMaxRecords)
	}
	if !netHasWarning(res, netDiagVolumeCapped, "listener") {
		t.Fatalf("the dropped listeners were not reported: %+v", res.Warnings)
	}
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q, want partial after a volume cap", res.Status)
	}
	if netArtifact(t, res, ArtifactListeners).Attributes["listener_list_truncated"] != "true" {
		t.Fatal("the set artifact does not say that the list was cut")
	}
}

// F16 LOW. A process name comes from the host and is bounded like every other
// attribute value of this package.
func TestListenersProcessNameIsBounded(t *testing.T) {
	long := strings.Repeat("a", 100000)
	line := "tcp   LISTEN 0      4096       0.0.0.0:22      0.0.0.0:*    users:((\"" + long + "\",pid=1,fd=3))\n"
	runner := probe.NewFakeRunner().AddTool(ListenersTool, "/usr/bin/ss").
		Script(ListenersTool, []string{"-V"}, probe.FakeResponse{Stdout: netFixture(t, "network.listeners/ss-version.txt")}).
		Script(ListenersTool, []string{"-H", "-lntup"}, probe.FakeResponse{Stdout: []byte(line)})
	cc, _ := netTestCollect(ListenersProbeID, runner)
	res := NewListenersProbe().Collect(context.Background(), cc)

	a := netArtifact(t, res, ListenerArtifactID("tcp", "0.0.0.0", "", "22"))
	if got := len(a.Attributes["process_name"]); got > listenersMaxValueBytes {
		t.Fatalf("process_name is %d bytes, want at most %d", got, listenersMaxValueBytes)
	}
}

// F2, F15. The inspect call is batched like systemctl show, and the container
// artifacts are bounded, so a host with thousands of containers produces a
// bounded result instead of one argument per container.
func TestContainersInspectIsBatched(t *testing.T) {
	spec := containerRuntimeSpecs()[0]
	ps, _ := tfDockerPS(containersMaxRecords+10, 0)
	runner := probe.NewFakeRunner().AddTool(ContainerRuntimeDocker, "/usr/bin/docker").
		Script(ContainerRuntimeDocker, spec.versionArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-version.txt")}).
		Script(ContainerRuntimeDocker, spec.infoArgs, probe.FakeResponse{Stdout: netFixture(t, "containers/docker-info.txt")}).
		Script(ContainerRuntimeDocker, spec.psArgs, probe.FakeResponse{Stdout: ps})
	cc, _ := netTestCollect(ContainersProbeID, runner)
	res := NewContainersProbe().Collect(context.Background(), cc)

	if len(res.NormalizedState) > containersMaxRecords+1 {
		t.Fatalf("%d artifacts, want at most %d containers plus the runtime", len(res.NormalizedState), containersMaxRecords)
	}
	for _, call := range runner.Calls() {
		if len(call.Args) > containersMaxInspectBatch+len(spec.inspectArgs) {
			t.Fatalf("an inspect call carried %d arguments; the batch size is %d", len(call.Args), containersMaxInspectBatch)
		}
	}
	if !netHasWarning(res, netDiagVolumeCapped, "container") {
		t.Fatalf("the dropped containers were not reported: %+v", res.Warnings)
	}
}

// F4 HIGH. A source that decides privileges and could not be read is a gap,
// and the gap belongs in the capabilities document even when no capability
// came out of it: an empty list must never read as "this host grants nothing".
func TestResolveCapabilitiesUnreadableSudoFilesAreAGap(t *testing.T) {
	arts := []trustfreeze.Artifact{
		capTestSudoFile("sudoers", false),
		capTestSudoFile("sudoers.d", true),
		capTestGroup("27", "sudo"),
		capTestUser("1000", "alice", "alice", ""),
	}
	caps, diags := ResolveCapabilities(arts)
	if len(caps) != 0 {
		t.Fatalf("capabilities %+v", caps)
	}
	d := capDiag(t, diags, capDiagSourceUnreadable)
	if !strings.Contains(d.Message, SudoFilePrefix+"sudoers") {
		t.Fatalf("the diagnostic does not name the unreadable file: %q", d.Message)
	}
}

// F4 HIGH, the other source: an authorized_keys file that exists and was
// refused is the same kind of gap.
func TestResolveCapabilitiesUnreadableKeyFileIsAGap(t *testing.T) {
	gap := capTestArtifact(ArtifactSSHAuthorizedKeysPrefix+"deploy", SSHAuthorizedKeysType, map[string]string{
		privAttrAccount:  "deploy",
		privAttrReadable: "false",
	})
	_, diags := ResolveCapabilities([]trustfreeze.Artifact{gap})
	d := capDiag(t, diags, capDiagSourceUnreadable)
	if !strings.Contains(d.Message, "deploy") {
		t.Fatalf("the diagnostic does not name the file: %q", d.Message)
	}
}

// F10 MEDIUM. A rule that grants a group whose membership nobody collected
// must say so; otherwise "the group is empty" and "nobody asked" read alike.
func TestResolveCapabilitiesGroupWithoutMembershipIsAGap(t *testing.T) {
	caps, diags := ResolveCapabilities([]trustfreeze.Artifact{capTestRule("sudoers/4", "%sudo", true)})
	capByID(t, caps, CapExecuteHostPrefix+"group/sudo")
	capDiag(t, diags, capDiagMembershipUnknown)

	// With the membership collected the gap is gone.
	_, withGroup := ResolveCapabilities([]trustfreeze.Artifact{
		capTestRule("sudoers/4", "%sudo", true),
		capTestGroup("27", "sudo", "alice"),
	})
	if capHasDiag(withGroup, capDiagMembershipUnknown) {
		t.Fatalf("a collected membership must not be reported as unknown: %+v", withGroup)
	}
}

// F5 HIGH. A rule whose command list names a Cmnd_Alias that expands to ALL
// grants unrestricted root, and the artifact and the capability must say so.
func TestSudoRuleWithCommandAliasGrantsRoot(t *testing.T) {
	file := "User_Alias ADMINS = alice, bob\n" +
		"Cmnd_Alias MAINT = ALL\n" +
		"ADMINS ALL=(ALL) NOPASSWD: MAINT\n" +
		"%ops ALL=(ALL:ALL) NOPASSWD: MAINT\n"
	doc := ParseSudoers([]byte(file))
	if len(doc.Rules) != 2 {
		t.Fatalf("rules %+v issues %+v", doc.Rules, doc.Issues)
	}
	for _, r := range doc.Rules {
		if !doc.RuleGrantsAllCommands(r) {
			t.Fatalf("the rule in line %d grants every command through MAINT: %+v", r.Line, r)
		}
	}
	files := probe.FakeFiles{Files: map[string][]byte{SudoersPath: []byte(file)}}
	res, _ := privRunProbe(t, NewSudoProbe(), sudoFixtureRunner(t), files)
	rule := privArtifact(t, res, SudoRulePrefix+"sudoers/3")
	privWantAttr(t, rule, sudoAttrAllCommands, "true")
	privWantAttr(t, rule, sudoAttrUsers, "alice,bob")
	privWantAttr(t, rule, sudoAttrResolvedAliases, "ADMINS,MAINT")

	caps, _ := ResolveCapabilities(res.NormalizedState)
	for _, want := range []string{"user/alice", "user/bob", "group/ops"} {
		c := capByID(t, caps, CapExecuteHostPrefix+want)
		if c.Privilege != CapPrivilegeRootViaSudoNoPassword {
			t.Fatalf("%s: privilege %q", want, c.Privilege)
		}
	}
}

// F5 HIGH, the other half: a command alias this capture never saw defined is
// a gap the artifact carries, never a rule that quietly grants nothing.
func TestSudoRuleWithUnknownCommandAliasIsAGap(t *testing.T) {
	files := probe.FakeFiles{Files: map[string][]byte{SudoersPath: []byte("alice ALL=(ALL) NOPASSWD: MAINT\n")}}
	res, _ := privRunProbe(t, NewSudoProbe(), sudoFixtureRunner(t), files)
	rule := privArtifact(t, res, SudoRulePrefix+"sudoers/1")
	privWantAttr(t, rule, sudoAttrUnresolvedAliases, "MAINT")
	if !privWarned(res, privDiagAliasUnresolved) {
		t.Fatalf("the unresolved command alias was not reported: %+v", res.Warnings)
	}
}

// tfPasswd is a getent passwd answer with an automation account below uid
// 1000 that has a home and a login shell, which is what "adduser --system"
// leaves behind on a bastion. The account is called bob because the gate
// scripts/check-no-real-names.sh keeps home paths inside the standard cast.
const tfPasswd = "root:x:0:0:root:/root:/bin/bash\n" +
	"bob:x:997:997::/home/bob:/bin/bash\n" +
	"backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n" +
	"alice:x:1000:1000:Alice Example:/home/alice:/bin/bash\n"

// F6 HIGH. An automation account below uid 1000 with a real home and a login
// shell holds exactly the access a bastion freeze is about, and the accounts
// that are skipped are counted instead of dropped in silence.
func TestSSHCollectsSystemAccountWithLoginShell(t *testing.T) {
	r := sshFixtureRunner(t)
	r.Script(getentExe, []string{"passwd"}, probe.FakeResponse{Stdout: []byte(tfPasswd)})
	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEYDATAFORTESTSONLYxxxxxxxxxxxxx bob@host-a.example\n")
	files := probe.FakeFiles{Files: map[string][]byte{
		SSHDConfigPath:                     privFixture(t, "ssh/sshd_config.txt"),
		"/home/bob/.ssh/authorized_keys":   key,
		"/home/alice/.ssh/authorized_keys": key,
		"/root/.ssh/authorized_keys":       key,
	}}
	res, _ := privRunProbe(t, NewSSHProbe(), r, files)
	privArtifact(t, res, ArtifactSSHAuthorizedKeysPrefix+"bob")
	if privHasArtifact(res, ArtifactSSHAuthorizedKeysPrefix+"backup") {
		t.Fatal("an account whose shell cannot start a session was looked at")
	}
	if !privWarned(res, sshDiagAccountsSkipped) {
		t.Fatalf("the skipped accounts were not counted: %+v", res.Warnings)
	}
}

// F14 LOW. commands.json records the argv a fixture was taken with; where the
// probe issues another argv, the index names it, so the two cannot drift
// apart unnoticed.
func TestFixtureIndexNamesTheProbeArgv(t *testing.T) {
	for _, tc := range []struct {
		path string
		want []string
	}{
		{"mounts/findmnt-json.json", []string{"findmnt", "--json", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"}},
		{"ssh/sshd-T-unprivileged.stderr.txt", []string{"sshd", "-T"}},
		{"ssh/sshd-version.stderr.txt", []string{"sshd", "-V"}},
	} {
		got := invEntry(t, tc.path).ProbeCommand
		if strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
			t.Fatalf("%s: probe_command %q, want %q", tc.path, got, tc.want)
		}
	}
}

// capDiag returns the first diagnostic with code, or fails.
func capDiag(t *testing.T, diags []trustfreeze.Diagnostic, code string) trustfreeze.Diagnostic {
	t.Helper()
	for _, d := range diags {
		if d.Code == code {
			return d
		}
	}
	t.Fatalf("no %s diagnostic in %+v", code, diags)
	return trustfreeze.Diagnostic{}
}
