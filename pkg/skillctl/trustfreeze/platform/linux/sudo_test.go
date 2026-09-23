package linux

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// The privilege probes are tested against the sanitized fixtures of
// testdata/, which were transcribed from an Ubuntu 24.04.1 host, and against
// synthetic inputs for the shapes that host could not produce (a readable
// sudoers file, an observable sshd -T, an authorized_keys file). Every test
// runs on any OS: no file of the running host is read, no command is executed
// (SPEC-0467 R9).

var privTestTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// privFixture reads one fixture file of testdata/.
func privFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return b
}

// privContext builds a CollectContext with the injected fakes.
func privContext(probeID string, runner probe.CommandRunner, files probe.FileReader) (probe.CollectContext, *probe.EvidenceBuffer) {
	ev := probe.NewEvidenceBuffer(probeID, probe.Limits{})
	return probe.CollectContext{
		HostContext: probe.HostContext{
			GOOS: "linux", GOARCH: "amd64",
			Hostname:  func() (string, error) { return "host-a.example", nil },
			Files:     files,
			Runner:    runner,
			Clock:     trustfreeze.FixedClock{T: privTestTime},
			Privilege: probe.PrivilegeUser,
		},
		ProbeID:  probeID,
		Redactor: redact.Default(),
		Evidence: ev,
		Support:  probe.Supported(),
	}, ev
}

// privRunProbe runs Support and Collect the way the capture engine does.
func privRunProbe(t *testing.T, p probe.Probe, runner probe.CommandRunner, files probe.FileReader) (trustfreeze.ProbeResult, []probe.EvidenceItem) {
	t.Helper()
	cc, ev := privContext(p.Descriptor().ID, runner, files)
	if err := p.Descriptor().Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	sup := p.Support(context.Background(), cc.HostContext)
	if err := sup.Validate(); err != nil {
		t.Fatalf("support: %v", err)
	}
	cc.Support = sup
	res := p.Collect(context.Background(), cc)
	if !res.Status.Valid() {
		t.Fatalf("invalid status %q", res.Status)
	}
	return res, ev.Close()
}

func privArtifact(t *testing.T, res trustfreeze.ProbeResult, id string) trustfreeze.Artifact {
	t.Helper()
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no artifact %q in %s", id, privArtifactIDs(res))
	return trustfreeze.Artifact{}
}

func privArtifactIDs(res trustfreeze.ProbeResult) []string {
	out := make([]string, 0, len(res.NormalizedState))
	for _, a := range res.NormalizedState {
		out = append(out, a.ID)
	}
	return out
}

func privHasArtifact(res trustfreeze.ProbeResult, id string) bool {
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return true
		}
	}
	return false
}

func privWarned(res trustfreeze.ProbeResult, code string) bool {
	for _, w := range res.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

func privWantAttr(t *testing.T, a trustfreeze.Artifact, name, want string) {
	t.Helper()
	if got := a.Attributes[name]; got != want {
		t.Fatalf("artifact %s attribute %s = %q, want %q", a.ID, name, got, want)
	}
}

func privEvidenceNames(items []probe.EvidenceItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Name)
	}
	return out
}

// sudoFixtureRunner scripts the two commands linux.sudo runs on the trial
// host, with the recorded argv of testdata/commands.json.
func sudoFixtureRunner(t *testing.T) *probe.FakeRunner {
	t.Helper()
	r := probe.NewFakeRunner()
	r.Script("stat", []string{"--version"}, probe.FakeResponse{Stdout: []byte("stat (GNU coreutils) 9.4\n")})
	r.Script("ls", []string{"--version"}, probe.FakeResponse{Stdout: []byte("ls (GNU coreutils) 9.4\n")})
	r.Script("ls", []string{"-la", SudoersDir}, probe.FakeResponse{Stdout: privFixture(t, "sudo/ls-la-etc-sudoers-d.txt")})
	r.Script("stat", []string{"-c", "%n %a %U %G %s", SudoersPath, SudoersDir, SudoersDir + "/README", SudoersDir + "/alice-nopasswd"},
		probe.FakeResponse{Stdout: privFixture(t, "sudo/stat-sudoers.txt")})
	return r
}

// TestParseLsLongFixture reads the recorded drop-in listing.
func TestParseLsLongFixture(t *testing.T) {
	entries, diags := ParseLsLong(privFixture(t, "sudo/ls-la-etc-sudoers-d.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics %+v", diags)
	}
	if len(entries) != 2 {
		t.Fatalf("entries %+v, want README and alice-nopasswd", entries)
	}
	if entries[0].Name != "README" || entries[1].Name != "alice-nopasswd" {
		t.Fatalf("names %q and %q", entries[0].Name, entries[1].Name)
	}
	if entries[1].Mode != "-r--r-----" || entries[1].Owner != "root" || entries[1].Group != "root" || entries[1].Size != "29" {
		t.Fatalf("entry %+v", entries[1])
	}
	info, ok := entries[1].statInfo()
	if !ok || info.Mode != "0440" {
		t.Fatalf("stat info %+v ok=%v", info, ok)
	}
}

// TestParseLsLongShapes covers the shapes a listing can carry.
func TestParseLsLongShapes(t *testing.T) {
	in := "total 12\n" +
		"drwxr-xr-x   2 root root    42 Sep 23 06:15 .\n" +
		"drwxr-xr-x 148 root root 12288 Sep 23 08:58 ..\n" +
		"-rw-r--r--   1 root root  3257 May  5  2025 sshd_config\n" +
		"lrwxrwxrwx   1 root root     7 Jan  1  2024 link -> target\n" +
		"crw-rw-rw-   1 root root  1, 3 Jan  1  2024 null\n" +
		"-rw-r--r--   1 root root    10 Jan  1  2024 a name with blanks\n" +
		"broken line\n"
	entries, diags := ParseLsLong([]byte(in))
	if len(diags) != 1 || diags[0].Code != privDiagRecordUnparsed {
		t.Fatalf("diagnostics %+v, want one unparsed record", diags)
	}
	got := map[string]LsEntry{}
	for _, e := range entries {
		got[e.Name] = e
	}
	if len(got) != 4 {
		t.Fatalf("entries %+v", entries)
	}
	if e := got["link"]; !e.IsSymlink || e.LinkTarget != "target" {
		t.Fatalf("symlink %+v", e)
	}
	if e := got["null"]; e.Size != "" {
		t.Fatalf("device node kept a size: %+v", e)
	}
	if _, ok := got["a name with blanks"]; !ok {
		t.Fatalf("a name with blanks was lost: %+v", entries)
	}
	if _, ok := got["."]; ok {
		t.Fatalf("the directory itself was kept")
	}
}

func TestParseSymbolicMode(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"-r--r-----", "0440", true},
		{"drwxr-xr-x", "0755", true},
		{"-rw-------", "0600", true},
		{"drwxr-xr-x.", "0755", true},
		{"-rw-rw-r--+", "0664", true},
		{"-rwsr-xr-x", "4755", true},
		{"drwxrwsr-x", "2775", true},
		{"drwxrwxrwt", "1777", true},
		{"-rwSr--r--", "4644", true},
		{"nonsense", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := ParseSymbolicMode(c.in)
		if got != c.want || ok != c.ok {
			t.Fatalf("ParseSymbolicMode(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestParseStatFixture reads the recorded stat output.
func TestParseStatFixture(t *testing.T) {
	info, diags := ParseStat(privFixture(t, "sudo/stat-sudoers.txt"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics %+v", diags)
	}
	if len(info) != 4 {
		t.Fatalf("entries %+v", info)
	}
	main := info[SudoersPath]
	if main.Mode != "0440" || main.Owner != "root" || main.Group != "root" || main.Size != "1800" {
		t.Fatalf("/etc/sudoers %+v", main)
	}
	if got := info[SudoersDir+"/alice-nopasswd"]; got.Size != "29" {
		t.Fatalf("drop-in %+v", got)
	}
}

func TestParseStatKeepsPathsWithBlanks(t *testing.T) {
	info, diags := ParseStat([]byte("/etc/sudoers.d/two words 440 root root 12\nshort line\n"))
	if len(diags) != 1 {
		t.Fatalf("diagnostics %+v", diags)
	}
	if _, ok := info["/etc/sudoers.d/two words"]; !ok {
		t.Fatalf("path with blanks lost: %+v", info)
	}
}

// TestParseSudoersRules covers the rule shapes a sudoers file carries.
func TestParseSudoersRules(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		users       []string
		hosts       []string
		runAsUsers  []string
		runAsGroups []string
		tags        []string
		commands    []string
		allCommands bool
		runsAsRoot  bool
		noPasswd    bool
	}{
		{
			name: "root all", in: "root\tALL=(ALL:ALL) ALL",
			users: []string{"root"}, hosts: []string{"ALL"},
			runAsUsers: []string{"ALL"}, runAsGroups: []string{"ALL"},
			commands: []string{"ALL"}, allCommands: true, runsAsRoot: true,
		},
		{
			name: "group with password", in: "%sudo   ALL=(ALL:ALL) ALL",
			users: []string{"%sudo"}, hosts: []string{"ALL"},
			runAsUsers: []string{"ALL"}, runAsGroups: []string{"ALL"},
			commands: []string{"ALL"}, allCommands: true, runsAsRoot: true,
		},
		{
			name: "nopasswd all", in: "alice ALL=(ALL) NOPASSWD: ALL",
			users: []string{"alice"}, hosts: []string{"ALL"}, runAsUsers: []string{"ALL"},
			tags: []string{"NOPASSWD"}, commands: []string{"ALL"},
			allCommands: true, runsAsRoot: true, noPasswd: true,
		},
		{
			name: "two tags and two commands", in: "deploy ALL=(root) NOPASSWD:SETENV: /usr/bin/systemctl restart app, /usr/bin/journalctl",
			users: []string{"deploy"}, hosts: []string{"ALL"}, runAsUsers: []string{"root"},
			tags:       []string{"NOPASSWD", "SETENV"},
			commands:   []string{"/usr/bin/systemctl restart app", "/usr/bin/journalctl"},
			runsAsRoot: true, noPasswd: true,
		},
		{
			name: "no runas means root", in: "deploy ALL=/usr/bin/id",
			users: []string{"deploy"}, hosts: []string{"ALL"},
			commands: []string{"/usr/bin/id"}, runsAsRoot: true,
		},
		{
			name: "runas other user is not root", in: "deploy ALL=(www-data) ALL",
			users: []string{"deploy"}, hosts: []string{"ALL"}, runAsUsers: []string{"www-data"},
			commands: []string{"ALL"}, allCommands: true,
		},
		{
			name: "two users one rule", in: "alice, deploy host-a.example=(ALL) ALL",
			users: []string{"alice", "deploy"}, hosts: []string{"host-a.example"},
			runAsUsers: []string{"ALL"}, commands: []string{"ALL"},
			allCommands: true, runsAsRoot: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := ParseSudoers([]byte(c.in + "\n"))
			if len(doc.Issues) != 0 {
				t.Fatalf("issues %+v", doc.Issues)
			}
			if len(doc.Rules) != 1 {
				t.Fatalf("rules %+v", doc.Rules)
			}
			r := doc.Rules[0]
			eq := func(name string, got, want []string) {
				t.Helper()
				if strings.Join(got, "|") != strings.Join(want, "|") {
					t.Fatalf("%s = %v, want %v", name, got, want)
				}
			}
			eq("users", r.Users, c.users)
			eq("hosts", r.Hosts, c.hosts)
			eq("runas users", r.RunAsUsers, c.runAsUsers)
			eq("runas groups", r.RunAsGroups, c.runAsGroups)
			eq("tags", r.Tags, c.tags)
			eq("commands", r.Commands, c.commands)
			if r.AllCommands() != c.allCommands || r.RunsAsRoot() != c.runsAsRoot || r.HasTag(SudoTagNoPasswd) != c.noPasswd {
				t.Fatalf("rule %+v: all=%v root=%v nopasswd=%v", r, r.AllCommands(), r.RunsAsRoot(), r.HasTag(SudoTagNoPasswd))
			}
		})
	}
}

// TestParseSudoersFile covers everything around the rules: comments, includes,
// aliases, Defaults and the line continuation.
func TestParseSudoersFile(t *testing.T) {
	in := "#\n" +
		"# This file MUST be edited with the visudo command.\n" +
		"#\n" +
		"Defaults\tenv_reset\n" +
		"Defaults\tsecure_path=\"/usr/local/sbin:/usr/bin\"\n" +
		"Defaults:alice !authenticate\n" +
		"User_Alias ADMINS = alice, deploy\n" +
		"Cmnd_Alias SERVICES = /usr/bin/systemctl\n" +
		"root\tALL=(ALL:ALL) ALL\n" +
		"ADMINS ALL=(ALL) NOPASSWD: SERVICES\n" +
		"deploy ALL=(root) /usr/bin/systemctl restart app, \\\n" +
		"    /usr/bin/systemctl status app\n" +
		"@includedir /etc/sudoers.d\n" +
		"this line has no equals sign\n"
	doc := ParseSudoers([]byte(in))
	if doc.CommentLines != 3 {
		t.Fatalf("comment lines %d, want 3", doc.CommentLines)
	}
	if len(doc.Includes) != 1 || doc.Includes[0].Path != SudoersDir || !doc.Includes[0].Dir {
		t.Fatalf("includes %+v", doc.Includes)
	}
	if len(doc.Aliases) != 2 || doc.Aliases[0].Kind != "User_Alias" || doc.Aliases[0].Name != "ADMINS" {
		t.Fatalf("aliases %+v", doc.Aliases)
	}
	if len(doc.Defaults) != 3 {
		t.Fatalf("defaults %+v", doc.Defaults)
	}
	if doc.Defaults[2].Name != "!authenticate" {
		t.Fatalf("the per-user Defaults line lost its setting: %+v", doc.Defaults[2])
	}
	if len(doc.Rules) != 3 {
		t.Fatalf("rules %+v", doc.Rules)
	}
	// The continued rule reports the line it starts on and carries both
	// commands.
	cont := doc.Rules[2]
	if cont.Line != 11 || len(cont.Commands) != 2 {
		t.Fatalf("continued rule %+v", cont)
	}
	if len(doc.Issues) != 1 || doc.Issues[0].Code != privDiagRecordUnparsed {
		t.Fatalf("issues %+v", doc.Issues)
	}
	if strings.Contains(doc.Issues[0].Message, "equals") {
		t.Fatalf("the diagnostic repeats the line content: %q", doc.Issues[0].Message)
	}
}

// TestParseSudoersRejectsSeveralHostSpecs: a shape the parser does not read is
// an issue, never a guessed rule (playbook L1).
func TestParseSudoersRejectsSeveralHostSpecs(t *testing.T) {
	doc := ParseSudoers([]byte("alice ALL=(root) /bin/ls : host-b.example=(ALL) ALL\n"))
	if len(doc.Rules) != 0 || len(doc.Issues) != 1 {
		t.Fatalf("rules %+v issues %+v", doc.Rules, doc.Issues)
	}
}

// TestSudoProbePermissionDenied is the shape of the trial host: the structure
// around the rule files is observable, the rule text is not (testdata
// sudo/cat-etc-sudoers.stderr.txt, expected_probe_status permission_denied).
func TestSudoProbePermissionDenied(t *testing.T) {
	files := probe.FakeFiles{Errs: map[string]error{
		SudoersPath:                    fs.ErrPermission,
		SudoersDir + "/README":         fs.ErrPermission,
		SudoersDir + "/alice-nopasswd": fs.ErrPermission,
	}}
	res, items := privRunProbe(t, NewSudoProbe(), sudoFixtureRunner(t), files)
	if res.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("status %q, want permission_denied (reason %q)", res.Status, res.Reason)
	}
	if res.Error == nil || res.Error.Class != probe.ClassPermissionDenied {
		t.Fatalf("error %+v", res.Error)
	}
	drop := privArtifact(t, res, SudoFilePrefix+"sudoers.d/alice-nopasswd")
	privWantAttr(t, drop, privAttrReadable, "false")
	privWantAttr(t, drop, privAttrMode, "0440")
	privWantAttr(t, drop, privAttrOwner, "root")
	privWantAttr(t, drop, privAttrSize, "29")
	if _, ok := drop.Attributes[privAttrContentSHA256]; ok {
		t.Fatalf("an unreadable file must not carry a content digest: %+v", drop.Attributes)
	}
	main := privArtifact(t, res, SudoFilePrefix+"sudoers")
	privWantAttr(t, main, privAttrReadable, "false")
	privWantAttr(t, main, privAttrSize, "1800")
	dir := privArtifact(t, res, SudoFilePrefix+"sudoers.d")
	privWantAttr(t, dir, sudoAttrEntryCount, "2")
	privWantAttr(t, dir, privAttrMode, "0755")
	// The empty rule list of an unreadable file must not look like "no rules".
	for _, a := range res.NormalizedState {
		if strings.HasPrefix(a.ID, SudoRulePrefix) {
			t.Fatalf("a rule artifact was invented although no file was readable: %s", a.ID)
		}
	}
	if !privWarned(res, probe.DiagFieldPermissionDenied) {
		t.Fatalf("no permission diagnostic in %+v", res.Warnings)
	}
	// The evidence is what ls and stat printed, never a rule file.
	for _, name := range privEvidenceNames(items) {
		if strings.Contains(name, "sudoers.txt") {
			t.Fatalf("evidence %q was persisted from an unreadable file", name)
		}
	}
	if len(res.Tools) == 0 || res.Tools[0].ToolVersion != "stat (GNU coreutils) 9.4" {
		t.Fatalf("tool version not recorded: %+v", res.Tools)
	}
}

// TestSudoProbeReadableRules is the root run the trial host could not produce:
// the rules are parsed, and the file with comments is not persisted (L4).
func TestSudoProbeReadableRules(t *testing.T) {
	main := "# This file MUST be edited with the visudo command.\n" +
		"Defaults\tenv_reset\n" +
		"root\tALL=(ALL:ALL) ALL\n" +
		"%sudo\tALL=(ALL:ALL) ALL\n" +
		"@includedir /etc/sudoers.d\n"
	dropIn := "alice ALL=(ALL) NOPASSWD: ALL\n"
	files := probe.FakeFiles{Files: map[string][]byte{
		SudoersPath:                    []byte(main),
		SudoersDir + "/README":         []byte("# just a readme\n"),
		SudoersDir + "/alice-nopasswd": []byte(dropIn),
	}}
	res, items := privRunProbe(t, NewSudoProbe(), sudoFixtureRunner(t), files)
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q (%s)", res.Status, res.Reason)
	}
	rule := privArtifact(t, res, SudoRulePrefix+"sudoers.d/alice-nopasswd/1")
	privWantAttr(t, rule, sudoAttrUsers, "alice")
	privWantAttr(t, rule, sudoAttrNoPasswd, "true")
	privWantAttr(t, rule, sudoAttrAllCommands, "true")
	privWantAttr(t, rule, sudoAttrRunAsRoot, "true")
	group := privArtifact(t, res, SudoRulePrefix+"sudoers/4")
	privWantAttr(t, group, sudoAttrUsers, "%sudo")
	privWantAttr(t, group, sudoAttrNoPasswd, "false")
	mainFile := privArtifact(t, res, SudoFilePrefix+"sudoers")
	privWantAttr(t, mainFile, privAttrReadable, "true")
	privWantAttr(t, mainFile, sudoAttrRuleCount, "2")
	privWantAttr(t, mainFile, sudoAttrCommentLines, "1")
	if !strings.HasPrefix(mainFile.Attributes[privAttrContentSHA256], "sha256:") {
		t.Fatalf("content digest %q", mainFile.Attributes[privAttrContentSHA256])
	}
	defaults := privArtifact(t, res, SudoDefaultsArtifactID)
	privWantAttr(t, defaults, "env_reset", "on")
	// The commented file stays out of the bundle, the comment-free drop-in
	// may be persisted.
	names := strings.Join(privEvidenceNames(items), ",")
	if strings.Contains(names, "sudoers.txt") {
		t.Fatalf("the commented sudoers file was persisted: %s", names)
	}
	if !strings.Contains(names, "sudoers.d-alice-nopasswd.txt") {
		t.Fatalf("the comment-free drop-in was not persisted: %s", names)
	}
	if !privWarned(res, privDiagEvidenceWithheld) {
		t.Fatalf("withholding the raw file was not reported: %+v", res.Warnings)
	}
	for _, it := range items {
		if strings.Contains(string(it.Data.Bytes()), "visudo") {
			t.Fatalf("evidence %s carries the comment text", it.Name)
		}
	}
}

// TestSudoProbeNotApplicable: a host without sudo says so, and does not report
// an empty rule set as a clean result.
func TestSudoProbeNotApplicable(t *testing.T) {
	r := probe.NewFakeRunner()
	r.Script("stat", []string{"--version"}, probe.FakeResponse{Stdout: []byte("stat (GNU coreutils) 9.4\n")})
	r.Script("ls", []string{"--version"}, probe.FakeResponse{Stdout: []byte("ls (GNU coreutils) 9.4\n")})
	r.Script("ls", []string{"-la", SudoersDir}, probe.FakeResponse{
		Stderr: []byte("ls: cannot access '/etc/sudoers.d': No such file or directory\n"), ExitCode: 2,
	})
	r.Script("stat", []string{"-c", "%n %a %U %G %s", SudoersPath, SudoersDir}, probe.FakeResponse{
		Stderr: []byte("stat: cannot statx '/etc/sudoers': No such file or directory\n"), ExitCode: 1,
	})
	res, _ := privRunProbe(t, NewSudoProbe(), r, probe.FakeFiles{})
	if res.Status != trustfreeze.StatusNotApplicable {
		t.Fatalf("status %q (%s)", res.Status, res.Reason)
	}
	if res.Reason == "" {
		t.Fatalf("not_applicable without a reason is not countable as complete")
	}
	if len(res.NormalizedState) != 0 {
		t.Fatalf("artifacts %v", privArtifactIDs(res))
	}
}

// TestSudoProbeUnsupportedPlatform keeps the probe honest on a host it was not
// written for.
func TestSudoProbeUnsupportedPlatform(t *testing.T) {
	p := NewSudoProbe()
	host := probe.HostContext{GOOS: "darwin"}
	if sup := p.Support(context.Background(), host); sup.Available || sup.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("support %+v", sup)
	}
	cc, _ := privContext(SudoProbeID, probe.NewFakeRunner(), probe.FakeFiles{})
	cc.GOOS = "darwin"
	if res := p.Collect(context.Background(), cc); res.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("status %q", res.Status)
	}
}

// TestSudoArtifactIDs pins the id shape: no absolute path, no drive letter, no
// segment an artifact id may not carry (SPEC-0466 R4).
func TestSudoArtifactIDs(t *testing.T) {
	for _, id := range []string{
		SudoFilePrefix + "sudoers", SudoFilePrefix + "sudoers.d/alice-nopasswd",
		SudoRulePrefix + "sudoers/4", SudoDefaultsArtifactID,
	} {
		if err := trustfreeze.ValidateArtifactID(id); err != nil {
			t.Fatalf("artifact id %q: %v", id, err)
		}
	}
	if _, ok := sudoFileArtifactID("/var/lib/elsewhere"); ok {
		t.Fatalf("a path outside /etc produced an id")
	}
	id, ok := sudoFileArtifactID(SudoersDir + "/alice-nopasswd")
	if !ok || id != SudoFilePrefix+"sudoers.d/alice-nopasswd" {
		t.Fatalf("id %q ok=%v", id, ok)
	}
}

// TestPrivLogicalLines pins the continuation rule the sudoers parser rests on.
func TestPrivLogicalLines(t *testing.T) {
	got := privLogicalLines([]byte("a \\\nb\nc\n"))
	if len(got) != 2 {
		t.Fatalf("lines %+v", got)
	}
	if got[0].Text != "a b" || got[0].Line != 1 || got[0].Lines != 2 {
		t.Fatalf("first %+v", got[0])
	}
	if got[1].Text != "c" || got[1].Line != 3 {
		t.Fatalf("second %+v", got[1])
	}
}

// TestSudoRuleCommandListIsCapped: a rule with a long command list keeps its
// count and says that the text was cut (playbook L6).
func TestSudoRuleCommandListIsCapped(t *testing.T) {
	cmds := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		cmds = append(cmds, "/usr/bin/tool-"+itoa(i))
	}
	rule := "deploy ALL=(root) NOPASSWD: " + strings.Join(cmds, ", ") + "\n"
	files := probe.FakeFiles{Files: map[string][]byte{
		SudoersPath:                    []byte(rule),
		SudoersDir + "/README":         []byte("# readme\n"),
		SudoersDir + "/alice-nopasswd": []byte("alice ALL=(ALL) NOPASSWD: ALL\n"),
	}}
	res, _ := privRunProbe(t, NewSudoProbe(), sudoFixtureRunner(t), files)
	a := privArtifact(t, res, SudoRulePrefix+"sudoers/1")
	privWantAttr(t, a, sudoAttrCommandCount, "100")
	privWantAttr(t, a, sudoAttrCommandsCut, "true")
	if got := len(a.Attributes[sudoAttrCommands]); got > sudoMaxCommandsBytes {
		t.Fatalf("command attribute is %d bytes, cap is %d", got, sudoMaxCommandsBytes)
	}
	if strings.HasSuffix(a.Attributes[sudoAttrCommands], ",") {
		t.Fatalf("the cut did not land on a comma boundary: %q", a.Attributes[sudoAttrCommands])
	}
}

func TestPrivCapList(t *testing.T) {
	if got, cut := privCapList([]string{"a", "b"}, 10); got != "a,b" || cut {
		t.Fatalf("got %q cut=%v", got, cut)
	}
	got, cut := privCapList([]string{"aaaa", "bbbb", "cccc"}, 6)
	if !cut || got != "aaaa" {
		t.Fatalf("got %q cut=%v", got, cut)
	}
}

// TestSudoProbeDeclaredContract pins what the probe promises the capture
// engine: the platform, the privilege it needs and the tools doctor resolves.
func TestSudoProbeDeclaredContract(t *testing.T) {
	p := NewSudoProbe()
	d := p.Descriptor()
	if d.ID != SudoProbeID || d.RequiredPrivilege != probe.PrivilegeUser {
		t.Fatalf("descriptor %+v", d)
	}
	if len(d.Platforms) != 1 || d.Platforms[0] != probe.PlatformLinux {
		t.Fatalf("platforms %v", d.Platforms)
	}
	if got := strings.Join(p.RequiredTools(), ","); got != "ls,stat" {
		t.Fatalf("required tools %q", got)
	}
	if levels := p.EvidenceClaims()[probe.PlatformLinux]; len(levels) != 2 {
		t.Fatalf("evidence claims %v", levels)
	}
	if got := strings.Join(SudoAllowedRoots(), ","); got != SudoersPath+","+SudoersDir {
		t.Fatalf("allowed roots %q", got)
	}
}

// sudoRunnerFor scripts ls and stat for a drop-in directory holding names,
// with the stat output the caller gives. Every value is synthetic.
func sudoRunnerFor(names []string, statOut string) *probe.FakeRunner {
	r := probe.NewFakeRunner()
	r.Script("stat", []string{"--version"}, probe.FakeResponse{Stdout: []byte("stat (GNU coreutils) 9.4\n")})
	r.Script("ls", []string{"--version"}, probe.FakeResponse{Stdout: []byte("ls (GNU coreutils) 9.4\n")})
	listing := "total 8\ndrwxr-xr-x  2 root root   42 Sep 23 06:15 .\ndrwxr-xr-x 148 root root 12288 Sep 23 08:58 ..\n"
	statArgs := []string{"-c", "%n %a %U %G %s", SudoersPath, SudoersDir}
	for _, n := range names {
		listing += "-r--r-----  1 root root   29 Jun  1 14:21 " + n + "\n"
		statArgs = append(statArgs, SudoersDir+"/"+n)
	}
	r.Script("ls", []string{"-la", SudoersDir}, probe.FakeResponse{Stdout: []byte(listing)})
	r.Script("stat", statArgs, probe.FakeResponse{Stdout: []byte(statOut)})
	return r
}

// O-T3: /etc/sudoers is absent while /etc/sudoers.d exists and was listed.
// That is a fact about the host, and a first capture has to record it: the
// probe is partial with a rule_file_missing diagnostic, not unavailable with
// a missing tool, and the drop-in rules are still collected.
func TestSudoProbeMainRuleFileMissing(t *testing.T) {
	statOut := "/etc/sudoers.d 755 root root 42\n/etc/sudoers.d/ops 440 root root 29\n"
	files := probe.FakeFiles{Files: map[string][]byte{
		SudoersDir + "/ops": []byte("%ops ALL=(ALL) ALL\n"),
	}}
	res, _ := privRunProbe(t, NewSudoProbe(), sudoRunnerFor([]string{"ops"}, statOut), files)
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %q (%s), want partial", res.Status, res.Reason)
	}
	if res.Error != nil {
		t.Fatalf("a missing main rule file is not a probe error: %+v", res.Error)
	}
	if !privWarned(res, privDiagRuleFileMissing) {
		t.Fatalf("the missing %s was not recorded: %+v", SudoersPath, res.Warnings)
	}
	var named bool
	for _, w := range res.Warnings {
		if w.Code == privDiagRuleFileMissing && w.Field == SudoersPath {
			named = true
		}
	}
	if !named {
		t.Fatalf("the diagnostic does not name %s: %+v", SudoersPath, res.Warnings)
	}
	// No artifact claims the file exists and could not be read.
	if privHasArtifact(res, SudoFilePrefix+"sudoers") {
		t.Fatalf("an absent file became a file artifact: %v", privArtifactIDs(res))
	}
	// The drop-in was read all the same.
	privArtifact(t, res, SudoRulePrefix+"sudoers.d/ops/1")
}

// O-T5: sudo keeps one alias namespace over /etc/sudoers and every drop-in, so
// a rule in a drop-in that names an alias the main file defines grants what
// the alias expands to. Before this, every file was resolved alone and the
// grant disappeared.
func TestSudoProbeAliasesResolveAcrossFiles(t *testing.T) {
	main := "User_Alias ADMINS = alice, bob\n" +
		"Cmnd_Alias MAINT = ALL\n" +
		"root ALL=(ALL:ALL) ALL\n"
	dropIn := "ADMINS ALL=(ALL) NOPASSWD: MAINT\n"
	statOut := "/etc/sudoers 440 root root 120\n/etc/sudoers.d 755 root root 42\n/etc/sudoers.d/ops 440 root root 33\n"
	files := probe.FakeFiles{Files: map[string][]byte{
		SudoersPath:         []byte(main),
		SudoersDir + "/ops": []byte(dropIn),
	}}
	res, _ := privRunProbe(t, NewSudoProbe(), sudoRunnerFor([]string{"ops"}, statOut), files)
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %q (%s)", res.Status, res.Reason)
	}
	rule := privArtifact(t, res, SudoRulePrefix+"sudoers.d/ops/1")
	privWantAttr(t, rule, sudoAttrUsers, "alice,bob")
	privWantAttr(t, rule, sudoAttrAllCommands, "true")
	privWantAttr(t, rule, sudoAttrRunAsRoot, "true")
	privWantAttr(t, rule, sudoAttrNoPasswd, "true")
	privWantAttr(t, rule, sudoAttrResolvedAliases, "ADMINS,MAINT")
	if _, ok := rule.Attributes[sudoAttrUnresolvedAliases]; ok {
		t.Fatalf("an alias the main file defines was reported as unresolved: %v", rule.Attributes)
	}
	// The resolver sees the expanded grant.
	caps, _ := ResolveCapabilities(res.NormalizedState)
	for _, who := range []string{"alice", "bob"} {
		found := false
		for _, c := range caps {
			if c.ID == CapExecuteHostPrefix+CapSubjectUserPrefix+who && c.Privilege == CapPrivilegeRootViaSudoNoPassword {
				found = true
			}
		}
		if !found {
			t.Fatalf("no passwordless root capability for %s: %+v", who, caps)
		}
	}
}

// O-T5: an alias that no rule file this capture read defines stays unresolved,
// with its diagnostic. That is the honest answer when a drop-in was unreadable.
func TestSudoProbeAliasNoFileDefines(t *testing.T) {
	main := "alice ALL=(ALL) NOPASSWD: MAINT\n"
	statOut := "/etc/sudoers 440 root root 40\n/etc/sudoers.d 755 root root 42\n/etc/sudoers.d/ops 440 root root 33\n"
	files := probe.FakeFiles{
		Files: map[string][]byte{SudoersPath: []byte(main)},
		Errs:  map[string]error{SudoersDir + "/ops": fs.ErrPermission},
	}
	res, _ := privRunProbe(t, NewSudoProbe(), sudoRunnerFor([]string{"ops"}, statOut), files)
	rule := privArtifact(t, res, SudoRulePrefix+"sudoers/1")
	privWantAttr(t, rule, sudoAttrUnresolvedAliases, "MAINT")
	privWantAttr(t, rule, sudoAttrAllCommands, "false")
	if !privWarned(res, privDiagAliasUnresolved) {
		t.Fatalf("the unresolved alias was not reported: %+v", res.Warnings)
	}
}

// O-T4: ParseStat gets the shape check its siblings have. A line that is not
// "<name> <mode> <owner> <group> <size>" becomes a diagnostic, never a record.
func TestParseStatRejectsWrongShape(t *testing.T) {
	for name, line := range map[string]string{
		"a tool diagnostic on stdout": "stat: cannot stat '/etc/sudoers.d/x': No such file or directory",
		"a symbolic mode":             "/etc/sudoers rw-r----- root root 120",
		"a mode that is not octal":    "/etc/sudoers 0990 root root 120",
		"a size that is not a number": "/etc/sudoers 0440 root root many",
		"an empty owner field":        "/etc/sudoers 0440 root root",
	} {
		t.Run(name, func(t *testing.T) {
			got, diags := ParseStat([]byte(line + "\n"))
			if len(got) != 0 {
				t.Fatalf("parsed %v", got)
			}
			if len(diags) != 1 || diags[0].Code != privDiagRecordUnparsed {
				t.Fatalf("diagnostics %+v", diags)
			}
		})
	}
	// Control: the shape stat really prints still parses, spaces included.
	got, diags := ParseStat([]byte("/etc/my sudoers 440 root root 1800\n"))
	if len(diags) != 0 {
		t.Fatalf("diagnostics %+v", diags)
	}
	info, ok := got["/etc/my sudoers"]
	if !ok || info.Mode != "0440" || info.Owner != "root" || info.Group != "root" || info.Size != "1800" {
		t.Fatalf("info %+v", got)
	}
}
