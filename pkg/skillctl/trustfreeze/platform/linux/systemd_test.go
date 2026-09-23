package linux

// Tests for linux.systemd (SPEC-0471 TF06-R3).
//
// Every input is either a fixture under testdata/ (transcribed from a real
// Ubuntu 24.04.1 host and sanitized, see testdata/README.md) or a value built
// from one, and every constructed input says so at the place it is built. The
// parsers are pure functions over bytes and the probe runs against
// probe.FakeRunner, so the whole file passes on any operating system.

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// linuxTestTime is the fixed clock of the linux probe tests.
var linuxTestTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// systemdFixture reads one fixture file.
func systemdFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return b
}

// systemdContext builds a CollectContext around runner.
func systemdContext(runner *probe.FakeRunner) (probe.CollectContext, *probe.EvidenceBuffer) {
	ev := probe.NewEvidenceBuffer(SystemdProbeID, probe.Limits{})
	return probe.CollectContext{
		HostContext: probe.HostContext{
			GOOS: "linux", GOARCH: "amd64",
			Hostname:  func() (string, error) { return "host-a.example", nil },
			Files:     probe.FakeFiles{},
			Runner:    runner,
			Clock:     trustfreeze.FixedClock{T: linuxTestTime},
			Privilege: probe.PrivilegeUser,
		},
		ProbeID:  SystemdProbeID,
		Redactor: redact.Default(),
		Evidence: ev,
		Support:  probe.Supported(),
	}, ev
}

// systemdRunnerWithVersion scripts "systemctl --version" from the fixture.
func systemdRunnerWithVersion(t *testing.T) *probe.FakeRunner {
	t.Helper()
	return probe.NewFakeRunner().AddTool(systemctlExe, "/usr/bin/systemctl").
		Script(systemctlExe, []string{"--version"},
			probe.FakeResponse{Stdout: systemdFixture(t, "systemd/systemctl-version.txt")})
}

func systemdArtifact(t *testing.T, res trustfreeze.ProbeResult, id string) trustfreeze.Artifact {
	t.Helper()
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no artifact %q in %d artifacts", id, len(res.NormalizedState))
	return trustfreeze.Artifact{}
}

func systemdHasArtifact(res trustfreeze.ProbeResult, id string) bool {
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return true
		}
	}
	return false
}

func systemdWarned(res trustfreeze.ProbeResult, code string) bool {
	for _, w := range res.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// TestParseUnitFilesFixture reads the measured unit file list.
func TestParseUnitFilesFixture(t *testing.T) {
	files, issues := ParseUnitFiles(systemdFixture(t, "systemd/systemctl-list-unit-files.txt"))
	if len(issues) != 0 {
		t.Fatalf("issues in the measured output: %+v", issues)
	}
	if len(files) != 55 {
		t.Fatalf("parsed %d rows, want 55", len(files))
	}
	states, types := map[string]bool{}, map[string]bool{}
	for _, f := range files {
		states[f.State] = true
		types[f.Type] = true
	}
	// The fixture carries all nine unit file states and all ten unit types of
	// the trial host (testdata/README.md).
	if len(states) != 9 {
		t.Fatalf("saw %d unit file states %v, want 9", len(states), states)
	}
	if len(types) != 10 {
		t.Fatalf("saw %d unit types %v, want 10", len(types), types)
	}
	byName := map[string]UnitFile{}
	for _, f := range files {
		byName[f.Name] = f
	}
	for _, tc := range []struct {
		name string
		want UnitFile
	}{
		// The root mount unit: a name that begins with a hyphen.
		{"-.mount", UnitFile{Name: "-.mount", Type: "mount", State: "generated"}},
		{"proc-sys-fs-binfmt_misc.mount", UnitFile{Name: "proc-sys-fs-binfmt_misc.mount", Type: "mount", State: "disabled", Preset: "disabled"}},
		// A preset column of "-" is no preset, not the value "-".
		{"machine.slice", UnitFile{Name: "machine.slice", Type: "slice", State: "static"}},
		// A unit name that carries a systemd escape, which is a literal
		// backslash in the name.
		{`system-systemd\x2dcryptsetup.slice`, UnitFile{Name: `system-systemd\x2dcryptsetup.slice`, Type: "slice", State: "static"}},
		{"autovt@.service", UnitFile{Name: "autovt@.service", Type: "service", State: "alias"}},
		{"netplan-ovs-cleanup.service", UnitFile{Name: "netplan-ovs-cleanup.service", Type: "service", State: "enabled-runtime", Preset: "enabled"}},
		{"alsa-utils.service", UnitFile{Name: "alsa-utils.service", Type: "service", State: "masked", Preset: "enabled"}},
		{"swap.img.swap", UnitFile{Name: "swap.img.swap", Type: "swap", State: "generated"}},
		{"dbus-fi.w1.wpa_supplicant1.service", UnitFile{Name: "dbus-fi.w1.wpa_supplicant1.service", Type: "service", State: "alias"}},
	} {
		if got := byName[tc.name]; got != tc.want {
			t.Errorf("%s = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestParseUnitFilesIgnoresColumnOffsets proves the parser reads columns and
// not byte offsets: column two starts at byte 79 on the trial host because of
// its longest unit name, which is a property of that host and of nothing else.
func TestParseUnitFilesIgnoresColumnOffsets(t *testing.T) {
	// Constructed from the measured row of debug-shell.service by collapsing
	// the padding to one space each.
	files, issues := ParseUnitFiles([]byte("debug-shell.service disabled disabled\n"))
	if len(issues) != 0 {
		t.Fatalf("issues: %+v", issues)
	}
	want := UnitFile{Name: "debug-shell.service", Type: "service", State: "disabled", Preset: "disabled"}
	if len(files) != 1 || files[0] != want {
		t.Fatalf("parsed %+v, want one %+v", files, want)
	}
}

// TestParseUnitFilesIssues covers the shapes a parser must not swallow.
func TestParseUnitFilesIssues(t *testing.T) {
	for _, tc := range []struct {
		name       string
		in         string
		wantRows   int
		wantIssues []SystemdLineIssue
	}{
		{"empty", "", 0, nil},
		{"only blank lines", "\n\n   \n", 0, nil},
		{"one column", "ssh.service\n", 0, []SystemdLineIssue{{Line: 1, Reason: SystemdIssueFieldCount}}},
		{"four columns", "ssh.service enabled enabled extra\n", 0, []SystemdLineIssue{{Line: 1, Reason: SystemdIssueFieldCount}}},
		{"no type suffix", "noSuffix enabled enabled\n", 1, []SystemdLineIssue{{Line: 1, Reason: SystemdIssueNoUnitType}}},
		{"trailing dot", "broken. enabled enabled\n", 1, []SystemdLineIssue{{Line: 1, Reason: SystemdIssueNoUnitType}}},
		{"two columns", "ssh.service enabled\n", 1, nil},
		{"carriage return", "ssh.service enabled enabled\r\n", 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files, issues := ParseUnitFiles([]byte(tc.in))
			if len(files) != tc.wantRows {
				t.Errorf("rows = %d, want %d (%+v)", len(files), tc.wantRows, files)
			}
			if len(issues) != len(tc.wantIssues) {
				t.Fatalf("issues = %+v, want %+v", issues, tc.wantIssues)
			}
			for i := range issues {
				if issues[i] != tc.wantIssues[i] {
					t.Errorf("issue %d = %+v, want %+v", i, issues[i], tc.wantIssues[i])
				}
			}
		})
	}
}

// TestParseShowBlocksFixtures reads every measured "systemctl show" answer.
func TestParseShowBlocksFixtures(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    map[string]string
	}{
		{"systemd/systemctl-show-enabled-running.txt", map[string]string{
			ShowPropID: "ssh.service", ShowPropLoadState: "loaded",
			ShowPropActiveState: "active", ShowPropSubState: "running",
			ShowPropUnitFileState: "enabled", ShowPropUnitFilePreset: "enabled",
			ShowPropFragmentPath: "/usr/lib/systemd/system/ssh.service",
			ShowPropDropInPaths:  "", ShowPropType: "notify",
			ShowPropUser: "", ShowPropGroup: "", ShowPropRestart: "on-failure",
			ShowPropConditionResult: "yes", ShowPropNeedDaemonReload: "no",
		}},
		{"systemd/systemctl-show-disabled.txt", map[string]string{
			ShowPropID: "debug-shell.service", ShowPropLoadState: "loaded",
			ShowPropActiveState: "inactive", ShowPropSubState: "dead",
			ShowPropUnitFileState: "disabled", ShowPropUnitFilePreset: "disabled",
			ShowPropFragmentPath:    "/usr/lib/systemd/system/debug-shell.service",
			ShowPropType:            "simple",
			ShowPropRestart:         "always",
			ShowPropConditionResult: "no", ShowPropNeedDaemonReload: "no",
		}},
		{"systemd/systemctl-show-local-unit.txt", map[string]string{
			ShowPropID: "connect-pm2.service", ShowPropLoadState: "loaded",
			ShowPropActiveState: "active", ShowPropSubState: "running",
			// A unit added under /etc, running as a human account.
			ShowPropFragmentPath: "/etc/systemd/system/connect-pm2.service",
			ShowPropUser:         "alice", ShowPropType: "forking",
			ShowPropConditionResult: "yes",
		}},
		{"systemd/systemctl-show-unknown-unit.txt", map[string]string{
			// Exit code 0 and a full set of empty properties: LoadState is
			// the only truthful signal (testdata/README.md).
			ShowPropID: "nosuchunit-trustfreeze.service", ShowPropLoadState: ShowLoadStateNotFound,
			ShowPropUnitFileState: "", ShowPropFragmentPath: "",
			ShowPropActiveState: "inactive", ShowPropSubState: "dead",
		}},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			blocks, issues := ParseShowBlocks(systemdFixture(t, tc.fixture))
			if len(issues) != 0 {
				t.Fatalf("issues in the measured output: %+v", issues)
			}
			if len(blocks) != 1 {
				t.Fatalf("got %d blocks, want 1", len(blocks))
			}
			for k, want := range tc.want {
				if got := blocks[0].First(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
		})
	}
}

// TestParseShowBlocksMultiUnit covers a batched call. Only the single unit
// shape was measured on the trial host, so both separators a multi unit
// answer can carry are built here from two measured single unit answers and
// both must split the same way.
func TestParseShowBlocksMultiUnit(t *testing.T) {
	a := systemdFixture(t, "systemd/systemctl-show-enabled-running.txt")
	b := systemdFixture(t, "systemd/systemctl-show-disabled.txt")
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"blank line between the blocks", append(append(append([]byte{}, a...), '\n'), b...)},
		{"no separator at all", append(append([]byte{}, a...), b...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocks, issues := ParseShowBlocks(tc.in)
			if len(issues) != 0 {
				t.Fatalf("issues: %+v", issues)
			}
			if len(blocks) != 2 {
				t.Fatalf("got %d blocks, want 2", len(blocks))
			}
			if got := blocks[0].First(ShowPropID); got != "ssh.service" {
				t.Errorf("first block id = %q", got)
			}
			if got := blocks[1].First(ShowPropID); got != "debug-shell.service" {
				t.Errorf("second block id = %q", got)
			}
			if got := blocks[1].First(ShowPropActiveState); got != "inactive" {
				t.Errorf("second block active state = %q", got)
			}
		})
	}
}

// TestParseShowBlocksKeepsRepeatedProperty proves that a property systemd
// prints more than once does not start a new block: only a second Id does. A
// unit with two ExecStart commands is such a case, built here by repeating
// the measured ExecStart line of ssh.service.
func TestParseShowBlocksKeepsRepeatedProperty(t *testing.T) {
	src := string(systemdFixture(t, "systemd/systemctl-show-enabled-running.txt"))
	var execLine string
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, ShowPropExecStart+"=") {
			execLine = line
		}
	}
	if execLine == "" {
		t.Fatal("the fixture has no ExecStart line")
	}
	blocks, issues := ParseShowBlocks([]byte(src + execLine + "\n"))
	if len(issues) != 0 {
		t.Fatalf("issues: %+v", issues)
	}
	if len(blocks) != 1 {
		t.Fatalf("got %d blocks, want 1", len(blocks))
	}
	if got := blocks[0].Count(ShowPropExecStart); got != 2 {
		t.Fatalf("ExecStart count = %d, want 2", got)
	}
}

// TestParseShowBlocksIssues covers lines that are not property assignments.
func TestParseShowBlocksIssues(t *testing.T) {
	blocks, issues := ParseShowBlocks([]byte("Id=a.service\nnot a property\n=novalue\nType=simple\n"))
	if len(blocks) != 1 {
		t.Fatalf("got %d blocks, want 1", len(blocks))
	}
	if blocks[0].First(ShowPropType) != "simple" {
		t.Errorf("the readable properties were not kept: %+v", blocks[0])
	}
	want := []SystemdLineIssue{
		{Line: 2, Reason: SystemdIssueNotAssignment},
		{Line: 3, Reason: SystemdIssueEmptyProperty},
	}
	if len(issues) != len(want) {
		t.Fatalf("issues = %+v, want %+v", issues, want)
	}
	for i := range issues {
		if issues[i] != want[i] {
			t.Errorf("issue %d = %+v, want %+v", i, issues[i], want[i])
		}
	}
}

// TestParseExecStartPath reads the path out of the measured ExecStart
// records and keeps everything volatile and everything secret-bearing out.
func TestParseExecStartPath(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		want    string
	}{
		{"systemd/systemctl-show-enabled-running.txt", "/usr/sbin/sshd"},
		{"systemd/systemctl-show-disabled.txt", "/usr/bin/bash"},
		{"systemd/systemctl-show-local-unit.txt", "/usr/lib/node_modules/pm2/bin/pm2"},
		// The unknown unit has no ExecStart property at all.
		{"systemd/systemctl-show-unknown-unit.txt", ""},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			blocks, _ := ParseShowBlocks(systemdFixture(t, tc.fixture))
			got := ParseExecStartPath(blocks[0].First(ShowPropExecStart))
			if got != tc.want {
				t.Fatalf("path = %q, want %q", got, tc.want)
			}
			// The argument vector and the volatile fields of the record are
			// never returned.
			for _, forbidden := range []string{"argv", "start_time", "stop_time", "pid=", "status="} {
				if strings.Contains(got, forbidden) {
					t.Errorf("the returned path carries %q", forbidden)
				}
			}
		})
	}
	if got := ParseExecStartPath(""); got != "" {
		t.Errorf("an empty value returned %q", got)
	}
	if got := ParseExecStartPath("{ ignore_errors=no }"); got != "" {
		t.Errorf("a record without a path returned %q", got)
	}
}

// TestParseSystemctlVersion keeps the version line and drops the feature flag
// line that follows it.
func TestParseSystemctlVersion(t *testing.T) {
	v, err := ParseSystemctlVersion(systemdFixture(t, "systemd/systemctl-version.txt"))
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if v != "systemd 255 (255.4-1ubuntu8.17)" {
		t.Fatalf("version = %q", v)
	}
	if _, err := ParseSystemctlVersion(nil); err == nil {
		t.Error("an empty answer returned no error")
	}
}

// systemdSelectedUnits is the selection the measured unit file list yields.
var systemdSelectedUnits = []string{
	"actions.runner.alice-m3c-tools.host-a.service",
	"anacron.timer",
	"ansible-pull.timer",
	"apport-autoreport.path",
	"apport-autoreport.timer",
	"apport-forward.socket",
	"avahi-daemon.socket",
	"cloud-init-hotplugd.socket",
	"cups.path",
	"netplan-ovs-cleanup.service",
	"snap-bare-5.mount",
	"snap-chromium-3525.mount",
	"snap-chromium-3529.mount",
	"snap-code-260.mount",
	"systemd-fsck-root.service",
	"systemd-remount-fs.service",
	"ua-timer.timer",
	"update-notifier-download.timer",
	"update-notifier-motd.timer",
	"xfs_scrub_all.timer",
}

// TestSelectUnitsForShow pins the selection rule: what is asked about decides
// what the bundle can say about the present.
func TestSelectUnitsForShow(t *testing.T) {
	files, _ := ParseUnitFiles(systemdFixture(t, "systemd/systemctl-list-unit-files.txt"))
	got, cut := SelectUnitsForShow(files, systemdMaxShowUnits)
	if cut {
		t.Fatal("the measured list hit the cap")
	}
	if len(got) != len(systemdSelectedUnits) {
		t.Fatalf("selected %d units, want %d: %v", len(got), len(systemdSelectedUnits), got)
	}
	for i := range got {
		if got[i] != systemdSelectedUnits[i] {
			t.Fatalf("unit %d = %q, want %q", i, got[i], systemdSelectedUnits[i])
		}
	}
	if !sort.StringsAreSorted(got) {
		t.Error("the selection is not sorted")
	}
	for _, u := range got {
		// A transient scope is the unit of a running container and is the
		// subject of linux.containers, never of this probe.
		if strings.HasSuffix(u, ".scope") {
			t.Errorf("a transient scope was selected: %s", u)
		}
		// An alias is a second name and a masked unit cannot start.
		if u == "autovt@.service" || u == "alsa-utils.service" {
			t.Errorf("an alias or masked unit was selected: %s", u)
		}
	}
}

// TestSelectUnitsForShowCap proves that a cut selection is reported.
func TestSelectUnitsForShowCap(t *testing.T) {
	files, _ := ParseUnitFiles(systemdFixture(t, "systemd/systemctl-list-unit-files.txt"))
	got, cut := SelectUnitsForShow(files, 3)
	if !cut || len(got) != 3 {
		t.Fatalf("selected %d units, cut %v, want 3 and true", len(got), cut)
	}
}

// TestSystemdDescriptor pins the declaration.
func TestSystemdDescriptor(t *testing.T) {
	d := NewSystemdProbe().Descriptor()
	if err := d.Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if d.ID != SystemdProbeID || d.Version != SystemdProbeVersion {
		t.Fatalf("identity = %s/%s", d.ID, d.Version)
	}
	if d.RequiredPrivilege != probe.PrivilegeUser {
		t.Errorf("required privilege = %q, want user: the probe never elevates", d.RequiredPrivilege)
	}
	if !d.SupportsPlatform("linux") || d.SupportsPlatform("darwin") || d.SupportsPlatform("windows") {
		t.Errorf("platforms = %v", d.Platforms)
	}
	if !sort.StringsAreSorted(d.Provides) {
		t.Errorf("provides is not sorted: %v", d.Provides)
	}
}

// TestSystemdSupport covers the availability answers.
func TestSystemdSupport(t *testing.T) {
	p := NewSystemdProbe()
	for _, tc := range []struct {
		name       string
		goos       string
		runner     *probe.FakeRunner
		wantAvail  bool
		wantStatus trustfreeze.ProbeStatus
	}{
		{"linux with systemctl", "linux", probe.NewFakeRunner().AddTool(systemctlExe, "/usr/bin/systemctl"), true, ""},
		// A missing tool is unavailable, never a silent empty result.
		{"systemctl missing", "linux", probe.NewFakeRunner(), false, trustfreeze.StatusUnavailable},
		{"systemctl not executable", "linux", probe.NewFakeRunner().DenyTool(systemctlExe, "/usr/bin/systemctl"), false, trustfreeze.StatusPermissionDenied},
		{"other platform", "darwin", probe.NewFakeRunner().AddTool(systemctlExe, "/usr/bin/systemctl"), false, trustfreeze.StatusUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := probe.HostContext{GOOS: tc.goos, Runner: tc.runner}
			got := p.Support(context.Background(), host)
			if err := got.Validate(); err != nil {
				t.Fatalf("support result: %v", err)
			}
			if got.Available != tc.wantAvail || got.Status != tc.wantStatus {
				t.Fatalf("support = %+v, want available %v status %q", got, tc.wantAvail, tc.wantStatus)
			}
		})
	}
}

// TestSystemdCollectFromMeasuredList runs the probe against the measured unit
// file list. The fake answers no "systemctl show" call, so the honest result
// is the declared inventory with an open question about the present.
func TestSystemdCollectFromMeasuredList(t *testing.T) {
	runner := systemdRunnerWithVersion(t)
	runner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
		probe.FakeResponse{Stdout: systemdFixture(t, "systemd/systemctl-list-unit-files.txt")})
	showArgs := append([]string{"show", "--no-pager", "-p", systemdShowProperties}, systemdSelectedUnits...)
	runner.Script(systemctlExe, showArgs, probe.FakeResponse{ExitCode: 1, Stderr: []byte("")})
	// The batch answered for nobody, so the probe asks for every name again,
	// one at a time. The fake refuses those the same way, so the honest
	// result stays "the present is unknown" and the retry path is scripted
	// instead of running into unscripted calls.
	for _, u := range systemdSelectedUnits {
		runner.Script(systemctlExe, []string{"show", "--no-pager", "-p", systemdShowProperties, u},
			probe.FakeResponse{ExitCode: 1, Stderr: []byte("")})
	}

	cc, ev := systemdContext(runner)
	res := NewSystemdProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status = %q reason %q, want partial: the runtime state of every selected unit is unknown", res.Status, res.Reason)
	}
	units := 0
	for _, a := range res.NormalizedState {
		if strings.HasPrefix(a.ID, ArtifactSystemdUnitPrefix) {
			units++
			if a.State != trustfreeze.StateDeclared {
				t.Fatalf("%s has state %q, want declared: a unit file on disk is declared", a.ID, a.State)
			}
		}
		if strings.HasPrefix(a.ID, ArtifactSystemdRuntimePrefix) {
			t.Fatalf("%s exists although no show call answered", a.ID)
		}
	}
	if units != 55 {
		t.Fatalf("%d declared unit artifacts, want 55", units)
	}
	mgr := systemdArtifact(t, res, ArtifactSystemdManager)
	if mgr.State != trustfreeze.StateObserved {
		t.Errorf("manager state = %q, want observed", mgr.State)
	}
	if mgr.Attributes[systemdAttrUnitFileCount] != "55" || mgr.Attributes[systemdAttrObservedCount] != "0" {
		t.Errorf("manager counts = %v", mgr.Attributes)
	}
	// The user managers are a scope of their own and are never asked about:
	// stated, not implied.
	if mgr.Attributes[systemdAttrUserScope] != systemdUserScopeNotCollected {
		t.Errorf("user scope = %q", mgr.Attributes[systemdAttrUserScope])
	}
	if !systemdWarned(res, DiagSystemdScopeNotCollected) {
		t.Error("no scope_not_collected diagnostic")
	}
	if !systemdWarned(res, trustfreeze.DiagFieldMissing) {
		t.Error("no diagnostic for the units with no observed state")
	}
	// A unit name with a backslash still yields a valid artifact id.
	slice := systemdArtifact(t, res, ArtifactSystemdUnitPrefix+"system-systemd_x2dcryptsetup.slice")
	if slice.Attributes[systemdAttrUnit] != `system-systemd\x2dcryptsetup.slice` {
		t.Errorf("the raw unit name was not kept: %v", slice.Attributes)
	}
	for _, a := range res.NormalizedState {
		if err := trustfreeze.ValidateArtifactID(a.ID); err != nil {
			t.Errorf("artifact id %q: %v", a.ID, err)
		}
		if a.Provenance.ToolVersion != "systemd 255 (255.4-1ubuntu8.17)" {
			t.Errorf("%s records tool version %q", a.ID, a.Provenance.ToolVersion)
		}
	}
	for i := 1; i < len(res.NormalizedState); i++ {
		if res.NormalizedState[i-1].ID >= res.NormalizedState[i].ID {
			t.Fatalf("the artifacts are not sorted by id: %q before %q", res.NormalizedState[i-1].ID, res.NormalizedState[i].ID)
		}
	}
	names := []string{}
	for _, it := range ev.Close() {
		names = append(names, it.Name)
	}
	if len(names) != 2 {
		t.Errorf("evidence = %v, want the version and the unit file list", names)
	}
}

// systemdDeclaredList is the input of the enrichment test. Two of its three
// rows are constructed: only the debug-shell.service row is a measured line
// of systemd/systemctl-list-unit-files.txt. The other two name the units the
// measured "systemctl show" fixtures answer for, in the column shape of the
// measured file, so the declared and the observed layer can be tested
// together at all. Nothing here claims to be host output.
const systemdDeclaredList = "" +
	"connect-pm2.service enabled enabled\n" +
	"debug-shell.service disabled disabled\n" +
	"nosuchunit-trustfreeze.service enabled enabled\n" +
	"ssh.service enabled enabled\n"

// TestSystemdCollectDeclaredAndObserved proves that enabled and active are
// two facts in two artifacts with two evidence states (playbook L3).
func TestSystemdCollectDeclaredAndObserved(t *testing.T) {
	show := strings.Join([]string{
		string(systemdFixture(t, "systemd/systemctl-show-local-unit.txt")),
		string(systemdFixture(t, "systemd/systemctl-show-disabled.txt")),
		string(systemdFixture(t, "systemd/systemctl-show-unknown-unit.txt")),
		string(systemdFixture(t, "systemd/systemctl-show-enabled-running.txt")),
	}, "\n")

	runner := systemdRunnerWithVersion(t)
	runner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
		probe.FakeResponse{Stdout: []byte(systemdDeclaredList)})
	selected := []string{"connect-pm2.service", "nosuchunit-trustfreeze.service", "ssh.service"}
	runner.Script(systemctlExe, append([]string{"show", "--no-pager", "-p", systemdShowProperties}, selected...),
		probe.FakeResponse{Stdout: []byte(show)})

	cc, _ := systemdContext(runner)
	res := NewSystemdProbe().Collect(context.Background(), cc)
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status = %q reason %q, want captured", res.Status, res.Reason)
	}

	declared := systemdArtifact(t, res, ArtifactSystemdUnitPrefix+"ssh.service")
	if declared.State != trustfreeze.StateDeclared {
		t.Errorf("declared artifact state = %q", declared.State)
	}
	for k, want := range map[string]string{
		systemdAttrUnit:          "ssh.service",
		systemdAttrUnitType:      "service",
		systemdAttrEnabledState:  "enabled",
		systemdAttrPreset:        "enabled",
		systemdAttrFragmentPath:  "/usr/lib/systemd/system/ssh.service",
		systemdAttrServiceType:   "notify",
		systemdAttrRestart:       "on-failure",
		systemdAttrExecStartPath: "/usr/sbin/sshd",
	} {
		if got := declared.Attributes[k]; got != want {
			t.Errorf("declared %s = %q, want %q", k, got, want)
		}
	}
	// The argument vector of the unit is not persisted anywhere.
	for k, v := range declared.Attributes {
		if strings.Contains(v, "argv") || strings.Contains(v, "SSHD_OPTS") {
			t.Errorf("attribute %s carries the argument vector: %q", k, v)
		}
	}
	if _, ok := declared.Attributes[systemdAttrActiveState]; ok {
		t.Error("the declared artifact carries the active state")
	}

	observed := systemdArtifact(t, res, ArtifactSystemdRuntimePrefix+"ssh.service")
	if observed.State != trustfreeze.StateObserved {
		t.Errorf("observed artifact state = %q", observed.State)
	}
	for k, want := range map[string]string{
		systemdAttrLoadState:       "loaded",
		systemdAttrActiveState:     "active",
		systemdAttrSubState:        "running",
		systemdAttrConditionResult: "yes",
		systemdAttrDaemonReload:    "no",
	} {
		if got := observed.Attributes[k]; got != want {
			t.Errorf("observed %s = %q, want %q", k, got, want)
		}
	}
	if _, ok := observed.Attributes[systemdAttrEnabledState]; ok {
		t.Error("the observed artifact carries the enablement")
	}

	// Disabled and dead: enabled and active disagree, and both are recorded.
	if got := systemdArtifact(t, res, ArtifactSystemdUnitPrefix+"debug-shell.service").Attributes[systemdAttrEnabledState]; got != "disabled" {
		t.Errorf("debug-shell enabled state = %q", got)
	}
	if got := systemdArtifact(t, res, ArtifactSystemdRuntimePrefix+"debug-shell.service").Attributes[systemdAttrActiveState]; got != "inactive" {
		t.Errorf("debug-shell active state = %q", got)
	}

	// A unit running as a human account: the capability model needs the name.
	if got := systemdArtifact(t, res, ArtifactSystemdUnitPrefix+"connect-pm2.service").Attributes[systemdAttrUser]; got != "alice" {
		t.Errorf("connect-pm2 user = %q, want alice", got)
	}

	// LoadState=not-found is the only truthful signal that a unit is gone:
	// no observed artifact, and a diagnostic that says so.
	if systemdHasArtifact(res, ArtifactSystemdRuntimePrefix+"nosuchunit-trustfreeze.service") {
		t.Error("a unit with LoadState=not-found got an observed artifact")
	}
	if !systemdWarned(res, DiagSystemdUnitNotFound) {
		t.Error("no unit_not_found diagnostic")
	}
	if got := systemdArtifact(t, res, ArtifactSystemdManager).Attributes[systemdAttrObservedCount]; got != "3" {
		t.Errorf("observed unit count = %q, want 3", got)
	}
}

// TestSystemdCollectHonestStatuses covers the failure shapes of the primary
// source. The refusal shapes come from the fixtures: a non-zero exit code
// alone is not a failure, and empty output alone is not one either
// (testdata/README.md).
func TestSystemdCollectHonestStatuses(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resp       probe.FakeResponse
		wantStatus trustfreeze.ProbeStatus
		wantClass  string
		wantUnits  int
	}{
		{
			// honest-status/empty-result-systemctl-no-match.txt: zero bytes,
			// exit 1. An empty result is captured with an empty list.
			name:       "empty result with exit 1",
			resp:       probe.FakeResponse{ExitCode: 1},
			wantStatus: trustfreeze.StatusCaptured,
			wantUnits:  0,
		},
		{
			name:       "no answer and an explanation on stderr",
			resp:       probe.FakeResponse{ExitCode: 1, Stderr: []byte("some refusal the host printed\n")},
			wantStatus: trustfreeze.StatusFailed,
			wantClass:  probe.ClassTerminated,
		},
		{
			name:       "the tool is missing",
			resp:       probe.FakeResponse{},
			wantStatus: trustfreeze.StatusUnavailable,
			wantClass:  probe.ClassToolMissing,
		},
		{
			name:       "the tool refuses to start",
			resp:       probe.FakeResponse{PermissionDenied: true, ErrMessage: "permission denied"},
			wantStatus: trustfreeze.StatusPermissionDenied,
			wantClass:  probe.ClassPermissionDenied,
		},
		{
			name:       "the tool times out",
			resp:       probe.FakeResponse{TimedOut: true, ErrMessage: "deadline"},
			wantStatus: trustfreeze.StatusTimeout,
			wantClass:  probe.ClassTimeout,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := systemdRunnerWithVersion(t)
			args := []string{"list-unit-files", "--no-legend", "--no-pager"}
			if tc.name == "the tool is missing" {
				// No path for the executable at all: the runner answers
				// tool_missing before any process starts.
				runner = probe.NewFakeRunner()
			} else {
				runner.Script(systemctlExe, args, tc.resp)
			}
			cc, _ := systemdContext(runner)
			res := NewSystemdProbe().Collect(context.Background(), cc)
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %q reason %q, want %q", res.Status, res.Reason, tc.wantStatus)
			}
			if tc.wantClass != "" {
				if res.Error == nil || res.Error.Class != tc.wantClass {
					t.Fatalf("error = %+v, want class %q", res.Error, tc.wantClass)
				}
			}
			units := 0
			for _, a := range res.NormalizedState {
				if strings.HasPrefix(a.ID, ArtifactSystemdUnitPrefix) {
					units++
				}
			}
			if units != tc.wantUnits {
				t.Fatalf("%d unit artifacts, want %d", units, tc.wantUnits)
			}
		})
	}
}

// TestSystemdCollectNeverElevates: no call of the probe goes through an
// elevation helper (playbook L2).
func TestSystemdCollectNeverElevates(t *testing.T) {
	runner := systemdRunnerWithVersion(t)
	runner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
		probe.FakeResponse{Stdout: systemdFixture(t, "systemd/systemctl-list-unit-files.txt")})
	cc, _ := systemdContext(runner)
	NewSystemdProbe().Collect(context.Background(), cc)
	for _, call := range runner.Calls() {
		if call.Executable != systemctlExe {
			t.Errorf("the probe ran %q", call.Executable)
		}
		for _, a := range call.Args {
			if a == "sudo" || a == "pkexec" || a == "doas" || a == "run0" {
				t.Errorf("an elevation helper is in the argument vector: %v", call.Args)
			}
		}
	}
}

// TestSystemdCollectIsDeterministic: two runs over the same input produce the
// same bytes (playbook L8).
func TestSystemdCollectIsDeterministic(t *testing.T) {
	run := func() []byte {
		runner := systemdRunnerWithVersion(t)
		runner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
			probe.FakeResponse{Stdout: systemdFixture(t, "systemd/systemctl-list-unit-files.txt")})
		cc, _ := systemdContext(runner)
		res := NewSystemdProbe().Collect(context.Background(), cc)
		b, err := trustfreeze.MarshalCanonical(res.NormalizedState)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}
	a, b := run(), run()
	if string(a) != string(b) {
		t.Fatal("two runs over the same input produced different artifacts")
	}
}

// TestIsTemplateUnit pins the unit name grammar the probe reads a template
// from: the instance part between "@" and the type suffix is empty. The
// grammar is the only detector; the manager is never asked whether a name is
// a template, because asking is exactly what fails.
func TestIsTemplateUnit(t *testing.T) {
	for name, want := range map[string]bool{
		// Templates, measured on an Ubuntu 22.04 bastion.
		"getty@.service":          true,
		"autovt@.service":         true,
		"apport-forward@.service": true,
		// Measured on the trial host, in systemd/systemctl-list-unit-files.txt.
		"saned@.service":   true,
		"blockdev@.target": true,
		// An instance of a template is a unit with a runtime state.
		"getty@tty1.service": false,
		// Ordinary units.
		"ssh.service":                          false,
		"anacron.timer":                        false,
		`system-systemd\x2dcryptsetup.slice`:   false,
		"actions.runner.alice-m3c-tools.x.svc": false,
		// Degenerate names: no prefix, no type suffix, no name at all.
		"@.service": false,
		"getty@":    false,
		"":          false,
	} {
		if got := IsTemplateUnit(name); got != want {
			t.Errorf("IsTemplateUnit(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestSelectUnitsForShowSkipsTemplateUnits: a template unit is never asked
// about. It has no instance and therefore no runtime state, and a
// "systemctl show" call that names one is refused and takes the rest of the
// batch with it (systemd/systemctl-show-template.stderr.txt).
func TestSelectUnitsForShowSkipsTemplateUnits(t *testing.T) {
	// The three template names are measured on an Ubuntu 22.04 bastion; the
	// column shape is the one of systemd/systemctl-list-unit-files.txt.
	const list = "" +
		"apport-forward@.service enabled enabled\n" +
		"autovt@.service enabled enabled\n" +
		"getty@.service enabled enabled\n" +
		"ssh.service enabled enabled\n"
	files, issues := ParseUnitFiles([]byte(list))
	if len(issues) != 0 {
		t.Fatalf("the list did not parse: %v", issues)
	}
	got, cut := SelectUnitsForShow(files, systemdMaxShowUnits)
	if cut {
		t.Fatal("four units hit the cap")
	}
	if len(got) != 1 || got[0] != "ssh.service" {
		t.Fatalf("selected %v, want only ssh.service", got)
	}
}

// systemdTemplateList names one template unit and one ordinary unit. The
// template name is measured on an Ubuntu 22.04 bastion; the two rows are
// constructed in the column shape of systemd/systemctl-list-unit-files.txt.
const systemdTemplateList = "" +
	"getty@.service enabled enabled\n" +
	"ssh.service enabled enabled\n"

// TestSystemdCollectRecordsTemplateUnit: the probe never asks the manager
// about a template unit, and records it as one instead of leaving a gap. Its
// runtime state is not_applicable WITH a reason, which is the one legitimate
// not_applicable: the thing cannot exist (playbook L1).
func TestSystemdCollectRecordsTemplateUnit(t *testing.T) {
	runner := systemdRunnerWithVersion(t)
	runner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
		probe.FakeResponse{Stdout: []byte(systemdTemplateList)})
	// The only show call the probe may make. A call that also names the
	// template is scripted with the measured refusal, so a probe that asks
	// anyway gets the measured answer and loses ssh.service with it.
	runner.Script(systemctlExe, []string{"show", "--no-pager", "-p", systemdShowProperties, "ssh.service"},
		probe.FakeResponse{Stdout: systemdFixture(t, "systemd/systemctl-show-enabled-running.txt")})
	runner.Script(systemctlExe, []string{"show", "--no-pager", "-p", systemdShowProperties, "getty@.service", "ssh.service"},
		probe.FakeResponse{ExitCode: 1, Stderr: systemdFixture(t, "systemd/systemctl-show-template.stderr.txt")})

	cc, _ := systemdContext(runner)
	res := NewSystemdProbe().Collect(context.Background(), cc)

	for _, call := range runner.Calls() {
		for _, a := range call.Args {
			if IsTemplateUnit(a) {
				t.Fatalf("the probe asked the manager about a template unit: %v", call.Args)
			}
		}
	}
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status = %q reason %q, want captured: a template is not a gap", res.Status, res.Reason)
	}
	tmpl := systemdArtifact(t, res, ArtifactSystemdUnitPrefix+"getty@.service")
	if tmpl.State != trustfreeze.StateDeclared {
		t.Errorf("template artifact state = %q, want declared", tmpl.State)
	}
	for k, want := range map[string]string{
		systemdAttrUnit:         "getty@.service",
		systemdAttrTemplate:     "true",
		systemdAttrRuntimeState: systemdRuntimeNotApplicable,
	} {
		if got := tmpl.Attributes[k]; got != want {
			t.Errorf("template %s = %q, want %q", k, got, want)
		}
	}
	if tmpl.Attributes[systemdAttrRuntimeReason] == "" {
		t.Error("the template artifact carries no reason for its not_applicable runtime state")
	}
	if systemdHasArtifact(res, ArtifactSystemdRuntimePrefix+"getty@.service") {
		t.Error("a template unit got an observed runtime artifact")
	}
	// The ordinary unit in the same list is unaffected.
	if !systemdHasArtifact(res, ArtifactSystemdRuntimePrefix+"ssh.service") {
		t.Error("ssh.service has no runtime artifact although its own call answered")
	}
	if got := systemdArtifact(t, res, ArtifactSystemdUnitPrefix+"ssh.service").Attributes[systemdAttrTemplate]; got != "" {
		t.Errorf("ssh.service carries template = %q", got)
	}
	mgr := systemdArtifact(t, res, ArtifactSystemdManager)
	if mgr.Attributes[systemdAttrTemplateCount] != "1" || mgr.Attributes[systemdAttrObservedCount] != "1" {
		t.Errorf("manager counts = %v", mgr.Attributes)
	}
	if !systemdWarned(res, DiagSystemdTemplateUnit) {
		t.Error("no diagnostic names the template units that were not asked about")
	}
	if systemdWarned(res, trustfreeze.DiagFieldMissing) {
		t.Error("a template counts as a unit with an unknown runtime state")
	}
}

// systemdBatchList is the input of the retry test. Every row is constructed,
// in the column shape of systemd/systemctl-list-unit-files.txt; two of the
// three unit names are the ones the measured "systemctl show" fixtures answer
// for. Nothing here claims to be host output.
const systemdBatchList = "" +
	"connect-pm2.service enabled enabled\n" +
	"debug-shell.service enabled enabled\n" +
	"refused-trustfreeze.service enabled enabled\n" +
	"ssh.service enabled enabled\n"

// TestSystemdCollectRetriesAfterAbortedBatch: one unit name the manager
// refuses must cost one unit, not the batch.
//
// The measured shape (Ubuntu 22.04 bastion, transcribed in
// systemd/systemctl-show-batch-aborted.txt and
// systemd/systemctl-show-template.stderr.txt): "systemctl show" for several
// units stops at the name it refuses. The units before it are answered for,
// the units after it are not, and the call exits 1. The refused name there
// was a template, which this build no longer asks about; the name below
// stands for any other name the manager refuses, and the refusal message is
// the measured one with that name in it.
func TestSystemdCollectRetriesAfterAbortedBatch(t *testing.T) {
	const refused = "refused-trustfreeze.service"
	refusal := []byte(strings.Replace(string(systemdFixture(t, "systemd/systemctl-show-template.stderr.txt")),
		"getty@.service", refused, 1))

	runner := systemdRunnerWithVersion(t)
	runner.Script(systemctlExe, []string{"list-unit-files", "--no-legend", "--no-pager"},
		probe.FakeResponse{Stdout: []byte(systemdBatchList)})
	batch := []string{"connect-pm2.service", "debug-shell.service", refused, "ssh.service"}
	runner.Script(systemctlExe, append([]string{"show", "--no-pager", "-p", systemdShowProperties}, batch...),
		probe.FakeResponse{
			ExitCode: 1,
			Stdout:   systemdFixture(t, "systemd/systemctl-show-batch-aborted.txt"),
			Stderr:   refusal,
		})
	// The two names the aborted call left unanswered, asked for one at a time.
	runner.Script(systemctlExe, []string{"show", "--no-pager", "-p", systemdShowProperties, refused},
		probe.FakeResponse{ExitCode: 1, Stderr: refusal})
	runner.Script(systemctlExe, []string{"show", "--no-pager", "-p", systemdShowProperties, "ssh.service"},
		probe.FakeResponse{Stdout: systemdFixture(t, "systemd/systemctl-show-enabled-running.txt")})

	cc, _ := systemdContext(runner)
	res := NewSystemdProbe().Collect(context.Background(), cc)

	// The units before the failure keep the answer the batch did give.
	for _, u := range []string{"connect-pm2.service", "debug-shell.service"} {
		if !systemdHasArtifact(res, ArtifactSystemdRuntimePrefix+u) {
			t.Errorf("%s has no runtime artifact although the batch answered for it before it stopped", u)
		}
	}
	// The unit after the failure comes back through the retry.
	if !systemdHasArtifact(res, ArtifactSystemdRuntimePrefix+"ssh.service") {
		t.Error("ssh.service has no runtime artifact: the name after the failure was not re-queried")
	}
	if got := systemdArtifact(t, res, ArtifactSystemdRuntimePrefix+"ssh.service").Attributes[systemdAttrActiveState]; got != "active" {
		t.Errorf("ssh.service active state = %q, want active", got)
	}
	// The name that truly could not be read stays unknown, and says so.
	if systemdHasArtifact(res, ArtifactSystemdRuntimePrefix+refused) {
		t.Error("the refused unit got a runtime artifact")
	}
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status = %q reason %q, want partial: one unit state is unknown", res.Status, res.Reason)
	}

	var split, notRead string
	for _, w := range res.Warnings {
		switch w.Code {
		case DiagSystemdBatchSplit:
			split = w.Message
		case DiagSystemdUnitStateNotRead:
			notRead = w.Message
		}
	}
	switch {
	case split == "":
		t.Fatalf("no %s diagnostic: %v", DiagSystemdBatchSplit, res.Warnings)
	case !strings.Contains(split, "2 of 4"):
		t.Errorf("the diagnostic does not say how much of the batch was answered: %q", split)
	case !strings.Contains(split, "2 unit(s)"):
		t.Errorf("the diagnostic does not say how many units were re-queried: %q", split)
	}
	if !strings.Contains(notRead, refused) {
		t.Errorf("the unreadable unit has no diagnostic of its own: %q", notRead)
	}
	// One bad name costs one unit: three of the four are known.
	runtime := 0
	for _, a := range res.NormalizedState {
		if strings.HasPrefix(a.ID, ArtifactSystemdRuntimePrefix) {
			runtime++
		}
	}
	if runtime != 3 {
		t.Fatalf("%d runtime artifacts, want 3", runtime)
	}
}
