package linux

// Tests for linux.mounts (SPEC-0471 TF06-R3).
//
// The document under test is mounts/findmnt-json.json, transcribed from a
// real Ubuntu 24.04.1 host and sanitized (testdata/README.md): 25 of the 113
// mount points of that host, in findmnt's own formatting. The parser is a
// pure function over bytes and the probe runs against probe.FakeRunner, so
// the whole file passes on any operating system.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// mountsContext builds a CollectContext around runner.
func mountsContext(runner *probe.FakeRunner) (probe.CollectContext, *probe.EvidenceBuffer) {
	ev := probe.NewEvidenceBuffer(MountsProbeID, probe.Limits{})
	return probe.CollectContext{
		HostContext: probe.HostContext{
			GOOS: "linux", GOARCH: "amd64",
			Hostname:  func() (string, error) { return "host-a.example", nil },
			Files:     probe.FakeFiles{},
			Runner:    runner,
			Clock:     trustfreeze.FixedClock{T: linuxTestTime},
			Privilege: probe.PrivilegeUser,
		},
		ProbeID:  MountsProbeID,
		Redactor: redact.Default(),
		Evidence: ev,
		Support:  probe.Supported(),
	}, ev
}

// mountsRunnerWithVersion scripts "findmnt --version" from the fixture.
func mountsRunnerWithVersion(t *testing.T) *probe.FakeRunner {
	t.Helper()
	return probe.NewFakeRunner().AddTool(findmntExe, "/usr/bin/findmnt").
		Script(findmntExe, []string{"--version"},
			probe.FakeResponse{Stdout: systemdFixture(t, "mounts/findmnt-version.txt")})
}

var mountsTableArgs = []string{"--json", "-o", findmntColumns}

func mountsArtifact(t *testing.T, res trustfreeze.ProbeResult, id string) trustfreeze.Artifact {
	t.Helper()
	for _, a := range res.NormalizedState {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no artifact %q in %d artifacts", id, len(res.NormalizedState))
	return trustfreeze.Artifact{}
}

// TestParseFindmntJSONFixture flattens the measured document.
func TestParseFindmntJSONFixture(t *testing.T) {
	entries, issues, err := ParseFindmntJSON(systemdFixture(t, "mounts/findmnt-json.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues in the measured document: %+v", issues)
	}
	if len(entries) != 25 {
		t.Fatalf("parsed %d mount points, want 25", len(entries))
	}
	// Document order is kept: the tree is walked depth first, so a child
	// follows its parent.
	if entries[0].Target != "/" || entries[1].Target != "/sys" {
		t.Fatalf("order = %q, %q", entries[0].Target, entries[1].Target)
	}
	if entries[0].Source != "/dev/sdb1" || entries[0].FSType != "xfs" {
		t.Errorf("root mount = %+v", entries[0])
	}
	if entries[1].Depth != 1 || entries[2].Depth != 2 {
		t.Errorf("depths = %d, %d, want 1 and 2", entries[1].Depth, entries[2].Depth)
	}
	// The same target carries two mounts: an autofs and the binfmt_misc
	// mounted over it. Both are kept, because an overmount hides what is
	// below it.
	var over []MountEntry
	for _, e := range entries {
		if e.Target == "/proc/sys/fs/binfmt_misc" {
			over = append(over, e)
		}
	}
	if len(over) != 2 {
		t.Fatalf("%d mounts at /proc/sys/fs/binfmt_misc, want 2", len(over))
	}
	if over[0].FSType != "autofs" || over[1].FSType != "binfmt_misc" {
		t.Errorf("overmount fstypes = %q, %q", over[0].FSType, over[1].FSType)
	}
	byTarget := map[string]MountEntry{}
	for _, e := range entries {
		if _, seen := byTarget[e.Target]; !seen {
			byTarget[e.Target] = e
		}
	}
	if got := byTarget["/sys"].Options; strings.Join(got, ",") != "rw,nosuid,nodev,noexec,relatime" {
		t.Errorf("/sys options = %v", got)
	}
	// The option string of an overlay mount carries a twelve element lowerdir
	// chain; the parser keeps it as options and the probe drops it.
	if n := len(byTarget["/var/lib/docker/overlay2/0101010101010101010101010101010101010101010101010101010101010101/merged"].Options); n == 0 {
		t.Error("the overlay mount lost its options")
	}
}

// TestParseFindmntJSONIssues covers documents a parser must not swallow.
func TestParseFindmntJSONIssues(t *testing.T) {
	for _, tc := range []struct {
		name       string
		in         string
		wantErr    bool
		wantCount  int
		wantIssues []MountIssue
	}{
		{"empty object", `{}`, false, 0, nil},
		{"not json", `findmnt: unknown column`, true, 0, nil},
		{"truncated", `{"filesystems":[{"target":"/"`, true, 0, nil},
		{
			"record without a target",
			`{"filesystems":[{"source":"tmpfs","fstype":"tmpfs","options":"rw"}]}`,
			false, 0,
			[]MountIssue{{Path: "filesystems[0]", Reason: MountIssueNoTarget}},
		},
		{
			// A record without a target still has its children read: the
			// subtree is not lost with it.
			"child of a record without a target",
			`{"filesystems":[{"children":[{"target":"/x","source":"s","fstype":"f","options":"rw"}]}]}`,
			false, 1,
			[]MountIssue{{Path: "filesystems[0]", Reason: MountIssueNoTarget}},
		},
		{
			"null source",
			`{"filesystems":[{"target":"/x","source":null,"fstype":"f","options":"rw"}]}`,
			false, 1, nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries, issues, err := ParseFindmntJSON([]byte(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Fatal("no error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(entries) != tc.wantCount {
				t.Errorf("entries = %d, want %d", len(entries), tc.wantCount)
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

// TestParseFindmntJSONDepthLimit: a document nested deeper than the parser
// follows is reported, not followed.
func TestParseFindmntJSONDepthLimit(t *testing.T) {
	doc := `{"filesystems":[`
	closing := "]}"
	for i := 0; i < mountsMaxDepth+2; i++ {
		doc += `{"target":"/x","source":"s","fstype":"f","options":"rw","children":[`
		closing = "]}" + closing
	}
	entries, issues, err := ParseFindmntJSON([]byte(doc + closing))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != mountsMaxDepth {
		t.Fatalf("entries = %d, want %d", len(entries), mountsMaxDepth)
	}
	if len(issues) != 1 || issues[0].Reason != MountIssueTooDeep {
		t.Fatalf("issues = %+v", issues)
	}
}

// TestSplitMountSource reads the mount root findmnt prints in brackets.
func TestSplitMountSource(t *testing.T) {
	for _, tc := range []struct{ in, name, root string }{
		{"/dev/sdb1", "/dev/sdb1", ""},
		{"tmpfs", "tmpfs", ""},
		{"tmpfs[/snapd/ns]", "tmpfs", "/snapd/ns"},
		// A namespace inode: the brackets nest, and the split is at the first
		// one.
		{"nsfs[net:[4026531833]]", "nsfs", "net:[4026531833]"},
		{"nsfs[mnt:[4026535078]]", "nsfs", "mnt:[4026535078]"},
		{"", "", ""},
		{"[/only]", "[/only]", ""},
	} {
		t.Run(tc.in, func(t *testing.T) {
			name, root := SplitMountSource(tc.in)
			if name != tc.name || root != tc.root {
				t.Fatalf("= %q, %q, want %q, %q", name, root, tc.name, tc.root)
			}
		})
	}
}

// TestMountTrustOptions reads the flags that decide what may be done on a
// mount, out of measured option strings.
func TestMountTrustOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want MountFlags
	}{
		{"root filesystem", "rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota",
			MountFlags{ReadOnly: MountValueNo, NoSUID: MountValueNo, NoDev: MountValueNo, NoExec: MountValueNo}},
		{"sysfs", "rw,nosuid,nodev,noexec,relatime",
			MountFlags{ReadOnly: MountValueNo, NoSUID: MountValueYes, NoDev: MountValueYes, NoExec: MountValueYes}},
		{"squashfs snap", "ro,nodev,relatime,errors=continue,threads=single",
			MountFlags{ReadOnly: MountValueYes, NoSUID: MountValueNo, NoDev: MountValueYes, NoExec: MountValueNo}},
		{"tmpfs with values", "rw,nosuid,nodev,relatime,size=2452144k,nr_inodes=613036,mode=700,uid=1000,gid=1000,inode64",
			MountFlags{ReadOnly: MountValueNo, NoSUID: MountValueYes, NoDev: MountValueYes, NoExec: MountValueNo}},
		{"no ro and no rw", "relatime",
			MountFlags{ReadOnly: MountValueUnknown, NoSUID: MountValueNo, NoDev: MountValueNo, NoExec: MountValueNo}},
		{"empty", "",
			MountFlags{ReadOnly: MountValueUnknown, NoSUID: MountValueNo, NoDev: MountValueNo, NoExec: MountValueNo}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MountTrustOptions(SplitMountOptions(tc.in)); got != tc.want {
				t.Fatalf("= %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestParseFindmntVersion keeps the version line.
func TestParseFindmntVersion(t *testing.T) {
	v, err := ParseFindmntVersion(systemdFixture(t, "mounts/findmnt-version.txt"))
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if v != "findmnt from util-linux 2.39.3" {
		t.Fatalf("version = %q", v)
	}
	if _, err := ParseFindmntVersion(nil); err == nil {
		t.Error("an empty answer returned no error")
	}
}

// TestMountsDescriptor pins the declaration.
func TestMountsDescriptor(t *testing.T) {
	d := NewMountsProbe().Descriptor()
	if err := d.Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if d.ID != MountsProbeID || d.Version != MountsProbeVersion {
		t.Fatalf("identity = %s/%s", d.ID, d.Version)
	}
	if d.RequiredPrivilege != probe.PrivilegeUser {
		t.Errorf("required privilege = %q, want user: the probe never elevates", d.RequiredPrivilege)
	}
	if !d.SupportsPlatform("linux") || d.SupportsPlatform("darwin") {
		t.Errorf("platforms = %v", d.Platforms)
	}
	if !sort.StringsAreSorted(d.Provides) {
		t.Errorf("provides is not sorted: %v", d.Provides)
	}
}

// TestMountsSupport covers the availability answers.
func TestMountsSupport(t *testing.T) {
	p := NewMountsProbe()
	for _, tc := range []struct {
		name       string
		goos       string
		runner     *probe.FakeRunner
		wantAvail  bool
		wantStatus trustfreeze.ProbeStatus
	}{
		{"linux with findmnt", "linux", probe.NewFakeRunner().AddTool(findmntExe, "/usr/bin/findmnt"), true, ""},
		{"findmnt missing", "linux", probe.NewFakeRunner(), false, trustfreeze.StatusUnavailable},
		{"findmnt not executable", "linux", probe.NewFakeRunner().DenyTool(findmntExe, "/usr/bin/findmnt"), false, trustfreeze.StatusPermissionDenied},
		{"other platform", "windows", probe.NewFakeRunner().AddTool(findmntExe, "/usr/bin/findmnt"), false, trustfreeze.StatusUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Support(context.Background(), probe.HostContext{GOOS: tc.goos, Runner: tc.runner})
			if err := got.Validate(); err != nil {
				t.Fatalf("support result: %v", err)
			}
			if got.Available != tc.wantAvail || got.Status != tc.wantStatus {
				t.Fatalf("support = %+v, want available %v status %q", got, tc.wantAvail, tc.wantStatus)
			}
		})
	}
}

// TestMountsCollectFromFixture runs the probe against the measured document.
func TestMountsCollectFromFixture(t *testing.T) {
	runner := mountsRunnerWithVersion(t)
	runner.Script(findmntExe, mountsTableArgs,
		probe.FakeResponse{Stdout: systemdFixture(t, "mounts/findmnt-json.json")})
	cc, ev := mountsContext(runner)
	res := NewMountsProbe().Collect(context.Background(), cc)

	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status = %q reason %q, want captured", res.Status, res.Reason)
	}
	mounts := 0
	for _, a := range res.NormalizedState {
		if err := trustfreeze.ValidateArtifactID(a.ID); err != nil {
			t.Errorf("artifact id %q: %v", a.ID, err)
		}
		if a.ID == ArtifactMountTable {
			continue
		}
		mounts++
		if a.State != trustfreeze.StateObserved {
			t.Errorf("%s has state %q, want observed", a.ID, a.State)
		}
		if a.Provenance.ToolVersion != "findmnt from util-linux 2.39.3" {
			t.Errorf("%s records tool version %q", a.ID, a.Provenance.ToolVersion)
		}
	}
	if mounts != 25 {
		t.Fatalf("%d mount artifacts, want 25", mounts)
	}
	if got := mountsArtifact(t, res, ArtifactMountTable).Attributes[mountsAttrCount]; got != "25" {
		t.Errorf("mount_count = %q, want 25", got)
	}

	for _, tc := range []struct {
		id   string
		want map[string]string
	}{
		{ArtifactMountPrefix + "root", map[string]string{
			mountsAttrTarget: "/", mountsAttrSource: "/dev/sdb1", mountsAttrFSType: "xfs",
			mountsAttrReadOnly: MountValueNo, mountsAttrNoSUID: MountValueNo,
			mountsAttrNoDev: MountValueNo, mountsAttrNoExec: MountValueNo,
			mountsAttrSubtree: MountValueNo,
		}},
		{ArtifactMountPrefix + "sys", map[string]string{
			mountsAttrTarget: "/sys", mountsAttrSource: "sysfs", mountsAttrFSType: "sysfs",
			mountsAttrReadOnly: MountValueNo, mountsAttrNoSUID: MountValueYes,
			mountsAttrNoDev: MountValueYes, mountsAttrNoExec: MountValueYes,
			mountsAttrSubtree: MountValueNo,
		}},
		// A read only snap image on a loop device.
		{ArtifactMountPrefix + "snap/bare/5", map[string]string{
			mountsAttrTarget: "/snap/bare/5", mountsAttrSource: "/dev/loop0",
			mountsAttrFSType: "squashfs", mountsAttrReadOnly: MountValueYes,
			mountsAttrNoDev: MountValueYes, mountsAttrNoExec: MountValueNo,
		}},
		// A mount whose root is a subtree of its source filesystem: the shape
		// a bind mount has.
		{ArtifactMountPrefix + "run/snapd/ns", map[string]string{
			mountsAttrTarget: "/run/snapd/ns", mountsAttrSource: "tmpfs",
			mountsAttrMountRoot: "/snapd/ns", mountsAttrSubtree: MountValueYes,
		}},
		// A namespace mount: the mount root is a runtime identifier, not a
		// path, so it is not recorded and the mount is not a subtree mount.
		{ArtifactMountPrefix + "run/docker/netns/default", map[string]string{
			mountsAttrTarget: "/run/docker/netns/default", mountsAttrSource: "nsfs",
			mountsAttrFSType: "nsfs", mountsAttrSubtree: MountValueNo,
		}},
		// The overmounted target: the first mount at it keeps the plain id.
		{ArtifactMountPrefix + "proc/sys/fs/binfmt_misc", map[string]string{
			mountsAttrTarget: "/proc/sys/fs/binfmt_misc", mountsAttrSource: "systemd-1",
			mountsAttrFSType: "autofs",
		}},
		{ArtifactMountPrefix + "proc/sys/fs/binfmt_misc+2", map[string]string{
			mountsAttrTarget: "/proc/sys/fs/binfmt_misc", mountsAttrSource: "binfmt_misc",
			mountsAttrFSType: "binfmt_misc",
		}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			a := mountsArtifact(t, res, tc.id)
			for k, want := range tc.want {
				if got := a.Attributes[k]; got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
		})
	}

	// A namespace inode is a runtime identifier and is never recorded.
	if _, ok := mountsArtifact(t, res, ArtifactMountPrefix+"run/docker/netns/default").Attributes[mountsAttrMountRoot]; ok {
		t.Error("the namespace mount root was recorded")
	}
	// Nothing volatile and nothing long from the option string reaches an
	// artifact (playbook L6, L8).
	for _, a := range res.NormalizedState {
		for k, v := range a.Attributes {
			for _, forbidden := range []string{"lowerdir", "upperdir", "LAYER01", "pipe_ino", "nr_inodes", "size=", "pgrp="} {
				if strings.Contains(v, forbidden) {
					t.Errorf("%s attribute %s carries %q: %q", a.ID, k, forbidden, v)
				}
			}
		}
	}
	names := []string{}
	for _, it := range ev.Close() {
		names = append(names, it.Name)
	}
	if len(names) != 2 {
		t.Errorf("evidence = %v, want the version and the document", names)
	}
}

// TestMountsCollectHonestStatuses covers the failure shapes of the primary
// source.
func TestMountsCollectHonestStatuses(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resp       probe.FakeResponse
		noTool     bool
		wantStatus trustfreeze.ProbeStatus
		wantClass  string
		wantMounts int
	}{
		{
			name:       "empty result with exit 0",
			resp:       probe.FakeResponse{},
			wantStatus: trustfreeze.StatusCaptured,
		},
		{
			name:       "empty result with exit 1",
			resp:       probe.FakeResponse{ExitCode: 1},
			wantStatus: trustfreeze.StatusCaptured,
		},
		{
			name:       "no answer and an explanation on stderr",
			resp:       probe.FakeResponse{ExitCode: 1, Stderr: []byte("some refusal the host printed\n")},
			wantStatus: trustfreeze.StatusFailed,
			wantClass:  probe.ClassTerminated,
		},
		{
			name:       "the document cannot be read",
			resp:       probe.FakeResponse{Stdout: []byte("{\"filesystems\":[")},
			wantStatus: trustfreeze.StatusFailed,
			wantClass:  MountsClassParseFailed,
		},
		{
			name:       "the tool is missing",
			noTool:     true,
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
			runner := probe.NewFakeRunner()
			if !tc.noTool {
				runner = mountsRunnerWithVersion(t)
				runner.Script(findmntExe, mountsTableArgs, tc.resp)
			}
			cc, _ := mountsContext(runner)
			res := NewMountsProbe().Collect(context.Background(), cc)
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %q reason %q, want %q", res.Status, res.Reason, tc.wantStatus)
			}
			if tc.wantClass != "" {
				if res.Error == nil || res.Error.Class != tc.wantClass {
					t.Fatalf("error = %+v, want class %q", res.Error, tc.wantClass)
				}
			}
			mounts := 0
			for _, a := range res.NormalizedState {
				if a.ID != ArtifactMountTable {
					mounts++
				}
			}
			if mounts != tc.wantMounts {
				t.Fatalf("%d mount artifacts, want %d", mounts, tc.wantMounts)
			}
		})
	}
}

// TestMountsCollectEmptyTableIsCaptured: an empty result that is genuinely
// empty is captured with an empty list, and the artifact says so
// (playbook L1).
func TestMountsCollectEmptyTableIsCaptured(t *testing.T) {
	runner := mountsRunnerWithVersion(t)
	runner.Script(findmntExe, mountsTableArgs, probe.FakeResponse{})
	cc, _ := mountsContext(runner)
	res := NewMountsProbe().Collect(context.Background(), cc)
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status = %q, want captured", res.Status)
	}
	if got := mountsArtifact(t, res, ArtifactMountTable).Attributes[mountsAttrCount]; got != "0" {
		t.Fatalf("mount_count = %q, want 0", got)
	}
}

// TestMountsCollectNeverElevates: no call of the probe goes through an
// elevation helper (playbook L2).
func TestMountsCollectNeverElevates(t *testing.T) {
	runner := mountsRunnerWithVersion(t)
	runner.Script(findmntExe, mountsTableArgs,
		probe.FakeResponse{Stdout: systemdFixture(t, "mounts/findmnt-json.json")})
	cc, _ := mountsContext(runner)
	NewMountsProbe().Collect(context.Background(), cc)
	for _, call := range runner.Calls() {
		if call.Executable != findmntExe {
			t.Errorf("the probe ran %q", call.Executable)
		}
	}
}

// TestMountsCollectIsDeterministic: two runs over the same input produce the
// same bytes, whatever order the kernel listed the mounts in (playbook L8).
func TestMountsCollectIsDeterministic(t *testing.T) {
	run := func() []byte {
		runner := mountsRunnerWithVersion(t)
		runner.Script(findmntExe, mountsTableArgs,
			probe.FakeResponse{Stdout: systemdFixture(t, "mounts/findmnt-json.json")})
		cc, _ := mountsContext(runner)
		res := NewMountsProbe().Collect(context.Background(), cc)
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

// TestMountArtifactSuffix covers the targets an artifact id may not carry
// verbatim.
func TestMountArtifactSuffix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/", "root"},
		{"/home", "home"},
		{"/run/user/1000", "run/user/1000"},
		{"/mnt/with space", "mnt/with_space"},
		{`/mnt/back\slash`, "mnt/back_slash"},
		{"/mnt/./dot", "mnt/_/dot"},
		{"/mnt/../up", "mnt/__/up"},
		{"/mnt//empty", "mnt/_/empty"},
		{"/mnt/~tilde", "mnt/_tilde"},
		{"/C:/drive", "C_/drive"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got := mountArtifactSuffix(tc.in)
			if got != tc.want {
				t.Fatalf("= %q, want %q", got, tc.want)
			}
			if err := trustfreeze.ValidateArtifactID(ArtifactMountPrefix + got); err != nil {
				t.Fatalf("the id is not valid: %v", err)
			}
		})
	}
}
