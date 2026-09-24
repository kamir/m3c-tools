package linux

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// invUsersRunner scripts the whole happy path of linux.users.
func invUsersRunner(t *testing.T) *probe.FakeRunner {
	t.Helper()
	r := probe.NewFakeRunner()
	invScript(t, r, "users/getent-passwd.txt")
	invScript(t, r, "users/getent-group.txt")
	invScript(t, r, "users/id.txt")
	invScript(t, r, "users/getent-version.txt")
	invScript(t, r, "users/id-version.txt")
	return r
}

// TestUsersProbeArgvMatchesFixtureIndex pins the calls of the probe to the
// argv the fixtures were taken with.
func TestUsersProbeArgvMatchesFixtureIndex(t *testing.T) {
	for _, tc := range []struct {
		path string
		want []string
	}{
		{"users/getent-passwd.txt", []string{"getent", "passwd"}},
		{"users/getent-group.txt", []string{"getent", "group"}},
		{"users/id.txt", []string{"id"}},
	} {
		if got := invEntry(t, tc.path).Command; !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s: commands.json argv %q, probe argv %q", tc.path, got, tc.want)
		}
	}
}

// TestPasswdEntryCarriesNoPasswordField is the type level of playbook L4: the
// second field of a passwd line holds "x" on a shadowed system and the hash
// itself on an unshadowed one, so the model has no place to put it.
func TestPasswdEntryCarriesNoPasswordField(t *testing.T) {
	for _, tc := range []struct {
		typ  reflect.Type
		want []string
	}{
		{reflect.TypeOf(PasswdEntry{}), []string{"Name", "UID", "GID", "Home", "Shell"}},
		{reflect.TypeOf(GroupEntry{}), []string{"Name", "GID", "Members"}},
	} {
		var got []string
		for i := 0; i < tc.typ.NumField(); i++ {
			got = append(got, tc.typ.Field(i).Name)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s has fields %q, want %q", tc.typ.Name(), got, tc.want)
		}
	}
}

func TestParseGetentPasswdFixture(t *testing.T) {
	users, issues := ParseGetentPasswd(invBytes(t, "users/getent-passwd.txt"))
	if len(issues) != 0 {
		t.Fatalf("issues %+v", issues)
	}
	if len(users) != 53 {
		t.Fatalf("parsed %d accounts, want 53", len(users))
	}
	byName := map[string]PasswdEntry{}
	for _, u := range users {
		byName[u.Name] = u
	}
	root := byName["root"]
	if root != (PasswdEntry{Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"}) {
		t.Fatalf("root parsed as %+v", root)
	}
	if !root.SystemAccount() || !root.HasLoginShell() || root.HumanUsable() {
		t.Fatalf("root: system %v login %v human %v", root.SystemAccount(), root.HasLoginShell(), root.HumanUsable())
	}
	// An empty GECOS field (_apt), a GECOS with trailing commas (dhcpcd) and
	// a false shell all parse without an issue.
	if byName["_apt"].UID != 42 || byName["dhcpcd"].Shell != "/bin/false" {
		t.Fatalf("_apt %+v dhcpcd %+v", byName["_apt"], byName["dhcpcd"])
	}
	for _, tc := range []struct {
		name   string
		system bool
		login  bool
		human  bool
	}{
		{"alice", false, true, true},         // the interactive account
		{"deploy", false, true, true},        // a service account with a shell
		{"nobody", false, false, false},      // uid 65534, never a person
		{"www-data", true, false, false},     // system, nologin
		{"snap_daemon", false, false, false}, // regular uid, /usr/bin/false
		{"systemd-network", true, false, false},
	} {
		u := byName[tc.name]
		if u.Name == "" {
			t.Fatalf("no account %s in the fixture", tc.name)
		}
		if u.SystemAccount() != tc.system || u.HasLoginShell() != tc.login || u.HumanUsable() != tc.human {
			t.Fatalf("%s (uid %d, shell %s): system %v login %v human %v, want %v %v %v",
				tc.name, u.UID, u.Shell, u.SystemAccount(), u.HasLoginShell(), u.HumanUsable(), tc.system, tc.login, tc.human)
		}
	}
}

func TestParseGetentPasswdIssues(t *testing.T) {
	// Constructed input, not a fixture.
	in := []byte("ok:x:1000:1000::/home/ok:/bin/bash\nshort:x:1\nbad:x:notanumber:1::/home/bad:/bin/sh\n:x:1:1::/h:/bin/sh\n")
	users, issues := ParseGetentPasswd(in)
	if len(users) != 1 {
		t.Fatalf("parsed %+v", users)
	}
	if len(issues) != 3 || issues[0].Line != 2 || issues[1].Line != 3 || issues[2].Line != 4 {
		t.Fatalf("issues %+v", issues)
	}
	for _, is := range issues {
		if strings.Contains(is.Reason, "/home/bad") {
			t.Fatalf("an issue reason repeats the record: %q", is.Reason)
		}
	}
}

func TestParseGetentGroupFixture(t *testing.T) {
	groups, issues := ParseGetentGroup(invBytes(t, "users/getent-group.txt"))
	if len(issues) != 0 {
		t.Fatalf("issues %+v", issues)
	}
	if len(groups) != 81 {
		t.Fatalf("parsed %d groups, want 81", len(groups))
	}
	byName := map[string]GroupEntry{}
	for _, g := range groups {
		byName[g.Name] = g
	}
	if got := byName["sudo"]; got.GID != 27 || !reflect.DeepEqual(got.Members, []string{"alice"}) {
		t.Fatalf("sudo group %+v", got)
	}
	if got := byName["docker"]; got.GID != 984 || !reflect.DeepEqual(got.Members, []string{"alice"}) {
		t.Fatalf("docker group %+v", got)
	}
	// A multi member list arrives sorted, an empty one arrives empty.
	if got := byName["adm"]; !reflect.DeepEqual(got.Members, []string{"alice", "syslog"}) {
		t.Fatalf("adm members %q", got.Members)
	}
	if len(byName["root"].Members) != 0 {
		t.Fatalf("root group members %q, want none", byName["root"].Members)
	}
}

func TestParseGetentGroupTwoKeysInOneCall(t *testing.T) {
	groups, issues := ParseGetentGroup(invBytes(t, "users/getent-group-sudo-docker.txt"))
	if len(issues) != 0 || len(groups) != 2 {
		t.Fatalf("groups %+v issues %+v", groups, issues)
	}
	if groups[0].Name != "sudo" || groups[1].Name != "docker" {
		t.Fatalf("groups %+v", groups)
	}
}

func TestParseIDFixtures(t *testing.T) {
	info, err := ParseID(invBytes(t, "users/id.txt"))
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	if info.UID != 1000 || info.User != "alice" || info.GID != 1000 || info.Group != "alice" {
		t.Fatalf("id parsed as %+v", info)
	}
	if len(info.Groups) != 9 {
		t.Fatalf("%d groups, want 9: %+v", len(info.Groups), info.Groups)
	}
	// The two privilege relevant memberships of this account.
	names := info.GroupNames()
	if !invContains(names, "sudo") || !invContains(names, "docker") {
		t.Fatalf("group names %q", names)
	}
	for i := 1; i < len(info.Groups); i++ {
		if info.Groups[i-1].GID > info.Groups[i].GID {
			t.Fatalf("groups are not sorted: %+v", info.Groups)
		}
	}

	service, err := ParseID(invBytes(t, "users/id-service-account.txt"))
	if err != nil {
		t.Fatalf("id deploy: %v", err)
	}
	if service.UID != 1001 || len(service.Groups) != 1 || service.Groups[0].Name != "deploy" {
		t.Fatalf("service account %+v", service)
	}
}

func TestParseIDTolerantAndStrict(t *testing.T) {
	// Constructed: an SELinux host appends a context field, and an id that
	// resolves no name prints the number alone. Neither is an error.
	info, err := ParseID([]byte("uid=0(root) gid=0(root) groups=0(root),4242 context=unconfined_u:unconfined_r:unconfined_t:s0\n"))
	if err != nil {
		t.Fatalf("tolerant parse: %v", err)
	}
	if !reflect.DeepEqual(info.GroupNames(), []string{"4242", "root"}) {
		t.Fatalf("group names %q", info.GroupNames())
	}
	for _, in := range []string{"", "\n", "no fields here"} {
		if _, err := ParseID([]byte(in)); !errors.Is(err, ErrNoIDLine) {
			t.Fatalf("input %q gave %v, want ErrNoIDLine", in, err)
		}
	}
	if _, err := ParseID([]byte("uid=notanumber(root)\n")); err == nil {
		t.Fatal("a uid that is not a number must be an error, never a zero")
	}
}

func TestParseGNUToolVersion(t *testing.T) {
	if got := ParseGNUToolVersion(invBytes(t, "users/getent-version.txt")); got != "2.39" {
		t.Fatalf("getent version %q", got)
	}
	if got := ParseGNUToolVersion(invBytes(t, "users/id-version.txt")); got != "9.4" {
		t.Fatalf("id version %q", got)
	}
	for _, in := range []string{"", "id\n", "id (GNU coreutils) unknown\n"} {
		if got := ParseGNUToolVersion([]byte(in)); got != "" {
			t.Fatalf("input %q yielded %q, want the empty string", in, got)
		}
	}
}

func TestUsersProbeCollectsFixtures(t *testing.T) {
	res, evidence := invRun(t, NewUsersProbe(), invUsersRunner(t))
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s, reason %q, warnings %+v", res.Status, res.Reason, res.Warnings)
	}
	if len(res.NormalizedState) != 53+81 {
		t.Fatalf("%d artifacts, want 134", len(res.NormalizedState))
	}

	alice := invArtifact(t, res, "device/user/1000")
	invWantAttr(t, alice, "name", "alice")
	invWantAttr(t, alice, "uid", "1000")
	invWantAttr(t, alice, "gid", "1000")
	invWantAttr(t, alice, "shell", "/bin/bash")
	invWantAttr(t, alice, "home", "/home/alice")
	invWantAttr(t, alice, "system_account", "false")
	invWantAttr(t, alice, "login_shell", "true")
	invWantAttr(t, alice, "human_usable", "true")
	invWantAttr(t, alice, "primary_group", "alice")
	// The privilege probe builds capabilities from this membership.
	invWantAttr(t, alice, "supplementary", "adm,cdrom,dip,docker,lpadmin,plugdev,sudo,users")
	invWantAttr(t, alice, "supplementary_count", "8")
	if alice.Sensitivity != trustfreeze.SensitivityInternal || alice.State != trustfreeze.StateObserved {
		t.Fatalf("sensitivity %q state %q", alice.Sensitivity, alice.State)
	}
	if alice.Provenance.ToolVersion != "getent 2.39" {
		t.Fatalf("tool version %q", alice.Provenance.ToolVersion)
	}

	root := invArtifact(t, res, "device/user/0")
	invWantAttr(t, root, "system_account", "true")
	invWantAttr(t, root, "human_usable", "false")
	invWantAttr(t, invArtifact(t, res, "device/user/1001"), "human_usable", "true")
	invWantAttr(t, invArtifact(t, res, "device/user/65534"), "human_usable", "false")
	if _, ok := invArtifact(t, res, "device/user/33").Attributes["supplementary"]; ok {
		t.Fatal("an account in no supplementary group must not carry the attribute")
	}

	sudo := invArtifact(t, res, "device/group/27")
	invWantAttr(t, sudo, "name", "sudo")
	invWantAttr(t, sudo, "members", "alice")
	invWantAttr(t, sudo, "member_count", "1")
	invWantAttr(t, sudo, "system_group", "true")
	invWantAttr(t, invArtifact(t, res, "device/group/984"), "name", "docker")
	empty := invArtifact(t, res, "device/group/5")
	invWantAttr(t, empty, "member_count", "0")
	if _, ok := empty.Attributes["members"]; ok {
		t.Fatalf("an empty group must not carry a members attribute: %v", empty.Attributes)
	}

	// The fixtures agree with each other, so no membership diagnostic is due.
	invWantNoWarning(t, res, usrDiagMembershipUnlisted)
	invWantNoWarning(t, res, usrDiagMembershipNotEffective)
	invWantNoWarning(t, res, usrDiagDuplicateID)
	invWantNoWarning(t, res, usrDiagUnresolvedPrimaryGroup)

	if names := invEvidenceNames(evidence); !invContains(names, "getent-passwd.stdout") || !invContains(names, "id.stdout") {
		t.Fatalf("evidence %v", names)
	}
	if len(res.Tools) != 5 {
		t.Fatalf("%d tool records, want 5: %+v", len(res.Tools), res.Tools)
	}
}

// TestUsersProbeKeepsNoPersonalName is playbook L4 at the bundle level: the
// GECOS field of the fixture carries the full name of a person, and nothing
// the probe persists may contain it.
func TestUsersProbeKeepsNoPersonalName(t *testing.T) {
	res, _ := invRun(t, NewUsersProbe(), invUsersRunner(t))
	b, err := trustfreeze.MarshalCanonical(res.NormalizedState)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"Alice Example", "Mailing List Manager", "Kernel Oops Tracking Daemon"} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatalf("the artifacts carry the GECOS value %q", forbidden)
		}
	}
	// The password placeholder must not survive as an attribute value either.
	for _, a := range res.NormalizedState {
		for name, v := range a.Attributes {
			if v == "x" {
				t.Fatalf("%s attribute %s is the password placeholder", a.ID, name)
			}
		}
	}
}

// TestUsersProbeIDMismatchIsDiagnosedNotRecorded: the capture runs as an
// account the local database does not list (an account from a directory
// service, for example). The bundle says so and invents nothing.
func TestUsersProbeIDMismatchIsDiagnosedNotRecorded(t *testing.T) {
	r := probe.NewFakeRunner()
	invScript(t, r, "users/getent-passwd.txt")
	invScript(t, r, "users/getent-group.txt")
	invScript(t, r, "users/getent-version.txt")
	invScript(t, r, "users/id-version.txt")
	// Constructed id line: a uid that the passwd fixture does not carry.
	invScriptRaw(r, "id", nil, probe.FakeResponse{Stdout: []byte("uid=4242(remote-maint) gid=4242(remote-maint) groups=4242(remote-maint),27(sudo)\n")})
	res, _ := invRun(t, NewUsersProbe(), r)
	w := invWantWarning(t, res, usrDiagMembershipUnlisted)
	if !strings.Contains(w.Message, "4242") {
		t.Fatalf("diagnostic %q", w.Message)
	}
	if invHasArtifact(res, "device/user/4242") {
		t.Fatal("id must not create an account artifact: it describes the session, not the host")
	}
}

func TestUsersProbeDuplicateUIDIsReported(t *testing.T) {
	// Constructed: the passwd fixture plus a second account with uid 0.
	passwd := append(append([]byte{}, invBytes(t, "users/getent-passwd.txt")...), []byte("toor:x:0:0::/root:/bin/bash\n")...)
	r := probe.NewFakeRunner()
	invScriptRaw(r, "getent", []string{"passwd"}, probe.FakeResponse{Stdout: passwd})
	invScript(t, r, "users/getent-group.txt")
	invScript(t, r, "users/id.txt")
	invScript(t, r, "users/getent-version.txt")
	invScript(t, r, "users/id-version.txt")
	res, _ := invRun(t, NewUsersProbe(), r)
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %s, want partial", res.Status)
	}
	w := invWantWarning(t, res, usrDiagDuplicateID)
	if !strings.Contains(w.Message, "root") || !strings.Contains(w.Message, "toor") {
		t.Fatalf("diagnostic %q does not name both accounts", w.Message)
	}
	if len(res.NormalizedState) != 53+81 {
		t.Fatalf("%d artifacts: the duplicate must be dropped, not doubled", len(res.NormalizedState))
	}
}

// TestUsersProbeEmptyResultIsCaptured uses the zero byte fixture with exit 2:
// an empty output with a non-zero exit is an empty result, not a failure and
// not a refusal (playbook L1).
func TestUsersProbeEmptyResultIsCaptured(t *testing.T) {
	e := invEntry(t, "honest-status/empty-result-getent-unknown-user.txt")
	if e.ExitCode != 2 {
		t.Fatalf("fixture exit code %d, want 2", e.ExitCode)
	}
	empty := probe.FakeResponse{Stdout: invBytes(t, e.Path), ExitCode: e.ExitCode}
	r := probe.NewFakeRunner()
	invScriptRaw(r, "getent", []string{"passwd"}, empty)
	invScriptRaw(r, "getent", []string{"group"}, empty)
	invScript(t, r, "users/id.txt")
	invScript(t, r, "users/getent-version.txt")
	invScript(t, r, "users/id-version.txt")
	res, _ := invRun(t, NewUsersProbe(), r)
	if res.Status != trustfreeze.StatusCaptured {
		t.Fatalf("status %s, reason %q", res.Status, res.Reason)
	}
	if len(res.NormalizedState) != 0 {
		t.Fatalf("%d artifacts, want none", len(res.NormalizedState))
	}
	w := invWantWarning(t, res, invDiagEmptyResult)
	if !strings.Contains(w.Message, "status 2") {
		t.Fatalf("diagnostic %q does not name the exit code", w.Message)
	}
}

func TestUsersProbeWithoutGroupDatabaseIsPartial(t *testing.T) {
	r := probe.NewFakeRunner()
	invScript(t, r, "users/getent-passwd.txt")
	invScript(t, r, "users/id.txt")
	invScript(t, r, "users/getent-version.txt")
	invScript(t, r, "users/id-version.txt")
	invScriptRaw(r, "getent", []string{"group"}, probe.FakeResponse{ExitCode: 1})
	res, _ := invRun(t, NewUsersProbe(), r)
	if res.Status != trustfreeze.StatusPartial {
		t.Fatalf("status %s, want partial", res.Status)
	}
	if len(res.NormalizedState) != 53 {
		t.Fatalf("%d artifacts, want the 53 accounts and no group", len(res.NormalizedState))
	}
	alice := invArtifact(t, res, "device/user/1000")
	for _, absent := range []string{"primary_group", "supplementary", "supplementary_count"} {
		if _, ok := alice.Attributes[absent]; ok {
			t.Fatalf("attribute %s must be absent when the group database could not be read: %v", absent, alice.Attributes)
		}
	}
	invWantWarning(t, res, probe.DiagFieldFailed)
}

func TestUsersProbeSupport(t *testing.T) {
	p := NewUsersProbe()
	if got := p.Support(context.Background(), probe.HostContext{GOOS: "linux", Runner: probe.NewFakeRunner()}); got.Available || got.Status != trustfreeze.StatusUnavailable {
		t.Fatalf("without getent: %+v", got)
	}
	denied := probe.NewFakeRunner().DenyTool("getent", "/usr/bin/getent")
	if got := p.Support(context.Background(), probe.HostContext{GOOS: "linux", Runner: denied}); got.Available || got.Status != trustfreeze.StatusPermissionDenied {
		t.Fatalf("with a getent that is not executable: %+v", got)
	}
	if got := p.Support(context.Background(), probe.HostContext{GOOS: "windows", Runner: probe.NewFakeRunner()}); got.Available || got.Status != trustfreeze.StatusUnsupported {
		t.Fatalf("on windows: %+v", got)
	}
}

func TestUsersProbeDescriptorAndTools(t *testing.T) {
	p := NewUsersProbe()
	d := p.Descriptor()
	if err := d.Validate(); err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if d.RequiredPrivilege != probe.PrivilegeUser {
		t.Fatalf("privilege %q: the probe must never need elevation (playbook L2)", d.RequiredPrivilege)
	}
	if d.Sensitivity != trustfreeze.SensitivityInternal {
		t.Fatalf("sensitivity %q: account names are not public data", d.Sensitivity)
	}
	if !reflect.DeepEqual(p.RequiredTools(), []string{"getent", "id"}) {
		t.Fatalf("required tools %q", p.RequiredTools())
	}
}

func TestInvMembershipDiff(t *testing.T) {
	cases := []struct {
		name             string
		session          []string
		database         []string
		wantSessionOnly  []string
		wantDatabaseOnly []string
	}{
		{"equal", []string{"alice", "sudo"}, []string{"alice", "sudo"}, nil, nil},
		{"session holds more", []string{"alice", "docker", "sudo"}, []string{"alice", "sudo"}, []string{"docker"}, nil},
		{"database holds more", []string{"alice"}, []string{"alice", "sudo"}, nil, []string{"sudo"}},
		{"both", []string{"alice", "docker"}, []string{"alice", "sudo"}, []string{"docker"}, []string{"sudo"}},
		{"empty", nil, nil, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessionOnly, databaseOnly := invMembershipDiff(tc.session, tc.database)
			if !reflect.DeepEqual(sessionOnly, tc.wantSessionOnly) || !reflect.DeepEqual(databaseOnly, tc.wantDatabaseOnly) {
				t.Fatalf("session only %q database only %q", sessionOnly, databaseOnly)
			}
		})
	}
}

func TestUsrDatabaseGroupsIncludesThePrimaryGroup(t *testing.T) {
	groups, _ := ParseGetentGroup(invBytes(t, "users/getent-group.txt"))
	users, _ := ParseGetentPasswd(invBytes(t, "users/getent-passwd.txt"))
	var alice PasswdEntry
	for _, u := range users {
		if u.Name == "alice" {
			alice = u
		}
	}
	got := usrDatabaseGroups(alice, groups)
	want := []string{"adm", "alice", "cdrom", "dip", "docker", "lpadmin", "plugdev", "sudo", "users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("database groups %q, want %q", got, want)
	}
	// The same set the session reports, which is why the fixtures produce no
	// membership diagnostic.
	info, err := ParseID(invBytes(t, "users/id.txt"))
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	if !reflect.DeepEqual(info.GroupNames(), want) {
		t.Fatalf("session groups %q, want %q", info.GroupNames(), want)
	}
}
