// Trust Freeze probe linux.users (SPEC-0471 TF06-R3): the local accounts and
// groups of a Linux host, and which account can be used by a human.
//
// Sources: getent passwd and getent group, which answer through the name
// service switch and are therefore the effective account database of the
// host, plus id for the account the capture runs as. Password material never
// appears in any of them, and the placeholder field that holds it in the file
// format is dropped inside the parser, so no caller can persist it
// (playbook L4).
//
// Every parser is a pure function over the bytes a tool printed, so the
// fixtures under testdata/users exercise all of them on any operating system.

package linux

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// linux.users identity.
const (
	UsersProbeID      = "linux.users"
	UsersProbeVersion = "1"
)

// Artifact id prefixes of linux.users. Accounts and groups are keyed by their
// numeric id, which is what the kernel enforces on and what survives a rename.
const (
	ArtifactUserPrefix  = "device/user/"
	ArtifactGroupPrefix = "device/group/"
)

// Executables linux.users runs.
const (
	getentTool = "getent"
	idTool     = "id"
)

// Account id conventions of Debian and Ubuntu (adduser.conf FIRST_UID, login.defs
// UID_MIN): uid and gid below 1000 belong to the system, 1000 and above to
// regular accounts. The uid and gid 65534 are the "nobody" and "nogroup"
// placeholders of the kernel, which are regular by number and by no means
// usable by a person.
const (
	usrMinRegularUID int64 = 1000
	usrNobodyID      int64 = 65534
)

// getent exit codes (getent(1)). Zero is success, 2 says the key was not
// found, which on an enumerating call means the database answered with
// nothing. Neither an empty output nor a non-zero exit is by itself a
// permission problem (playbook L1).
const (
	getentExitKeyNotFound   = 2
	getentExitNoEnumeration = 3
)

// Diagnostic codes of linux.users.
const (
	// usrDiagMembershipUnlisted: the running session holds a group that the
	// account database does not attribute to that account.
	usrDiagMembershipUnlisted = "membership_unlisted"
	// usrDiagMembershipNotEffective: the account database attributes a group
	// to the account that the running session does not hold.
	usrDiagMembershipNotEffective = "membership_not_effective"
	// usrDiagDuplicateID: two accounts or two groups share one numeric id.
	usrDiagDuplicateID = "duplicate_numeric_id"
	// usrDiagUnresolvedPrimaryGroup: an account names a primary group id that
	// the group database does not list.
	usrDiagUnresolvedPrimaryGroup = "unresolved_primary_group"
	// usrDiagRootAccountMissing: getent passwd printed accounts, and none of
	// the artifacts this probe kept is uid 0. Every general purpose Linux
	// system has that account, so its absence from the inventory is either a
	// refused record or a dropped artifact, and in both cases the inventory
	// is not what a reader would take it for. Counting the artifacts does not
	// show it; this diagnostic does.
	usrDiagRootAccountMissing = "account_root_missing"
)

// usrRootUID is the uid the kernel grants everything to.
const usrRootUID int64 = 0

// UsersProbe is linux.users.
type UsersProbe struct{}

// NewUsersProbe returns the probe.
func NewUsersProbe() *UsersProbe { return &UsersProbe{} }

// Descriptor implements probe.Probe.
func (p *UsersProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                UsersProbeID,
		Version:           UsersProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    30 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides:          []string{ArtifactGroupPrefix, ArtifactUserPrefix},
	}
}

// RequiredTools implements the structural ToolUser interface of the capture
// package: doctor resolves these names through LookPath and never runs one.
func (p *UsersProbe) RequiredTools() []string { return []string{getentTool, idTool} }

// EvidenceClaims implements probe.EvidenceClaimer.
func (p *UsersProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe: platform and the availability of getent,
// nothing else.
func (p *UsersProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("linux.users has no source on " + host.GOOS)
	}
	if host.Runner == nil {
		return probe.Unavailable("no command runner")
	}
	if _, err := host.Runner.LookPath(getentTool); err != nil {
		if probe.ErrorClass(err) == probe.ClassPermissionDenied {
			return probe.PermissionDenied(getentTool + " is present but not executable for this account")
		}
		return probe.Unavailable(getentTool + " was not found: the account database cannot be read through the name service switch")
	}
	return probe.Supported()
}

// Collect implements probe.Probe.
func (p *UsersProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	c := invNewCollector(ctx, cc)
	res := invBaseResult(UsersProbeID, UsersProbeVersion, cc, start)
	if cc.Runner == nil {
		return c.fail(res, trustfreeze.StatusFailed, probe.ClassInvalidRequest, "no command runner", start)
	}

	// The account database. Its failure is the failure of the probe.
	out := c.run(getentTool, []string{"passwd"}, "getent-passwd")
	switch {
	case out.class != "":
		return c.fail(res, invStatusForClass(out.class), out.class,
			fmt.Sprintf("%s passwd did not answer: %s", getentTool, out.errText()), start)
	case out.exitCode == getentExitKeyNotFound && len(out.stdout) == 0:
		c.warn(invDiagEmptyResult, "passwd",
			fmt.Sprintf("getent passwd exited with status %d and printed nothing: the account database answered with no entry", getentExitKeyNotFound))
	case out.exitCode == getentExitNoEnumeration && len(out.stdout) == 0:
		return c.fail(res, trustfreeze.StatusFailed, probe.ClassStartFailed,
			fmt.Sprintf("getent passwd exited with status %d: this system does not enumerate the passwd database, so the account list is not observable this way", getentExitNoEnumeration), start)
	case out.exitCode != 0 && len(out.stdout) == 0:
		return c.fail(res, trustfreeze.StatusFailed, probe.ClassStartFailed,
			fmt.Sprintf("getent passwd exited with status %d and printed nothing", out.exitCode), start)
	case out.exitCode != 0:
		c.warnPartial(probe.DiagFieldFailed, "passwd",
			fmt.Sprintf("getent passwd exited with status %d after printing %d byte(s); the account list may be incomplete", out.exitCode, len(out.stdout)))
	}
	c.truncationCheck(getentTool, out, "the account list is incomplete")
	users, issues := ParseGetentPasswd(out.stdout)
	c.addIssues("getent passwd", issues)

	groups, groupsKnown := c.getentGroups()
	getentVersion := c.toolVersion(getentTool, "getent-version", ParseGNUToolVersion)

	sources := []string{"command:getent passwd"}
	if groupsKnown {
		sources = append(sources, "command:getent group")
	}
	sort.Strings(sources)
	observed := trustfreeze.FormatTime(start)
	userProv := trustfreeze.Provenance{
		Method:      "command",
		Confidence:  trustfreeze.ConfidenceProven,
		Sources:     sources,
		ObservedAt:  observed,
		ToolVersion: invToolVersionList([]string{getentTool}, []string{getentVersion}),
	}
	groupProv := userProv
	groupProv.Sources = []string{"command:getent group"}

	arts := c.capArtifacts(c.keepValid(c.userArtifacts(users, groups, groupsKnown, userProv)), maxUserArtifacts, "account")
	// Checked on the artifacts that survived every filter, not on the parsed
	// records: a record the parser refused and an artifact a cap dropped both
	// end with the same missing account.
	c.checkRootAccount(arts, len(out.stdout))
	arts = append(arts, c.capArtifacts(c.keepValid(c.groupArtifacts(groups, groupProv)), maxGroupArtifacts, "group")...)

	// id describes the session the capture runs in, not the host, so it
	// creates no artifact of its own: a bundle must not differ because
	// another operator ran the capture. It is used for what only it can say,
	// namely whether the effective group set of the running session agrees
	// with the account database (playbook L3).
	c.checkSession(users, groups, groupsKnown)
	return c.finish(res, arts, start)
}

// getentGroups reads the group database. It is a second call, so its failure
// costs the membership information and caps the probe at partial, but it does
// not make the account list unreadable.
func (c *invCollector) getentGroups() ([]GroupEntry, bool) {
	out := c.run(getentTool, []string{"group"}, "getent-group")
	switch {
	case out.class != "":
		c.warnPartial(invDiagClassCode(out.class), "group", "getent group did not answer: "+out.errText())
		return nil, false
	case out.exitCode == getentExitKeyNotFound && len(out.stdout) == 0:
		c.warn(invDiagEmptyResult, "group",
			fmt.Sprintf("getent group exited with status %d and printed nothing: the group database answered with no entry", getentExitKeyNotFound))
		return nil, true
	case out.exitCode != 0 && len(out.stdout) == 0:
		c.warnPartial(probe.DiagFieldFailed, "group",
			fmt.Sprintf("getent group exited with status %d and printed nothing; group membership is not recorded", out.exitCode))
		return nil, false
	case out.exitCode != 0:
		c.warnPartial(probe.DiagFieldFailed, "group",
			fmt.Sprintf("getent group exited with status %d after printing %d byte(s); the group list may be incomplete", out.exitCode, len(out.stdout)))
	}
	c.truncationCheck(getentTool, out, "the group list is incomplete")
	groups, issues := ParseGetentGroup(out.stdout)
	c.addIssues("getent group", issues)
	return groups, true
}

// userArtifacts builds one artifact per account.
func (c *invCollector) userArtifacts(users []PasswdEntry, groups []GroupEntry, groupsKnown bool, prov trustfreeze.Provenance) []trustfreeze.Artifact {
	primaryName := usrPrimaryGroupNames(groups)
	member := usrMembership(groups)
	unresolved, cut := 0, 0
	arts := make([]trustfreeze.Artifact, 0, len(users))
	for _, u := range users {
		// An attribute that nothing resolved is left out rather than filled
		// with a placeholder: an absent attribute is an honest gap, an empty
		// string would read as an observed empty value.
		attrs := map[string]string{
			"name":           u.Name,
			"uid":            strconv.FormatInt(u.UID, 10),
			"gid":            strconv.FormatInt(u.GID, 10),
			"shell":          u.Shell,
			"home":           u.Home,
			"system_account": strconv.FormatBool(u.SystemAccount()),
			"login_shell":    strconv.FormatBool(u.HasLoginShell()),
			"human_usable":   strconv.FormatBool(u.HumanUsable()),
		}
		if groupsKnown {
			if n, ok := primaryName[u.GID]; ok {
				attrs["primary_group"] = n
			} else {
				unresolved++
			}
			if names := member[u.Name]; len(names) > 0 {
				joined, dropped := invJoinNames(names, invMaxNamesInAttribute)
				attrs["supplementary"] = joined
				attrs["supplementary_count"] = strconv.Itoa(len(names))
				cut += dropped
			}
		}
		arts = append(arts, trustfreeze.Artifact{
			ID: ArtifactUserPrefix + strconv.FormatInt(u.UID, 10), Type: "user", Scope: "device", Source: UsersProbeID,
			State:       trustfreeze.StateObserved,
			Attributes:  attrs,
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
	}
	if unresolved > 0 {
		c.warn(usrDiagUnresolvedPrimaryGroup, "primary_group",
			fmt.Sprintf("%d account(s) name a primary group id that the group database does not list; those artifacts carry the numeric gid only", unresolved))
	}
	if cut > 0 {
		c.warnPartial(invDiagLimitExceeded, "supplementary",
			fmt.Sprintf("%d group name(s) were dropped from account attributes because one account is in more than %d groups", cut, invMaxNamesInAttribute))
	}
	c.reportDuplicates(usrUserIDs(users), "account")
	return arts
}

// groupArtifacts builds one artifact per group. The member list is the
// explicit one of the group database; an account whose primary group this is
// does not appear in it, which is how the format works. That side of the
// membership is on the account artifact, as primary_group.
func (c *invCollector) groupArtifacts(groups []GroupEntry, prov trustfreeze.Provenance) []trustfreeze.Artifact {
	cut := 0
	arts := make([]trustfreeze.Artifact, 0, len(groups))
	for _, g := range groups {
		attrs := map[string]string{
			"name":         g.Name,
			"gid":          strconv.FormatInt(g.GID, 10),
			"system_group": strconv.FormatBool(g.GID < usrMinRegularUID),
			"member_count": strconv.Itoa(len(g.Members)),
		}
		if len(g.Members) > 0 {
			joined, dropped := invJoinNames(g.Members, invMaxNamesInAttribute)
			attrs["members"] = joined
			cut += dropped
		}
		arts = append(arts, trustfreeze.Artifact{
			ID: ArtifactGroupPrefix + strconv.FormatInt(g.GID, 10), Type: "group", Scope: "device", Source: UsersProbeID,
			State:       trustfreeze.StateObserved,
			Attributes:  attrs,
			Provenance:  prov,
			Sensitivity: trustfreeze.SensitivityInternal,
		})
	}
	if cut > 0 {
		c.warnPartial(invDiagLimitExceeded, "members",
			fmt.Sprintf("%d member name(s) were dropped from group attributes because one group has more than %d members; member_count still names the full size", cut, invMaxNamesInAttribute))
	}
	c.reportDuplicates(usrGroupIDs(groups), "group")
	return arts
}

// checkRootAccount states by name that the inventory holds no uid 0, which a
// reader would otherwise have to notice by counting. outputBytes is the size
// of what getent passwd printed: a database that answered with nothing is
// already reported as empty_result, and a second diagnostic over the same
// silence would say nothing new.
//
// The absence is not repaired here. A record the redactor or the tool broke
// stays broken, and record_unparsed still names it; this diagnostic names the
// consequence, so a bundle that lost the most privileged account of the host
// says so where the accounts are.
func (c *invCollector) checkRootAccount(accounts []trustfreeze.Artifact, outputBytes int) {
	if outputBytes == 0 {
		return
	}
	rootID := ArtifactUserPrefix + strconv.FormatInt(usrRootUID, 10)
	for _, a := range accounts {
		if a.ID == rootID {
			return
		}
	}
	c.warnPartial(usrDiagRootAccountMissing, "passwd",
		fmt.Sprintf("getent passwd printed %d byte(s) and the inventory holds %d account(s), none of them uid 0; the account %s is absent from this capture and the account list is therefore not complete",
			outputBytes, len(accounts), rootID))
}

// checkSession compares the effective group set of the running session with
// what the account database says about the same account. Both directions are
// reported, and neither changes an artifact: a session group that the
// database does not list stays out of the recorded membership, because
// observed session state and the declared database are two different facts
// (playbook L3).
func (c *invCollector) checkSession(users []PasswdEntry, groups []GroupEntry, groupsKnown bool) {
	out := c.run(idTool, nil, "id")
	switch {
	case out.class == probe.ClassToolMissing:
		c.warnPartial(probe.DiagFieldUnavailable, idTool,
			"id was not found; the group set of the capturing session could not be compared with the account database")
		return
	case out.class != "":
		c.warnPartial(invDiagClassCode(out.class), idTool, "id did not answer: "+out.errText())
		return
	case out.exitCode != 0:
		c.warnPartial(probe.DiagFieldFailed, idTool, fmt.Sprintf("id exited with status %d", out.exitCode))
		return
	}
	// The version of id goes through the same path as every other tool: its
	// output is kept as evidence and an unreadable version becomes a
	// diagnostic (playbook L7). It is read before the line is parsed, so a
	// line this build does not recognize is reported together with the
	// version that printed it. It enters no artifact provenance, because id
	// contributes no artifact.
	c.toolVersion(idTool, "id-version", ParseGNUToolVersion)
	// A cut id line lists fewer groups than the session holds, which would
	// turn into a false statement about the account database below.
	c.truncationCheck(idTool, out, "the group set of this session is incomplete")
	info, err := ParseID(out.stdout)
	if err != nil {
		c.warnPartial(invDiagRecordUnparsed, idTool, "id printed a line this build does not recognize: "+err.Error())
		return
	}
	if !groupsKnown {
		return
	}
	var account PasswdEntry
	for _, u := range users {
		if u.UID == info.UID {
			account = u
			break
		}
	}
	if account.Name == "" {
		c.warn(usrDiagMembershipUnlisted, idTool,
			fmt.Sprintf("the capture runs as uid %d, which the account database does not list", info.UID))
		return
	}
	sessionOnly, databaseOnly := invMembershipDiff(info.GroupNames(), usrDatabaseGroups(account, groups))
	if len(sessionOnly) > 0 {
		listed, rest := invJoinNames(sessionOnly, invMaxNamesInMessage)
		c.warn(usrDiagMembershipUnlisted, idTool,
			fmt.Sprintf("the capturing session holds %d group(s) that the account database does not attribute to this account (%s%s); they are not recorded as membership", len(sessionOnly), listed, usrAndMore(rest)))
	}
	if len(databaseOnly) > 0 {
		listed, rest := invJoinNames(databaseOnly, invMaxNamesInMessage)
		c.warn(usrDiagMembershipNotEffective, idTool,
			fmt.Sprintf("the account database attributes %d group(s) to this account that the capturing session does not hold (%s%s); the membership is recorded, the session is not", len(databaseOnly), listed, usrAndMore(rest)))
	}
}

func usrAndMore(rest int) string {
	if rest <= 0 {
		return ""
	}
	return fmt.Sprintf(" and %d more", rest)
}

// reportDuplicates names numeric ids that more than one object claims. A
// second account with uid 0 is a fact worth its own line, so the diagnostic
// names the id and the objects, and the probe drops to partial.
func (c *invCollector) reportDuplicates(ids map[int64][]string, kind string) {
	var dup []int64
	for id, names := range ids {
		if len(names) > 1 {
			dup = append(dup, id)
		}
	}
	if len(dup) == 0 {
		return
	}
	sort.Slice(dup, func(i, j int) bool { return dup[i] < dup[j] })
	for _, id := range dup {
		names := append([]string(nil), ids[id]...)
		sort.Strings(names)
		listed, rest := invJoinNames(names, invMaxNamesInMessage)
		c.warnPartial(usrDiagDuplicateID, kind,
			fmt.Sprintf("the numeric %s id %d is claimed by %d objects (%s%s); only the first was recorded under that artifact id", kind, id, len(names), listed, usrAndMore(rest)))
	}
}

// PasswdEntry is one account of getent passwd. The second field of the line,
// the password placeholder, is deliberately not part of this type: a shadowed
// system prints "x" there and an unshadowed one would print the hash itself,
// so the parser drops it and no caller can persist it (playbook L4). The
// GECOS field is dropped for the same reason at a lower level of severity: it
// carries the full name of a person and adds nothing to a privilege
// statement.
type PasswdEntry struct {
	Name  string
	UID   int64
	GID   int64
	Home  string
	Shell string
}

// SystemAccount reports whether the uid is below the first regular uid.
func (p PasswdEntry) SystemAccount() bool { return p.UID < usrMinRegularUID }

// HasLoginShell reports whether the shell of the account can start a session.
// nologin and false exist precisely to refuse one, and an empty shell field
// falls back to /bin/sh only for some callers, so it is not counted either.
func (p PasswdEntry) HasLoginShell() bool {
	shell := strings.TrimSpace(p.Shell)
	if shell == "" {
		return false
	}
	base := shell
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case "nologin", "false":
		return false
	}
	return true
}

// HumanUsable reports whether a person can use this account: a regular uid
// with a shell that starts a session. The privilege probe builds capabilities
// from this, so the rule is an attribute of the artifact and not a judgement
// made later. The kernel placeholder uid 65534 is regular by number and
// usable by nobody, hence the explicit exclusion.
func (p PasswdEntry) HumanUsable() bool {
	return !p.SystemAccount() && p.UID != usrNobodyID && p.HasLoginShell()
}

// GroupEntry is one group of getent group. The password placeholder field is
// dropped in the parser, like the one of PasswdEntry.
type GroupEntry struct {
	Name string
	GID  int64
	// Members are the explicit members, sorted and without duplicates. An
	// account whose primary group this is does not appear here.
	Members []string
}

// IDGroup is one group of an id(1) line. Name is empty when id printed the
// number alone, which happens when nothing resolves the id.
type IDGroup struct {
	GID  int64
	Name string
}

// IDInfo is the parsed output of id(1) for the account the capture runs as.
type IDInfo struct {
	UID    int64
	User   string
	GID    int64
	Group  string
	Groups []IDGroup
}

// GroupNames returns the group set of the session as names, sorted and
// without duplicates. A group id that resolved to no name is rendered as its
// number, so the comparison never silently drops it.
func (i IDInfo) GroupNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range i.Groups {
		n := g.Name
		if n == "" {
			n = strconv.FormatInt(g.GID, 10)
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ParseGetentPasswd parses getent passwd: seven colon separated fields per
// line. A line with another field count, or with a uid or gid that is not a
// number, becomes an issue and no account.
func ParseGetentPasswd(b []byte) ([]PasswdEntry, []InventoryIssue) {
	var (
		out    []PasswdEntry
		issues []InventoryIssue
	)
	for i, line := range invLines(b) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: fmt.Sprintf("expected 7 colon separated fields, found %d", len(fields))})
			continue
		}
		uid, err := strconv.ParseInt(strings.TrimSpace(fields[2]), 10, 64)
		if err != nil {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: "uid is not a number"})
			continue
		}
		gid, err := strconv.ParseInt(strings.TrimSpace(fields[3]), 10, 64)
		if err != nil {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: "gid is not a number"})
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name == "" {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: "empty account name"})
			continue
		}
		// fields[1] is the password placeholder and fields[4] the GECOS
		// field; neither is read.
		out = append(out, PasswdEntry{Name: name, UID: uid, GID: gid, Home: fields[5], Shell: fields[6]})
	}
	return out, issues
}

// ParseGetentGroup parses getent group: four colon separated fields per line,
// the last one a comma separated member list.
func ParseGetentGroup(b []byte) ([]GroupEntry, []InventoryIssue) {
	var (
		out    []GroupEntry
		issues []InventoryIssue
	)
	for i, line := range invLines(b) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: fmt.Sprintf("expected 4 colon separated fields, found %d", len(fields))})
			continue
		}
		gid, err := strconv.ParseInt(strings.TrimSpace(fields[2]), 10, 64)
		if err != nil {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: "gid is not a number"})
			continue
		}
		name := strings.TrimSpace(fields[0])
		if name == "" {
			issues = append(issues, InventoryIssue{Line: i + 1, Reason: "empty group name"})
			continue
		}
		// fields[1] is the password placeholder and is not read.
		out = append(out, GroupEntry{Name: name, GID: gid, Members: usrSplitMembers(fields[3])})
	}
	return out, issues
}

// usrSplitMembers turns the member field into a sorted set of names.
func usrSplitMembers(field string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range strings.Split(field, ",") {
		m = strings.TrimSpace(m)
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// ErrNoIDLine is returned by ParseID for output that carries no uid field.
var ErrNoIDLine = errors.New("linux: id printed no uid field")

// ParseID parses one line of id(1), for example
// "uid=1000(alice) gid=1000(alice) groups=1000(alice),27(sudo)". Tokens this
// build does not know, such as the context= field of an SELinux host, are
// ignored rather than treated as an error.
func ParseID(b []byte) (IDInfo, error) {
	line := invFirstLine(b)
	if line == "" {
		return IDInfo{}, ErrNoIDLine
	}
	var (
		info   IDInfo
		hasUID bool
	)
	for _, token := range strings.Fields(line) {
		key, value, ok := strings.Cut(token, "=")
		if !ok {
			continue
		}
		switch key {
		case "uid":
			id, name, err := usrParseIDEntry(value)
			if err != nil {
				return IDInfo{}, fmt.Errorf("uid field: %w", err)
			}
			info.UID, info.User, hasUID = id, name, true
		case "gid":
			id, name, err := usrParseIDEntry(value)
			if err != nil {
				return IDInfo{}, fmt.Errorf("gid field: %w", err)
			}
			info.GID, info.Group = id, name
		case "groups":
			for _, entry := range strings.Split(value, ",") {
				id, name, err := usrParseIDEntry(entry)
				if err != nil {
					return IDInfo{}, fmt.Errorf("groups field: %w", err)
				}
				info.Groups = append(info.Groups, IDGroup{GID: id, Name: name})
			}
		}
	}
	if !hasUID {
		return IDInfo{}, ErrNoIDLine
	}
	sort.SliceStable(info.Groups, func(i, j int) bool {
		if info.Groups[i].GID != info.Groups[j].GID {
			return info.Groups[i].GID < info.Groups[j].GID
		}
		return info.Groups[i].Name < info.Groups[j].Name
	})
	return info, nil
}

// usrParseIDEntry reads one "1000(alice)" or "1000" entry of an id line.
func usrParseIDEntry(s string) (int64, string, error) {
	s = strings.TrimSpace(s)
	num, name := s, ""
	if i := strings.IndexByte(s, '('); i >= 0 && strings.HasSuffix(s, ")") {
		num, name = s[:i], s[i+1:len(s)-1]
	}
	id, err := strconv.ParseInt(num, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("%q is not a numeric id with an optional name", s)
	}
	return id, name, nil
}

// ParseGNUToolVersion reads the version out of the first line of a GNU style
// "--version" output, where the version is the last field: "id (GNU
// coreutils) 9.4" and "getent (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39" both end
// in it. A last field that does not start with a digit is no version, and the
// caller reports the unknown version as a diagnostic (playbook L7).
func ParseGNUToolVersion(b []byte) string {
	fields := strings.Fields(invFirstLine(b))
	if len(fields) < 2 {
		return ""
	}
	last := fields[len(fields)-1]
	if last[0] < '0' || last[0] > '9' {
		return ""
	}
	return last
}

// invMembershipDiff compares two sorted, duplicate free name sets and returns
// what only the first and what only the second holds.
func invMembershipDiff(session, database []string) (sessionOnly, databaseOnly []string) {
	inDatabase := make(map[string]bool, len(database))
	for _, n := range database {
		inDatabase[n] = true
	}
	inSession := make(map[string]bool, len(session))
	for _, n := range session {
		inSession[n] = true
		if !inDatabase[n] {
			sessionOnly = append(sessionOnly, n)
		}
	}
	for _, n := range database {
		if !inSession[n] {
			databaseOnly = append(databaseOnly, n)
		}
	}
	sort.Strings(sessionOnly)
	sort.Strings(databaseOnly)
	return sessionOnly, databaseOnly
}

// usrDatabaseGroups returns every group name the account database attributes
// to one account: the groups whose member list names it, plus the group of
// its primary gid, which the member lists never repeat. This is the set that
// an id(1) line is comparable with, since id prints the primary group among
// the groups as well.
func usrDatabaseGroups(account PasswdEntry, groups []GroupEntry) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	if n, ok := usrPrimaryGroupNames(groups)[account.GID]; ok {
		add(n)
	}
	for _, g := range groups {
		for _, m := range g.Members {
			if m == account.Name {
				add(g.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// usrPrimaryGroupNames maps a gid to its group name. When two groups share a
// gid the lexicographically first name wins, so the mapping does not depend
// on the order the database happened to answer in (playbook L8).
func usrPrimaryGroupNames(groups []GroupEntry) map[int64]string {
	out := map[int64]string{}
	for _, g := range groups {
		if prev, ok := out[g.GID]; !ok || g.Name < prev {
			out[g.GID] = g.Name
		}
	}
	return out
}

// usrMembership maps an account name to the sorted group names that list it
// as an explicit member.
func usrMembership(groups []GroupEntry) map[string][]string {
	out := map[string][]string{}
	for _, g := range groups {
		for _, m := range g.Members {
			out[m] = append(out[m], g.Name)
		}
	}
	for m := range out {
		sort.Strings(out[m])
	}
	return out
}

// usrUserIDs maps a uid to the account names that claim it.
func usrUserIDs(users []PasswdEntry) map[int64][]string {
	out := map[int64][]string{}
	for _, u := range users {
		out[u.UID] = append(out[u.UID], u.Name)
	}
	return out
}

// usrGroupIDs maps a gid to the group names that claim it.
func usrGroupIDs(groups []GroupEntry) map[int64][]string {
	out := map[int64][]string{}
	for _, g := range groups {
		out[g.GID] = append(out[g.GID], g.Name)
	}
	return out
}
