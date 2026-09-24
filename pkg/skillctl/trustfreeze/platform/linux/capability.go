package linux

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// Capability resolution turns the artifacts of the privilege probes into the
// statements a report can make about who may do what (SPEC-0466 section 4.6,
// SPEC-0468 R7). The resolver is pure: artifacts in, capabilities out, no file
// system, no command, no clock, so every rule is table-tested on any OS.
//
// Four rules live here, in the order the report needs them:
//
//  1. A sudo rule that grants every command as root becomes an execute
//     capability on the host. NOPASSWD makes it root-via-sudo without a
//     password, anything else root-via-sudo after authentication.
//  2. Membership in a group that grants sudo (sudo, admin, wheel) becomes the
//     same execute capability for the member. Where the rule file was readable
//     the membership only expands the rule (two sources, corroborated); where
//     it was not readable, the membership alone carries the statement, which
//     is an inference and is marked as one.
//  3. An authorized key becomes a remote.shell.public-key capability for its
//     account, carrying the privilege that account holds on this host.
//  4. A container the runtime reports as privileged becomes an execute
//     capability on the host whose subject is the container itself: it keeps
//     the host devices and can write the host filesystem, and no principal has
//     to be logged in for that to hold.
//
// Every capability names at least one source artifact. One without a source is
// dropped with a diagnostic, because a statement nobody can check is worse
// than no statement.
const (
	// CapExecuteHostPrefix prefixes an execute capability on the host.
	CapExecuteHostPrefix = "capability/execute/host/"
	// CapRemoteShellPublicKeyPrefix prefixes the public key capability. The
	// kind is spelled in the id, because the capability model has no kind
	// field: action and resource say "access the remote shell", the id says
	// through what.
	CapRemoteShellPublicKeyPrefix = "capability/remote.shell.public-key/"
	// CapExecuteHostViaRuntimePrefix prefixes an execute capability that a
	// container runtime socket grants. The id carries the runtime, because
	// the grant is a different one from the sudo grant of the same subject
	// and both can hold at once.
	CapExecuteHostViaRuntimePrefix = "capability/execute/host/via/"
)

// Attribute names of a capability this resolver produces. They say which path
// grants the privilege and why that path is one, which the fixed fields of the
// model cannot express.
const (
	// CapAttrGrantPath names the mechanism: "container-runtime-socket".
	CapAttrGrantPath = "grant_path"
	// CapAttrGroup names the group membership the statement rests on.
	CapAttrGroup = "group"
	// CapAttrRuntime names the container runtime of a socket grant.
	CapAttrRuntime = "runtime"
	// CapAttrRuntimeObserved says whether this capture saw that runtime.
	CapAttrRuntimeObserved = "runtime_observed"
	// CapAttrContainer names the container a privileged-container capability
	// rests on, and CapAttrContainerImage the image it runs.
	CapAttrContainer      = "container"
	CapAttrContainerImage = "image"
	// CapAttrRationale is one sentence saying why the path grants what the
	// privilege field claims.
	CapAttrRationale = "rationale"
)

// Actions and resources of the capabilities this resolver produces.
const (
	CapActionExecute = "execute"
	CapActionAccess  = "access"
	// CapResourceHost is the host itself: every command on it.
	CapResourceHost = "host"
	// CapResourceRemoteShell is an interactive session over the network.
	CapResourceRemoteShell = "remote.shell"
)

// CapEffectAllowed is the only effect this resolver emits: a denial is not
// derivable from the artifacts these probes collect.
const CapEffectAllowed = "allowed"

// Privilege values of a capability.
//
// #nosec G101 -- these are the NAMES of the privilege values this resolver
// writes into a capability, and their values are those same names. Nothing
// here is a credential: "root-via-sudo-nopasswd" is the statement that a sudo
// rule needs no password, which is the finding the report exists to make. The
// rule fires on the word "Password" in the identifier.
const (
	// CapPrivilegeRoot: the account is root itself.
	CapPrivilegeRoot = "root"
	// CapPrivilegeRootViaSudo: the subject can become root through sudo after
	// authenticating with its own password.
	CapPrivilegeRootViaSudo = "root-via-sudo"
	// CapPrivilegeRootViaSudoNoPassword: the same, without any password.
	CapPrivilegeRootViaSudoNoPassword = "root-via-sudo-nopasswd"
	// CapPrivilegeRootViaContainerRuntime: the subject can reach a container
	// runtime socket, which is root on the host in practice: a container
	// started through it can mount the host filesystem and write as root. No
	// password and no sudo rule are involved, which is why it is a privilege
	// of its own and not one of the sudo values.
	CapPrivilegeRootViaContainerRuntime = "root-via-container-runtime"
	// CapPrivilegeRootViaPrivilegedContainer: a container the runtime runs
	// privileged. It keeps the host device nodes and can mount and write the
	// host filesystem, so what runs inside it is root on the host, with no
	// account and no password involved (R-T4).
	CapPrivilegeRootViaPrivilegedContainer = trustfreeze.PrivilegeValueRootViaPrivilegedContainer
	// CapPrivilegeUser: an ordinary account, no privilege escalation known
	// from the artifacts of this capture.
	CapPrivilegeUser = "user"
)

// Grant paths: the value of CapAttrGrantPath, naming the mechanism a
// capability rests on.
const (
	capGrantPathRuntimeSocket       = "container-runtime-socket"
	capGrantPathGroupMembership     = "group-membership"
	capGrantPathPrivilegedContainer = "privileged-container"
)

// Exposure of a capability: where it can be used from.
const (
	CapExposureLocal   = "local"
	CapExposureNetwork = "network"
)

// CapScopeHost is the scope of every capability here: this one host.
const CapScopeHost = "host"

// Subject prefixes. A capability subject is the principal that holds it, not
// the observed device (SPEC-0466 section 4.6: "remote-maint may execute any
// command as root without a password").
const (
	CapSubjectUserPrefix  = "user/"
	CapSubjectGroupPrefix = "group/"
	CapSubjectAliasPrefix = "alias/"
	// CapSubjectEveryone is the subject of a rule whose user list is ALL.
	CapSubjectEveryone = "everyone"
)

// Diagnostic codes of the resolver.
const (
	// capDiagNoSource: a capability was dropped because it named no source.
	capDiagNoSource = "capability_without_source"
	// capDiagAliasUnresolved: a sudo rule names an alias, and the alias
	// definition was not readable, so the members behind it are unknown.
	capDiagAliasUnresolved = "sudo_alias_not_resolved"
	// capDiagInferredFromGroup: the sudo rule file could not be read, so the
	// capability rests on the group name convention alone.
	capDiagInferredFromGroup = "capability_inferred_from_group"
	// capDiagNoInput: no artifact of the privilege probes was present, so the
	// empty capability list says nothing about the host.
	capDiagNoInput = "no_privilege_artifacts"
	// capDiagSourceUnreadable: a source that decides privileges exists and
	// could not be read. It is emitted whether or not a capability came out
	// of the rest, because an empty list must never read as "this host grants
	// nothing" (F4).
	capDiagSourceUnreadable = "privilege_source_unreadable"
	// capDiagMembershipUnknown: a capability rests on a group whose
	// membership nobody collected, so "no member" and "never asked" would
	// otherwise look the same (F10).
	capDiagMembershipUnknown = "group_membership_unknown"
	// capDiagRuntimeGroup: a capability rests on membership in a group that
	// reaches a container runtime socket (F3).
	capDiagRuntimeGroup = "capability_from_runtime_group"
	// capDiagPrivilegedContainer: a container runs privileged, which is root
	// on the host with no account involved (R-T4).
	capDiagPrivilegedContainer = "capability_from_privileged_container"
)

// capSudoGroups are the group names that grant sudo on a Debian or Ubuntu
// system and on the common RPM distributions. The list is a convention, not an
// observation: a capability derived from it alone is inferred, never declared.
var capSudoGroups = map[string]bool{"admin": true, "sudo": true, "wheel": true}

// capRuntimeGroups are the groups whose members can reach a container runtime
// socket. That socket is root on the host in practice, with no sudo rule and
// no password: a member starts a container that mounts the host filesystem and
// writes into it as root. The membership is therefore a capability of its own,
// and the attributes of that capability say why (F3).
var capRuntimeGroups = map[string]string{"docker": "docker", "lxd": "lxd"}

// Artifact types the resolver accepts for accounts and groups. linux.users
// owns those artifacts; the resolver reads several spellings so that it does
// not break on a naming decision made in another file.
var (
	capGroupTypes = map[string]bool{"group": true, "os-group": true, "local-group": true, "user-group": true}
	capUserTypes  = map[string]bool{"user": true, "os-user": true, "local-user": true, "account": true}
)

// Attribute names the resolver reads on an account or group artifact, in
// order of preference. linux.users writes "name", "members", "member_count",
// "supplementary" and "primary_group"; the other spellings are accepted so
// that a naming decision in another file does not silently drop a privilege.
var (
	capNameAttrs         = []string{"name", "group", "group_name", "user", "user_name", "account"}
	capMembersAttrs      = []string{"members", "member_names", "group_members"}
	capMemberCountAttrs  = []string{"member_count"}
	capGroupsAttrs       = []string{"supplementary", "groups", "group_names", "supplementary_groups"}
	capPrimaryGroupAttrs = []string{"primary_group"}
)

// capDiagMembershipTruncated: the member list of a group was cut by the volume
// cap of the account probe, so a member may hold a capability this resolver
// cannot see.
const capDiagMembershipTruncated = "group_membership_truncated"

// CapabilityResolver turns artifacts into capabilities. The zero value uses
// the built-in privileged group list.
type CapabilityResolver struct {
	// PrivilegedGroups overrides capSudoGroups when it is not empty.
	PrivilegedGroups []string
	// RuntimeGroups overrides capRuntimeGroups when it is not empty.
	RuntimeGroups []string
}

// Resolve implements the capability resolver seam of SPEC-0466 section 4.6:
// pure, deterministic and sorted by capability id. The error return exists for
// the interface; this resolver reports every problem as a diagnostic and never
// fails a capture.
func (r CapabilityResolver) Resolve(_ context.Context, arts []trustfreeze.Artifact) ([]trustfreeze.Capability, []trustfreeze.Diagnostic, error) {
	caps, diags := r.resolve(arts)
	return caps, diags, nil
}

// ResolveCapabilities is the package level form of CapabilityResolver.Resolve.
func ResolveCapabilities(arts []trustfreeze.Artifact) ([]trustfreeze.Capability, []trustfreeze.Diagnostic) {
	return CapabilityResolver{}.resolve(arts)
}

func (r CapabilityResolver) resolve(arts []trustfreeze.Artifact) ([]trustfreeze.Capability, []trustfreeze.Diagnostic) {
	var diags []trustfreeze.Diagnostic
	idx := newCapIndex(arts)
	if idx.empty() {
		return nil, append(diags, trustfreeze.Diagnostic{
			Code:    capDiagNoInput,
			Message: "no sudo, ssh or account artifact was present, so no capability could be resolved",
		})
	}
	diags = append(diags, idx.diags...)
	diags = append(diags, r.coverage(idx)...)
	acc := &capAccumulator{}
	diags = append(diags, r.fromSudoRules(idx, acc)...)
	diags = append(diags, r.fromGroupMembership(idx, acc)...)
	diags = append(diags, r.fromRuntimeGroups(idx, acc)...)
	diags = append(diags, r.fromAuthorizedKeys(idx, acc)...)
	diags = append(diags, r.fromPrivilegedContainers(idx, acc)...)
	caps, dropped := acc.capabilities()
	diags = append(diags, dropped...)
	return caps, diags
}

// privilegedGroups returns the group name set this resolver treats as a sudo
// group.
func (r CapabilityResolver) privilegedGroups() map[string]bool {
	if len(r.PrivilegedGroups) == 0 {
		return capSudoGroups
	}
	out := make(map[string]bool, len(r.PrivilegedGroups))
	for _, g := range r.PrivilegedGroups {
		out[strings.ToLower(strings.TrimSpace(g))] = true
	}
	return out
}

// runtimeGroups returns the group names this resolver treats as a container
// runtime socket group.
func (r CapabilityResolver) runtimeGroups() map[string]string {
	if len(r.RuntimeGroups) == 0 {
		return capRuntimeGroups
	}
	out := make(map[string]string, len(r.RuntimeGroups))
	for _, g := range r.RuntimeGroups {
		name := strings.ToLower(strings.TrimSpace(g))
		if name != "" {
			out[name] = name
		}
	}
	return out
}

// coverage reports the sources that decide privileges and could not be read.
// It runs before any rule and independently of what the rules produce: a
// capabilities document with an empty list and no diagnostic would read as
// "this host grants nothing", which is a statement nobody measured (F4).
func (r CapabilityResolver) coverage(idx *capIndex) []trustfreeze.Diagnostic {
	var diags []trustfreeze.Diagnostic
	if files := idx.unreadableSudoFiles(); len(files) > 0 {
		diags = append(diags, trustfreeze.Diagnostic{
			Code:  capDiagSourceUnreadable,
			Field: strings.Join(files, ","),
			Message: fmt.Sprintf("%d sudo rule file(s) exist and could not be read by this capture, so the privileges they grant are not in this document: %s",
				len(files), strings.Join(files, ", ")),
		})
	}
	if files := idx.unreadableKeyFiles(); len(files) > 0 {
		diags = append(diags, trustfreeze.Diagnostic{
			Code:  capDiagSourceUnreadable,
			Field: strings.Join(files, ","),
			Message: fmt.Sprintf("%d authorized_keys file(s) exist and could not be read by this capture, so the access they grant is not in this document: %s",
				len(files), strings.Join(files, ", ")),
		})
	}
	return diags
}

// fromRuntimeGroups implements the fourth rule: membership in a group that
// reaches a container runtime socket. The grant does not pass through sudo, so
// it gets an id and a privilege of its own, and the attributes say why the
// socket is root (F3). Where this capture also observed the runtime, the
// runtime artifact is a second source; where it did not, the attribute
// runtime_observed says false and the diagnostic says what is unproven.
func (r CapabilityResolver) fromRuntimeGroups(idx *capIndex, acc *capAccumulator) []trustfreeze.Diagnostic {
	var diags []trustfreeze.Diagnostic
	groups := r.runtimeGroups()
	for _, group := range idx.groupNames() {
		runtime, ok := groups[strings.ToLower(group)]
		if !ok {
			continue
		}
		runtimeArtifact, observed := idx.runtimes[runtime]
		// One member can be visible twice, in the group artifact and in the
		// account's own supplementary list. Both are sources of the one
		// capability, and the diagnostic belongs to that capability, so it is
		// written once per member name and not once per entry (O-T2).
		reported := map[string]bool{}
		for _, m := range idx.members(group) {
			subject := CapSubjectUserPrefix + m.name
			sources := []string{m.source}
			if observed {
				sources = append(sources, runtimeArtifact)
			}
			acc.add(trustfreeze.Capability{
				ID:        CapExecuteHostViaRuntimePrefix + runtime + "/" + subject,
				SubjectID: subject,
				Action:    CapActionExecute,
				Resource:  CapResourceHost,
				Effect:    CapEffectAllowed,
				// Nobody wrote this grant down and nobody watched it being
				// used: it follows from the membership and from how the
				// runtime socket works.
				State:     trustfreeze.StateInferred,
				Scope:     CapScopeHost,
				Exposure:  CapExposureLocal,
				Privilege: CapPrivilegeRootViaContainerRuntime,
				Attributes: map[string]string{
					CapAttrGrantPath:       capGrantPathRuntimeSocket,
					CapAttrGroup:           group,
					CapAttrRuntime:         runtime,
					CapAttrRuntimeObserved: privBool(observed),
					CapAttrRationale: "a member of the group " + group + " may use the " + runtime +
						" socket, and a container started through that socket can mount the host filesystem and write as root, " +
						"so the membership grants root on this host without a sudo rule and without a password",
				},
				Sources:    sources,
				Confidence: trustfreeze.ConfidenceReported,
			})
			capID := CapExecuteHostViaRuntimePrefix + runtime + "/" + subject
			if reported[capID] {
				continue
			}
			reported[capID] = true
			msg := m.name + " is a member of the group " + group + ", which reaches the " + runtime + " socket"
			if observed {
				msg += ", and this capture observed that runtime (" + runtimeArtifact + ")"
			} else {
				msg += "; this capture observed no " + runtime + " runtime, so whether the socket exists on this host is not established"
			}
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    capDiagRuntimeGroup,
				Field:   capID,
				Message: msg,
			})
		}
	}
	return diags
}

// fromPrivilegedContainers implements rule 4: a container the runtime reports
// as privileged. The subject is the container, not a principal: a privileged
// container holds the host with nobody logged in, so a capability that named a
// user would name the wrong holder. The flag is configuration the runtime
// reports about a container this capture observed, so the state is declared
// (playbook L3): nobody watched the container reach the host.
func (r CapabilityResolver) fromPrivilegedContainers(idx *capIndex, acc *capAccumulator) []trustfreeze.Diagnostic {
	var diags []trustfreeze.Diagnostic
	for _, a := range idx.privilegedContainers {
		runtime := capFirstAttr(a, []string{"runtime"})
		name := capFirstAttr(a, []string{"name"})
		if name == "" {
			name = capLastSegment(a.ID)
		}
		attrs := map[string]string{
			CapAttrGrantPath: capGrantPathPrivilegedContainer,
			CapAttrContainer: name,
			CapAttrRationale: "the container runs privileged, so it keeps the host device nodes and may mount and write the host filesystem; " +
				"what runs in it acts as root on this host, without an account, a sudo rule or a password",
		}
		if runtime != "" {
			attrs[CapAttrRuntime] = runtime
		}
		if img := capFirstAttr(a, []string{"image"}); img != "" {
			attrs[CapAttrContainerImage] = img
		}
		acc.add(trustfreeze.Capability{
			ID:         CapExecuteHostPrefix + a.ID,
			SubjectID:  a.ID,
			Action:     CapActionExecute,
			Resource:   CapResourceHost,
			Effect:     CapEffectAllowed,
			State:      trustfreeze.StateDeclared,
			Scope:      CapScopeHost,
			Exposure:   CapExposureLocal,
			Privilege:  CapPrivilegeRootViaPrivilegedContainer,
			Attributes: attrs,
			Sources:    []string{a.ID},
			Confidence: trustfreeze.ConfidenceProven,
		})
		diags = append(diags, trustfreeze.Diagnostic{
			Code:    capDiagPrivilegedContainer,
			Field:   CapExecuteHostPrefix + a.ID,
			Message: "the container " + name + " runs privileged, which is root on this host; who may start or enter it is not answered by the artifacts of this capture",
		})
	}
	return diags
}

// fromSudoRules implements rule 1: a rule that grants every command as root.
func (r CapabilityResolver) fromSudoRules(idx *capIndex, acc *capAccumulator) []trustfreeze.Diagnostic {
	var diags []trustfreeze.Diagnostic
	for _, a := range idx.sudoRules {
		if a.Attributes[sudoAttrAllCommands] != "true" || a.Attributes[sudoAttrRunAsRoot] != "true" {
			continue
		}
		noPasswd := a.Attributes[sudoAttrNoPasswd] == "true"
		priv := CapPrivilegeRootViaSudo
		if noPasswd {
			priv = CapPrivilegeRootViaSudoNoPassword
		}
		for _, who := range strings.Split(a.Attributes[sudoAttrUsers], ",") {
			who = strings.TrimSpace(who)
			if who == "" {
				continue
			}
			subject, kind := idx.subjectOf(who)
			switch kind {
			case capSubjectAlias:
				diags = append(diags, trustfreeze.Diagnostic{
					Code:    capDiagAliasUnresolved,
					Field:   a.ID,
					Message: "the rule grants " + who + ", and the alias members are not resolved by this capture",
				})
			case capSubjectNetgroup:
				diags = append(diags, trustfreeze.Diagnostic{
					Code:    capDiagAliasUnresolved,
					Field:   a.ID,
					Message: "the rule grants the netgroup " + who + ", whose members come from a source this capture does not read",
				})
			}
			acc.add(trustfreeze.Capability{
				ID:         CapExecuteHostPrefix + subject,
				SubjectID:  subject,
				Action:     CapActionExecute,
				Resource:   CapResourceHost,
				Effect:     CapEffectAllowed,
				State:      trustfreeze.StateDeclared,
				Scope:      CapScopeHost,
				Exposure:   CapExposureLocal,
				Privilege:  priv,
				Sources:    []string{a.ID},
				Confidence: trustfreeze.ConfidenceProven,
			})
			if kind != capSubjectGroup {
				continue
			}
			// The rule names a group: every member holds the capability. The
			// member statement rests on two distinguishable sources, the rule
			// and the membership, so it is corroborated, and it is derived
			// rather than written down anywhere, so it is inferred.
			group := strings.TrimPrefix(subject, CapSubjectGroupPrefix)
			members := idx.members(group)
			if len(members) == 0 && !idx.groupArtifacts[capNormalizeName(group)] {
				// Nobody collected the membership of this group, so the empty
				// member list is not the statement "the group is empty" (F10).
				diags = append(diags, trustfreeze.Diagnostic{
					Code:  capDiagMembershipUnknown,
					Field: a.ID,
					Message: "the rule grants the group " + group +
						", and this capture holds no membership for it, so who holds this capability is not established",
				})
			}
			for _, m := range members {
				acc.add(trustfreeze.Capability{
					ID:         CapExecuteHostPrefix + CapSubjectUserPrefix + m.name,
					SubjectID:  CapSubjectUserPrefix + m.name,
					Action:     CapActionExecute,
					Resource:   CapResourceHost,
					Effect:     CapEffectAllowed,
					State:      trustfreeze.StateInferred,
					Scope:      CapScopeHost,
					Exposure:   CapExposureLocal,
					Privilege:  priv,
					Sources:    []string{a.ID, m.source},
					Confidence: trustfreeze.ConfidenceCorroborated,
				})
			}
		}
	}
	return diags
}

// fromGroupMembership implements rule 2: membership in a sudo group where no
// readable rule says so.
func (r CapabilityResolver) fromGroupMembership(idx *capIndex, acc *capAccumulator) []trustfreeze.Diagnostic {
	var diags []trustfreeze.Diagnostic
	priv := r.privilegedGroups()
	unreadable := idx.unreadableSudoFiles()
	readable := idx.readableSudoFiles()
	for _, group := range idx.groupNames() {
		if !priv[strings.ToLower(group)] {
			continue
		}
		for _, m := range idx.members(group) {
			id := CapExecuteHostPrefix + CapSubjectUserPrefix + m.name
			if acc.has(id) {
				// A readable rule already proved it; the membership only adds
				// a source.
				acc.addSource(id, m.source)
				continue
			}
			sources := append([]string{m.source}, unreadable...)
			acc.add(trustfreeze.Capability{
				ID:        id,
				SubjectID: CapSubjectUserPrefix + m.name,
				Action:    CapActionExecute,
				Resource:  CapResourceHost,
				Effect:    CapEffectAllowed,
				State:     trustfreeze.StateInferred,
				Scope:     CapScopeHost,
				Exposure:  CapExposureLocal,
				// Without the rule text the password requirement cannot be
				// observed. The conservative reading of a distribution default
				// is "root after authenticating", and the diagnostic says that
				// NOPASSWD could not be ruled out.
				Privilege: CapPrivilegeRootViaSudo,
				Attributes: map[string]string{
					CapAttrGrantPath: capGrantPathGroupMembership,
					CapAttrGroup:     group,
					CapAttrRationale: "the group " + group + " grants sudo on this distribution by convention; " +
						"the command set and the password requirement follow from the rule file, not from the membership",
				},
				Sources:    sources,
				Confidence: trustfreeze.ConfidenceReported,
			})
			// The wording follows the evidence: claiming that no readable rule
			// file confirms the grant is false where one was read and does not
			// grant it (F8).
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    capDiagInferredFromGroup,
				Field:   id,
				Message: capGroupInferenceMessage(m.name, group, readable, unreadable),
			})
		}
	}
	return diags
}

// capGroupInferenceMessage says what the membership rests on, in the words the
// evidence allows: a rule file that could not be read, a rule set that was
// read and does not grant the group, or no rule file at all.
func capGroupInferenceMessage(member, group string, readable, unreadable []string) string {
	base := member + " is a member of the group " + group + ", which grants sudo on this distribution by convention"
	switch {
	case len(unreadable) > 0:
		return base + "; the rule file(s) " + strings.Join(unreadable, ", ") +
			" could not be read, so neither the command set nor a NOPASSWD tag is known"
	case len(readable) > 0:
		return base + "; the rule file(s) this capture read (" + strings.Join(readable, ", ") +
			") grant nothing to that group, so the grant is either withdrawn or written in a file this capture did not read"
	}
	return base + "; this capture read no sudo rule file at all, so the statement rests on the group name alone"
}

// fromAuthorizedKeys implements rule 3: a public key that opens a remote shell.
// A key on a privileged account is the case the report must be able to name,
// so the capability carries the privilege of its account; a key on an ordinary
// account is recorded too, because leaving it out would hide an access path.
func (r CapabilityResolver) fromAuthorizedKeys(idx *capIndex, acc *capAccumulator) []trustfreeze.Diagnostic {
	var diags []trustfreeze.Diagnostic
	for _, a := range idx.authorizedKeys {
		account := strings.TrimSpace(a.Attributes[privAttrAccount])
		if account == "" {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    capDiagNoSource,
				Field:   a.ID,
				Message: "the key artifact names no account, so no capability subject can be derived",
			})
			continue
		}
		subject := CapSubjectUserPrefix + account
		sources := []string{a.ID}
		privilege := CapPrivilegeUser
		switch account {
		case "root":
			privilege = CapPrivilegeRoot
		default:
			if c, ok := acc.get(CapExecuteHostPrefix + subject); ok {
				privilege = c.Privilege
				sources = capMergeSources(sources, c.Sources)
			}
		}
		suffix := strings.TrimPrefix(a.ID, ArtifactSSHAuthorizedKeyPrefix)
		acc.add(trustfreeze.Capability{
			ID:        CapRemoteShellPublicKeyPrefix + suffix,
			SubjectID: subject,
			Action:    CapActionAccess,
			Resource:  CapResourceRemoteShell,
			Effect:    CapEffectAllowed,
			// A key in authorized_keys grants access; nobody observed it being
			// used (playbook L3).
			State:      trustfreeze.StateDeclared,
			Scope:      CapScopeHost,
			Exposure:   CapExposureNetwork,
			Privilege:  privilege,
			Sources:    sources,
			Confidence: trustfreeze.ConfidenceProven,
		})
	}
	return diags
}

// capSubjectKind says what a sudoers user entry names.
type capSubjectKind int

const (
	capSubjectUser capSubjectKind = iota
	capSubjectGroup
	capSubjectNetgroup
	capSubjectAlias
	capSubjectAll
)

// capSubjectOf maps one sudoers user entry to a capability subject: "%sudo"
// is a group, "+netgroup" a netgroup, "ALL" everyone, an all upper case name
// an alias, anything else an account.
func capSubjectOf(who string) (string, capSubjectKind) {
	switch {
	case who == SudoAll:
		return CapSubjectEveryone, capSubjectAll
	case strings.HasPrefix(who, "%#"):
		return CapSubjectGroupPrefix + "gid:" + strings.TrimPrefix(who, "%#"), capSubjectGroup
	case strings.HasPrefix(who, "%"):
		return CapSubjectGroupPrefix + strings.TrimPrefix(who, "%"), capSubjectGroup
	case strings.HasPrefix(who, "+"):
		return CapSubjectAliasPrefix + strings.TrimPrefix(who, "+"), capSubjectNetgroup
	case strings.HasPrefix(who, "#"):
		return CapSubjectUserPrefix + "uid:" + strings.TrimPrefix(who, "#"), capSubjectUser
	case who == strings.ToUpper(who) && strings.ContainsAny(who, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
		return CapSubjectAliasPrefix + who, capSubjectAlias
	}
	return CapSubjectUserPrefix + who, capSubjectUser
}

// capMember is one group member with the artifact it was read from.
type capMember struct {
	name   string
	source string
}

// capIndex is the artifact set the rules read, grouped by what they are.
type capIndex struct {
	sudoRules      []trustfreeze.Artifact
	sudoFiles      []trustfreeze.Artifact
	authorizedKeys []trustfreeze.Artifact
	// keyFiles are the authorized_keys file artifacts, readable or not. An
	// unreadable one is the gap the coverage diagnostic reports.
	keyFiles []trustfreeze.Artifact
	// groups maps a group name to its members, each with its source artifact.
	groups map[string][]capMember
	// groupArtifacts holds the names the account probe really reported as a
	// group, so that a group named only by a rule or by a user's group list
	// can be told from one whose membership was collected (F10).
	groupArtifacts map[string]bool
	// users maps an account name to the artifact that reported it, so that an
	// upper case account name is not mistaken for a sudoers alias (F9).
	users map[string]string
	// runtimes maps a container runtime name to its artifact id.
	runtimes map[string]string
	// privilegedContainers are the container artifacts whose runtime reported
	// declared_privileged true. A container whose privileged flag was never
	// read carries no such attribute and is not in this list: the resolver
	// claims nothing about it.
	privilegedContainers []trustfreeze.Artifact
	// diags carries what the index itself noticed about its input.
	diags []trustfreeze.Diagnostic
}

func newCapIndex(arts []trustfreeze.Artifact) *capIndex {
	idx := &capIndex{
		groups:         map[string][]capMember{},
		groupArtifacts: map[string]bool{},
		users:          map[string]string{},
		runtimes:       map[string]string{},
	}
	for _, a := range arts {
		switch {
		case a.Type == SudoRuleType:
			idx.sudoRules = append(idx.sudoRules, a)
		case a.Type == SudoFileType:
			idx.sudoFiles = append(idx.sudoFiles, a)
		case a.Type == SSHAuthorizedKeyType:
			idx.authorizedKeys = append(idx.authorizedKeys, a)
		case a.Type == SSHAuthorizedKeysType:
			idx.keyFiles = append(idx.keyFiles, a)
		case a.Type == artifactTypeContainerRuntime:
			if name := capFirstAttr(a, []string{"runtime", "name"}); name != "" {
				idx.runtimes[strings.ToLower(name)] = a.ID
			}
		case a.Type == artifactTypeContainer:
			if a.Attributes[containerAttrDeclaredPrivileged] == "true" {
				idx.privilegedContainers = append(idx.privilegedContainers, a)
			}
		case capGroupTypes[a.Type]:
			idx.addGroupArtifact(a)
		case capUserTypes[a.Type]:
			idx.addUserArtifact(a)
		}
	}
	sortByID(idx.sudoRules)
	sortByID(idx.sudoFiles)
	sortByID(idx.authorizedKeys)
	sortByID(idx.keyFiles)
	sortByID(idx.privilegedContainers)
	for g := range idx.groups {
		m := idx.groups[g]
		sort.Slice(m, func(i, j int) bool {
			if m[i].name != m[j].name {
				return m[i].name < m[j].name
			}
			return m[i].source < m[j].source
		})
		idx.groups[g] = capDedupeMembers(m)
	}
	return idx
}

// addGroupArtifact reads a group artifact: a name plus a member list.
func (idx *capIndex) addGroupArtifact(a trustfreeze.Artifact) {
	name := capFirstAttr(a, capNameAttrs)
	if name == "" {
		name = capLastSegment(a.ID)
	}
	name = capNormalizeName(name)
	if name == "" {
		return
	}
	idx.groupArtifacts[name] = true
	members := capSplitNames(capFirstAttr(a, capMembersAttrs))
	for _, m := range members {
		idx.groups[name] = append(idx.groups[name], capMember{name: m, source: a.ID})
	}
	if _, ok := idx.groups[name]; !ok {
		// A group with no member is still a known group: the map entry keeps
		// the name visible to the privileged group rule.
		idx.groups[name] = nil
	}
	if n, ok := capIntAttr(a, capMemberCountAttrs); ok && n > len(members) {
		idx.diags = append(idx.diags, trustfreeze.Diagnostic{
			Code:  capDiagMembershipTruncated,
			Field: a.ID,
			Message: fmt.Sprintf("the group %s has %d members and the artifact lists %d of them, so a member capability may be missing",
				name, n, len(members)),
		})
	}
}

// addUserArtifact reads an account artifact that lists its groups. The primary
// group counts as membership: an account whose primary group grants sudo does
// not appear in that group's member list, because the group database does not
// repeat it there.
func (idx *capIndex) addUserArtifact(a trustfreeze.Artifact) {
	name := capFirstAttr(a, capNameAttrs)
	if name == "" {
		name = capLastSegment(a.ID)
	}
	name = capNormalizeName(name)
	if name == "" {
		return
	}
	idx.users[name] = a.ID
	groups := capSplitNames(capFirstAttr(a, capGroupsAttrs))
	if primary := capNormalizeName(capFirstAttr(a, capPrimaryGroupAttrs)); primary != "" {
		groups = privAppendUnique(groups, primary)
	}
	for _, g := range groups {
		idx.groups[g] = append(idx.groups[g], capMember{name: name, source: a.ID})
	}
}

func (idx *capIndex) empty() bool {
	return len(idx.sudoRules) == 0 && len(idx.sudoFiles) == 0 &&
		len(idx.authorizedKeys) == 0 && len(idx.keyFiles) == 0 && len(idx.groups) == 0 &&
		len(idx.privilegedContainers) == 0
}

func (idx *capIndex) members(group string) []capMember {
	return idx.groups[capNormalizeName(group)]
}

func (idx *capIndex) groupNames() []string {
	out := make([]string, 0, len(idx.groups))
	for g := range idx.groups {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// unreadableSudoFiles returns the ids of the rule files that exist but could
// not be read. They are the second source of an inferred capability: they say
// where the missing proof would be.
func (idx *capIndex) unreadableSudoFiles() []string {
	var out []string
	for _, a := range idx.sudoFiles {
		if a.Attributes[privAttrReadable] == "false" {
			out = append(out, a.ID)
		}
	}
	sort.Strings(out)
	return out
}

// unreadableKeyFiles returns the ids of the authorized_keys files that exist
// and could not be read.
func (idx *capIndex) unreadableKeyFiles() []string {
	var out []string
	for _, a := range idx.keyFiles {
		if a.Attributes[privAttrReadable] == "false" {
			out = append(out, a.ID)
		}
	}
	sort.Strings(out)
	return out
}

// subjectOf classifies one sudoers user entry against what this capture saw.
// capSubjectOf alone reads every upper case token as an alias, and an upper
// case account name is legal on Linux, so an artifact of that exact name
// decides it (F9).
func (idx *capIndex) subjectOf(who string) (string, capSubjectKind) {
	subject, kind := capSubjectOf(who)
	if kind != capSubjectAlias {
		return subject, kind
	}
	switch {
	case idx.users[who] != "":
		return CapSubjectUserPrefix + who, capSubjectUser
	case idx.groupArtifacts[who]:
		return CapSubjectGroupPrefix + who, capSubjectGroup
	}
	return subject, kind
}

// readableSudoFiles returns the ids of the rule files this capture read.
func (idx *capIndex) readableSudoFiles() []string {
	var out []string
	for _, a := range idx.sudoFiles {
		if a.Attributes[privAttrReadable] == "true" {
			out = append(out, a.ID)
		}
	}
	sort.Strings(out)
	return out
}

// capAccumulator collects capabilities by id, merging the sources of two
// statements about the same subject and keeping the stronger one.
type capAccumulator struct {
	order []string
	byID  map[string]trustfreeze.Capability
}

func (a *capAccumulator) add(c trustfreeze.Capability) {
	if a.byID == nil {
		a.byID = map[string]trustfreeze.Capability{}
	}
	// Sources are sorted and deduplicated on the way in, so two runs over the
	// same artifacts in another order produce the same capability (playbook
	// L8).
	c.Sources = capMergeSources(nil, c.Sources)
	old, ok := a.byID[c.ID]
	if !ok {
		a.order = append(a.order, c.ID)
		a.byID[c.ID] = c
		return
	}
	merged := old
	if capStronger(c, old) {
		merged = c
	}
	merged.Sources = capMergeSources(old.Sources, c.Sources)
	a.byID[c.ID] = merged
}

func (a *capAccumulator) has(id string) bool {
	_, ok := a.byID[id]
	return ok
}

func (a *capAccumulator) get(id string) (trustfreeze.Capability, bool) {
	c, ok := a.byID[id]
	return c, ok
}

func (a *capAccumulator) addSource(id, source string) {
	if c, ok := a.byID[id]; ok {
		c.Sources = capMergeSources(c.Sources, []string{source})
		a.byID[id] = c
	}
}

// capabilities returns the collected capabilities sorted by id, and one
// diagnostic per dropped capability.
func (a *capAccumulator) capabilities() ([]trustfreeze.Capability, []trustfreeze.Diagnostic) {
	var (
		out   []trustfreeze.Capability
		diags []trustfreeze.Diagnostic
	)
	ids := append([]string(nil), a.order...)
	sort.Strings(ids)
	for _, id := range ids {
		c := a.byID[id]
		if err := ValidateCapability(c); err != nil {
			diags = append(diags, trustfreeze.Diagnostic{Code: capDiagNoSource, Field: id, Message: err.Error()})
			continue
		}
		out = append(out, c)
	}
	return out, diags
}

// ValidateCapability rejects a capability that cannot be checked: SPEC-0468 R7
// requires every capability to name its sources, and the other identity fields
// must be present for a report to say anything at all.
func ValidateCapability(c trustfreeze.Capability) error {
	switch {
	case strings.TrimSpace(c.ID) == "":
		return fmt.Errorf("capability without an id")
	case strings.TrimSpace(c.SubjectID) == "":
		return fmt.Errorf("capability %s without a subject", c.ID)
	case strings.TrimSpace(c.Action) == "":
		return fmt.Errorf("capability %s without an action", c.ID)
	case strings.TrimSpace(c.Resource) == "":
		return fmt.Errorf("capability %s without a resource", c.ID)
	case len(c.Sources) == 0:
		return fmt.Errorf("capability %s names no source", c.ID)
	case !c.State.Valid():
		return fmt.Errorf("capability %s has state %q", c.ID, c.State)
	case !c.Confidence.Valid():
		return fmt.Errorf("capability %s has confidence %q", c.ID, c.Confidence)
	}
	for _, s := range c.Sources {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("capability %s has an empty source", c.ID)
		}
	}
	return nil
}

// capStronger reports whether b should replace a: a proven statement beats an
// inferred one, and a capability without a password requirement beats one with
// it, because the bundle must state the strongest grant it can prove.
func capStronger(b, a trustfreeze.Capability) bool {
	if rb, ra := capStateRank(b.State), capStateRank(a.State); rb != ra {
		return rb > ra
	}
	return capPrivilegeRank(b.Privilege) > capPrivilegeRank(a.Privilege)
}

func capStateRank(s trustfreeze.EvidenceState) int {
	switch s {
	case trustfreeze.StateObserved:
		return 4
	case trustfreeze.StateResolved:
		return 3
	case trustfreeze.StateDeclared:
		return 2
	case trustfreeze.StateInferred:
		return 1
	}
	return 0
}

func capPrivilegeRank(p string) int {
	switch p {
	case CapPrivilegeRoot, CapPrivilegeRootViaSudoNoPassword:
		return 3
	case CapPrivilegeRootViaSudo:
		return 2
	case CapPrivilegeUser:
		return 1
	}
	return 0
}

func capMergeSources(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, s := range b {
		out = privAppendUnique(out, s)
	}
	sort.Strings(out)
	return out
}

func capDedupeMembers(in []capMember) []capMember {
	out := in[:0]
	seen := map[string]bool{}
	for _, m := range in {
		key := m.name + "\x00" + m.source
		if m.name == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out
}

// capIntAttr returns the first attribute of names that parses as a number.
func capIntAttr(a trustfreeze.Artifact, names []string) (int, bool) {
	for _, n := range names {
		if v, err := strconv.Atoi(strings.TrimSpace(a.Attributes[n])); err == nil {
			return v, true
		}
	}
	return 0, false
}

// capFirstAttr returns the first non empty attribute of names.
func capFirstAttr(a trustfreeze.Artifact, names []string) string {
	for _, n := range names {
		if v := strings.TrimSpace(a.Attributes[n]); v != "" {
			return v
		}
	}
	return ""
}

// capSplitNames splits a comma or space separated name list and normalizes
// every entry.
func capSplitNames(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if n := capNormalizeName(p); n != "" {
			out = privAppendUnique(out, n)
		}
	}
	return out
}

// capNormalizeName accepts the spellings a group or account name reaches the
// resolver in: a plain name, the "%group" form of a sudoers rule and the
// "27(sudo)" form the id command prints.
func capNormalizeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "%")
	if i := strings.IndexByte(s, '('); i >= 0 && strings.HasSuffix(s, ")") {
		s = s[i+1 : len(s)-1]
	}
	return strings.TrimSpace(s)
}

// capLastSegment returns the last path segment of an artifact id.
func capLastSegment(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 {
		return id[i+1:]
	}
	return id
}

func sortByID(a []trustfreeze.Artifact) {
	sort.Slice(a, func(i, j int) bool { return a[i].ID < a[j].ID })
}
