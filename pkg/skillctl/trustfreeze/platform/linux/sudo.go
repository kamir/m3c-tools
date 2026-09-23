package linux

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// Probe identity of linux.sudo (SPEC-0471 TF06-R3).
const (
	SudoProbeID      = "linux.sudo"
	SudoProbeVersion = "1"
)

// Paths linux.sudo reads.
const (
	// SudoersPath is the main rule file.
	SudoersPath = "/etc/sudoers"
	// SudoersDir holds the drop-in rule files.
	SudoersDir = "/etc/sudoers.d"
)

// Artifact id prefixes of linux.sudo. A file id keeps the path below /etc so
// the id stays stable and carries no absolute path (SPEC-0466 R4): /etc/sudoers
// becomes sudo/file/sudoers, /etc/sudoers.d/alice-nopasswd becomes
// sudo/file/sudoers.d/alice-nopasswd. A rule id names its file and the line the
// rule starts on, which is stable while the file is unchanged.
const (
	SudoFilePrefix         = "sudo/file/"
	SudoRulePrefix         = "sudo/rule/"
	SudoDefaultsArtifactID = "sudo/defaults"
)

// Artifact types of linux.sudo.
const (
	SudoFileType     = "sudoers-file"
	SudoRuleType     = "sudo-rule"
	SudoDefaultsType = "sudo-defaults"
)

// Attribute names shared by the artifacts of the privilege probes. The
// capability resolver reads artifacts by these names only (capability.go), so
// they are part of the contract between the probes and the resolver.
const (
	// privAttrPath is a system path such as /etc/sudoers. Never a user home path.
	privAttrPath = "path"
	// privAttrMode is the permission bits in octal, for example "0440".
	privAttrMode = "mode"
	// privAttrOwner and privAttrGroup are the owning user and group names.
	privAttrOwner = "owner"
	privAttrGroup = "group"
	// privAttrSize is the file size in bytes as a decimal string.
	privAttrSize = "size"
	// privAttrReadable is "true" or "false": whether this capture could read the
	// file. A false value with an existing file is a collection gap, never an
	// empty rule set (playbook L1).
	privAttrReadable = "readable"
	// privAttrContentSHA256 is "sha256:<hex>" over the raw file bytes.
	privAttrContentSHA256 = "content_sha256"
	// privAttrLine is the line a record starts on.
	privAttrLine = "line"
	// privAttrFile is the path of the file a record came from.
	privAttrFile = "file"
	// privAttrAccount is a local account name.
	privAttrAccount = "account"
)

// Attribute names of a sudo rule artifact.
const (
	sudoAttrUsers         = "users"
	sudoAttrHosts         = "hosts"
	sudoAttrRunAsUsers    = "runas_users"
	sudoAttrRunAsGroups   = "runas_groups"
	sudoAttrTags          = "tags"
	sudoAttrCommands      = "commands"
	sudoAttrNoPasswd      = "nopasswd"
	sudoAttrAllCommands   = "all_commands"
	sudoAttrRunAsRoot     = "runas_root"
	sudoAttrCommandCount  = "command_count"
	sudoAttrCommandsCut   = "commands_truncated"
	sudoAttrRuleCount     = "rule_count"
	sudoAttrDefaultsCount = "defaults_count"
	sudoAttrCommentLines  = "comment_lines"
	sudoAttrIncludeCount  = "include_count"
	sudoAttrEntryCount    = "entry_count"
	// sudoAttrResolvedAliases names the aliases of the same file that were
	// expanded into users, runas targets and commands of this rule.
	sudoAttrResolvedAliases = "resolved_aliases"
	// sudoAttrUnresolvedAliases names the command aliases no rule file this
	// capture read defines. A command entry can only be ALL or a Cmnd_Alias,
	// so an unresolved one is a gap in the grant this rule carries.
	sudoAttrUnresolvedAliases = "unresolved_aliases"
)

// sudoRuleAttrNames is the attribute set of a rule artifact. The rule
// artifact declares it as configuration: every one of these fields says what
// a rule grants, and nopasswd in particular is the answer a review needs,
// not a password (SPEC-0471 TF06-R3).
var sudoRuleAttrNames = []string{
	privAttrFile, privAttrLine,
	sudoAttrUsers, sudoAttrHosts, sudoAttrRunAsUsers, sudoAttrRunAsGroups,
	sudoAttrTags, sudoAttrCommands, sudoAttrCommandCount, sudoAttrCommandsCut,
	sudoAttrNoPasswd, sudoAttrAllCommands, sudoAttrRunAsRoot,
	sudoAttrResolvedAliases, sudoAttrUnresolvedAliases,
}

// privDiagAliasUnresolved marks a sudoers alias that no rule file this capture
// read defines. It is the code the capability resolver uses for the same gap
// seen from the other end (capability.go).
const privDiagAliasUnresolved = capDiagAliasUnresolved

// SudoTagNoPasswd and the other sudoers tags this probe understands. A tag is
// written without its colon.
const (
	SudoTagNoPasswd = "NOPASSWD"
	SudoTagPasswd   = "PASSWD"
	SudoTagSetEnv   = "SETENV"
	SudoTagNoSetEnv = "NOSETENV"
	SudoTagNoExec   = "NOEXEC"
	SudoTagExec     = "EXEC"
)

// sudoMaxCommandsBytes caps the command list of one rule artifact. A rule that
// lists dozens of commands would otherwise put a kilobyte into every capture
// (playbook L6). The cut is deterministic, it happens at a comma boundary, and
// it is marked: command_count keeps the full number, so a rule that gains a
// command is still visible as a change.
const sudoMaxCommandsBytes = 512

// SudoAll is the sudoers keyword that stands for every user, host, runas
// target or command.
const SudoAll = "ALL"

// privDiagEvidenceWithheld marks raw evidence that was deliberately not persisted
// although it was read: a sudoers file with comment lines can name people and
// carry pasted secrets, so only the parsed rules and the content digest are
// kept (playbook L4).
const privDiagEvidenceWithheld = "evidence_withheld"

// privDiagRecordUnparsed marks one input record the parser could not read. The
// message never repeats the line content, only its position and the reason.
const privDiagRecordUnparsed = "record_unparsed"

// privDiagRuleFileMissing marks a rule file that does not exist on this host
// while the drop-in directory does. The absence is a fact about the host, not
// a missing tool, and a first capture has to record it (O-T3).
const privDiagRuleFileMissing = "rule_file_missing"

// Executables linux.sudo runs. Neither is ever prefixed with an elevation
// helper (playbook L2); probe.ExecRunner refuses those by name anyway.
const (
	sudoListTool = "ls"
	sudoStatTool = "stat"
)

// SudoAllowedRoots returns the file roots linux.sudo reads. The registry
// aggregates the roots of every linux probe for the restricted file reader.
func SudoAllowedRoots() []string { return []string{SudoersPath, SudoersDir} }

// SudoProbe collects the sudo rule structure of the host.
//
// What it records: which rule files exist, their mode, owner, group and size,
// and for every readable file the parsed rules (who, host, runas, tags,
// commands) plus a digest of the raw bytes. What it never records: the raw
// file when it carries comments, and no probe ever runs sudo itself (playbook
// L2; probe.ExecRunner refuses every elevation helper by name).
//
// Required privilege stays "user" on purpose. On a stock Ubuntu host
// /etc/sudoers is 0440 root:root, so an unprivileged capture cannot read the
// rule text. Declaring the probe elevated would make the capture engine skip
// it entirely and the bundle would say nothing at all; instead the probe runs,
// records the structure it can observe and reports permission_denied for the
// files it could not read (playbook L1).
type SudoProbe struct{}

// NewSudoProbe returns the linux.sudo probe.
func NewSudoProbe() *SudoProbe { return &SudoProbe{} }

// Descriptor implements probe.Probe.
func (p *SudoProbe) Descriptor() probe.ProbeDescriptor {
	return probe.ProbeDescriptor{
		ID:                SudoProbeID,
		Version:           SudoProbeVersion,
		Platforms:         []probe.Platform{probe.PlatformLinux},
		RequiredPrivilege: probe.PrivilegeUser,
		DefaultTimeout:    20 * time.Second,
		Sensitivity:       trustfreeze.SensitivityInternal,
		Provides:          []string{SudoDefaultsArtifactID, SudoFilePrefix, SudoRulePrefix},
	}
}

// RequiredTools implements the structural ToolUser interface of the capture
// engine: doctor resolves these through LookPath and never runs one. The rule
// files themselves are read through the file reader, so a missing tool costs
// the metadata and the drop-in enumeration, not the rules.
func (p *SudoProbe) RequiredTools() []string { return []string{sudoListTool, sudoStatTool} }

// EvidenceClaims implements probe.EvidenceClaimer: every parser is covered by
// fixture tests that run on any host, and the package compiles for linux. A
// real platform run is recorded outside the code (SPEC-0471 TF06-R7).
func (p *SudoProbe) EvidenceClaims() map[probe.Platform][]probe.EvidenceLevel {
	return map[probe.Platform][]probe.EvidenceLevel{
		probe.PlatformLinux: {probe.FixtureTested, probe.CrossCompiled},
	}
}

// Support implements probe.Probe. It checks availability only: the probe reads
// files through the injected reader, so it can always run on linux; a missing
// ls or stat costs metadata, not the rules, and shows up as a diagnostic.
func (p *SudoProbe) Support(_ context.Context, host probe.HostContext) probe.SupportResult {
	if !p.Descriptor().SupportsPlatform(host.GOOS) {
		return probe.Unsupported("no sudoers source for " + host.GOOS)
	}
	return probe.Supported()
}

// Collect implements probe.Probe.
func (p *SudoProbe) Collect(ctx context.Context, cc probe.CollectContext) trustfreeze.ProbeResult {
	start := cc.Now()
	c := newPrivCollector(ctx, cc)
	res := privBaseResult(SudoProbeID, SudoProbeVersion, cc, start)
	if cc.GOOS != "linux" {
		res.Status = trustfreeze.StatusUnsupported
		res.Reason = "no sudoers source for " + cc.GOOS
		return res
	}
	// Playbook L7: a parser is only valid for the tool version it was measured
	// against, so both versions are recorded.
	c.recordVersion(sudoStatTool, []string{"--version"}, privStdout)
	c.recordVersion(sudoListTool, []string{"--version"}, privStdout)

	entries, dirState, dirDetail := c.listDir(SudoersDir, "sudoers.d")
	dropIns := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir || e.IsSymlink {
			// A directory below /etc/sudoers.d is ignored by sudo, and a
			// symlink is not followed into an unknown root.
			continue
		}
		dropIns = append(dropIns, SudoersDir+"/"+e.Name)
	}
	sort.Strings(dropIns)

	paths := append([]string{SudoersPath, SudoersDir}, dropIns...)
	stats, statRan := c.statPaths(paths)
	// ls already reported mode, owner, group and size for the drop-ins; stat
	// is the authoritative source and its octal mode needs no conversion, so
	// the listing only fills what stat could not answer.
	for _, e := range entries {
		full := SudoersDir + "/" + e.Name
		if _, ok := stats[full]; ok {
			continue
		}
		if info, ok := e.statInfo(); ok {
			stats[full] = info
		}
	}

	var (
		arts   []trustfreeze.Artifact
		states []privState
	)
	dirExists := stats[SudoersDir].Known || dirState == privOK
	if dirState != privOK {
		c.warn(privStateCode(dirState), SudoersDir, dirDetail)
		if dirExists {
			states = append(states, dirState)
		}
	}
	if a, ok := c.sudoDirArtifact(stats[SudoersDir], len(dropIns), dirState); ok {
		arts = append(arts, a)
	}

	// Two phases: read and parse every rule file first, then build the
	// artifacts. sudo keeps ONE alias namespace over /etc/sudoers and every
	// drop-in, so a rule cannot be read without the alias definitions of the
	// other files (O-T5).
	readable, present := 0, 0
	mainFound := false
	var reads []sudoFileRead
	for _, fp := range append([]string{SudoersPath}, dropIns...) {
		rd, st, found := c.readSudoersFile(fp, stats[fp])
		if !found {
			continue
		}
		if fp == SudoersPath {
			mainFound = true
		}
		reads = append(reads, rd)
		present++
		if st == privOK {
			readable++
		}
		states = append(states, st)
	}
	var aliases []SudoAlias
	for _, rd := range reads {
		aliases = append(aliases, rd.doc.Aliases...)
	}
	for _, rd := range reads {
		arts = append(arts, c.sudoFileArtifacts(rd, aliases)...)
	}
	if !mainFound && dirExists {
		// The main rule file does not exist while the drop-in directory does.
		// That is a fact about this host, and a first capture has to record
		// it: a diff against a baseline that had the file would otherwise be
		// the only place it ever surfaced (O-T3).
		c.warn(privDiagRuleFileMissing, SudoersPath,
			SudoersPath+" does not exist on this host, while "+SudoersDir+" does: the rules of this host are the drop-in files alone")
		states = append(states, privPartial)
	}

	states = append(states, c.extraStates()...)
	res.Status, res.Reason, res.Error = privStatus(states, "the sudoers files")
	switch {
	case present == 0 && !dirExists && statRan:
		// Neither a rule file nor the drop-in directory exists: this host has
		// no sudo configuration at all (playbook L1).
		res.Status = trustfreeze.StatusNotApplicable
		res.Reason = "neither " + SudoersPath + " nor " + SudoersDir + " exists on this host"
		res.Error = nil
	case res.Status == trustfreeze.StatusCaptured && present > 0 && readable == 0:
		res.Status = trustfreeze.StatusPartial
		res.Reason = "no sudoers file was readable"
	}
	return c.finish(res, arts, start)
}

// sudoDirArtifact records the drop-in directory itself: its mode says who may
// add a rule file.
func (c *privCollector) sudoDirArtifact(info StatInfo, entries int, st privState) (trustfreeze.Artifact, bool) {
	if !info.Known && st != privOK {
		return trustfreeze.Artifact{}, false
	}
	attrs := map[string]string{
		privAttrPath:       SudoersDir,
		sudoAttrEntryCount: strconv.Itoa(entries),
		privAttrReadable:   privBool(st == privOK),
	}
	info.apply(attrs)
	return c.artifact(SudoFilePrefix+"sudoers.d", SudoFileType, "host", trustfreeze.StateObserved,
		attrs, "command", trustfreeze.ConfidenceProven,
		[]string{"command:ls -la " + SudoersDir, "command:stat " + SudoersDir},
		c.versions[sudoStatTool], trustfreeze.SensitivityInternal), true
}

// sudoFileRead is one rule file after reading and parsing it, before its
// artifacts are built. The artifacts wait for every file, because the aliases
// of one file are visible to the rules of another (O-T5).
type sudoFileRead struct {
	path string
	id   string
	// attrs are the file artifact attributes, complete except for what the
	// rules add.
	attrs map[string]string
	// doc is the parsed content; the zero value for a file that exists and
	// could not be read, which readable then says.
	doc      SudoersDoc
	readable bool
}

// readSudoersFile reads and parses one rule file. found is false when the file
// does not exist: neither stat nor the read saw it, or the read said so.
func (c *privCollector) readSudoersFile(fp string, info StatInfo) (rd sudoFileRead, st privState, found bool) {
	id, ok := sudoFileArtifactID(fp)
	if !ok {
		c.warn(probe.DiagArtifactDropped, fp, "path does not produce a valid artifact id")
		return sudoFileRead{}, privOK, false
	}
	attrs := map[string]string{privAttrPath: fp}
	info.apply(attrs)

	raw, st, detail := c.readFile(fp)
	if st != privOK {
		if st == privUnavailable && (!info.Known || privLooksMissing(detail)) {
			// The file is simply not there. An artifact saying "exists and is
			// unreadable" would claim more than was measured.
			return sudoFileRead{}, st, false
		}
		attrs[privAttrReadable] = privBool(false)
		c.warn(privStateCode(st), fp, detail)
		return sudoFileRead{path: fp, id: id, attrs: attrs}, st, true
	}
	attrs[privAttrReadable] = privBool(true)
	attrs[privAttrContentSHA256] = trustfreeze.Digest(raw)
	attrs[privAttrSize] = strconv.Itoa(len(raw))

	doc := ParseSudoers(raw)
	attrs[sudoAttrRuleCount] = strconv.Itoa(len(doc.Rules))
	attrs[sudoAttrDefaultsCount] = strconv.Itoa(len(doc.Defaults))
	attrs[sudoAttrCommentLines] = strconv.Itoa(doc.CommentLines)
	attrs[sudoAttrIncludeCount] = strconv.Itoa(len(doc.Includes))
	for _, d := range doc.Issues {
		c.warn(d.Code, fp, d.Message)
		st = privPartial
	}
	// Playbook L4: a sudoers file with comments can name people and can carry
	// a pasted secret in a comment. The parsed rules and the digest are enough
	// to compare two captures, so the raw bytes stay out of the bundle.
	if doc.CommentLines > 0 {
		c.warn(privDiagEvidenceWithheld, fp, "the file carries comment lines; only the parsed rules and the content digest are persisted")
	} else if red, ok := c.redactFile(fp, raw); ok {
		c.addEvidence(privEvidenceName(fp), "file:"+fp, red, false)
	}
	return sudoFileRead{path: fp, id: id, attrs: attrs, doc: doc, readable: true}, st, true
}

// sudoFileArtifacts turns one read rule file into its artifacts, resolving the
// aliases of every rule file this capture read.
func (c *privCollector) sudoFileArtifacts(rd sudoFileRead, aliases []SudoAlias) []trustfreeze.Artifact {
	arts := []trustfreeze.Artifact{c.sudoFileArtifact(rd.id, rd.path, rd.attrs)}
	if !rd.readable {
		return arts
	}
	doc := rd.doc.withAliases(aliases)
	for _, r := range doc.Rules {
		arts = append(arts, c.sudoRuleArtifact(doc, rd.id, rd.path, r))
	}
	if a, ok := c.sudoDefaultsArtifact(rd.path, doc); ok {
		arts = append(arts, a)
	}
	return arts
}

func (c *privCollector) sudoFileArtifact(id, fp string, attrs map[string]string) trustfreeze.Artifact {
	sources := []string{"file:" + fp}
	if c.versions[sudoStatTool] != "" {
		sources = append(sources, "command:stat "+fp)
	}
	return c.artifact(id, SudoFileType, "host", trustfreeze.StateDeclared, attrs, "file",
		trustfreeze.ConfidenceProven, sources, "", trustfreeze.SensitivityInternal)
}

func (c *privCollector) sudoRuleArtifact(doc SudoersDoc, fileID, fp string, r SudoRule) trustfreeze.Artifact {
	// The grant a rule carries is what it grants after the aliases of the same
	// file are resolved, so the artifact records the resolved lists and names
	// the aliases behind them (F5).
	users := doc.RuleUsers(r)
	commandList := doc.RuleCommands(r)
	resolved, unresolved := doc.RuleAliasGaps(r)
	attrs := map[string]string{
		privAttrFile:         fp,
		privAttrLine:         strconv.Itoa(r.Line),
		sudoAttrUsers:        privJoin(users),
		sudoAttrHosts:        privJoin(r.Hosts),
		sudoAttrRunAsUsers:   privJoin(r.RunAsUsers),
		sudoAttrRunAsGroups:  privJoin(r.RunAsGroups),
		sudoAttrTags:         privJoin(r.Tags),
		sudoAttrCommandCount: strconv.Itoa(len(commandList)),
		sudoAttrNoPasswd:     privBool(r.HasTag(SudoTagNoPasswd)),
		sudoAttrAllCommands:  privBool(doc.RuleGrantsAllCommands(r)),
		sudoAttrRunAsRoot:    privBool(doc.RuleRunsAsRoot(r)),
	}
	if len(resolved) > 0 {
		attrs[sudoAttrResolvedAliases] = privJoin(resolved)
	}
	if len(unresolved) > 0 {
		attrs[sudoAttrUnresolvedAliases] = privJoin(unresolved)
		c.warn(privDiagAliasUnresolved, fp, fmt.Sprintf(
			"the rule in line %d names the command alias %s, which no rule file this capture read defines; whether it grants every command is unknown",
			r.Line, privJoin(unresolved)))
	}
	commands, cut := privCapList(commandList, sudoMaxCommandsBytes)
	attrs[sudoAttrCommands] = commands
	if cut {
		attrs[sudoAttrCommandsCut] = privBool(true)
		c.warn(probe.DiagFieldFailed, fp, fmt.Sprintf("the command list of the rule in line %d is longer than %d bytes and was cut; command_count keeps the full number", r.Line, sudoMaxCommandsBytes))
	}
	id := strings.TrimPrefix(fileID, SudoFilePrefix)
	return c.declareConfigAttrs(c.artifact(SudoRulePrefix+id+"/"+strconv.Itoa(r.Line), SudoRuleType, "host",
		trustfreeze.StateDeclared, attrs, "file", trustfreeze.ConfidenceProven,
		[]string{"file:" + fp}, "", trustfreeze.SensitivityInternal), sudoRuleAttrNames)
}

// sudoDefaultsArtifact records the Defaults settings that change how a rule is
// authenticated. Only a fixed set is recorded, so the artifact stays small
// (playbook L6) and carries no environment values.
func (c *privCollector) sudoDefaultsArtifact(fp string, doc SudoersDoc) (trustfreeze.Artifact, bool) {
	if len(doc.Defaults) == 0 {
		return trustfreeze.Artifact{}, false
	}
	watched := map[string]string{
		"authenticate": "", "targetpw": "", "rootpw": "", "runaspw": "",
		"env_reset": "", "secure_path": "", "requiretty": "", "timestamp_timeout": "",
	}
	for _, d := range doc.Defaults {
		name := strings.TrimPrefix(d.Name, "!")
		if _, ok := watched[name]; !ok {
			continue
		}
		switch {
		case strings.HasPrefix(d.Name, "!"):
			watched[name] = "off"
		case d.Value != "":
			watched[name] = "set"
		default:
			watched[name] = "on"
		}
	}
	attrs := map[string]string{privAttrFile: fp, sudoAttrDefaultsCount: strconv.Itoa(len(doc.Defaults))}
	for k, v := range watched {
		if v != "" {
			attrs[k] = v
		}
	}
	id := SudoDefaultsArtifactID
	if fp != SudoersPath {
		slug, ok := sudoFileArtifactID(fp)
		if !ok {
			return trustfreeze.Artifact{}, false
		}
		id = SudoDefaultsArtifactID + "/" + strings.TrimPrefix(slug, SudoFilePrefix)
	}
	return c.artifact(id, SudoDefaultsType, "host", trustfreeze.StateDeclared, attrs, "file",
		trustfreeze.ConfidenceProven, []string{"file:" + fp}, "", trustfreeze.SensitivityInternal), true
}

// sudoFileArtifactID maps /etc/sudoers to sudo/file/sudoers and
// /etc/sudoers.d/<name> to sudo/file/sudoers.d/<name>.
func sudoFileArtifactID(fp string) (string, bool) {
	rel := strings.TrimPrefix(fp, "/etc/")
	if rel == fp || rel == "" {
		return "", false
	}
	id := SudoFilePrefix + rel
	if trustfreeze.ValidateArtifactID(id) != nil {
		return "", false
	}
	return id, true
}

// SudoRule is one user specification of a sudoers file: who may run which
// commands, on which host, as whom, and under which tags.
type SudoRule struct {
	// Line is the line the rule starts on, counted from 1.
	Line int
	// Users are the user and group entries on the left, a group written with
	// its leading "%" and a netgroup with its leading "+".
	Users []string
	// Hosts are the host entries between the users and the "=".
	Hosts []string
	// RunAsUsers and RunAsGroups are the "(user:group)" part. An absent runas
	// specification means root, which sudoers spells implicitly; the parser
	// keeps it empty and RunsAsRoot answers the question.
	RunAsUsers  []string
	RunAsGroups []string
	// Tags are the sudoers tags without their colon, for example NOPASSWD.
	Tags []string
	// Commands are the command entries on the right.
	Commands []string
}

// HasTag reports whether the rule carries tag (case-insensitive).
func (r SudoRule) HasTag(tag string) bool {
	for _, t := range r.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// AllCommands reports whether the rule grants the ALL command set.
func (r SudoRule) AllCommands() bool {
	for _, cmd := range r.Commands {
		if cmd == SudoAll {
			return true
		}
	}
	return false
}

// RunsAsRoot reports whether the rule lets the command run as root: an
// explicit root or ALL runas user, or no runas specification at all, which
// sudoers reads as root.
func (r SudoRule) RunsAsRoot() bool {
	if len(r.RunAsUsers) == 0 {
		return true
	}
	for _, u := range r.RunAsUsers {
		if u == "root" || u == SudoAll {
			return true
		}
	}
	return false
}

// SudoDefault is one Defaults setting. Value is the text after "=", which is
// kept only for the settings the probe records.
type SudoDefault struct {
	Line  int
	Name  string
	Value string
}

// SudoAlias is one alias definition (User_Alias, Runas_Alias, Host_Alias or
// Cmnd_Alias).
type SudoAlias struct {
	Line    int
	Kind    string
	Name    string
	Members []string
}

// SudoInclude is one include directive, either the classic "#include" form or
// the modern "@include" form, with "dir" true for an includedir.
type SudoInclude struct {
	Line int
	Path string
	Dir  bool
}

// SudoersDoc is the parsed content of one sudoers file. The raw text is not
// part of it: only structure leaves the parser.
type SudoersDoc struct {
	Rules    []SudoRule
	Defaults []SudoDefault
	Aliases  []SudoAlias
	Includes []SudoInclude
	// CommentLines counts the comment lines that are not include directives.
	// A file with comments is never persisted as raw evidence (playbook L4).
	CommentLines int
	// Issues names every line the parser could not read, by position and
	// reason, never by content.
	Issues []trustfreeze.Diagnostic
}

// ParseSudoers parses a sudoers file (sudoers(5)). It is pure: bytes in,
// structure out, no file system and no clock, so every shape is table-tested
// on any OS.
//
// Handled: comment lines, the "#include"/"#includedir" and "@include"/
// "@includedir" directives, backslash line continuation, Defaults with their
// per-host, per-user, per-runas and per-command suffixes, the four alias
// kinds, and user specifications with an optional "(runas)" part and tags.
// Not handled, and reported as an issue instead of guessed: a user
// specification with several host specs separated by ":".
func ParseSudoers(b []byte) SudoersDoc {
	var doc SudoersDoc
	for _, ln := range privLogicalLines(b) {
		text := strings.TrimSpace(ln.Text)
		switch {
		case text == "":
			continue
		case strings.HasPrefix(text, "#"), strings.HasPrefix(text, "@"):
			if inc, ok := parseSudoInclude(text, ln.Line); ok {
				doc.Includes = append(doc.Includes, inc)
				continue
			}
			if strings.HasPrefix(text, "#") {
				doc.CommentLines += ln.Lines
				continue
			}
			doc.Issues = append(doc.Issues, trustfreeze.Diagnostic{
				Code:    privDiagRecordUnparsed,
				Message: fmt.Sprintf("line %d: unknown @ directive", ln.Line),
			})
		case strings.HasPrefix(text, "Defaults"):
			doc.Defaults = append(doc.Defaults, parseSudoDefaults(text, ln.Line)...)
		case sudoAliasKind(text) != "":
			if a, ok := parseSudoAlias(text, ln.Line); ok {
				doc.Aliases = append(doc.Aliases, a...)
				continue
			}
			doc.Issues = append(doc.Issues, trustfreeze.Diagnostic{
				Code:    privDiagRecordUnparsed,
				Message: fmt.Sprintf("line %d: alias definition without a name and members", ln.Line),
			})
		default:
			r, err := parseSudoRule(text, ln.Line)
			if err != nil {
				doc.Issues = append(doc.Issues, trustfreeze.Diagnostic{
					Code:    privDiagRecordUnparsed,
					Message: fmt.Sprintf("line %d: %s", ln.Line, err.Error()),
				})
				continue
			}
			doc.Rules = append(doc.Rules, r)
		}
	}
	return doc
}

func parseSudoInclude(text string, line int) (SudoInclude, bool) {
	for _, pfx := range []string{"#includedir", "@includedir", "#include", "@include"} {
		if !strings.HasPrefix(text, pfx) {
			continue
		}
		rest := strings.TrimSpace(text[len(pfx):])
		if rest == "" {
			return SudoInclude{}, false
		}
		return SudoInclude{Line: line, Path: strings.Trim(rest, `"`), Dir: strings.HasSuffix(pfx, "dir")}, true
	}
	return SudoInclude{}, false
}

// parseSudoDefaults reads one Defaults line. Several settings may share a
// line, separated by commas.
func parseSudoDefaults(text string, line int) []SudoDefault {
	rest := strings.TrimPrefix(text, "Defaults")
	// Defaults@host, Defaults:user, Defaults>runas and Defaults!command bind
	// the settings to a scope; the scope itself is not recorded.
	if rest != "" && strings.ContainsAny(rest[:1], "@:>!") {
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			rest = rest[i:]
		} else {
			rest = ""
		}
	}
	var out []SudoDefault
	for _, part := range sudoSplitOutsideQuotes(rest, ',') {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value := part, ""
		if i := strings.IndexAny(part, "=+-"); i > 0 {
			name = strings.TrimSpace(part[:i])
			value = strings.Trim(strings.TrimSpace(strings.TrimLeft(part[i:], "=+-")), `"`)
		}
		out = append(out, SudoDefault{Line: line, Name: name, Value: value})
	}
	return out
}

// sudoSplitOutsideQuotes splits on sep, but never inside a double quoted
// value. "Defaults env_keep += \"LANG,LC_ALL\"" is one setting whose value
// carries commas, not three settings (defaults_count is a compared
// attribute, so the wrong number would read as drift).
func sudoSplitOutsideQuotes(s string, sep byte) []string {
	var (
		out   []string
		start int
		quote bool
	)
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '"':
			quote = !quote
		case s[i] == sep && !quote:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// Alias resolution. A sudoers file may name a rule's users, runas targets and
// commands through aliases it defines itself, and the grant a rule carries is
// only visible once they are resolved: "Cmnd_Alias MAINT = ALL" plus
// "ADMINS ALL=(ALL) NOPASSWD: MAINT" grants unrestricted passwordless root
// while no token of the rule says ALL. The resolution happens inside one file,
// which is where sudoers puts an alias in practice; an alias this file does
// not define stays in the list and is recorded as an unresolved alias, so the
// gap is visible rather than silently granting nothing (SPEC-0471 TF06-R3).
const (
	sudoAliasUser  = "User_Alias"
	sudoAliasRunas = "Runas_Alias"
	sudoAliasCmnd  = "Cmnd_Alias"
)

// sudoAliasMaxDepth bounds nested aliases, so a file that defines an alias in
// terms of itself cannot loop.
const sudoAliasMaxDepth = 8

// aliasTable indexes the alias definitions of the document by kind and name.
func (d SudoersDoc) aliasTable() map[string]map[string][]string {
	out := map[string]map[string][]string{}
	for _, a := range d.Aliases {
		if out[a.Kind] == nil {
			out[a.Kind] = map[string][]string{}
		}
		out[a.Kind][a.Name] = a.Members
	}
	return out
}

// withAliases returns d with the alias definitions of every rule file this
// capture read. sudo keeps one alias namespace over /etc/sudoers and every
// drop-in, so a rule in a drop-in grants what an alias of the main file
// expands to (O-T5). The document's own definitions come last, so a name a
// file defines itself decides for that file's rules.
func (d SudoersDoc) withAliases(all []SudoAlias) SudoersDoc {
	if len(all) == 0 {
		return d
	}
	merged := make([]SudoAlias, 0, len(all)+len(d.Aliases))
	merged = append(merged, all...)
	merged = append(merged, d.Aliases...)
	d.Aliases = merged
	return d
}

// sudoLooksLikeAlias reports whether a token has the shape of an alias name:
// sudoers requires upper case letters, digits and underscores, starting with
// an upper case letter. ALL is the keyword, not an alias.
func sudoLooksLikeAlias(tok string) bool {
	if tok == "" || tok == SudoAll || strings.ContainsAny(tok, "/ %+#") {
		return false
	}
	if tok[0] < 'A' || tok[0] > 'Z' {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		default:
			return false
		}
	}
	return true
}

// ExpandAliases resolves the alias names in list against the aliases of kind
// that this document defines. It returns the expanded list, the alias names
// it resolved and the alias shaped tokens it could not resolve, each sorted
// and free of duplicates. It never invents a member: an unresolved token
// stays in the expanded list exactly as the file spelled it.
func (d SudoersDoc) ExpandAliases(kind string, list []string) (expanded, resolved, unresolved []string) {
	table := d.aliasTable()[kind]
	var walk func(items []string, depth int)
	seen := map[string]bool{}
	walk = func(items []string, depth int) {
		for _, tok := range items {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			members, ok := table[tok]
			switch {
			case ok && depth < sudoAliasMaxDepth && !seen[kind+"\x00"+tok]:
				seen[kind+"\x00"+tok] = true
				resolved = privAppendUnique(resolved, tok)
				walk(members, depth+1)
			case ok:
				// Depth limit or a cycle: the token stays as it is and is
				// reported, never expanded further.
				unresolved = privAppendUnique(unresolved, tok)
				expanded = privAppendUnique(expanded, tok)
			case sudoLooksLikeAlias(tok):
				unresolved = privAppendUnique(unresolved, tok)
				expanded = privAppendUnique(expanded, tok)
			default:
				expanded = privAppendUnique(expanded, tok)
			}
		}
	}
	walk(list, 0)
	sort.Strings(resolved)
	sort.Strings(unresolved)
	return expanded, resolved, unresolved
}

// RuleUsers returns the principals a rule grants, with the User_Alias names
// of this file resolved.
func (d SudoersDoc) RuleUsers(r SudoRule) []string {
	users, _, _ := d.ExpandAliases(sudoAliasUser, r.Users)
	return users
}

// RuleCommands returns the command list of a rule with the Cmnd_Alias names
// of this file resolved.
func (d SudoersDoc) RuleCommands(r SudoRule) []string {
	cmds, _, _ := d.ExpandAliases(sudoAliasCmnd, r.Commands)
	return cmds
}

// RuleGrantsAllCommands reports whether the rule grants the ALL command set
// once the command aliases of this file are resolved. SudoRule.AllCommands
// compares the literal token and cannot see an alias that expands to ALL.
func (d SudoersDoc) RuleGrantsAllCommands(r SudoRule) bool {
	for _, cmd := range d.RuleCommands(r) {
		if cmd == SudoAll {
			return true
		}
	}
	return false
}

// RuleRunsAsRoot reports whether the rule lets the command run as root, with
// the Runas_Alias names of this file resolved.
func (d SudoersDoc) RuleRunsAsRoot(r SudoRule) bool {
	if len(r.RunAsUsers) == 0 {
		return true
	}
	users, _, _ := d.ExpandAliases(sudoAliasRunas, r.RunAsUsers)
	for _, u := range users {
		if u == "root" || u == SudoAll {
			return true
		}
	}
	return false
}

// RuleAliasGaps returns the alias shaped tokens of a rule that no alias
// definition in this file explains, in the order users, runas, commands.
func (d SudoersDoc) RuleAliasGaps(r SudoRule) (resolved, unresolved []string) {
	for _, pair := range []struct {
		kind string
		list []string
	}{
		{sudoAliasUser, r.Users},
		{sudoAliasRunas, r.RunAsUsers},
		{sudoAliasCmnd, r.Commands},
	} {
		_, res, un := d.ExpandAliases(pair.kind, pair.list)
		for _, x := range res {
			resolved = privAppendUnique(resolved, x)
		}
		for _, x := range un {
			// A user entry that looks like an alias may also be an upper case
			// account name, which is legal on Linux; only a command entry can
			// be nothing but ALL or a Cmnd_Alias. The resolver decides the
			// user side against the account artifacts (capability.go).
			if pair.kind == sudoAliasCmnd {
				unresolved = privAppendUnique(unresolved, x)
			}
		}
	}
	sort.Strings(resolved)
	sort.Strings(unresolved)
	return resolved, unresolved
}

var sudoAliasKinds = []string{"User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias"}

func sudoAliasKind(text string) string {
	for _, k := range sudoAliasKinds {
		if strings.HasPrefix(text, k) && len(text) > len(k) && (text[len(k)] == ' ' || text[len(k)] == '\t') {
			return k
		}
	}
	return ""
}

// parseSudoAlias reads one alias definition line. Several aliases of the same
// kind may share a line, separated by ":".
func parseSudoAlias(text string, line int) ([]SudoAlias, bool) {
	kind := sudoAliasKind(text)
	rest := strings.TrimSpace(text[len(kind):])
	var out []SudoAlias
	for _, part := range strings.Split(rest, ":") {
		name, members, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out = append(out, SudoAlias{Line: line, Kind: kind, Name: name, Members: privSplitList(members)})
	}
	return out, len(out) > 0
}

// parseSudoRule reads one user specification.
func parseSudoRule(text string, line int) (SudoRule, error) {
	left, right, ok := strings.Cut(text, "=")
	if !ok {
		return SudoRule{}, errors.New("user specification without \"=\"")
	}
	left = strings.TrimSpace(left)
	fields := strings.Fields(left)
	if len(fields) < 2 {
		return SudoRule{}, errors.New("user specification without a host list")
	}
	r := SudoRule{
		Line:  line,
		Users: privSplitList(strings.Join(fields[:len(fields)-1], " ")),
		Hosts: privSplitList(fields[len(fields)-1]),
	}
	rest := strings.TrimSpace(right)
	if strings.HasPrefix(rest, "(") {
		inner, after, closed := strings.Cut(rest[1:], ")")
		if !closed {
			return SudoRule{}, errors.New("runas specification without a closing parenthesis")
		}
		user, group, hasGroup := strings.Cut(inner, ":")
		r.RunAsUsers = privSplitList(user)
		if hasGroup {
			r.RunAsGroups = privSplitList(group)
		}
		rest = strings.TrimSpace(after)
	}
	for {
		tag, after, ok := strings.Cut(rest, ":")
		tag = strings.TrimSpace(tag)
		if !ok || tag == "" || !sudoIsTag(tag) {
			break
		}
		r.Tags = append(r.Tags, strings.ToUpper(tag))
		rest = strings.TrimSpace(after)
	}
	// sudoers spells several host specifications as
	// "user host1 = cmds : host2 = cmds", so a further "=" is a second host
	// specification only where a ":" separator stands before it. An "=" with
	// no colon in front of it belongs to a command, for example
	// "/usr/bin/env FOO=bar", and the rule is read as written.
	if i := strings.IndexByte(rest, '='); i >= 0 && strings.IndexByte(rest[:i], ':') >= 0 {
		return SudoRule{}, errors.New("several host specifications in one rule are not parsed")
	}
	r.Commands = privSplitList(rest)
	if len(r.Commands) == 0 {
		return SudoRule{}, errors.New("user specification without a command list")
	}
	return r, nil
}

var sudoTags = map[string]bool{
	SudoTagNoPasswd: true, SudoTagPasswd: true, SudoTagSetEnv: true, SudoTagNoSetEnv: true,
	SudoTagNoExec: true, SudoTagExec: true, "LOG_INPUT": true, "NOLOG_INPUT": true,
	"LOG_OUTPUT": true, "NOLOG_OUTPUT": true, "MAIL": true, "NOMAIL": true,
	"FOLLOW": true, "NOFOLLOW": true, "INTERCEPT": true, "NOINTERCEPT": true,
}

func sudoIsTag(s string) bool { return sudoTags[strings.ToUpper(s)] }

// StatInfo is the metadata of one path: mode in octal, owner, group and
// size. Known is false when no source reported the path.
type StatInfo struct {
	Known bool
	Mode  string
	Owner string
	Group string
	Size  string
}

// apply writes the known fields into an attribute map.
func (s StatInfo) apply(attrs map[string]string) {
	if !s.Known {
		return
	}
	for k, v := range map[string]string{privAttrMode: s.Mode, privAttrOwner: s.Owner, privAttrGroup: s.Group, privAttrSize: s.Size} {
		if v != "" {
			attrs[k] = v
		}
	}
}

// ParseStat reads the output of "stat -c %n %a %U %G %s <path>...": one line
// per path, the name first and four fields after it. The name is taken from
// the left, so a path with spaces survives.
//
// Like its siblings it checks the shape before it believes a line: the mode
// must be an octal number and the size a decimal one. Without that check any
// five-field line becomes a record, and a tool diagnostic that reached stdout
// would be read as file metadata (O-T4).
func ParseStat(b []byte) (map[string]StatInfo, []trustfreeze.Diagnostic) {
	out := map[string]StatInfo{}
	var diags []trustfreeze.Diagnostic
	bad := func(i int, why string) {
		diags = append(diags, trustfreeze.Diagnostic{
			Code:    privDiagRecordUnparsed,
			Message: fmt.Sprintf("stat line %d: %s", i+1, why),
		})
	}
	for i, line := range privLines(b) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			bad(i, "fewer than five fields")
			continue
		}
		n := len(fields)
		mode, owner, group, size := fields[n-4], fields[n-3], fields[n-2], fields[n-1]
		if _, err := strconv.ParseUint(mode, 8, 32); err != nil {
			bad(i, "the mode field is not an octal number")
			continue
		}
		if _, err := strconv.ParseUint(size, 10, 64); err != nil {
			bad(i, "the size field is not a number")
			continue
		}
		out[strings.Join(fields[:n-4], " ")] = StatInfo{
			Known: true,
			Mode:  privOctalMode(mode),
			Owner: owner,
			Group: group,
			Size:  size,
		}
	}
	return out, diags
}

// privOctalMode spells a stat "%a" mode with four digits, so 440 and 0440 are
// the same string in two captures of the same host (playbook L8).
func privOctalMode(s string) string {
	if s == "" {
		return ""
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return s
	}
	return fmt.Sprintf("%04o", v)
}

// LsEntry is one line of a long directory listing ("ls -la"). The three date
// columns are deliberately dropped: a modification time is volatile and would
// create drift without a change of substance (playbook L8).
type LsEntry struct {
	// Mode is the symbolic mode as ls printed it, for example "-r--r-----".
	Mode  string
	Owner string
	Group string
	// Size is the size field; empty for a device node, which prints a major
	// and a minor number instead.
	Size string
	Name string
	// LinkTarget is the text after " -> " of a symlink line.
	LinkTarget string
	IsDir      bool
	IsSymlink  bool
}

// statInfo converts the listing fields into the same shape stat produces.
func (e LsEntry) statInfo() (StatInfo, bool) {
	mode, ok := ParseSymbolicMode(e.Mode)
	if !ok {
		return StatInfo{}, false
	}
	return StatInfo{Known: true, Mode: mode, Owner: e.Owner, Group: e.Group, Size: e.Size}, true
}

// ParseLsLong reads the output of "ls -la": one entry per line after the
// "total" header, with "." and ".." dropped. It is pure and tolerant: a line
// it cannot read becomes a diagnostic, never a guess.
func ParseLsLong(b []byte) ([]LsEntry, []trustfreeze.Diagnostic) {
	var (
		out   []LsEntry
		diags []trustfreeze.Diagnostic
	)
	for i, line := range privLines(b) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "total ") {
			continue
		}
		fields := privFieldsN(line, 9)
		if len(fields) < 9 {
			diags = append(diags, trustfreeze.Diagnostic{
				Code:    privDiagRecordUnparsed,
				Message: fmt.Sprintf("listing line %d: fewer than nine fields", i+1),
			})
			continue
		}
		size := fields[4]
		name := fields[8]
		if strings.HasSuffix(size, ",") {
			// A device node prints "major, minor" where a file prints its
			// size, which shifts the name one field to the right.
			shifted := privFieldsN(line, 10)
			if len(shifted) < 10 {
				diags = append(diags, trustfreeze.Diagnostic{
					Code:    privDiagRecordUnparsed,
					Message: fmt.Sprintf("listing line %d: device entry without a name", i+1),
				})
				continue
			}
			size, name = "", shifted[9]
		}
		e := LsEntry{Mode: fields[0], Owner: fields[2], Group: fields[3], Size: size, Name: name}
		e.IsDir = strings.HasPrefix(e.Mode, "d")
		e.IsSymlink = strings.HasPrefix(e.Mode, "l")
		if e.IsSymlink {
			if n, t, ok := strings.Cut(e.Name, " -> "); ok {
				e.Name, e.LinkTarget = n, t
			}
		}
		if e.Name == "." || e.Name == ".." || e.Name == "" {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, diags
}

// ParseSymbolicMode converts an "ls -l" mode such as "-r--r-----" or
// "drwxr-xr-x." into four octal digits. The trailing "." or "+" of an SELinux
// context or an ACL is ignored. ok is false for anything else.
func ParseSymbolicMode(s string) (string, bool) {
	s = strings.TrimRight(s, ".+")
	if len(s) != 10 {
		return "", false
	}
	var mode uint32
	bits := []struct {
		i  int
		ch byte
		v  uint32
	}{
		{1, 'r', 0400}, {2, 'w', 0200},
		{4, 'r', 0040}, {5, 'w', 0020},
		{7, 'r', 0004}, {8, 'w', 0002},
	}
	for _, b := range bits {
		if s[b.i] == b.ch {
			mode |= b.v
		}
	}
	// The execute positions also carry setuid, setgid and the sticky bit.
	special := []struct {
		i    int
		exec uint32
		sp   uint32
		low  byte
		up   byte
	}{
		{3, 0100, 04000, 's', 'S'},
		{6, 0010, 02000, 's', 'S'},
		{9, 0001, 01000, 't', 'T'},
	}
	for _, sp := range special {
		switch s[sp.i] {
		case 'x':
			mode |= sp.exec
		case sp.low:
			mode |= sp.exec | sp.sp
		case sp.up:
			mode |= sp.sp
		case '-':
		default:
			return "", false
		}
	}
	return fmt.Sprintf("%04o", mode), true
}

// listDir enumerates dir with "ls -la" and keeps the output as evidence.
func (c *privCollector) listDir(dir, evidence string) ([]LsEntry, privState, string) {
	r := c.run(sudoListTool, "-la", dir)
	switch {
	case r.State != privOK:
		return nil, r.State, "ls -la " + dir + ": " + r.Detail
	case r.ExitCode != 0:
		st := privFailed
		detail := fmt.Sprintf("ls -la %s: exit status %d", dir, r.ExitCode)
		if line := privFirstLine(r.Stderr); line != "" {
			detail += ": " + line
			if privLooksDenied(line) {
				st = privPermissionDenied
			} else if privLooksMissing(line) {
				st = privUnavailable
			}
		}
		return nil, st, detail
	}
	c.addEvidence(evidence+"-listing.txt", "stdout:ls", r.StdoutData, r.StdoutTruncated)
	c.addSource("command:ls -la " + dir)
	entries, diags := ParseLsLong(r.Stdout)
	st := privOK
	for _, d := range diags {
		c.warn(d.Code, dir, d.Message)
		st = privPartial
	}
	return entries, st, ""
}

// statPaths asks stat for the mode, owner, group and size of every path. A
// missing path makes stat exit non-zero while the other lines are still
// printed, so the output is parsed whatever the exit code says. ran is false
// when stat itself could not run, so a caller cannot read an empty result as
// "the path does not exist".
func (c *privCollector) statPaths(paths []string) (info map[string]StatInfo, ran bool) {
	if len(paths) == 0 {
		return map[string]StatInfo{}, false
	}
	args := append([]string{"-c", "%n %a %U %G %s"}, paths...)
	r := c.run(sudoStatTool, args...)
	if r.State != privOK {
		c.warn(privStateCode(r.State), sudoStatTool, "stat: "+r.Detail)
		return map[string]StatInfo{}, false
	}
	out, diags := ParseStat(r.Stdout)
	for _, d := range diags {
		c.warn(d.Code, sudoStatTool, d.Message)
	}
	if len(out) > 0 {
		c.addEvidence("stat.txt", "stdout:stat", r.StdoutData, r.StdoutTruncated)
		c.addSource("command:stat")
	}
	return out, true
}

// privEvidenceName turns a path into a single evidence file name.
func privEvidenceName(fp string) string {
	name := strings.TrimPrefix(strings.ReplaceAll(strings.TrimPrefix(fp, "/"), "/", "-"), "etc-")
	if name == "" {
		name = "file"
	}
	return name + ".txt"
}

// privLogicalLine is one line after backslash continuation has been joined.
type privLogicalLine struct {
	// Line is the number of the first physical line, counted from 1.
	Line int
	// Lines is how many physical lines were joined.
	Lines int
	Text  string
}

// privLogicalLines splits b into lines and joins a line whose last character
// is a backslash with the line that follows it.
func privLogicalLines(b []byte) []privLogicalLine {
	var out []privLogicalLine
	cur := ""
	start, count := 0, 0
	for i, line := range privLines(b) {
		if count == 0 {
			start = i + 1
		}
		count++
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, `\`) {
			cur += strings.TrimSuffix(trimmed, `\`)
			continue
		}
		out = append(out, privLogicalLine{Line: start, Lines: count, Text: cur + line})
		cur, count = "", 0
	}
	if count > 0 {
		out = append(out, privLogicalLine{Line: start, Lines: count, Text: cur})
	}
	return out
}

// privLines splits b into lines without the line terminators, tolerating both
// LF and CRLF, and without a trailing empty element.
func privLines(b []byte) []string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// privFieldsN splits s into at most n fields on runs of spaces and tabs; the
// last field keeps the rest of the line, so a name with spaces survives.
func privFieldsN(s string, n int) []string {
	var out []string
	for len(out) < n {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			break
		}
		if len(out) == n-1 {
			out = append(out, s)
			break
		}
		i := strings.IndexAny(s, " \t")
		if i < 0 {
			out = append(out, s)
			break
		}
		out = append(out, s[:i])
		s = s[i:]
	}
	return out
}

// privSplitList splits a comma separated sudoers list and drops empty
// entries. The "!" negation of an entry is kept, because a negated command is
// a different grant from the command itself.
func privSplitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func privJoin(v []string) string { return strings.Join(v, ",") }

// privCapList joins a list and cuts it at a comma boundary once it exceeds max
// bytes. cut says whether anything was dropped.
func privCapList(v []string, max int) (string, bool) {
	joined := privJoin(v)
	if len(joined) <= max {
		return joined, false
	}
	kept := joined[:max]
	if i := strings.LastIndexByte(kept, ','); i > 0 {
		kept = kept[:i]
	}
	return kept, true
}

func privBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func privFirstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// privLooksDenied and privLooksMissing read the diagnostic a tool printed.
// Both are only used where the runner reports no error of its own, that is
// where a tool ran and refused; the wording comes from the recorded fixtures
// ("cat: /etc/sudoers: Permission denied").
func privLooksDenied(s string) bool {
	return strings.Contains(strings.ToLower(s), "permission denied")
}

func privLooksMissing(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "no such file or directory")
}

// privState is the outcome of one input of a privilege probe.
type privState int

const (
	privOK privState = iota
	privPartial
	privUnavailable
	privPermissionDenied
	privTimeout
	privFailed
	privNotApplicable
)

var privStateCodes = map[privState]string{
	privPartial:          privDiagRecordUnparsed,
	privUnavailable:      probe.DiagFieldUnavailable,
	privPermissionDenied: probe.DiagFieldPermissionDenied,
	privTimeout:          probe.DiagFieldTimeout,
	privFailed:           probe.DiagFieldFailed,
	privNotApplicable:    probe.DiagFieldNotApplicable,
}

func privStateCode(st privState) string {
	if c, ok := privStateCodes[st]; ok {
		return c
	}
	return probe.DiagFieldFailed
}

// privStatus turns the per input states into the probe status. The precedence
// is the one common.identity uses (SPEC-0467 section 5.5): a privilege block
// outranks a timeout, a timeout outranks a missing tool, and anything unread
// leaves the probe partial. not_applicable never lowers the status.
func privStatus(states []privState, what string) (trustfreeze.ProbeStatus, string, *trustfreeze.ProbeError) {
	count := map[privState]int{}
	for _, s := range states {
		count[s]++
	}
	read := count[privOK] + count[privPartial] + count[privNotApplicable]
	switch {
	case count[privPermissionDenied] > 0:
		reason := "permission denied reading " + what
		return trustfreeze.StatusPermissionDenied, reason, &trustfreeze.ProbeError{Class: probe.ClassPermissionDenied, Message: reason}
	case count[privTimeout] > 0:
		reason := "timed out reading " + what
		return trustfreeze.StatusTimeout, reason, &trustfreeze.ProbeError{Class: probe.ClassTimeout, Message: reason}
	case count[privUnavailable] > 0 && read == 0:
		// Nothing was read at all: the sources of this probe are missing, and
		// that is what unavailable means (playbook L1).
		reason := "source missing for " + what
		return trustfreeze.StatusUnavailable, reason, &trustfreeze.ProbeError{Class: probe.ClassToolMissing, Message: reason}
	case count[privUnavailable] > 0:
		// One source is missing and the rest was read: the result is partial
		// with the gap named by the diagnostics, never unavailable over a
		// result that carries artifacts.
		return trustfreeze.StatusPartial, "not fully read: " + what + " (a source is missing)", nil
	case count[privFailed]+count[privPartial] > 0:
		return trustfreeze.StatusPartial, "not fully read: " + what, nil
	}
	return trustfreeze.StatusCaptured, "", nil
}

// privStream names which stream a tool writes its version banner to.
type privStream int

const (
	privStdout privStream = iota
	privStderr
)

// privRun is the outcome of one command run, already redacted by the runner.
type privRun struct {
	Stdout          []byte
	Stderr          []byte
	StdoutData      redact.Redacted
	StderrData      redact.Redacted
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int
	State           privState
	Detail          string
}

// privCollector is the shared bookkeeping of the two privilege probes
// (linux.sudo and linux.ssh): tool invocations, diagnostics, sources and
// recorded tool versions of one Collect call.
type privCollector struct {
	ctx      context.Context
	cc       probe.CollectContext
	tools    []trustfreeze.ToolInvocation
	warnings []trustfreeze.Diagnostic
	sources  []string
	versions map[string]string
	now      string
	// truncated says that a byte cap cut the output of at least one run of
	// this probe, so the result is partial whatever the inputs say.
	truncated bool
}

// extraStates returns the states that belong to the collector itself rather
// than to one input, so the caller folds them into privStatus.
func (c *privCollector) extraStates() []privState {
	if c.truncated {
		return []privState{privPartial}
	}
	return nil
}

func newPrivCollector(ctx context.Context, cc probe.CollectContext) *privCollector {
	return &privCollector{ctx: ctx, cc: cc, versions: map[string]string{}, now: trustfreeze.FormatTime(cc.Now())}
}

// run runs one command through the injected runner. A non-zero exit is not an
// error: the caller decides what it means.
func (c *privCollector) run(exe string, args ...string) privRun {
	res := c.cc.Runner.Run(c.ctx, probe.CommandRequest{Executable: exe, Args: args, Redactor: c.cc.Redactor})
	inv := res.Invocation()
	if v := c.versions[exe]; v != "" {
		inv.ToolVersion = v
	}
	c.tools = append(c.tools, inv)
	out := privRun{
		Stdout: res.Stdout.Bytes(), Stderr: res.Stderr.Bytes(),
		StdoutData: res.Stdout, StderrData: res.Stderr,
		StdoutTruncated: res.StdoutTruncated, StderrTruncated: res.StderrTruncated,
		ExitCode: res.ExitCode,
	}
	switch {
	case res.Err != nil:
		out.State, out.Detail = privCommandState(res.Err), res.Err.Error()
	case res.RedactionFailed:
		out.State, out.Detail = privFailed, "output could not be redacted and was dropped"
	default:
		out.State = privOK
	}
	// A cut stream is a cut answer: the diagnostic names the stream and the
	// cap, and the run is recorded so that the probe status drops to partial
	// instead of reporting a prefix as the whole truth (F1).
	outCap, errCap := outputCap(c.cc)
	if res.StdoutTruncated {
		c.truncated = true
		c.warn(trustfreeze.DiagOutputTruncated, exe, truncationNote(exe, "stdout", len(out.Stdout), res.StdoutBytes, outCap,
			"what the tool printed beyond the cut was not read"))
	}
	if res.StderrTruncated {
		c.truncated = true
		c.warn(trustfreeze.DiagOutputTruncated, exe, truncationNote(exe, "stderr", len(out.Stderr), res.StderrBytes, errCap,
			"the recorded cause of the failure is incomplete"))
	}
	return out
}

// recordVersion asks exe for its version and keeps the first line (playbook
// L7). sshd prints its banner on stderr, so the caller names the stream. An
// unknown version becomes a diagnostic, never a guess.
func (c *privCollector) recordVersion(exe string, args []string, stream privStream) string {
	r := c.run(exe, args...)
	out := r.Stdout
	if stream == privStderr {
		out = r.Stderr
	}
	switch {
	case r.State != privOK:
		c.warn(privStateCode(r.State), "tool_version", exe+": "+r.Detail)
		return ""
	case r.ExitCode != 0:
		c.warn(probe.DiagFieldFailed, "tool_version", fmt.Sprintf("%s: exit status %d", exe, r.ExitCode))
		return ""
	}
	v := privFirstLine(out)
	if v == "" {
		c.warn(trustfreeze.DiagFieldMissing, "tool_version", exe+": empty version output")
		return ""
	}
	c.versions[exe] = v
	c.tools[len(c.tools)-1].ToolVersion = v
	return v
}

// readFile reads one file through the restricted reader.
func (c *privCollector) readFile(fp string) ([]byte, privState, string) {
	b, err := c.cc.ReadFile(fp)
	if err == nil {
		c.addSource("file:" + fp)
		return b, privOK, ""
	}
	st, detail := privFileState(err)
	return nil, st, fp + ": " + detail
}

// redactFile redacts file bytes before they may be persisted as evidence.
// A redaction failure drops the evidence (fail-closed, SPEC-0467 R5).
func (c *privCollector) redactFile(fp string, raw []byte) (redact.Redacted, bool) {
	rr, err := c.cc.Redactor.RedactBytes(c.ctx, redact.EvidenceDescriptor{
		ProbeID: c.cc.ProbeID, Name: privEvidenceName(fp), Source: "file:" + fp,
	}, raw)
	if err != nil {
		c.warn(trustfreeze.DiagRedactionFailed, fp, "content could not be redacted; evidence dropped")
		return redact.Redacted{}, false
	}
	return rr.Data, true
}

func (c *privCollector) addEvidence(name, source string, data redact.Redacted, truncated bool) {
	if _, err := c.cc.AddEvidence(name, source, data, truncated); err != nil {
		c.warn(probe.DiagEvidenceDropped, "", name+": "+err.Error())
	}
}

func (c *privCollector) warn(code, field, msg string) {
	c.warnings = append(c.warnings, trustfreeze.Diagnostic{Code: code, Field: field, Message: msg})
}

func (c *privCollector) addSource(s string) {
	for _, x := range c.sources {
		if x == s {
			return
		}
	}
	c.sources = append(c.sources, s)
}

// artifact builds one artifact with its digest already computed.
func (c *privCollector) artifact(id, typ, scope string, state trustfreeze.EvidenceState,
	attrs map[string]string, method string, conf trustfreeze.Confidence, sources []string,
	toolVersion string, sens trustfreeze.Sensitivity,
) trustfreeze.Artifact {
	src := append([]string(nil), sources...)
	sort.Strings(src)
	a := trustfreeze.Artifact{
		ID: id, Type: typ, Scope: scope, Source: c.cc.ProbeID, State: state,
		Attributes: attrs,
		Provenance: trustfreeze.Provenance{
			Method: method, Confidence: conf, Sources: src,
			ObservedAt: c.now, ToolVersion: toolVersion,
		},
		Sensitivity: sens,
	}
	if d, err := trustfreeze.ComputeArtifactDigest(a); err == nil {
		a.Digest = d
	} else {
		c.warn(probe.DiagArtifactDropped, id, "digest could not be computed: "+err.Error())
	}
	return a
}

// declareConfigAttrs records what this probe knows about its own fields: the
// named attributes hold configuration, never a credential (SPEC-0467 section
// 5.2), so the generic key name rule of the redactor does not apply to them.
// Only the names that rule would take for a credential are recorded, because
// only there does the class change what redaction does; the artifact stays
// small and the declaration stays a statement about a real risk. Every value
// pattern still applies, so a key body under one of these names is still
// removed. The artifact digest covers identity and attributes, not the
// classes, so it does not change here.
func (c *privCollector) declareConfigAttrs(a trustfreeze.Artifact, names []string) trustfreeze.Artifact {
	var classes map[string]trustfreeze.AttributeClass
	for _, n := range names {
		if _, ok := a.Attributes[n]; !ok {
			continue
		}
		if _, sensitive := redact.SensitiveKeyClass(n); !sensitive {
			continue
		}
		if classes == nil {
			classes = map[string]trustfreeze.AttributeClass{}
		}
		classes[n] = trustfreeze.AttributeClassPolicy
	}
	a.AttributeClasses = classes
	return a
}

// finish sorts the artifacts, drops the invalid ones and fills the result.
func (c *privCollector) finish(res trustfreeze.ProbeResult, arts []trustfreeze.Artifact, start time.Time) trustfreeze.ProbeResult {
	kept := make([]trustfreeze.Artifact, 0, len(arts))
	seen := map[string]bool{}
	for _, a := range arts {
		switch {
		case trustfreeze.ValidateArtifactID(a.ID) != nil:
			c.warn(probe.DiagArtifactDropped, a.ID, "invalid artifact id")
		case seen[a.ID]:
			c.warn(probe.DiagArtifactDropped, a.ID, "duplicate artifact id")
		default:
			seen[a.ID] = true
			kept = append(kept, a)
		}
	}
	trustfreeze.SortArtifacts(kept)
	res.NormalizedState = kept
	res.Tools = c.tools
	res.Warnings = c.warnings
	res.DurationMS = c.cc.Now().Sub(start).Milliseconds()
	return res
}

// privBaseResult is the skeleton of a probe result; the engine overwrites the
// recorded fields with what it observed itself.
func privBaseResult(id, version string, cc probe.CollectContext, start time.Time) trustfreeze.ProbeResult {
	return trustfreeze.ProbeResult{
		ProbeID:      id,
		ProbeVersion: version,
		Support:      cc.Support.Record(),
		StartedAt:    trustfreeze.FormatTime(start),
		Privilege:    cc.Privilege,
	}
}

func privCommandState(err error) privState {
	switch {
	case errors.Is(err, probe.ErrToolMissing):
		return privUnavailable
	case errors.Is(err, probe.ErrPermissionDenied):
		return privPermissionDenied
	case errors.Is(err, probe.ErrTimeout):
		return privTimeout
	}
	return privFailed
}

func privFileState(err error) (privState, string) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return privUnavailable, "file does not exist"
	case errors.Is(err, fs.ErrPermission):
		return privPermissionDenied, "permission denied"
	case errors.Is(err, probe.ErrOutsideRoots):
		return privNotApplicable, "path is outside the roots this capture may read"
	case errors.Is(err, probe.ErrLimitExceeded):
		return privFailed, "file is larger than the probe limit"
	case errors.Is(err, context.DeadlineExceeded):
		return privTimeout, "timed out"
	}
	return privFailed, err.Error()
}
